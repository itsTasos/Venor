#include "decompiler.h"
#include <algorithm>
#include <stdexcept>
#include <windows.h>

namespace vnr {
namespace {
quint64 address(const QJsonValue &value, bool empty = false) {
    auto text = value.toString();
    if (empty && text.isEmpty())
        return 0;
    bool ok = false;
    auto n = text.mid(2).toULongLong(&ok, 16);
    if (!text.startsWith("0x") || !ok || text.size() > 18)
        throw std::runtime_error("Invalid Ghidra address");
    return n;
}
QJsonObject readJson(QString path, qint64 limit = 16 * 1024 * 1024) {
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly) || f.size() > limit)
        throw std::runtime_error("Missing or oversized Ghidra response");
    QJsonParseError error;
    auto doc = QJsonDocument::fromJson(f.readAll(), &error);
    if (error.error != QJsonParseError::NoError || !doc.isObject())
        throw std::runtime_error("Malformed Ghidra response");
    return doc.object();
}
void writeJson(QString path, QJsonObject object) {
    QSaveFile f(path);
    auto bytes = QJsonDocument(object).toJson(QJsonDocument::Compact);
    if (!f.open(QIODevice::WriteOnly) || f.write(bytes) != bytes.size() || !f.commit())
        throw std::runtime_error("Cannot write local Ghidra request/cache");
}
QString scriptDirectory() {
    auto installed = QCoreApplication::applicationDirPath() + "/ghidra";
    if (QFileInfo::exists(installed + "/VenorWorker.java"))
        return installed;
    return QStringLiteral(VENOR_GHIDRA_SCRIPTS);
}
} // namespace
bool RecoveredFunction::contains(quint64 address) const {
    for (auto range : ranges)
        if (address >= range.first && address <= range.second)
            return true;
    return false;
}
GhidraConfig GhidraConfig::load() {
    QSettings s;
    return {
        qEnvironmentVariable("VENOR_GHIDRA_HOME", s.value("decompiler/home").toString()),
        qEnvironmentVariable("VENOR_JAVA_HOME",
                             s.value("decompiler/javaHome", qEnvironmentVariable("JAVA_HOME")).toString())};
}
QString GhidraConfig::error() const {
    if (!QFileInfo::exists(home + "/support/analyzeHeadless.bat") ||
        !QFileInfo::exists(home + "/Ghidra/Framework/Utility/lib/Utility.jar"))
        return "Choose an extracted Ghidra installation (tested with 12.1.4). Assembly and debugging remain "
               "available.";
    if (!QFileInfo::exists(javaHome + "/bin/java.exe") || !QFileInfo::exists(javaHome + "/bin/javac.exe"))
        return "Choose a supported 64-bit JDK, not a JRE (Ghidra 12.1.4 requires JDK 21 or newer).";
    return {};
}
void GhidraConfig::save() const {
    QSettings s;
    s.setValue("decompiler/home", home);
    s.setValue("decompiler/javaHome", javaHome);
}
std::optional<quint64> preferredAddress(const Binary &binary, quint64 a, bool runtime,
                                        const QVector<Row> &modules) {
    if (!runtime) {
        if (a >= binary.base && a - binary.base < binary.imageSize)
            return a;
        return {};
    }
    for (const auto &module : modules) {
        // DbgEng reports the image path; refuse unrelated modules and out-of-image addresses.
        if (QFileInfo(module.name)
                    .fileName()
                    .compare(QFileInfo(binary.path).fileName(), Qt::CaseInsensitive) == 0 &&
            a >= module.address && a - module.address < binary.imageSize)
            return binary.base + (a - module.address);
    }
    return {};
}
bool matchingRuntimeBytes(const Binary &binary, const QVector<Instruction> &code, quint64 runtimeBase,
                          const RecoveredFunction &function, QString *reason) {
    bool matched = false;
    for (const auto &i : code) {
        if (i.address < runtimeBase || i.address - runtimeBase >= binary.imageSize)
            continue;
        auto va = binary.base + i.address - runtimeBase;
        if (!function.contains(va))
            continue;
        if (i.bytes.isEmpty() || binary.bytesAt(va, i.bytes.size()) != i.bytes) {
            if (reason)
                *reason = "Runtime bytes differ from the file (patching, unpacking or relocations). On-disk "
                          "pseudocode is withheld.";
            return false;
        }
        matched = true;
    }
    if (!matched && reason)
        *reason = "No captured bytes from this recovered function are available for comparison.";
    return matched;
}
DecompilerService::DecompilerService(QObject *parent) : QObject(parent) {
    qRegisterMetaType<DecompiledFunction>();
    poll.setInterval(60);
    deadline.setSingleShot(true);
    connect(&poll, &QTimer::timeout, this, &DecompilerService::tick);
    connect(&deadline, &QTimer::timeout, this, [this] {
        fail("Ghidra exceeded its analysis/request deadline. Retry or choose a smaller function.");
    });
    connect(&process, &QProcess::readyReadStandardOutput, this, [this] {
        log += QString::fromUtf8(process.readAllStandardOutput());
        if (log.size() > 12000)
            log = log.right(12000);
    });
    process.setProcessChannelMode(QProcess::MergedChannels);
    connect(&process, &QProcess::errorOccurred, this, [this](QProcess::ProcessError error) {
        if (!closing && error == QProcess::FailedToStart)
            fail("Cannot launch the configured JDK: " + process.errorString());
    });
    connect(&process, &QProcess::finished, this, [this](int exit, QProcess::ExitStatus state) {
        if (closing || phase == Closed)
            return;
        if (phase == Importing && exit == 0 && state == QProcess::NormalExit) {
            try {
                loadIndex();
                writeJson(cacheDir + "/complete.json",
                          {{"schema", 1}, {"hash", image->hash}, {"project", project}});
                start(false);
            } catch (const std::exception &e) {
                fail(QString::fromUtf8(e.what()) + "\n" + log.right(3000));
            }
        } else
            fail("Ghidra worker exited unexpectedly.\n" + log.right(5000));
    });
}
DecompilerService::~DecompilerService() {
    close();
}
void DecompilerService::close() {
    closing = true;
    poll.stop();
    deadline.stop();
    pending.reset();
    if (session) {
        QFile f(session->filePath("stop"));
        f.open(QIODevice::WriteOnly);
    }
    if (phase == Ready && !active && process.state() != QProcess::NotRunning)
        process.waitForFinished(700); // Let the read-only headless session release its project lock normally.
    if (process.state() != QProcess::NotRunning) {
        // No shell is involved; kill only this worker's process tree, including its native decompiler.
        QProcess killer;
        killer.start(qEnvironmentVariable("SystemRoot") + "/System32/taskkill.exe",
                     {"/PID", QString::number(process.processId()), "/T", "/F"});
        killer.waitForFinished(3000);
        process.kill();
        process.waitForFinished(1000);
    }
    phase = Closed;
    active = false;
    recovered.clear();
    image.reset();
    session.reset();
    lock.reset();
    analysisWarning.clear();
    closing = false;
}
void DecompilerService::fail(QString text) {
    close();
    failure = text;
    emit busyChanged(false);
    emit failed(text);
}
void DecompilerService::open(std::shared_ptr<Binary> binary, GhidraConfig settings) {
    close();
    image = std::move(binary);
    config = std::move(settings);
    failure.clear();
    if (!image)
        return;
    if (!(failure = config.error()).isEmpty()) {
        emit failed(failure);
        return;
    }
    try {
        scripts = scriptDirectory();
        QByteArray version("venor-ghidra-v4");
        for (const auto &file : {"VenorIndex.java", "VenorWorker.java", "VenorPrepare.java"}) {
            QFile script(scripts + '/' + file);
            if (!script.open(QIODevice::ReadOnly))
                throw std::runtime_error("Ghidra integration scripts are missing");
            version += script.readAll();
        }
        QFile properties(config.home + "/Ghidra/application.properties");
        properties.open(QIODevice::ReadOnly);
        version += properties.readAll();
        auto digest = QCryptographicHash::hash(version, QCryptographicHash::Sha256).toHex().left(16);
        cacheDir = qEnvironmentVariable("VENOR_GHIDRA_CACHE",
                                        QStandardPaths::writableLocation(QStandardPaths::CacheLocation) +
                                            "/ghidra") +
                   '/' + image->hash + '-' + digest;
        QDir().mkpath(cacheDir);
        lock = std::make_unique<QLockFile>(cacheDir + "/worker-owner.lock");
        if (!lock->tryLock())
            throw std::runtime_error("This binary's Ghidra analysis is already open in another Venor window");
        session = std::make_unique<QTemporaryDir>(QDir::tempPath() + "/venor-ghidra-XXXXXX");
        if (!session->isValid())
            throw std::runtime_error("Cannot create the local Ghidra mailbox");
        // Use the parsed bytes, not a path that may have been replaced after opening.
        QSaveFile binaryFile(cacheDir + "/image.exe");
        if (!binaryFile.open(QIODevice::WriteOnly) || binaryFile.write(image->data) != image->data.size() ||
            !binaryFile.commit())
            throw std::runtime_error("Cannot snapshot the analyzed binary for Ghidra");
        bool imported = QFileInfo::exists(cacheDir + "/complete.json");
        if (imported) {
            auto marker = readJson(cacheDir + "/complete.json");
            project = marker["project"].toString();
            imported = marker["hash"].toString() == image->hash &&
                       QRegularExpression("^Venor_[a-f0-9]{32}$").match(project).hasMatch() &&
                       QFileInfo::exists(cacheDir + '/' + project + ".gpr");
        }
        if (!imported)
            project = "Venor_" + QUuid::createUuid().toString(QUuid::Id128);
        if (imported)
            loadIndex();
        start(!imported);
    } catch (const std::exception &e) {
        fail(QString::fromUtf8(e.what()));
    }
}
void DecompilerService::start(bool importing) {
    phase = importing ? Importing : Starting;
    log.clear();
    emit busyChanged(true);
    emit status(importing ? "Ghidra: recovering functions and types… (first analysis is cached)"
                          : "Ghidra: opening cached analysis…");
    // Same Java entry point/classloader as Ghidra's official analyzeHeadless launcher, without cmd.exe
    // quoting.
    QStringList args{"-Xmx2G",
                     "-XX:ParallelGCThreads=2",
                     "-XX:CICompilerCount=2",
                     "-Djava.system.class.loader=ghidra.GhidraClassLoader",
                     "-Dfile.encoding=UTF8",
                     "-Duser.language=en",
                     "-Duser.country=US",
                     "-Djava.awt.headless=true",
                     "-Duser.home=" + cacheDir + "/java-user",
                     "-Dapplication.settingsdir=" + cacheDir + "/settings",
                     "-Dapplication.cachedir=" + cacheDir + "/cache",
                     "-Dapplication.tempdir=" + session->path(),
                     "-cp",
                     config.home + "/Ghidra/Framework/Utility/lib/Utility.jar",
                     "ghidra.Ghidra",
                     "ghidra.app.util.headless.AnalyzeHeadless",
                     cacheDir,
                     project};
    if (importing)
        args << "-import" << cacheDir + "/image.exe" << "-overwrite" << "-analysisTimeoutPerFile" << "240";
    else
        args << "-process" << "image.exe" << "-noanalysis" << "-readOnly";
    args << "-scriptPath" << scripts;
    if (importing)
        args << "-preScript" << "VenorPrepare.java";
    args << "-postScript" << (importing ? "VenorIndex.java" : "VenorWorker.java")
         << (importing ? cacheDir + "/index.json" : session->path()) << "-max-cpu" << "2";
    process.setWorkingDirectory(config.home);
    auto env = QProcessEnvironment::systemEnvironment();
    env.insert("JAVA_HOME", config.javaHome);
    // Ghidra may otherwise try to fetch PDBs; no symbol-server or external-analysis options are enabled.
    process.setProcessEnvironment(env);
    process.start(config.javaHome + "/bin/java.exe", args);
    deadline.start(importing ? 300000 : 60000);
    poll.start();
}
void DecompilerService::loadIndex() {
    auto root = readJson(cacheDir + "/index.json", 48 * 1024 * 1024);
    if (root["schema"].toInt() != 1 || address(root["base"]) != image->base ||
        !root["language"].toString().startsWith("x86:LE:64:"))
        throw std::runtime_error("Ghidra returned an incompatible program");
    auto array = root["functions"].toArray();
    analysisWarning = root["analysis_timed_out"].toBool()
                          ? "Initial Ghidra analysis timed out; recovered functions, types and references "
                            "may be incomplete."
                          : QString();
    if (array.size() > 200000)
        throw std::runtime_error("Oversized Ghidra function index");
    recovered.clear();
    for (auto item : array) {
        auto o = item.toObject();
        RecoveredFunction f;
        f.entry = address(o["entry"]);
        f.name = o["name"].toString().left(512);
        f.signature = o["signature"].toString().left(4096);
        for (auto range : o["ranges"].toArray()) {
            auto a = range.toArray();
            if (a.size() != 2)
                throw std::runtime_error("Invalid function range");
            auto first = address(a[0]), last = address(a[1]);
            if (first < image->base || last < first || last - image->base >= image->imageSize)
                throw std::runtime_error("Ghidra function is outside the PE image");
            f.ranges << qMakePair(first, last);
        }
        if (!f.contains(f.entry))
            throw std::runtime_error("Invalid Ghidra function entry");
        recovered << f;
    }
    std::sort(recovered.begin(), recovered.end(), [](auto &a, auto &b) { return a.entry < b.entry; });
}
const RecoveredFunction *DecompilerService::containing(quint64 a) const {
    auto it = std::upper_bound(recovered.begin(), recovered.end(), a,
                               [](quint64 va, auto &f) { return va < f.entry; });
    // Most functions are contiguous; retain correctness for split bodies/shared tails.
    if (it != recovered.begin() && (it - 1)->contains(a))
        return &*(it - 1);
    for (const auto &f : recovered)
        if (f.contains(a))
            return &f;
    return nullptr;
}
QString DecompilerService::cachePath(quint64 a, const QJsonArray &edits) const {
    auto digest = QCryptographicHash::hash(QJsonDocument(edits).toJson(QJsonDocument::Compact),
                                           QCryptographicHash::Sha256)
                      .toHex();
    return cacheDir + '/' + QString::number(a, 16) + '-' + digest + ".json";
}
void DecompilerService::request(quint64 a, QJsonArray edits) {
    if (!image || phase == Closed) {
        emit failed(failure.isEmpty() ? "Configure Ghidra and open a binary first" : failure);
        return;
    }
    if (edits.size() > 1000) {
        emit failed("Investigation exceeds 1,000 decompiler edits");
        return;
    }
    if (!ready() || active) {
        pending = qMakePair(a, edits);
        return;
    }
    auto *f = containing(a);
    if (!f) {
        emit failed("Ghidra did not recover a function containing this instruction");
        return;
    }
    try {
        auto cached = cachePath(f->entry, edits);
        if (QFileInfo::exists(cached)) {
            try {
                auto result = parse(readJson(cached), edits);
                result.cached = true;
                emit completed(result);
                return;
            } catch (const std::exception &) {
                QFile::remove(cached);
                emit status("Cached result was invalid; reconstructing it again…");
            }
        }
        QFile::remove(session->filePath("cancel"));
        QFile::remove(session->filePath("response.json"));
        id = QUuid::createUuid().toString(QUuid::WithoutBraces);
        activeEdits = edits;
        activeAddress = f->entry;
        writeJson(session->filePath("request.json"),
                  {{"schema", 1}, {"id", id}, {"address", hex(a)}, {"edits", edits}});
        active = true;
        cancelled = false;
        deadline.start(120000);
        emit busyChanged(true);
        emit status("Ghidra: reconstructing " + f->name + "…");
    } catch (const std::exception &e) {
        fail(QString::fromUtf8(e.what()));
    }
}
void DecompilerService::cancel() {
    pending.reset();
    if (active && session) {
        cancelled = true;
        QFile f(session->filePath("cancel"));
        f.open(QIODevice::WriteOnly);
        emit status("Cancelling decompilation…");
    } else if (phase == Importing || phase == Starting) {
        close();
        emit busyChanged(false);
        emit requestCancelled();
        emit status("Ghidra analysis cancelled. Reopen or retry to resume.");
    }
}
DecompiledFunction DecompilerService::parse(const QJsonObject &o, QJsonArray edits) const {
    DecompiledFunction r;
    r.data = o;
    r.entry = address(o["entry"]);
    r.name = o["name"].toString();
    r.data["analysis_warning"] = analysisWarning;
    r.signature = o["signature"].toString();
    r.code = o["code"].toString();
    r.edits = edits;
    const auto *f = containing(r.entry);
    if (!f || f->entry != r.entry || r.code.isEmpty() || r.code.size() > 1024 * 1024 ||
        o["tokens"].toArray().size() > 100000)
        throw std::runtime_error("Invalid Ghidra function response");
    for (auto token : o["tokens"].toArray()) {
        auto t = token.toObject();
        int start = t["start"].toInt(-1), length = t["length"].toInt(-1);
        if (start < 0 || length < 0 || start > r.code.size() || length > r.code.size() - start)
            throw std::runtime_error("Invalid Ghidra source mapping");
        auto a = address(t["address"], true);
        if (a && !f->contains(a))
            throw std::runtime_error("Source mapping outside function");
    }
    auto assembly = o["assembly"].toArray();
    if (assembly.size() > 30000)
        throw std::runtime_error("Oversized function assembly");
    for (auto row : assembly) {
        auto i = row.toObject();
        quint64 a = address(i["address"]);
        auto bytes = QByteArray::fromHex(i["bytes"].toString().toLatin1());
        if (!f->contains(a) || bytes.isEmpty() || bytes.size() > 15 ||
            image->bytesAt(a, bytes.size()) != bytes)
            throw std::runtime_error("Ghidra instructions do not match the opened PE");
        auto decoded = decode(bytes, a, 1);
        if (decoded.size() != 1 || decoded[0].size != bytes.size())
            throw std::runtime_error("Instruction decoder disagreement");
        r.instructions << decoded[0];
    }
    if (r.instructions.isEmpty())
        throw std::runtime_error("Ghidra supplied no instruction evidence");
    return r;
}
void DecompilerService::tick() {
    if (!session)
        return;
    try {
        if (phase == Starting && QFileInfo::exists(session->filePath("ready.json"))) {
            if (readJson(session->filePath("ready.json"))["schema"].toInt() != 1)
                throw std::runtime_error("Unsupported Ghidra worker protocol");
            phase = Ready;
            deadline.stop();
            emit busyChanged(false);
            emit status(QString("Ghidra ready · %1 recovered functions").arg(recovered.size()));
            emit analysisReady();
        }
        if (active && QFileInfo::exists(session->filePath("response.json"))) {
            auto response = readJson(session->filePath("response.json"));
            QFile::remove(session->filePath("response.json"));
            if (response["id"].toString() != id)
                throw std::runtime_error("Ghidra response identity mismatch");
            active = false;
            deadline.stop();
            emit busyChanged(false);
            if (!cancelled) {
                if (response.contains("error"))
                    emit failed(response["error"].toString().left(4096));
                else {
                    auto result = parse(response["result"].toObject(), activeEdits);
                    writeJson(cachePath(activeAddress, activeEdits), result.data);
                    emit completed(result);
                }
            } else {
                emit requestCancelled();
                emit status("Decompilation cancelled");
            }
        }
        if (phase == Ready && !active && pending) {
            auto next = *pending;
            pending.reset();
            request(next.first, next.second);
        }
    } catch (const std::exception &e) {
        fail(QString::fromUtf8(e.what()));
    }
}
} // namespace vnr
