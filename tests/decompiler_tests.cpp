#include "ai.h"
#include "decompiler.h"
#include <QtTest>
using namespace vnr;
static QString executable, library;
class DecompilerTests : public QObject {
    Q_OBJECT
  private slots:
    void addressAndRuntimeEvidence() {
        auto binary = analyze(executable);
        auto exported = std::find_if(binary->exports.begin(), binary->exports.end(),
                                     [](const Row &r) { return r.name == "inspect_record"; });
        QVERIFY(exported != binary->exports.end());
        auto a = exported->address;
        quint64 loaded = 0x7ff600000000;
        QVector<Row> modules{{loaded, binary->path, "test module mapping"}};
        QCOMPARE(*preferredAddress(*binary, loaded + a - binary->base, true, modules), a);
        QVERIFY(!preferredAddress(*binary, loaded - 1, true, modules));
        QVERIFY(!preferredAddress(*binary, a, true, {{binary->base, "unrelated.dll", {}}}));
        RecoveredFunction f{a, "test", {}, {{a, a + 127}}};
        auto code = decode(binary->bytesAt(a, 64), loaded + a - binary->base);
        QVERIFY(matchingRuntimeBytes(*binary, code, loaded, f));
        code.first().bytes[0] ^= 1;
        QVERIFY(!matchingRuntimeBytes(*binary, code, loaded, f));
        QVERIFY(!matchingRuntimeBytes(*binary, {}, loaded, f));
    }
    void unavailableDoesNotBreakStaticAnalysis() {
        DecompilerService service;
        QSignalSpy failed(&service, &DecompilerService::failed);
        auto binary = analyze(executable);
        service.open(binary, {"missing", "missing"});
        QCOMPARE(failed.size(), 1);
        QVERIFY(!service.ready());
        QVERIFY(!binary->code.isEmpty());
    }
    void realGhidra() {
        if (qEnvironmentVariableIsEmpty("VENOR_GHIDRA_HOME"))
            QSKIP("Set VENOR_GHIDRA_HOME and VENOR_JAVA_HOME to run real Ghidra integration");
        auto binary = analyze(executable);
        DecompilerService service;
        QSignalSpy errors(&service, &DecompilerService::failed),
            ready(&service, &DecompilerService::analysisReady), done(&service, &DecompilerService::completed);
        service.open(binary);
        QTRY_VERIFY_WITH_TIMEOUT(ready.size() || errors.size(), 300000);
        QVERIFY2(errors.isEmpty(), errors.isEmpty() ? "" : qPrintable(errors.first().first().toString()));
        QVERIFY(service.ready());
        QVERIFY(service.functions().size() >= 3);
        auto entry = [&](QString name) {
            for (const auto &r : binary->exports)
                if (r.name == name)
                    return r.address;
            return quint64(0);
        };
        auto receive = [&](quint64 a, QJsonArray edits = {}) {
            done.clear();
            errors.clear();
            service.request(a, edits);
            QElapsedTimer timer;
            timer.start();
            while (done.isEmpty() && errors.isEmpty() && timer.elapsed() < 120000)
                QTest::qWait(30);
        };
        receive(entry("inspect_record") + 1);
        QVERIFY2(errors.isEmpty(), errors.isEmpty() ? "" : qPrintable(errors.first().first().toString()));
        QCOMPARE(done.size(), 1);
        auto result = qvariant_cast<DecompiledFunction>(done.first().first());
        QCOMPARE(result.entry, entry("inspect_record"));
        QVERIFY(result.code.contains("if"));
        QVERIFY(!result.data["tokens"].toArray().isEmpty());
        QVERIFY(!result.instructions.isEmpty());
        auto context = makeAiContext(binary.get(), result.instructions, result.instructions.first().address,
                                     AiScope::Function, "real Ghidra test", nullptr, nullptr, &result);
        QCOMPARE(context.data["decompilation"].toObject()["pseudocode"].toString(), result.code);
        QVERIFY(!context.data["control_flow"].toArray().isEmpty());
        auto block = makeAiContext(binary.get(), result.instructions, result.instructions.first().address,
                                   AiScope::Block, "test", nullptr, nullptr, &result);
        QVERIFY(block.data.contains("containing_block"));
        QJsonArray edits{QJsonObject{
            {"kind", "function_name"}, {"function", hex(result.entry)}, {"text", "inspect_user_record"}}};
        receive(result.entry, edits);
        QCOMPARE(done.size(), 1);
        auto renamed = qvariant_cast<DecompiledFunction>(done.first().first());
        QVERIFY(renamed.code.contains("inspect_user_record"));
        edits.append(QJsonObject{{"kind", "signature"},
                                 {"function", hex(result.entry)},
                                 {"text", "int inspect_user_record(void *record, int limit);"}});
        receive(result.entry, edits);
        QVERIFY2(errors.isEmpty(), errors.isEmpty() ? "" : qPrintable(errors.first().first().toString()));
        QCOMPARE(done.size(), 1);
        auto typed = qvariant_cast<DecompiledFunction>(done.first().first());
        QVERIFY(typed.signature.contains("record"));
        auto vars = typed.data["variables"].toArray();
        QVERIFY(!vars.isEmpty());
        auto variable = vars.first().toObject();
        edits.append(QJsonObject{{"kind", "variable_name"},
                                 {"function", hex(result.entry)},
                                 {"previous", variable["name"]},
                                 {"storage", variable["storage"]},
                                 {"text", "reviewed_value"}});
        receive(result.entry, edits);
        QVERIFY2(errors.isEmpty(), errors.isEmpty() ? "" : qPrintable(errors.first().first().toString()));
        QCOMPARE(done.size(), 1);
        QVERIFY(qvariant_cast<DecompiledFunction>(done.first().first()).code.contains("reviewed_value"));
        auto renamedVars =
            qvariant_cast<DecompiledFunction>(done.first().first()).data["variables"].toArray();
        for (auto item : renamedVars)
            if (item.toObject()["name"].toString() == "reviewed_value") {
                auto v = item.toObject();
                edits.append(QJsonObject{{"kind", "variable_type"},
                                         {"function", hex(result.entry)},
                                         {"previous", "reviewed_value"},
                                         {"storage", v["storage"]},
                                         {"text", "unsigned long long"}});
                break;
            }
        receive(result.entry, edits);
        QVERIFY2(errors.isEmpty(), errors.isEmpty() ? "" : qPrintable(errors.first().first().toString()));
        QCOMPARE(done.size(), 1);
        Workspace work;
        work.binary = binary->path;
        work.hash = binary->hash;
        work.decompilerEdits = edits;
        QTemporaryDir directory(QDir::currentPath() + "/decompiler-case-XXXXXX");
        saveWorkspace(directory.filePath("case.venor"), work);
        QCOMPARE(loadWorkspace(directory.filePath("case.venor")).decompilerEdits, edits);
        receive(entry("summarize_records"));
        QCOMPARE(done.size(), 1);
        auto loop = qvariant_cast<DecompiledFunction>(done.first().first());
        QVERIFY(loop.code.contains("while") || loop.code.contains("for") || loop.code.contains("do "));
        QVERIFY(loop.code.contains("inspect_record"));
        receive(entry("platform_probe"));
        QCOMPARE(done.size(), 1);
        auto api = qvariant_cast<DecompiledFunction>(done.first().first());
        QVERIFY(api.code.contains("CreateEventW"));
        auto apiContext = makeAiContext(binary.get(), api.instructions, api.entry, AiScope::Function, "test",
                                        nullptr, nullptr, &api);
        QVERIFY(apiContext.serialized().contains("CreateEventW"));
        done.clear();
        errors.clear();
        auto cancelledEdits = edits;
        cancelledEdits.append(QJsonObject{
            {"kind", "function_name"}, {"function", hex(result.entry)}, {"text", "cancelled_name"}});
        service.request(result.entry, cancelledEdits);
        service.cancel();
        QTRY_VERIFY_WITH_TIMEOUT(!service.busy(), 120000);
        QCOMPARE(done.size(), 0);
        QVERIFY(errors.isEmpty());
        auto invalid = edits;
        invalid.append(QJsonObject{
            {"kind", "signature"}, {"function", hex(result.entry)}, {"text", "this is invalid C"}});
        receive(result.entry, invalid);
        QCOMPARE(errors.size(), 1);
        QVERIFY(done.isEmpty());
        QVERIFY(service.ready());
        receive(result.entry, edits);
        QCOMPARE(done.size(), 1);
        QVERIFY(qvariant_cast<DecompiledFunction>(done.first().first()).cached);
        service.close();
        ready.clear();
        errors.clear();
        service.open(binary);
        QTRY_VERIFY_WITH_TIMEOUT(ready.size() || errors.size(), 60000);
        QVERIFY2(errors.isEmpty(), errors.isEmpty() ? "" : qPrintable(errors.first().first().toString()));
        receive(result.entry, edits);
        QCOMPARE(done.size(), 1);
        QVERIFY(qvariant_cast<DecompiledFunction>(done.first().first()).code.contains("reviewed_value"));
        // The shared analysis is immutable: no edits leak into another investigation.
        receive(result.entry);
        QCOMPARE(done.size(), 1);
        QVERIFY(
            !qvariant_cast<DecompiledFunction>(done.first().first()).code.contains("inspect_user_record"));
        service.close();
        ready.clear();
        errors.clear();
        service.open(analyze(library));
        QTRY_VERIFY_WITH_TIMEOUT(ready.size() || errors.size(), 300000);
        QVERIFY2(errors.isEmpty(), errors.isEmpty() ? "" : qPrintable(errors.first().first().toString()));
        QVERIFY(service.ready());
        quint64 dllEntry = 0;
        for (const auto &f : service.functions())
            if (f.name == "inspect_record")
                dllEntry = f.entry;
        QVERIFY(dllEntry);
        receive(dllEntry);
        QCOMPARE(done.size(), 1);
    }
};
int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    app.setOrganizationName("VenorTests");
    app.setApplicationName("Decompiler");
    if (argc < 3)
        return 2;
    executable = argv[1];
    library = argv[2];
    DecompilerTests tests;
    return QTest::qExec(&tests, QStringList{argv[0], "-o", "decompiler-results.txt,txt"});
}
#include "decompiler_tests.moc"
