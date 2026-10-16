#include "types.h"
#include <QtSql>
#include <stdexcept>
namespace vnr {
static QString num(quint64 n) {
    return QString::number(n, 16);
}
static quint64 number(const QJsonValue &j) {
    bool ok;
    auto n = j.toString().toULongLong(&ok, 16);
    if (!ok)
        throw std::runtime_error("Invalid workspace address/value");
    return n;
}
static QJsonArray rows(const QVector<Row> &rs) {
    QJsonArray a;
    for (auto &r : rs)
        a.append(QJsonArray{num(r.address), r.name, r.detail});
    return a;
}
static QVector<Row> unrows(const QJsonArray &a) {
    QVector<Row> r;
    for (auto v : a) {
        auto x = v.toArray();
        if (x.size() != 3)
            throw std::runtime_error("Invalid evidence frame");
        r.push_back({number(x[0]), x[1].toString(), x[2].toString()});
    }
    return r;
}
static QJsonObject regs(const QMap<QString, quint64> &rs) {
    QJsonObject a;
    for (auto i = rs.begin(); i != rs.end(); ++i)
        a[i.key()] = num(i.value());
    return a;
}
static QMap<QString, quint64> unregs(const QJsonObject &a) {
    QMap<QString, quint64> r;
    for (auto i = a.begin(); i != a.end(); ++i)
        r[i.key()] = number(i.value());
    return r;
}
static QJsonArray annotations(const QMap<quint64, QString> &m) {
    QJsonArray a;
    for (auto i = m.begin(); i != m.end(); ++i)
        a.append(QJsonArray{num(i.key()), i.value()});
    return a;
}
static QMap<quint64, QString> unannotations(const QJsonArray &a) {
    QMap<quint64, QString> m;
    for (auto v : a) {
        auto x = v.toArray();
        if (x.size() != 2)
            throw std::runtime_error("Invalid annotation");
        m[number(x[0])] = x[1].toString();
    }
    return m;
}
static QJsonObject serialize(const Workspace &w) {
    QJsonObject j{{"version", 1},
                  {"binary", w.binary},
                  {"sha256", w.hash},
                  {"selected", num(w.selected)},
                  {"notes", w.notes},
                  {"layout", QString::fromLatin1(w.layout.toBase64())},
                  {"geometry", QString::fromLatin1(w.geometry.toBase64())},
                  {"comments", annotations(w.comments)},
                  {"renames", annotations(w.renames)},
                  {"bookmarks", annotations(w.bookmarks)}};
    j["decompiler_edits"] = w.decompilerEdits;
    QJsonArray bs, es, trail;
    for (auto &b : w.breakpoints)
        bs.append(QJsonObject{{"id", b.id},
                              {"expression", b.expression},
                              {"condition", b.condition},
                              {"group", b.group},
                              {"kind", b.kind},
                              {"size", b.size},
                              {"hits", num(b.hits)},
                              {"after", num(b.after)},
                              {"enabled", b.enabled},
                              {"once", b.once},
                              {"log", b.log},
                              {"returns", b.returns}});
    for (auto &e : w.events) {
        QJsonArray arguments;
        for (const auto &argument : e.arguments)
            arguments.append(
                QJsonObject{{"name", argument.name}, {"value", argument.value}, {"source", argument.source}});
        es.append(QJsonObject{{"time", e.time},
                              {"type", e.type},
                              {"detail", e.detail},
                              {"address", num(e.address)},
                              {"thread", int(e.thread)},
                              {"registers", regs(e.registers)},
                              {"stack", QString::fromLatin1(e.stack.toBase64())},
                              {"ip", num(e.ip)},
                              {"code", QString::fromLatin1(e.code.toBase64())},
                              {"frames", rows(e.frames)},
                              {"api", e.api},
                              {"arguments", arguments}});
    }
    for (auto a : w.trail)
        trail.append(num(a));
    j["breakpoints"] = bs;
    j["events"] = es;
    j["trail"] = trail;
    return j;
}
static Workspace deserialize(const QJsonObject &j) {
    if (j["version"].toInt() != 1)
        throw std::runtime_error("Unsupported investigation schema version");
    Workspace w;
    w.binary = j["binary"].toString();
    w.hash = j["sha256"].toString();
    w.notes = j["notes"].toString();
    w.selected = number(j["selected"]);
    w.layout = QByteArray::fromBase64(j["layout"].toString().toLatin1());
    w.geometry = QByteArray::fromBase64(j["geometry"].toString().toLatin1());
    w.comments = unannotations(j["comments"].toArray());
    w.renames = unannotations(j["renames"].toArray());
    w.bookmarks = unannotations(j["bookmarks"].toArray());
    w.decompilerEdits = j["decompiler_edits"].toArray();
    if (w.decompilerEdits.size() > 1000 || QJsonDocument(w.decompilerEdits).toJson().size() > 1024 * 1024)
        throw std::runtime_error("Oversized decompiler edit history");
    for (auto value : j["breakpoints"].toArray()) {
        auto a = value.toObject();
        Breakpoint b;
        b.id = a["id"].toString();
        b.expression = a["expression"].toString();
        b.condition = a["condition"].toString();
        b.group = a["group"].toString();
        b.kind = a["kind"].toString();
        b.size = a["size"].toInt(1);
        b.hits = number(a["hits"]);
        b.after = number(a["after"]);
        b.enabled = a["enabled"].toBool();
        b.once = a["once"].toBool();
        b.log = a["log"].toBool();
        b.returns = a["returns"].toBool();
        if (!conditionSyntax(b.condition) ||
            !QStringList{"Software", "Execute", "Write", "Read/write"}.contains(b.kind) ||
            !QList<int>{1, 2, 4, 8}.contains(b.size))
            throw std::runtime_error("Invalid persisted breakpoint policy");
        w.breakpoints.push_back(b);
    }
    for (auto value : j["events"].toArray()) {
        auto a = value.toObject();
        Event e;
        e.time = a["time"].toString();
        e.type = a["type"].toString();
        e.detail = a["detail"].toString();
        e.address = number(a["address"]);
        e.thread = quint32(a["thread"].toInt());
        e.registers = unregs(a["registers"].toObject());
        e.stack = QByteArray::fromBase64(a["stack"].toString().toLatin1());
        e.ip = a.contains("ip") ? number(a["ip"]) : e.registers.value("rip");
        e.code = QByteArray::fromBase64(a["code"].toString().toLatin1());
        e.frames = unrows(a["frames"].toArray());
        e.api = a["api"].toString();
        for (const auto &value : a["arguments"].toArray()) {
            auto argument = value.toObject();
            e.arguments.push_back(
                {argument["name"].toString(), argument["value"].toString(), argument["source"].toString()});
        }
        w.events.push_back(e);
    }
    for (auto a : j["trail"].toArray())
        w.trail.push_back(number(a));
    return w;
}
class Database {
    QString name = QUuid::createUuid().toString();

  public:
    QSqlDatabase db;
    Database(const QString &path, bool read) : db(QSqlDatabase::addDatabase("QSQLITE", name)) {
        db.setDatabaseName(path);
        if (read)
            db.setConnectOptions("QSQLITE_OPEN_READONLY");
        if (!db.open()) {
            auto message = db.lastError().text();
            db = QSqlDatabase();
            QSqlDatabase::removeDatabase(name);
            throw std::runtime_error(message.toStdString());
        }
    }
    ~Database() {
        db.close();
        db = QSqlDatabase();
        QSqlDatabase::removeDatabase(name);
    }
};
void saveWorkspace(const QString &path, const Workspace &w) {
    Database d(path, false);
    if (!d.db.transaction())
        throw std::runtime_error("Cannot begin investigation transaction");
    QSqlQuery q(d.db);
    if (!q.exec("CREATE TABLE IF NOT EXISTS investigation (id INTEGER PRIMARY KEY CHECK(id=1), document BLOB "
                "NOT NULL)"))
        throw std::runtime_error(q.lastError().text().toStdString());
    q.prepare("INSERT OR REPLACE INTO investigation(id,document) VALUES(1,?)");
    q.addBindValue(QJsonDocument(serialize(w)).toJson(QJsonDocument::Compact));
    if (!q.exec() || !d.db.commit())
        throw std::runtime_error(q.lastError().text().toStdString());
}
Workspace loadWorkspace(const QString &path) {
    if (!QFileInfo::exists(path) || QFileInfo(path).size() > 256 * 1024 * 1024)
        throw std::runtime_error("Investigation missing or exceeds 256 MiB limit");
    Database d(path, true);
    QSqlQuery q(d.db);
    if (!q.exec("SELECT document FROM investigation WHERE id=1") || !q.next())
        throw std::runtime_error("Not a valid investigation database");
    QJsonParseError error;
    auto doc = QJsonDocument::fromJson(q.value(0).toByteArray(), &error);
    if (error.error != QJsonParseError::NoError || !doc.isObject())
        throw std::runtime_error("Corrupt investigation document");
    return deserialize(doc.object());
}
} // namespace vnr
