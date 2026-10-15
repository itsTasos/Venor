#pragma once
#include <QtCore>
#include <atomic>
#include <memory>

namespace vnr {
inline QString hex(quint64 n) {
    return QString("0x%1").arg(n, 16, 16, QChar('0'));
}
struct Row {
    quint64 address = 0;
    QString name, detail;
};
struct Section {
    QString name;
    quint32 rva = 0, virtualSize = 0, raw = 0, rawSize = 0, flags = 0;
};
struct Instruction {
    quint64 address = 0, target = 0;
    int size = 1;
    QByteArray bytes;
    QString text, fact, derived, unknown;
    QStringList reads, writes;
    bool branch = false, conditional = false, call = false, terminal = false, valid = false;
};
struct Binary {
    QString path, hash, analysisError;
    QByteArray data;
    quint64 base = 0, entry = 0;
    quint32 imageSize = 0;
    bool dll = false;
    QVector<Section> sections;
    QVector<Row> imports, exports, strings, functions;
    QVector<Instruction> code;
    QMultiMap<quint64, quint64> xrefs;
    QByteArray bytesAt(quint64 va, int count) const;
    qint64 fileOffset(quint64 va) const;
    int instructionIndex(quint64 va) const;
};
struct Breakpoint {
    QString id = QUuid::createUuid().toString(QUuid::WithoutBraces), expression, condition, group = "Custom";
    QString kind = "Software", status = "Pending", error;
    int size = 1;
    quint64 hits = 0, after = 1, bound = 0;
    bool enabled = true, once = false, log = false, returns = false;
};
struct CapturedArgument {
    QString name, value, source;
};
struct Event {
    QString time = QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs), type, detail;
    quint64 address = 0;
    quint32 thread = 0;
    QMap<QString, quint64> registers;
    QByteArray stack;
    quint64 ip = 0;
    QByteArray code;
    QVector<Row> frames;
    QString api;
    QVector<CapturedArgument> arguments;
};
struct Snapshot {
    QMap<QString, quint64> registers;
    QVector<Row> threads, modules, frames, stack;
    QVector<Instruction> code;
    quint64 ip = 0, sp = 0, memoryAddress = 0, viewAddress = 0;
    quint32 thread = 0;
    QByteArray memory;
    QString reason;
};
struct Workspace {
    QString binary, hash, notes;
    quint64 selected = 0;
    QByteArray layout, geometry;
    QMap<quint64, QString> comments, renames, bookmarks;
    QVector<Breakpoint> breakpoints;
    QVector<Event> events;
    QVector<quint64> trail;
};
struct Api {
    QString category, symbol, purpose, observation, limits;
    QStringList args;
    QMap<int, QMap<quint64, QString>> flags;
    QMap<int, QMap<quint64, QString>> enums;
};
QVector<Api> apiCatalog();
QString describeApi(const Api &, const QMap<QString, quint64> &,
                    const std::function<QByteArray(quint64, int)> &, bool entry = true,
                    QVector<CapturedArgument> *arguments = nullptr);
std::shared_ptr<Binary> analyze(const QString &, const std::shared_ptr<std::atomic_bool> &cancel = {});
QVector<Instruction> decode(const QByteArray &, quint64, int limit = 2000000,
                            const std::shared_ptr<std::atomic_bool> &cancel = {});
QString blockSummary(const QVector<Instruction> &);
QVector<QPair<quint64, quint64>> flowEdges(const QVector<Instruction> &);
void saveWorkspace(const QString &, const Workspace &);
Workspace loadWorkspace(const QString &);
bool conditionSyntax(const QString &);
} // namespace vnr
Q_DECLARE_METATYPE(vnr::Snapshot)
Q_DECLARE_METATYPE(vnr::Event)
Q_DECLARE_METATYPE(vnr::Breakpoint)
