#pragma once
#include "types.h"
#include <QProcess>
#include <optional>

namespace vnr {
struct RecoveredFunction {
    quint64 entry = 0;
    QString name, signature;
    QVector<QPair<quint64, quint64>> ranges;
    bool contains(quint64 address) const;
};
struct DecompiledFunction {
    QJsonObject data;
    QVector<Instruction> instructions;
    quint64 entry = 0;
    QString code, name, signature;
    bool cached = false;
    QJsonArray edits;
};
struct GhidraConfig {
    QString home, javaHome;
    static GhidraConfig load();
    QString error() const;
    void save() const;
};
// Only exact mapped file bytes are eligible. Runtime addresses never become preferred VAs implicitly.
std::optional<quint64> preferredAddress(const Binary &, quint64 address, bool runtime,
                                        const QVector<Row> &modules);
bool matchingRuntimeBytes(const Binary &, const QVector<Instruction> &, quint64 runtimeBase,
                          const RecoveredFunction &, QString *reason = nullptr);
class DecompilerService : public QObject {
    Q_OBJECT
  public:
    explicit DecompilerService(QObject *parent = nullptr);
    ~DecompilerService() override;
    void open(std::shared_ptr<Binary> binary, GhidraConfig config = GhidraConfig::load());
    void request(quint64 preferredAddress, QJsonArray edits = {});
    void cancel();
    void close();
    bool ready() const {
        return phase == Ready;
    }
    bool busy() const {
        return phase == Importing || phase == Starting || active;
    }
    const QVector<RecoveredFunction> &functions() const {
        return recovered;
    }
    const RecoveredFunction *containing(quint64 address) const;
    QString lastError() const {
        return failure;
    }
    QByteArray sourceHash() const {
        return image ? image->hash.toLatin1() : QByteArray();
    }
  signals:
    void status(QString text);
    void analysisReady();
    void completed(vnr::DecompiledFunction result);
    void failed(QString message);
    void busyChanged(bool);
    void requestCancelled();

  private:
    enum Phase { Closed, Importing, Starting, Ready } phase = Closed;
    std::shared_ptr<Binary> image;
    GhidraConfig config;
    QProcess process;
    QTimer poll, deadline;
    std::unique_ptr<QTemporaryDir> session;
    std::unique_ptr<QLockFile> lock;
    QString cacheDir, scripts, failure, id, log, project, analysisWarning;
    bool active = false, cancelled = false, closing = false;
    QVector<RecoveredFunction> recovered;
    std::optional<QPair<quint64, QJsonArray>> pending;
    QJsonArray activeEdits;
    quint64 activeAddress = 0;
    void start(bool importing);
    void tick();
    void fail(QString text);
    void loadIndex();
    DecompiledFunction parse(const QJsonObject &, QJsonArray edits) const;
    QString cachePath(quint64 address, const QJsonArray &) const;
};
} // namespace vnr
Q_DECLARE_METATYPE(vnr::DecompiledFunction)
