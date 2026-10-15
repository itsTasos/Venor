#pragma once
#include "types.h"
#include <QThread>
#include <dbgeng.h>
#include <deque>
#include <mutex>
#include <windows.h>

namespace vnr {
class Debugger final : public QThread {
    Q_OBJECT
  public:
    enum class State { Disconnected, Starting, Running, Paused, Exited };
    explicit Debugger(QObject *parent = nullptr);
    ~Debugger() override;
    void launch(const QString &path, const QString &args = "");
    void attach(quint32 pid);
    void command(QString command, QString arg = {});
    void setBreakpoints(QVector<Breakpoint>);
    void pause();
    State state() const {
        return m_state.load();
    }
  signals:
    void stateChanged(vnr::Debugger::State, QString);
    void stopped(vnr::Snapshot);
    void eventRecorded(vnr::Event);
    void breakpointChanged(vnr::Breakpoint);
    void output(QString);
    void error(QString);

  protected:
    void run() override;

  private:
    struct Request {
        QString command, arg;
        QVector<Breakpoint> breakpoints;
    };
    std::mutex mutex;
    std::deque<Request> requests;
    std::atomic<State> m_state{State::Disconnected};
    std::atomic_bool quit{false};
    std::atomic<IDebugControl *> interruptControl{nullptr};
    QString target, arguments;
    quint32 attachPid = 0;
    IDebugClient *client = nullptr;
    IDebugControl *control = nullptr;
    IDebugSymbols *symbols = nullptr;
    IDebugRegisters *registers = nullptr;
    IDebugDataSpaces *spaces = nullptr;
    IDebugSystemObjects *systems = nullptr;
    QMap<ULONG, Breakpoint> bindings;
    struct Return {
        QString api;
        quint32 thread;
        quint64 expectedSp;
        quint64 address;
    };
    QMap<ULONG, Return> returns;
    QMap<quint64, quint64> moduleSizes;
    void discardReturns(const std::function<bool(const Return &)> &, const QString &);
    QVector<Breakpoint> policies;
    QString reason = "Debugger stop";
    bool exceptionPending = false;
    bool captureException = false;
    quint64 exceptionAddress = 0;
    void stateTo(State, QString);
    QByteArray memory(quint64, int);
    QMap<QString, quint64> registerValues();
    QString symbol(quint64);
    Snapshot snapshot();
    void install();
    void handle(Request);
    HRESULT onBreakpoint(IDebugBreakpoint *);
    void record(QString, QString, quint64 = 0, bool evidence = false);
    class Callbacks;
};
} // namespace vnr
Q_DECLARE_METATYPE(vnr::Debugger::State)
