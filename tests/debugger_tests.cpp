#include "debugger.h"
#include <QtTest>
using namespace vnr;
static QString sample;
class DebuggerTests : public QObject {
    Q_OBJECT
  private slots:
    void launchBreakStepMemoryDetach() {
        Debugger d;
        QSignalSpy stops(&d, &Debugger::stopped), events(&d, &Debugger::eventRecorded),
            errors(&d, &Debugger::error), changes(&d, &Debugger::breakpointChanged);
        connect(&d, &Debugger::error, &d, [](QString s) { qWarning() << s; });
        Breakpoint marker;
        marker.expression = "benign_target!investigation_marker";
        marker.condition = "@rcx == 0n1";
        marker.returns = true;
        Breakpoint missing;
        missing.expression = "ws2_32!connect";
        d.setBreakpoints({marker, missing});
        d.launch(sample);
        QTRY_VERIFY_WITH_TIMEOUT(stops.size() >= 1, 20000);
        QCOMPARE(d.state(), Debugger::State::Paused);
        auto initial = qvariant_cast<Snapshot>(stops.last()[0]);
        QVERIFY(initial.ip);
        QVERIFY(initial.registers.contains("rsp"));
        QVERIFY(!initial.code.isEmpty());
        QVERIFY(!initial.modules.isEmpty());
        QVERIFY(!initial.threads.isEmpty());
        d.command("run");
        QTRY_VERIFY_WITH_TIMEOUT(stops.size() >= 2, 20000);
        auto hit = qvariant_cast<Snapshot>(stops.last()[0]);
        QCOMPARE(hit.registers.value("rcx"), 1ULL);
        QVERIFY(hit.reason.contains("investigation_marker"));
        QVERIFY(!hit.frames.isEmpty());
        bool evidence = false;
        for (auto row : events) {
            auto e = qvariant_cast<Event>(row[0]);
            if (e.type == "Breakpoint hit") {
                evidence = true;
                QCOMPARE(e.registers.value("rcx"), 1ULL);
                QVERIFY(!e.stack.isEmpty());
            }
        }
        QVERIFY(evidence);
        int count = stops.size();
        d.command("into");
        QTRY_VERIFY_WITH_TIMEOUT(stops.size() > count, 10000);
        auto step = qvariant_cast<Snapshot>(stops.last()[0]);
        QVERIFY(step.ip != hit.ip);
        count = stops.size();
        d.command("memory", hex(step.ip));
        QTRY_VERIFY_WITH_TIMEOUT(stops.size() > count, 5000);
        auto mem = qvariant_cast<Snapshot>(stops.last()[0]);
        QCOMPARE(mem.memoryAddress, step.ip);
        QVERIFY(mem.memory.startsWith(step.code[0].bytes));
        count = stops.size();
        d.command("over");
        QTRY_VERIFY_WITH_TIMEOUT(stops.size() > count, 10000);
        count = stops.size();
        d.command("out");
        QTRY_VERIFY_WITH_TIMEOUT(stops.size() > count, 10000);
        auto returned = qvariant_cast<Snapshot>(stops.last()[0]);
        QCOMPARE(returned.registers.value("rax"), 8ULL);
        d.command("detach");
        QTRY_VERIFY_WITH_TIMEOUT(!d.isRunning(), 10000);
        QCOMPARE(d.state(), Debugger::State::Disconnected);
        QVERIFY2(errors.isEmpty(), "Unexpected debugger error");
    }
    void logOnceAndReturn() {
        Debugger d;
        QSignalSpy stops(&d, &Debugger::stopped), events(&d, &Debugger::eventRecorded),
            errors(&d, &Debugger::error), changes(&d, &Debugger::breakpointChanged);
        connect(&d, &Debugger::error, &d, [](QString s) { qWarning() << s; });
        Breakpoint marker;
        marker.expression = "benign_target!investigation_marker";
        marker.log = true;
        marker.once = true;
        marker.returns = true;
        Breakpoint api;
        api.expression = "kernelbase!VirtualAlloc";
        api.log = true;
        api.returns = true;
        d.setBreakpoints({marker, api});
        d.launch(sample);
        QTRY_VERIFY_WITH_TIMEOUT(stops.size() >= 1, 20000);
        d.command("run");
        QTRY_VERIFY_WITH_TIMEOUT(!d.isRunning() || stops.size() > 1, 20000);
        if (d.isRunning()) {
            qWarning() << "Additional stop" << qvariant_cast<Snapshot>(stops.last()[0]).reason;
            d.command("run");
        }
        QTRY_VERIFY_WITH_TIMEOUT(!d.isRunning(), 20000);
        int markers = 0, returns = 0;
        bool allocation = false;
        for (auto row : events) {
            auto e = qvariant_cast<Event>(row[0]);
            if (e.type == "Breakpoint hit" && e.api.contains("investigation_marker"))
                markers++;
            if (e.type == "API return")
                returns++;
            if (e.type == "Breakpoint hit" && e.api.contains("VirtualAlloc")) {
                allocation = true;
                QVERIFY(e.detail.contains("MEM_COMMIT"));
                QVERIFY(e.detail.contains("PAGE_READWRITE"));
            }
        }
        QCOMPARE(markers, 1);
        QVERIFY(returns >= 1);
        QVERIFY(allocation);
        QVERIFY(errors.isEmpty());
    }
    void hardwareWriteAndLimit() {
        Debugger d;
        QSignalSpy stops(&d, &Debugger::stopped), changes(&d, &Debugger::breakpointChanged),
            events(&d, &Debugger::eventRecorded), errors(&d, &Debugger::error);
        QVector<Breakpoint> watch;
        for (int n = 0; n < 5; n++) {
            Breakpoint b;
            b.kind = "Write";
            b.size = 8;
            b.expression = "benign_target!investigation_watch+0x" + QString::number(n * 8, 16);
            watch << b;
        }
        d.setBreakpoints(watch);
        d.launch(sample);
        QTRY_VERIFY_WITH_TIMEOUT(stops.size() >= 1, 20000);
        bool limit = false;
        for (auto row : changes) {
            auto b = qvariant_cast<Breakpoint>(row[0]);
            if (b.id == watch[4].id && b.status == "Error")
                limit = b.error.contains("four");
        }
        QVERIFY(limit);
        d.command("run");
        QTRY_VERIFY_WITH_TIMEOUT(stops.size() >= 2, 10000);
        auto s = qvariant_cast<Snapshot>(stops.last()[0]);
        QVERIFY(s.reason.contains("investigation_watch"));
        bool hit = false;
        for (auto row : events) {
            auto e = qvariant_cast<Event>(row[0]);
            if (e.type == "Breakpoint hit" && e.api.contains("investigation_watch"))
                hit = true;
        }
        QVERIFY(hit);
        d.setBreakpoints({});
        d.command("run");
        QTRY_VERIFY_WITH_TIMEOUT(!d.isRunning(), 15000);
        QVERIFY(errors.isEmpty());
    }
    void hardwareExecuteAndReadWrite() {
        Debugger d;
        QSignalSpy stops(&d, &Debugger::stopped), events(&d, &Debugger::eventRecorded),
            errors(&d, &Debugger::error);
        Breakpoint execution;
        execution.kind = "Execute";
        execution.expression = "benign_target!investigation_marker";
        execution.log = true;
        execution.once = true;
        Breakpoint read;
        read.kind = "Read/write";
        read.size = 8;
        read.expression = "benign_target!investigation_watch";
        read.log = true;
        read.once = true;
        d.setBreakpoints({execution, read});
        d.launch(sample);
        QTRY_VERIFY_WITH_TIMEOUT(stops.size() >= 1, 20000);
        d.command("run");
        QTRY_VERIFY_WITH_TIMEOUT(!d.isRunning(), 20000);
        bool execHit = false, readHit = false;
        for (auto row : events) {
            auto e = qvariant_cast<Event>(row[0]);
            if (e.type == "Breakpoint hit") {
                if (e.api == execution.expression)
                    execHit = true;
                if (e.api == read.expression)
                    readHit = true;
            }
        }
        QVERIFY(execHit);
        QVERIFY(readHit);
        QVERIFY(errors.isEmpty());
    }
    void attachPauseDetach() {
        QProcess process;
        process.setProgram(sample);
        process.setArguments({"--wait"});
        process.start();
        QVERIFY(process.waitForStarted());
        Debugger d;
        QSignalSpy stops(&d, &Debugger::stopped), errors(&d, &Debugger::error);
        d.attach(quint32(process.processId()));
        QTRY_VERIFY_WITH_TIMEOUT(stops.size() >= 1, 20000);
        d.command("run");
        QTest::qWait(40);
        d.pause();
        QTRY_VERIFY_WITH_TIMEOUT(stops.size() >= 2, 10000);
        d.command("detach");
        QTRY_VERIFY_WITH_TIMEOUT(!d.isRunning(), 10000);
        QVERIFY(process.waitForFinished(10000));
        QVERIFY(errors.isEmpty());
    }
    void invalidAttach() {
        Debugger d;
        QSignalSpy errors(&d, &Debugger::error);
        d.attach(0xfffffffe);
        QTRY_VERIFY_WITH_TIMEOUT(!errors.isEmpty(), 10000);
        QTRY_VERIFY_WITH_TIMEOUT(!d.isRunning(), 10000);
        QCOMPARE(d.state(), Debugger::State::Disconnected);
    }
    void arbitraryLiveCodeNavigation() {
        Debugger d;
        connect(&d, &Debugger::error, &d, [](const QString &message) { qWarning() << message; });
        QSignalSpy stops(&d, &Debugger::stopped), errors(&d, &Debugger::error);
        d.launch(sample);
        QTRY_VERIFY_WITH_TIMEOUT(stops.size() >= 1, 20000);
        auto initial = qvariant_cast<Snapshot>(stops.last()[0]);
        int before = stops.size();
        d.command("disassemble", "benign_target!investigation_marker");
        QTRY_VERIFY_WITH_TIMEOUT(stops.size() > before, 10000);
        auto browsed = qvariant_cast<Snapshot>(stops.last()[0]);
        QVERIFY(browsed.viewAddress);
        QCOMPARE(browsed.ip, initial.ip);
        QVERIFY(!browsed.code.isEmpty());
        QCOMPARE(browsed.code[0].address, browsed.viewAddress);
        QVERIFY(browsed.viewAddress != initial.ip);
        before = stops.size();
        d.command("disassemble", "0x1");
        QTRY_VERIFY_WITH_TIMEOUT(stops.size() > before, 5000);
        auto unreadable = qvariant_cast<Snapshot>(stops.last()[0]);
        QCOMPARE(unreadable.viewAddress, 1ULL);
        QVERIFY(unreadable.code.isEmpty());
        d.command("detach");
        QTRY_VERIFY_WITH_TIMEOUT(!d.isRunning(), 10000);
        QVERIFY(errors.isEmpty());
    }
    void exceptions() {
        Debugger d;
        QSignalSpy stops(&d, &Debugger::stopped), events(&d, &Debugger::eventRecorded),
            errors(&d, &Debugger::error);
        d.launch(sample, "--exception");
        QTRY_VERIFY_WITH_TIMEOUT(stops.size() >= 1, 20000);
        d.command("run");
        QTRY_VERIFY_WITH_TIMEOUT(stops.size() >= 2, 10000);
        auto s = qvariant_cast<Snapshot>(stops.last()[0]);
        QVERIFY(s.reason.contains("e0424242"));
        d.command("pass");
        QTRY_VERIFY_WITH_TIMEOUT(!d.isRunning(), 15000);
        bool found = false;
        for (auto row : events) {
            auto e = qvariant_cast<Event>(row[0]);
            if (e.type == "Exception" && e.detail.contains("e0424242")) {
                found = true;
                qInfo() << "Exception evidence IP" << hex(e.ip) << "address" << hex(e.address) << "registers"
                        << e.registers.size() << "bytes" << e.code.size() << "stopped IP" << hex(s.ip)
                        << "stopped code" << s.code.size();
                QVERIFY(!e.code.isEmpty());
            }
        }
        QVERIFY(found);
        QVERIFY(errors.isEmpty());
    }
    void recursiveReturnPairing() {
        Debugger d;
        QSignalSpy stops(&d, &Debugger::stopped), events(&d, &Debugger::eventRecorded),
            errors(&d, &Debugger::error);
        Breakpoint b;
        b.expression = "benign_target!recursive_marker";
        b.log = true;
        b.returns = true;
        d.setBreakpoints({b});
        d.launch(sample, "--recursive");
        QTRY_VERIFY_WITH_TIMEOUT(stops.size() >= 1, 20000);
        d.command("run");
        QTRY_VERIFY_WITH_TIMEOUT(!d.isRunning(), 15000);
        int entries = 0, returns = 0;
        QSet<quint64> values;
        for (auto row : events) {
            auto e = qvariant_cast<Event>(row[0]);
            if (e.api == b.expression && e.type == "Breakpoint hit")
                entries++;
            if (e.api == b.expression && e.type == "API return") {
                returns++;
                values.insert(e.registers.value("rax"));
            }
        }
        QCOMPARE(entries, 4);
        QCOMPARE(returns, 4);
        QCOMPARE(values, QSet<quint64>({1, 2, 3, 4}));
        QVERIFY(errors.isEmpty());
    }
    void deferredReloadAndFailedResult() {
        Debugger d;
        QSignalSpy stops(&d, &Debugger::stopped), events(&d, &Debugger::eventRecorded),
            errors(&d, &Debugger::error), changes(&d, &Debugger::breakpointChanged);
        Breakpoint b;
        b.expression = "version!GetFileVersionInfoSizeW";
        b.log = true;
        b.returns = true;
        d.setBreakpoints({b});
        d.launch(sample, "--modules");
        QTRY_VERIFY_WITH_TIMEOUT(stops.size() >= 1, 20000);
        bool pending = false;
        for (auto row : changes) {
            auto bp = qvariant_cast<Breakpoint>(row[0]);
            if (bp.id == b.id && bp.status == "Pending")
                pending = true;
        }
        QVERIFY(pending);
        d.command("run");
        QTRY_VERIFY_WITH_TIMEOUT(!d.isRunning(), 15000);
        int hits = 0, results = 0;
        for (auto row : events) {
            auto e = qvariant_cast<Event>(row[0]);
            if (e.api == b.expression && e.type == "Breakpoint hit")
                hits++;
            if (e.api == b.expression && e.type == "API return") {
                results++;
                QCOMPARE(e.registers.value("rax"), 0ULL);
            }
        }
        QCOMPARE(hits, 2);
        QCOMPARE(results, 2);
        QVERIFY(errors.isEmpty());
    }
};
int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    sample = QString::fromLocal8Bit(argv[1]);
    DebuggerTests t;
    return QTest::qExec(&t, QStringList{"debugger_tests", "-o", "debugger-results.txt,txt"});
}
#include "debugger_tests.moc"
