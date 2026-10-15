#include "debugger.h"
#include <objbase.h>
#include <stdexcept>

namespace vnr {
static void checked(HRESULT hr, const QString &action) {
    if (FAILED(hr))
        throw std::runtime_error((action + ": HRESULT " + QString::number(quint32(hr), 16) +
                                  ". Check target architecture, permissions and local symbols.")
                                     .toStdString());
}
class Debugger::Callbacks final : public IDebugEventCallbacks, public IDebugOutputCallbacks {
    Debugger *d;

  public:
    explicit Callbacks(Debugger *engine) : d(engine) {}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID id, void **out) override {
        if (!out)
            return E_POINTER;
        *out = nullptr;
        if (IsEqualIID(id, __uuidof(IUnknown)) || IsEqualIID(id, __uuidof(IDebugEventCallbacks)))
            *out = static_cast<IDebugEventCallbacks *>(this);
        else if (IsEqualIID(id, __uuidof(IDebugOutputCallbacks)))
            *out = static_cast<IDebugOutputCallbacks *>(this);
        else
            return E_NOINTERFACE;
        return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override {
        return 1;
    }
    ULONG STDMETHODCALLTYPE Release() override {
        return 1;
    }
    HRESULT STDMETHODCALLTYPE Output(ULONG, PCSTR text) override {
        emit d->output(QString::fromLocal8Bit(text));
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetInterestMask(PULONG mask) override {
        *mask = DEBUG_EVENT_BREAKPOINT | DEBUG_EVENT_EXCEPTION | DEBUG_EVENT_CREATE_THREAD |
                DEBUG_EVENT_EXIT_THREAD | DEBUG_EVENT_CREATE_PROCESS | DEBUG_EVENT_EXIT_PROCESS |
                DEBUG_EVENT_LOAD_MODULE | DEBUG_EVENT_UNLOAD_MODULE;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Breakpoint(PDEBUG_BREAKPOINT bp) override {
        return d->onBreakpoint(bp);
    }
    HRESULT STDMETHODCALLTYPE Exception(PEXCEPTION_RECORD64 e, ULONG first) override {
        d->exceptionPending = true;
        d->reason = QString("%1-chance exception %2 at %3")
                        .arg(first ? "First" : "Second", hex(e->ExceptionCode), hex(e->ExceptionAddress));
        // The engine's event context is finalized only after WaitForEvent returns.
        d->captureException = true;
        d->exceptionAddress = e->ExceptionAddress;
        return DEBUG_STATUS_BREAK;
    }
    HRESULT STDMETHODCALLTYPE CreateThread(ULONG64, ULONG64, ULONG64 start) override {
        d->record("Thread created", "Start address " + hex(start), start);
        return DEBUG_STATUS_NO_CHANGE;
    }
    HRESULT STDMETHODCALLTYPE ExitThread(ULONG code) override {
        ULONG id = DEBUG_ANY_ID;
        d->systems->GetCurrentThreadId(&id);
        d->discardReturns([id](const Return &r) { return r.thread == id; },
                          "Thread exited before a matching return");
        d->record("Thread exited", "Exit code " + hex(code));
        return DEBUG_STATUS_NO_CHANGE;
    }
    HRESULT STDMETHODCALLTYPE CreateProcess(ULONG64, ULONG64, ULONG64 base, ULONG, PCSTR name, PCSTR, ULONG,
                                            ULONG, ULONG64, ULONG64, ULONG64) override {
        d->record("Process created", QString::fromLocal8Bit(name ? name : "") + " at " + hex(base), base);
        return DEBUG_STATUS_NO_CHANGE;
    }
    HRESULT STDMETHODCALLTYPE ExitProcess(ULONG code) override {
        d->record("Process exited", "Exit code " + hex(code));
        return DEBUG_STATUS_NO_CHANGE;
    }
    HRESULT STDMETHODCALLTYPE LoadModule(ULONG64, ULONG64 base, ULONG size, PCSTR name, PCSTR, ULONG,
                                         ULONG) override {
        d->moduleSizes[base] = size;
        d->record("Module loaded", QString::fromLocal8Bit(name ? name : "") + " at " + hex(base), base);
        return DEBUG_STATUS_NO_CHANGE;
    }
    HRESULT STDMETHODCALLTYPE UnloadModule(PCSTR name, ULONG64 base) override {
        auto size = d->moduleSizes.take(base);
        d->discardReturns(
            [base, size](const Return &r) { return r.address >= base && r.address - base < size; },
            "Return-site module unloaded");
        d->record("Module unloaded", QString::fromLocal8Bit(name ? name : "") + " at " + hex(base), base);
        return DEBUG_STATUS_NO_CHANGE;
    }
    HRESULT STDMETHODCALLTYPE SystemError(ULONG, ULONG) override {
        return DEBUG_STATUS_NO_CHANGE;
    }
    HRESULT STDMETHODCALLTYPE SessionStatus(ULONG) override {
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE ChangeDebuggeeState(ULONG, ULONG64) override {
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE ChangeEngineState(ULONG, ULONG64) override {
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE ChangeSymbolState(ULONG, ULONG64) override {
        return S_OK;
    }
};
Debugger::Debugger(QObject *p) : QThread(p) {
    qRegisterMetaType<Snapshot>();
    qRegisterMetaType<Event>();
    qRegisterMetaType<Breakpoint>();
    qRegisterMetaType<State>();
}
Debugger::~Debugger() {
    quit = true;
    pause();
    if (isRunning())
        wait();
}
void Debugger::launch(const QString &p, const QString &a) {
    if (isRunning())
        return;
    target = p;
    arguments = a;
    attachPid = 0;
    quit = false;
    start();
}
void Debugger::attach(quint32 pid) {
    if (isRunning())
        return;
    target.clear();
    attachPid = pid;
    quit = false;
    start();
}
void Debugger::command(QString c, QString arg) {
    std::lock_guard lock(mutex);
    requests.push_back({c, arg, {}});
}
void Debugger::setBreakpoints(QVector<Breakpoint> bs) {
    std::lock_guard lock(mutex);
    requests.push_back({"breakpoints", {}, bs});
}
void Debugger::pause() {
    std::lock_guard lock(mutex);
    if (auto c = interruptControl.load()) {
        requests.push_back({"pause", {}, {}});
        c->SetInterrupt(DEBUG_INTERRUPT_ACTIVE);
    }
}
void Debugger::stateTo(State s, QString detail) {
    m_state = s;
    emit stateChanged(s, detail);
}
QByteArray Debugger::memory(quint64 a, int n) {
    QByteArray bytes(n, 0);
    ULONG got = 0;
    if (!spaces || FAILED(spaces->ReadVirtual(a, bytes.data(), n, &got))) {
        // Some system DbgEng builds cannot service a cached read at exception stops.
        // Read the same target address through its real process handle; never substitute file bytes.
        if (!got && systems) {
            ULONG64 handle = 0;
            SIZE_T count = 0;
            if (SUCCEEDED(systems->GetCurrentProcessHandle(&handle)) && handle) {
                ReadProcessMemory(reinterpret_cast<HANDLE>(quintptr(handle)),
                                  reinterpret_cast<LPCVOID>(quintptr(a)), bytes.data(), n, &count);
                got = ULONG(count);
            }
        }
    }
    bytes.resize(got);
    return bytes;
}
QMap<QString, quint64> Debugger::registerValues() {
    QMap<QString, quint64> result;
    for (auto r : QStringList{"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10",
                              "r11", "r12", "r13", "r14", "r15", "rip", "efl"}) {
        ULONG index = 0;
        DEBUG_VALUE v{};
        if (SUCCEEDED(registers->GetIndexByName(r.toLatin1().constData(), &index)) &&
            SUCCEEDED(registers->GetValue(index, &v)))
            result[r] = v.Type == DEBUG_VALUE_INT32 ? v.I32 : v.I64;
    }
    return result;
}
QString Debugger::symbol(quint64 a) {
    char text[1024]{};
    ULONG64 disp = 0;
    if (SUCCEEDED(symbols->GetNameByOffset(a, text, sizeof text, nullptr, &disp)))
        return QString::fromLocal8Bit(text) + (disp ? "+0x" + QString::number(disp, 16) : "");
    return hex(a);
}
Snapshot Debugger::snapshot() {
    Snapshot s;
    s.reason = reason;
    s.registers = registerValues();
    s.ip = s.registers.value("rip");
    s.sp = s.registers.value("rsp");
    ULONG thread = 0;
    systems->GetCurrentThreadSystemId(&thread);
    s.thread = thread;
    auto bytes = memory(s.ip, 1024);
    s.code = decode(bytes, s.ip, 160);
    s.memoryAddress = s.sp;
    s.memory = memory(s.sp, 512);
    for (int n = 0; n + 7 < s.memory.size(); n += 8) {
        quint64 value = qFromLittleEndian<quint64>(s.memory.constData() + n);
        s.stack.push_back({s.sp + quint64(n), hex(value), symbol(value)});
    }
    DEBUG_STACK_FRAME frames[64]{};
    ULONG count = 0;
    if (SUCCEEDED(control->GetStackTrace(0, 0, 0, frames, 64, &count)))
        for (ULONG n = 0; n < count; n++)
            s.frames.push_back({frames[n].InstructionOffset, symbol(frames[n].InstructionOffset),
                                "SP " + hex(frames[n].StackOffset) + " → " + hex(frames[n].ReturnOffset)});
    ULONG threads = 0;
    systems->GetNumberThreads(&threads);
    threads = std::min<ULONG>(threads, 4096);
    std::vector<ULONG> ids(threads), pids(threads);
    if (threads && SUCCEEDED(systems->GetThreadIdsByIndex(0, threads, ids.data(), pids.data())))
        for (ULONG n = 0; n < threads; n++)
            s.threads.push_back(
                {ids[n], QString::number(pids[n]),
                 pids[n] == s.thread ? "Selected thread" : "Thread (engine ID in address column)"});
    ULONG loaded = 0, unloaded = 0;
    symbols->GetNumberModules(&loaded, &unloaded);
    for (ULONG n = 0; n < std::min<ULONG>(loaded, 4096); n++) {
        ULONG64 base = 0;
        char name[2048]{};
        symbols->GetModuleByIndex(n, &base);
        symbols->GetModuleNames(n, base, name, sizeof name, nullptr, nullptr, 0, nullptr, nullptr, 0,
                                nullptr);
        s.modules.push_back({base, QString::fromLocal8Bit(name), "Loaded module"});
    }
    return s;
}
void Debugger::record(QString type, QString detail, quint64 a, bool evidence) {
    Event e;
    e.type = type;
    e.detail = detail;
    e.address = a;
    ULONG thread = 0;
    if (systems)
        systems->GetCurrentThreadSystemId(&thread);
    e.thread = thread;
    if (evidence) {
        auto s = snapshot();
        e.registers = s.registers;
        e.stack = s.memory;
        e.frames = s.frames;
        e.ip = s.ip;
        e.code = memory(s.ip, 256);
        if (e.code.isEmpty())
            e.detail +=
                "\nInstruction bytes at this captured IP were unreadable; no code snapshot is asserted.";
        if (!e.address)
            e.address = s.ip;
    }
    emit eventRecorded(e);
}
void Debugger::install() {
    // Reinstall policies only while stopped; deferred engine expressions rebind on module loads.
    // DbgEng breakpoint lifetime is owned by RemoveBreakpoint, not IUnknown::Release.
    for (auto id : bindings.keys()) {
        IDebugBreakpoint *bp = nullptr;
        if (SUCCEEDED(control->GetBreakpointById(id, &bp)))
            control->RemoveBreakpoint(bp);
    }
    bindings.clear();
    int hw = 0;
    for (auto policy : policies) {
        policy.bound = 0;
        policy.error.clear();
        policy.status = policy.enabled ? "Pending" : "Disabled";
        if (!policy.enabled) {
            emit breakpointChanged(policy);
            continue;
        }
        if (!conditionSyntax(policy.condition)) {
            policy.status = "Error";
            policy.error = "Condition contains unsupported/unsafe syntax";
            emit breakpointChanged(policy);
            continue;
        }
        if (policy.expression.contains('!') && !policy.expression.contains('+')) {
            ULONG64 address = 0;
            if (symbols->GetOffsetByName(policy.expression.toLocal8Bit().constData(), &address) == S_FALSE) {
                policy.status = "Error";
                policy.error = "Symbol is ambiguous; use an exact address or module+RVA";
                emit breakpointChanged(policy);
                continue;
            }
        }
        if (policy.kind != "Software" && ++hw > 4) {
            policy.status = "Error";
            policy.error = "x64 has four hardware debug address slots";
            emit breakpointChanged(policy);
            continue;
        }
        IDebugBreakpoint *bp = nullptr;
        HRESULT hr = control->AddBreakpoint(
            policy.kind == "Software" ? DEBUG_BREAKPOINT_CODE : DEBUG_BREAKPOINT_DATA, DEBUG_ANY_ID, &bp);
        if (SUCCEEDED(hr) && bp) {
            hr = bp->SetOffsetExpression(policy.expression.toLocal8Bit().constData());
            if (SUCCEEDED(hr) && policy.kind != "Software")
                hr = bp->SetDataParameters(policy.kind == "Execute" ? 1 : policy.size,
                                           policy.kind == "Execute" ? DEBUG_BREAK_EXECUTE
                                           : policy.kind == "Write" ? DEBUG_BREAK_WRITE
                                                                    : DEBUG_BREAK_READ | DEBUG_BREAK_WRITE);
            if (SUCCEEDED(hr))
                hr = bp->AddFlags(DEBUG_BREAKPOINT_ENABLED);
            if (SUCCEEDED(hr)) {
                ULONG id = 0, flags = 0;
                ULONG64 address = 0;
                bp->GetId(&id);
                bp->GetFlags(&flags);
                if (!(flags & DEBUG_BREAKPOINT_DEFERRED) && SUCCEEDED(bp->GetOffset(&address))) {
                    policy.bound = address;
                    policy.status =
                        policy.hits && reason == "Breakpoint: " + policy.expression ? "Hit (bound)" : "Bound";
                }
                bindings[id] = policy;
            } else
                control->RemoveBreakpoint(bp);
        }
        if (FAILED(hr)) {
            policy.status = "Error";
            policy.error = "DbgEng rejected breakpoint: " + QString::number(quint32(hr), 16) +
                           " (check symbol, alignment or hardware resources)";
        }
        emit breakpointChanged(policy);
    }
}
HRESULT Debugger::onBreakpoint(IDebugBreakpoint *bp) {
    exceptionPending = false;
    ULONG id = 0;
    bp->GetId(&id);
    ULONG64 address = 0;
    bp->GetOffset(&address);
    if (returns.contains(id)) {
        auto ret = returns[id];
        auto r = registerValues();
        if (r.value("rsp") != ret.expectedSp)
            return DEBUG_STATUS_GO;
        Event e;
        e.type = "API return";
        e.api = ret.api;
        e.address = address;
        ULONG thread = 0;
        systems->GetCurrentThreadSystemId(&thread);
        e.thread = thread;
        e.registers = r;
        e.stack = memory(r.value("rsp"), 512);
        e.frames = snapshot().frames;
        e.ip = r.value("rip");
        e.code = memory(e.ip, 256);
        e.detail = "Observed return from " + ret.api + "\nRAX = " + hex(r.value("rax")) +
                   "\nInterpret using the API result contract; no successful effect is inferred.\nPaired by "
                   "engine thread and expected stack pointer.";
        emit eventRecorded(e);
        returns.remove(id);
        control->RemoveBreakpoint(bp);
        return DEBUG_STATUS_GO;
    }
    if (!bindings.contains(id)) {
        reason = "Engine breakpoint at " + hex(address);
        return DEBUG_STATUS_BREAK;
    }
    auto &b = bindings[id];
    b.hits++;
    b.bound = address;
    b.status = "Hit";
    for (auto &p : policies)
        if (p.id == b.id)
            p.hits = b.hits;
    emit breakpointChanged(b);
    if (b.hits < b.after)
        return DEBUG_STATUS_GO;
    if (!b.condition.isEmpty()) {
        DEBUG_VALUE value{};
        ULONG remainder = 0;
        auto expr = b.condition.toLocal8Bit();
        HRESULT hr = control->Evaluate(expr.constData(), DEBUG_VALUE_INT64, &value, &remainder);
        if (FAILED(hr) || remainder < ULONG(expr.size())) {
            b.status = "Condition error";
            b.error = "Expression could not be fully evaluated; paused for inspection";
            emit breakpointChanged(b);
            reason = b.error;
            return DEBUG_STATUS_BREAK;
        }
        if (!value.I64)
            return DEBUG_STATUS_GO;
    }
    auto r = registerValues();
    QString apiName = b.expression;
    QVector<CapturedArgument> arguments;
    QString detail = "Breakpoint " + b.expression + " hit " + QString::number(b.hits) +
                     "\nWatched address: " + hex(address) + "\nCaptured stop IP: " + hex(r.value("rip"));
    if (b.kind == "Write" || b.kind == "Read/write")
        detail += "\nHardware data traps are reported after the access. This stop IP is not asserted to be "
                  "the accessing instruction.";
    for (auto &api : apiCatalog())
        if (api.symbol.compare(b.expression, Qt::CaseInsensitive) == 0) {
            detail +=
                '\n' + describeApi(api, r, [&](quint64 a, int n) { return memory(a, n); }, true, &arguments);
            apiName = api.symbol;
            break;
        }
    Event e;
    e.type = "Breakpoint hit";
    e.address = address;
    ULONG thread = 0;
    systems->GetCurrentThreadSystemId(&thread);
    e.thread = thread;
    e.registers = r;
    e.stack = memory(r.value("rsp"), 512);
    e.frames = snapshot().frames;
    e.ip = r.value("rip");
    e.code = memory(e.ip, 256);
    e.detail = detail;
    e.api = apiName;
    e.arguments = arguments;
    emit eventRecorded(e);
    if (b.returns) {
        auto bytes = memory(r.value("rsp"), 8);
        if (bytes.size() == 8 && returns.size() < 256) {
            quint64 ret = qFromLittleEndian<quint64>(bytes.constData());
            IDebugBreakpoint *out = nullptr;
            ULONG tid = 0;
            systems->GetCurrentThreadId(&tid);
            if (SUCCEEDED(control->AddBreakpoint(DEBUG_BREAKPOINT_CODE, DEBUG_ANY_ID, &out))) {
                HRESULT hr = out->SetOffset(ret);
                if (SUCCEEDED(hr))
                    hr = out->SetMatchThreadId(tid);
                if (SUCCEEDED(hr))
                    hr = out->AddFlags(DEBUG_BREAKPOINT_ENABLED);
                if (SUCCEEDED(hr)) {
                    ULONG rid = 0;
                    out->GetId(&rid);
                    returns[rid] = {apiName, tid, r.value("rsp") + 8, ret};
                } else {
                    control->RemoveBreakpoint(out);
                    emit error("Could not install API return observer");
                }
            }
        } else
            emit error("API return observer unavailable: unreadable return address or 256 observer limit");
    }
    if (b.once) {
        bp->RemoveFlags(DEBUG_BREAKPOINT_ENABLED);
        b.enabled = false;
        b.status = "Disabled (one-shot)";
        for (auto &p : policies)
            if (p.id == b.id)
                p.enabled = false;
        emit breakpointChanged(b);
    }
    reason = "Breakpoint: " + b.expression;
    return b.log ? DEBUG_STATUS_GO : DEBUG_STATUS_BREAK;
}
void Debugger::handle(Request r) {
    if (r.command == "pause") {
        reason = "User-requested pause";
        return;
    }
    if (r.command == "breakpoints") {
        policies = r.breakpoints;
        if (m_state == State::Paused)
            install();
        return;
    }
    if (r.command == "detach") {
        checked(client->DetachProcesses(), "Detach");
        stateTo(State::Disconnected, "Detached; target continues independently");
        quit = true;
        return;
    }
    if (m_state != State::Paused) {
        emit error("Pause the target before this operation.");
        return;
    }
    if (r.command == "memory" || r.command == "disassemble") {
        DEBUG_VALUE v{};
        auto expression = r.arg.toLocal8Bit();
        ULONG64 namedAddress = 0;
        auto symbolResult = symbols->GetOffsetByName(expression.constData(), &namedAddress);
        if (symbolResult != S_OK && r.arg.contains('!')) {
            auto module = r.arg.section('!', 0, 0).toLocal8Bit();
            ULONG index = 0;
            ULONG64 base = 0;
            char imageName[4096]{};
            if (SUCCEEDED(symbols->GetModuleByModuleName(module.constData(), 0, &index, &base)) &&
                SUCCEEDED(symbols->GetModuleNames(index, base, imageName, sizeof imageName, nullptr, nullptr,
                                                  0, nullptr, nullptr, 0, nullptr))) {
                auto file = QFileInfo(QString::fromLocal8Bit(imageName)).fileName();
                if (QRegularExpression("^[A-Za-z0-9_.-]+$").match(file).hasMatch()) {
                    auto reload = ("/f " + file).toLocal8Bit();
                    symbols->Reload(reload.constData());
                }
                symbolResult = symbols->GetOffsetByName(expression.constData(), &namedAddress);
            }
        }
        if (symbolResult == S_FALSE)
            throw std::runtime_error("Symbol is ambiguous; navigate to an exact address or module+RVA");
        if (symbolResult == S_OK)
            v.I64 = namedAddress;
        else {
            ULONG remainder = 0;
            checked(control->Evaluate(expression.constData(), DEBUG_VALUE_INT64, &v, &remainder),
                    "Address expression");
            if (remainder < ULONG(expression.size()))
                throw std::runtime_error("Address expression was not fully parsed");
        }
        auto s = snapshot();
        s.memoryAddress = v.I64;
        s.memory = memory(v.I64, 1024);
        if (r.command == "disassemble") {
            s.viewAddress = v.I64;
            s.code = decode(s.memory, v.I64, 160);
        }
        emit stopped(s);
        return;
    }
    if (r.command == "thread") {
        bool ok;
        auto id = r.arg.toUInt(&ok);
        if (!ok)
            throw std::runtime_error("Invalid engine thread ID");
        checked(systems->SetCurrentThreadId(id), "Select thread");
        emit stopped(snapshot());
        return;
    }
    if (r.command == "refresh") {
        emit stopped(snapshot());
        return;
    }
    if (r.command == "out") {
        reason = "Step out completed";
        checked(control->Execute(DEBUG_OUTCTL_THIS_CLIENT, "gu", DEBUG_EXECUTE_NOT_LOGGED), "Step out");
    } else {
        ULONG status = DEBUG_STATUS_GO;
        if (r.command == "into") {
            status = DEBUG_STATUS_STEP_INTO;
            reason = "Step into completed";
        } else if (r.command == "over") {
            status = DEBUG_STATUS_STEP_OVER;
            reason = "Step over completed";
        } else if (r.command == "pass")
            status = DEBUG_STATUS_GO_NOT_HANDLED;
        else if (r.command == "handled")
            status = DEBUG_STATUS_GO_HANDLED;
        else if (r.command != "run")
            throw std::runtime_error("Unsupported debugger action");
        else if (exceptionPending)
            status = DEBUG_STATUS_GO_NOT_HANDLED;
        checked(control->SetExecutionStatus(status), "Resume");
    }
    exceptionPending = false;
    stateTo(State::Running, "Running");
}
void Debugger::discardReturns(const std::function<bool(const Return &)> &predicate, const QString &why) {
    for (auto id : returns.keys())
        if (predicate(returns[id])) {
            IDebugBreakpoint *bp = nullptr;
            if (SUCCEEDED(control->GetBreakpointById(id, &bp)))
                control->RemoveBreakpoint(bp);
            record("Return not captured", returns[id].api + ": " + why, returns[id].address);
            returns.remove(id);
        }
}
void Debugger::run() {
    CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    Callbacks callbacks(this);
    try {
        stateTo(State::Starting, "Starting Windows debug engine");
        checked(DebugCreate(__uuidof(IDebugClient), reinterpret_cast<void **>(&client)),
                "Create DbgEng client");
        checked(client->QueryInterface(__uuidof(IDebugControl), reinterpret_cast<void **>(&control)),
                "Debug control");
        checked(client->QueryInterface(__uuidof(IDebugSymbols), reinterpret_cast<void **>(&symbols)),
                "Symbols");
        checked(client->QueryInterface(__uuidof(IDebugRegisters), reinterpret_cast<void **>(&registers)),
                "Registers");
        checked(client->QueryInterface(__uuidof(IDebugDataSpaces), reinterpret_cast<void **>(&spaces)),
                "Memory");
        checked(client->QueryInterface(__uuidof(IDebugSystemObjects), reinterpret_cast<void **>(&systems)),
                "Threads");
        client->SetEventCallbacks(&callbacks);
        client->SetOutputCallbacks(&callbacks);
        interruptControl = control;
        // Local symbols only: no symbol server, downloads, extensions or external inference.
        symbols->SetSymbolPath("");
        control->AddEngineOptions(DEBUG_ENGOPT_INITIAL_BREAK | DEBUG_ENGOPT_DISALLOW_SHELL_COMMANDS);
        IDebugControl3 *extended = nullptr;
        checked(client->QueryInterface(__uuidof(IDebugControl3), reinterpret_cast<void **>(&extended)),
                "Expression evaluator");
        extended->SetExpressionSyntax(DEBUG_EXPR_MASM);
        extended->Release();
        if (attachPid)
            checked(client->AttachProcess(0, attachPid, DEBUG_ATTACH_DEFAULT), "Attach to process");
        else {
            IDebugClient3 *wide = nullptr;
            checked(client->QueryInterface(__uuidof(IDebugClient3), reinterpret_cast<void **>(&wide)),
                    "Unicode process launch");
            auto cmd = ("\"" + QDir::toNativeSeparators(target) + "\"" +
                        (arguments.isEmpty() ? "" : " " + arguments))
                           .toStdWString();
            auto result =
                wide->CreateProcessWide(0, cmd.data(), DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE);
            wide->Release();
            checked(result, "Launch target");
        }
        stateTo(State::Running, "Waiting for initial debug event");
        while (!quit) {
            std::deque<Request> batch;
            {
                std::lock_guard lock(mutex);
                batch.swap(requests);
            }
            for (auto &request : batch) {
                try {
                    handle(std::move(request));
                } catch (const std::exception &e) {
                    emit error(QString::fromUtf8(e.what()));
                }
            }
            if (quit)
                break;
            if (m_state == State::Paused) {
                QThread::msleep(15);
                continue;
            }
            HRESULT hr = control->WaitForEvent(DEBUG_WAIT_DEFAULT, 100);
            if (hr == S_FALSE || hr == E_PENDING)
                continue;
            if (FAILED(hr)) {
                ULONG status = 0;
                control->GetExecutionStatus(&status);
                if (status == DEBUG_STATUS_NO_DEBUGGEE) {
                    stateTo(State::Exited, "Target exited");
                    break;
                }
                checked(hr, "Wait for debug event");
            }
            ULONG status = 0;
            checked(control->GetExecutionStatus(&status), "Execution status");
            if (status == DEBUG_STATUS_NO_DEBUGGEE) {
                stateTo(State::Exited, "Target exited");
                break;
            }
            if (status == DEBUG_STATUS_BREAK) {
                ULONG arch = 0;
                checked(control->GetActualProcessorType(&arch), "Target architecture");
                if (arch != IMAGE_FILE_MACHINE_AMD64)
                    throw std::runtime_error(
                        "Only x64 user-mode targets are supported; detach without continuing.");
                if (captureException) {
                    record("Exception", reason, exceptionAddress, true);
                    captureException = false;
                }
                stateTo(State::Paused, reason);
                install();
                emit stopped(snapshot());
            }
        }
    } catch (const std::exception &e) {
        emit error(QString::fromUtf8(e.what()));
        stateTo(State::Disconnected, "Debugger error");
    }
    {
        std::lock_guard lock(mutex);
        interruptControl = nullptr;
    }
    if (!returns.isEmpty())
        record("Return not captured", QString::number(returns.size()) +
                                          " entry observation(s) had no matched return before session end");
    if (client) {
        client->DetachProcesses();
        client->SetEventCallbacks(nullptr);
        client->SetOutputCallbacks(nullptr);
    }
    bindings.clear();
    returns.clear();
    moduleSizes.clear();
    for (auto &b : policies) {
        b.bound = 0;
        b.status = b.enabled ? "Pending" : "Disabled";
        emit breakpointChanged(b);
    }
    if (systems) {
        systems->Release();
        systems = nullptr;
    }
    if (spaces) {
        spaces->Release();
        spaces = nullptr;
    }
    if (registers) {
        registers->Release();
        registers = nullptr;
    }
    if (symbols) {
        symbols->Release();
        symbols = nullptr;
    }
    if (control) {
        control->Release();
        control = nullptr;
    }
    if (client) {
        client->Release();
        client = nullptr;
    }
    CoUninitialize();
    if (m_state != State::Exited)
        stateTo(State::Disconnected, "Disconnected");
}
} // namespace vnr
