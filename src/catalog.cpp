#include "types.h"
namespace vnr {
QVector<Api> apiCatalog() {
    QVector<Api> a;
    auto add = [&](QString c, QString s, QString p, QString obs, QString limits, QStringList args) {
        a.push_back({c, s, p, obs, limits, args, {}});
    };
    add("Process", "kernelbase!CreateProcessW", "Watch process creation requests",
        "Entry captures application, command line and flags; BOOL return indicates success only when "
        "nonzero.",
        "Entry is a request, not proof a child was created. Outputs require inspecting PROCESS_INFORMATION "
        "after success.",
        {"lpApplicationName:wstr", "lpCommandLine:wstr", "lpProcessAttributes:ptr", "lpThreadAttributes:ptr",
         "bInheritHandles:bool", "dwCreationFlags:flags", "lpEnvironment:ptr", "lpCurrentDirectory:wstr",
         "lpStartupInfo:ptr", "lpProcessInformation:ptr"});
    add("Process", "kernelbase!OpenProcess", "Watch process handle requests",
        "Desired access and process ID identify the request; return is a handle or NULL.",
        "Permission failure is common. No implication of injection or intent.",
        {"dwDesiredAccess:flags", "bInheritHandle:bool", "dwProcessId:uint"});
    add("Process", "kernelbase!CreateThread", "Watch thread creation requests",
        "Entry includes start routine address and parameter; return is HANDLE or NULL.",
        "A requested start address is not proof it executed.",
        {"lpThreadAttributes:ptr", "dwStackSize:size", "lpStartAddress:ptr", "lpParameter:ptr",
         "dwCreationFlags:flags", "lpThreadId:ptr"});
    add("Memory", "kernelbase!VirtualAlloc", "Watch virtual memory allocation",
        "Address, size, allocation flags and page protection; return is allocation base or NULL.",
        "Allocation does not imply executable use or content. Return value alone does not show later writes.",
        {"lpAddress:ptr", "dwSize:size", "flAllocationType:flags", "flProtect:flags"});
    a.last().flags[2] = {{0x1000, "MEM_COMMIT"}, {0x2000, "MEM_RESERVE"}, {0x100000, "MEM_TOP_DOWN"}};
    a.last().flags[3] = {{1, "PAGE_NOACCESS"},        {2, "PAGE_READONLY"},
                         {4, "PAGE_READWRITE"},       {0x10, "PAGE_EXECUTE"},
                         {0x20, "PAGE_EXECUTE_READ"}, {0x40, "PAGE_EXECUTE_READWRITE"},
                         {0x100, "PAGE_GUARD"}};
    add("Memory", "kernelbase!VirtualProtect", "Watch protection changes",
        "Address range, new protection, old-protection output; BOOL result.",
        "A request can fail. Entry cannot prove that permissions changed.",
        {"lpAddress:ptr", "dwSize:size", "flNewProtect:flags", "lpflOldProtect:ptr"});
    a.last().flags[2] = {{1, "PAGE_NOACCESS"},        {2, "PAGE_READONLY"},
                         {4, "PAGE_READWRITE"},       {0x10, "PAGE_EXECUTE"},
                         {0x20, "PAGE_EXECUTE_READ"}, {0x40, "PAGE_EXECUTE_READWRITE"},
                         {0x100, "PAGE_GUARD"}};
    add("Memory", "kernelbase!VirtualFree", "Watch release/decommit requests",
        "Address, size and free type; BOOL result.", "Does not show original allocation content.",
        {"lpAddress:ptr", "dwSize:size", "dwFreeType:flags"});
    add("Memory", "kernelbase!WriteProcessMemory", "Watch cross-process writes",
        "Handle, destination, source buffer and count; BOOL result.",
        "Handle ownership and successful bytes require further evidence; no intent inference.",
        {"hProcess:handle", "lpBaseAddress:ptr", "lpBuffer:ptr", "nSize:size", "lpNumberOfBytesWritten:ptr"});
    add("File", "kernelbase!CreateFileW", "Watch file/device open requests",
        "UTF-16 path, access, sharing and disposition; return is HANDLE or INVALID_HANDLE_VALUE.",
        "Paths may name devices or pipes. Entry does not prove file creation.",
        {"lpFileName:wstr", "dwDesiredAccess:flags", "dwShareMode:flags", "lpSecurityAttributes:ptr",
         "dwCreationDisposition:uint", "dwFlagsAndAttributes:flags", "hTemplateFile:handle"});
    a.last().flags[1] = {
        {0x80000000, "GENERIC_READ"}, {0x40000000, "GENERIC_WRITE"}, {0x10000000, "GENERIC_ALL"}};
    a.last().flags[2] = {{1, "FILE_SHARE_READ"}, {2, "FILE_SHARE_WRITE"}, {4, "FILE_SHARE_DELETE"}};
    a.last().enums[4] = {{1, "CREATE_NEW"},
                         {2, "CREATE_ALWAYS"},
                         {3, "OPEN_EXISTING"},
                         {4, "OPEN_ALWAYS"},
                         {5, "TRUNCATE_EXISTING"}};
    add("File", "kernelbase!ReadFile", "Watch reads",
        "Handle, buffer, requested byte count and output count; BOOL result.",
        "Overlapped I/O can be pending. Buffer at entry is not the completed read.",
        {"hFile:handle", "lpBuffer:ptr", "nNumberOfBytesToRead:uint", "lpNumberOfBytesRead:ptr",
         "lpOverlapped:ptr"});
    add("File", "kernelbase!WriteFile", "Watch writes",
        "Handle, source buffer and requested count; BOOL result.",
        "A successful async request need not be complete; inspect actual byte count.",
        {"hFile:handle", "lpBuffer:ptr", "nNumberOfBytesToWrite:uint", "lpNumberOfBytesWritten:ptr",
         "lpOverlapped:ptr"});
    add("File", "kernelbase!DeleteFileW", "Watch deletion requests", "UTF-16 path; BOOL result.",
        "Open handles may defer deletion; entry does not establish deletion.", {"lpFileName:wstr"});
    add("Registry", "advapi32!RegOpenKeyExW", "Watch registry key opens",
        "Root handle, subkey, options and desired access; LSTATUS zero means success.",
        "May be forwarded to another DLL. Key view depends on WOW64 flags.",
        {"hKey:handle", "lpSubKey:wstr", "ulOptions:uint", "samDesired:flags", "phkResult:ptr"});
    add("Registry", "advapi32!RegSetValueExW", "Watch registry writes",
        "Key, value name, type, buffer and size; LSTATUS zero means success.",
        "Buffer content interpretation depends on type. Entry is only an attempted write.",
        {"hKey:handle", "lpValueName:wstr", "Reserved:uint", "dwType:uint", "lpData:ptr", "cbData:uint"});
    add("Registry", "advapi32!RegQueryValueExW", "Watch registry queries",
        "Key, value name and output buffers; LSTATUS result.",
        "Output buffers and sizes are not final at entry.",
        {"hKey:handle", "lpValueName:wstr", "lpReserved:ptr", "lpType:ptr", "lpData:ptr", "lpcbData:ptr"});
    add("Network", "ws2_32!connect", "Watch socket connection requests",
        "Socket, sockaddr pointer and byte length; return 0 on success or SOCKET_ERROR.",
        "Nonblocking connection may be in progress. Raw sockaddr must be inspected for address family.",
        {"s:handle", "name:ptr", "namelen:int"});
    add("Network", "ws2_32!send", "Watch socket sends",
        "Socket, buffer, length and flags; return is bytes sent or SOCKET_ERROR.",
        "May be partial; does not prove remote delivery.", {"s:handle", "buf:ptr", "len:int", "flags:flags"});
    add("Network", "ws2_32!recv", "Watch socket receives", "Socket, output buffer, maximum length and flags.",
        "Output buffer is not received data at entry; return 0 denotes orderly shutdown.",
        {"s:handle", "buf:ptr", "len:int", "flags:flags"});
    add("Network", "winhttp!WinHttpSendRequest", "Watch HTTP request submissions",
        "Request handle, headers and optional payload; BOOL result.",
        "No automatic network activity is performed by this workstation. Encrypted traffic is not inferred.",
        {"hRequest:handle", "lpszHeaders:wstr", "dwHeadersLength:uint", "lpOptional:ptr",
         "dwOptionalLength:uint", "dwTotalLength:uint", "dwContext:ptr"});
    add("Module", "kernelbase!LoadLibraryExW", "Watch DLL loads",
        "UTF-16 module path, file handle and flags; return HMODULE or NULL.",
        "May resolve an already loaded module. Entry is not a load event; see module timeline.",
        {"lpLibFileName:wstr", "hFile:handle", "dwFlags:flags"});
    add("Module", "kernelbase!GetProcAddress", "Watch export lookup",
        "Module handle and export name or ordinal; return code/data address or NULL.",
        "Name pointer values <= 65535 encode ordinals. No proof returned code is executed.",
        {"hModule:handle", "lpProcName:astr"});
    add("Exception", "kernelbase!RaiseException", "Watch explicitly raised exceptions",
        "Exception code, flags, argument count and pointer.",
        "Not all exceptions use this API. Native first/second-chance exceptions also appear in the timeline. "
        "This API need not return.",
        {"dwExceptionCode:uint", "dwExceptionFlags:flags", "nNumberOfArguments:uint", "lpArguments:ptr"});
    add("Exception", "ntdll!RtlRaiseException", "Watch native exception requests",
        "EXCEPTION_RECORD pointer at entry.",
        "Inspect the raw record; this API may never return. Hardware exceptions bypass this routine.",
        {"ExceptionRecord:ptr"});
    return a;
}
QString describeApi(const Api &a, const QMap<QString, quint64> &r,
                    const std::function<QByteArray(quint64, int)> &memory, bool entry,
                    QVector<CapturedArgument> *arguments) {
    if (arguments)
        arguments->clear();
    QString text = "Observed runtime " + QString(entry ? "entry" : "context") + " for " + a.symbol +
                   "\nWindows x64 ABI: RCX, RDX, R8, R9, then [RSP+0x28].\n";
    QStringList regs{"rcx", "rdx", "r8", "r9"};
    for (int n = 0; n < a.args.size(); n++) {
        quint64 v = 0;
        bool known = false;
        if (n < 4) {
            known = r.contains(regs[n]);
            v = r.value(regs[n]);
        } else if (r.contains("rsp")) {
            auto bytes = memory(r["rsp"] + 40 + (n - 4) * 8, 8);
            if (bytes.size() == 8) {
                v = qFromLittleEndian<quint64>(bytes.constData());
                known = true;
            }
        }
        auto parts = a.args[n].split(':');
        if (parts[1] == "uint" || parts[1] == "int" || parts[1] == "bool" || parts[1] == "flags")
            v = quint32(v); // DWORD/BOOL/int register arguments use their low 32 bits.
        text += QString("%1 (%2): ")
                    .arg(parts[0], n < 4 ? regs[n] : "[rsp+" + QString::number(40 + (n - 4) * 8, 16) + "]");
        QString source = n < 4 ? regs[n] : "[rsp+" + QString::number(40 + (n - 4) * 8, 16) + "]";
        int valueStart = text.size();
        if (!known) {
            if (arguments)
                arguments->push_back({parts[0], "unavailable", source});
            text += "unavailable\n";
            continue;
        }
        text += hex(v);
        if (parts[1] == "int")
            text += " (" + QString::number(qint32(v)) + ")";
        if (parts[1] == "uint" || parts[1] == "bool" || parts[1] == "size")
            text += " (" + QString::number(parts[1] == "size" ? v : quint64(quint32(v))) +
                    (parts[1] == "size" ? " bytes)" : ")");
        if ((parts[1] == "wstr" || parts[1] == "astr") && v) {
            if (parts[1] == "astr" && v <= 65535)
                text += " ordinal " + QString::number(v);
            else {
                auto bytes = memory(v, 512);
                QString value;
                bool terminated = false;
                if (parts[1] == "wstr") {
                    for (int k = 0; k + 1 < bytes.size(); k += 2) {
                        ushort c = qFromLittleEndian<ushort>(bytes.constData() + k);
                        if (!c) {
                            terminated = true;
                            break;
                        }
                        value += QChar(c);
                    }
                } else {
                    auto end = bytes.indexOf('\0');
                    terminated = end >= 0;
                    value = QString::fromLatin1(end < 0 ? bytes : bytes.left(end));
                }
                text += bytes.isEmpty() ? " <unreadable>"
                                        : " \"" + value + "\"" + (terminated ? "" : " <truncated>");
            }
        }
        if (a.flags.contains(n)) {
            QStringList names;
            quint64 knownMask = 0;
            const auto &flagNames = a.flags.constFind(n).value();
            for (auto it = flagNames.begin(); it != flagNames.end(); ++it)
                if ((v & it.key()) == it.key()) {
                    names << it.value();
                    knownMask |= it.key();
                }
            if (v & ~knownMask)
                names << "unknown bits " + hex(v & ~knownMask);
            text += " [" + names.join(" | ") + "]";
        }
        if (a.enums.contains(n))
            text += " [" + a.enums.constFind(n).value().value(v, "unknown enum value") + "]";
        if (arguments)
            arguments->push_back({parts[0], text.mid(valueStart), source});
        text += '\n';
    }
    return text + "\nMeaning / result contract: " + a.observation + "\nLimits: " + a.limits;
}
} // namespace vnr
