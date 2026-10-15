#include "types.h"
#include <Zydis/Zydis.h>
#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <windows.h>

namespace vnr {
static void fail(const QString &s) {
    throw std::runtime_error(s.toStdString());
}
template <class T> static T at(const QByteArray &b, quint64 p) {
    if (p > quint64(b.size()) || sizeof(T) > quint64(b.size()) - p)
        fail("Truncated PE structure at file offset " + hex(p));
    T t;
    memcpy(&t, b.constData() + p, sizeof t);
    return t;
}
qint64 Binary::fileOffset(quint64 va) const {
    if (va < base)
        return -1;
    quint64 r = va - base;
    for (const auto &s : sections)
        if (r >= s.rva && r - s.rva < s.rawSize) {
            quint64 p = s.raw + (r - s.rva);
            if (p < quint64(data.size()))
                return qint64(p);
        }
    return -1;
}
QByteArray Binary::bytesAt(quint64 va, int count) const {
    auto p = fileOffset(va);
    if (p < 0 || count < 0)
        return {};
    for (auto &s : sections)
        if (va - base >= s.rva && va - base - s.rva < s.rawSize)
            return data.mid(p, std::min<quint64>(count, s.rawSize - (va - base - s.rva)));
    return {};
}
int Binary::instructionIndex(quint64 va) const {
    auto it = std::lower_bound(code.begin(), code.end(), va,
                               [](const Instruction &i, quint64 a) { return i.address < a; });
    return it != code.end() && it->address == va ? int(it - code.begin()) : -1;
}
QVector<Instruction> decode(const QByteArray &data, quint64 base, int limit,
                            const std::shared_ptr<std::atomic_bool> &cancel) {
    QVector<Instruction> result;
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    ZydisFormatter fmt;
    ZydisFormatterInit(&fmt, ZYDIS_FORMATTER_STYLE_INTEL);
    for (qsizetype p = 0; p < data.size() && result.size() < limit;) {
        if (cancel && !(result.size() % 256) && *cancel)
            fail("Analysis canceled.");
        Instruction i;
        i.address = base + p;
        ZydisDecodedInstruction d{};
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT]{};
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, data.constData() + p, data.size() - p, &d, ops))) {
            i.bytes = data.mid(p, 1);
            i.text = "db 0x" + QString::fromLatin1(i.bytes.toHex());
            i.fact = "Undecodable byte. No instruction semantics are asserted.";
            i.unknown = "May be data, truncated code or an unsupported encoding.";
        } else {
            i.valid = true;
            i.size = d.length;
            i.bytes = data.mid(p, i.size);
            char text[512]{};
            ZydisFormatterFormatInstruction(&fmt, &d, ops, d.operand_count_visible, text, sizeof text,
                                            i.address, nullptr);
            i.text = QString::fromLatin1(text);
            i.call = d.meta.category == ZYDIS_CATEGORY_CALL;
            i.conditional = d.meta.category == ZYDIS_CATEGORY_COND_BR;
            i.branch = i.conditional || d.meta.category == ZYDIS_CATEGORY_UNCOND_BR;
            i.terminal = d.meta.category == ZYDIS_CATEGORY_RET ||
                         d.meta.category == ZYDIS_CATEGORY_UNCOND_BR || d.mnemonic == ZYDIS_MNEMONIC_INT3 ||
                         d.mnemonic == ZYDIS_MNEMONIC_UD2;
            bool segmentedAddress = false;
            for (int n = 0; n < d.operand_count; n++) {
                const auto &o = ops[n];
                if (o.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    QString r = QString::fromLatin1(ZydisRegisterGetString(o.reg.value));
                    if (o.actions & ZYDIS_OPERAND_ACTION_MASK_READ)
                        i.reads << r;
                    if (o.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE)
                        i.writes << r;
                }
                if (o.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                    if (o.mem.base != ZYDIS_REGISTER_NONE)
                        i.reads << QString::fromLatin1(ZydisRegisterGetString(o.mem.base));
                    if (o.mem.index != ZYDIS_REGISTER_NONE)
                        i.reads << QString::fromLatin1(ZydisRegisterGetString(o.mem.index));
                    if (d.mnemonic != ZYDIS_MNEMONIC_LEA &&
                        (o.mem.segment == ZYDIS_REGISTER_FS || o.mem.segment == ZYDIS_REGISTER_GS)) {
                        i.reads << QString::fromLatin1(ZydisRegisterGetString(o.mem.segment));
                        segmentedAddress = true;
                    }
                }
                if (n < d.operand_count_visible &&
                    ((o.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && o.imm.is_relative) ||
                     (o.type == ZYDIS_OPERAND_TYPE_MEMORY && o.mem.base == ZYDIS_REGISTER_RIP &&
                      (d.mnemonic == ZYDIS_MNEMONIC_LEA ||
                       (o.mem.segment != ZYDIS_REGISTER_FS && o.mem.segment != ZYDIS_REGISTER_GS))))) {
                    ZyanU64 target = 0;
                    if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&d, &o, i.address, &target)))
                        i.target = target;
                }
            }
            i.reads.removeDuplicates();
            i.writes.removeDuplicates();
            QString mn = QString::fromLatin1(ZydisMnemonicGetString(d.mnemonic));
            if (d.mnemonic == ZYDIS_MNEMONIC_MOV)
                i.fact = "Copies the source value to the destination. Flags are unchanged.";
            else if (d.mnemonic == ZYDIS_MNEMONIC_LEA)
                i.fact = "Computes an effective address; does not read the memory at that address.";
            else if (d.mnemonic == ZYDIS_MNEMONIC_CMP)
                i.fact = "Computes subtraction flags without storing the difference.";
            else if (d.mnemonic == ZYDIS_MNEMONIC_TEST)
                i.fact = "Computes bitwise AND flags without storing the result.";
            else if (d.mnemonic == ZYDIS_MNEMONIC_XOR)
                i.fact = "Bitwise exclusive OR; updates arithmetic flags. Identical operands yield zero.";
            else if (d.mnemonic == ZYDIS_MNEMONIC_ADD)
                i.fact = "Adds source to destination and updates arithmetic flags.";
            else if (d.mnemonic == ZYDIS_MNEMONIC_SUB)
                i.fact = "Subtracts source from destination and updates arithmetic flags.";
            else if (d.mnemonic == ZYDIS_MNEMONIC_PUSH)
                i.fact = "Decrements the stack pointer and stores the operand on the stack.";
            else if (d.mnemonic == ZYDIS_MNEMONIC_POP)
                i.fact = "Reads the old top-of-stack value. The stack pointer advances before the "
                         "destination is assigned; POP RSP can replace that advanced pointer.";
            else if (d.mnemonic == ZYDIS_MNEMONIC_RET)
                i.fact = "Loads the return instruction pointer from the stack and advances the stack "
                         "pointer; may include an additional immediate adjustment.";
            else if (i.call)
                i.fact = "Pushes the next instruction address and transfers control to the call target.";
            else if (i.conditional) {
                static const QMap<QString, QString> predicates{{"jz", "ZF = 1"},
                                                               {"jnz", "ZF = 0"},
                                                               {"jb", "CF = 1"},
                                                               {"jnb", "CF = 0"},
                                                               {"jbe", "CF = 1 or ZF = 1"},
                                                               {"jnbe", "CF = 0 and ZF = 0"},
                                                               {"jl", "SF differs from OF"},
                                                               {"jnl", "SF equals OF"},
                                                               {"jle", "ZF = 1 or SF differs from OF"},
                                                               {"jnle", "ZF = 0 and SF equals OF"},
                                                               {"jo", "OF = 1"},
                                                               {"jno", "OF = 0"},
                                                               {"js", "SF = 1"},
                                                               {"jns", "SF = 0"},
                                                               {"jp", "PF = 1"},
                                                               {"jnp", "PF = 0"},
                                                               {"jrcxz", "RCX = 0"},
                                                               {"jecxz", "ECX = 0"}};
                i.fact = "Branches when " +
                         predicates.value(mn, "the " + mn +
                                                  " architectural predicate holds (not further modeled)") +
                         "; otherwise falls through. Flags are unchanged.";
            } else if (i.branch)
                i.fact = "Transfers control unconditionally to the branch target.";
            else if (d.mnemonic == ZYDIS_MNEMONIC_NOP)
                i.fact = "No operation; advances the instruction pointer.";
            else
                i.fact = "Decoded x64 instruction: " + mn +
                         ". Detailed operation is not modeled; inspect operands and the architectural "
                         "register access below.";
            if (i.target)
                i.derived = "Resolved relative address: " + hex(i.target) +
                            ". For an indirect memory call this is the pointer slot, not the final callee.";
            i.unknown = "Static decoding does not prove reachability, runtime operand values, program intent "
                        "or API success.";
            if (segmentedAddress)
                i.unknown += " FS/GS segment base is not available here; no complete segmented operand "
                             "address is asserted.";
            for (auto &r : i.writes)
                if (QRegularExpression("^(e(ax|bx|cx|dx|si|di|bp|sp)|r(8|9|1[0-5])d)$").match(r).hasMatch())
                    i.derived += " Writing " + r +
                                 " clears the upper 32 bits of the corresponding 64-bit general register.";
        }
        p += i.size;
        result.push_back(std::move(i));
    }
    return result;
}
std::shared_ptr<Binary> analyze(const QString &path, const std::shared_ptr<std::atomic_bool> &cancel) {
    auto b = std::make_shared<Binary>();
    b->path = QFileInfo(path).absoluteFilePath();
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly))
        fail(f.errorString());
    if (f.size() > 512 * 1024 * 1024)
        fail("File exceeds the 512 MiB analysis limit.");
    b->data = f.readAll();
    b->hash = QString::fromLatin1(QCryptographicHash::hash(b->data, QCryptographicHash::Sha256).toHex());
    auto dos = at<IMAGE_DOS_HEADER>(b->data, 0);
    if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0)
        fail("Not a Windows PE file (missing MZ header).");
    auto nt = at<IMAGE_NT_HEADERS64>(b->data, dos.e_lfanew);
    if (nt.Signature != IMAGE_NT_SIGNATURE || nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        fail("Only Windows x64 PE executables and DLLs are supported.");
    if (nt.FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64) ||
        nt.FileHeader.NumberOfSections > 96)
        fail("Invalid PE optional header or section count.");
    b->base = nt.OptionalHeader.ImageBase;
    b->imageSize = nt.OptionalHeader.SizeOfImage;
    b->entry = b->base + nt.OptionalHeader.AddressOfEntryPoint;
    if (!b->imageSize || nt.OptionalHeader.AddressOfEntryPoint >= b->imageSize ||
        nt.OptionalHeader.NumberOfRvaAndSizes > IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
        fail("Invalid image size, entry point or PE directory count.");
    if (b->base + b->imageSize < b->base)
        fail("Invalid image address range.");
    b->dll = (nt.FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;
    quint64 p = quint64(dos.e_lfanew) + 24 + nt.FileHeader.SizeOfOptionalHeader;
    for (int n = 0; n < nt.FileHeader.NumberOfSections; n++) {
        auto s = at<IMAGE_SECTION_HEADER>(b->data, p + n * sizeof(IMAGE_SECTION_HEADER));
        if (quint64(s.PointerToRawData) + s.SizeOfRawData > quint64(b->data.size()))
            fail("Section raw data extends beyond the file.");
        if (quint64(s.VirtualAddress) + std::max(s.Misc.VirtualSize, s.SizeOfRawData) > b->imageSize)
            fail("Section extends beyond SizeOfImage.");
        b->sections.push_back(
            {QString::fromLatin1(reinterpret_cast<char *>(s.Name), 8).split(QChar(0)).first(),
             s.VirtualAddress, s.Misc.VirtualSize, s.PointerToRawData, s.SizeOfRawData, s.Characteristics});
    }
    auto rva = [&](quint32 r) -> quint64 {
        auto o = b->fileOffset(b->base + r);
        if (o < 0)
            fail("PE directory references unmapped raw data.");
        return quint64(o);
    };
    for (int n = 0; n < b->sections.size(); n++)
        for (int j = n + 1; j < b->sections.size(); j++) {
            const auto &a = b->sections[n];
            const auto &c = b->sections[j];
            if (a.rawSize && c.rawSize && quint64(a.raw) < quint64(c.raw) + c.rawSize &&
                quint64(c.raw) < quint64(a.raw) + a.rawSize)
                fail("Overlapping section raw ranges are ambiguous and unsupported.");
            auto as = std::max(a.virtualSize, a.rawSize), cs = std::max(c.virtualSize, c.rawSize);
            if (as && cs && quint64(a.rva) < quint64(c.rva) + cs && quint64(c.rva) < quint64(a.rva) + as)
                fail("Overlapping virtual sections are ambiguous and unsupported.");
        }
    auto str = [&](quint32 r) -> QString {
        quint64 o = rva(r);
        auto e = b->data.indexOf('\0', o);
        if (e < 0 || e - qint64(o) > 4096)
            fail("Invalid PE string.");
        return QString::fromLatin1(b->data.constData() + o, e - o);
    };
    auto dir = [&](int n) {
        return n < int(nt.OptionalHeader.NumberOfRvaAndSizes) ? nt.OptionalHeader.DataDirectory[n]
                                                              : IMAGE_DATA_DIRECTORY{};
    };
    auto imp = dir(IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (imp.VirtualAddress)
        for (quint32 n = 0; n < imp.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR) && n < 65536; n++) {
            auto d = at<IMAGE_IMPORT_DESCRIPTOR>(b->data, rva(imp.VirtualAddress) +
                                                              n * sizeof(IMAGE_IMPORT_DESCRIPTOR));
            if (!d.Name)
                break;
            QString module = str(d.Name);
            quint32 lookup = d.OriginalFirstThunk ? d.OriginalFirstThunk : d.FirstThunk;
            for (quint32 j = 0; j < 65536; j++) {
                auto t = at<quint64>(b->data, rva(lookup) + 8 * j);
                if (!t)
                    break;
                QString name =
                    (t & IMAGE_ORDINAL_FLAG64) ? "#" + QString::number(t & 0xffff) : str(quint32(t) + 2);
                b->imports.push_back(
                    {b->base + d.FirstThunk + 8 * j, module + "!" + name, "Import address table slot"});
            }
        }
    auto exp = dir(IMAGE_DIRECTORY_ENTRY_EXPORT);
    if (exp.VirtualAddress) {
        auto d = at<IMAGE_EXPORT_DIRECTORY>(b->data, rva(exp.VirtualAddress));
        if (d.NumberOfFunctions > 1000000 || d.NumberOfNames > 1000000)
            fail("Excessive export count.");
        QMap<quint32, QString> names;
        for (quint32 j = 0; j < d.NumberOfNames; j++)
            names[at<quint16>(b->data, rva(d.AddressOfNameOrdinals) + j * 2)] =
                str(at<quint32>(b->data, rva(d.AddressOfNames) + j * 4));
        for (quint32 j = 0; j < d.NumberOfFunctions; j++) {
            quint32 a = at<quint32>(b->data, rva(d.AddressOfFunctions) + j * 4);
            if (!a)
                continue;
            bool forward = a >= exp.VirtualAddress && quint64(a) < quint64(exp.VirtualAddress) + exp.Size;
            b->exports.push_back({b->base + a, names.value(j, "ordinal_" + QString::number(d.Base + j)),
                                  forward ? "Forwarder: " + str(a) : "Export"});
        }
    }
    QMap<quint64, QString> functions;
    if (nt.OptionalHeader.AddressOfEntryPoint)
        functions[b->entry] = "entry";
    for (auto &e : b->exports)
        if (!e.detail.startsWith("Forwarder"))
            functions[e.address] = e.name;
    auto unwind = dir(IMAGE_DIRECTORY_ENTRY_EXCEPTION);
    if (unwind.VirtualAddress)
        for (quint32 j = 0; j < unwind.Size / 12 && j < 1000000; j++) {
            auto off = rva(unwind.VirtualAddress) + j * 12;
            quint32 a = at<quint32>(b->data, off), end = at<quint32>(b->data, off + 4);
            if (a && a < end && end <= b->imageSize && !functions.contains(b->base + a))
                functions[b->base + a] = "sub_" + QString::number(a, 16);
        }
    quint64 executableBytes = 0;
    for (auto &s : b->sections) {
        if (cancel && *cancel)
            fail("Analysis canceled.");
        if (s.flags & IMAGE_SCN_MEM_EXECUTE) {
            executableBytes += s.rawSize;
            if (executableBytes > 4000000)
                fail("Executable sections exceed the 4 million byte linear-analysis budget.");
            auto code = decode(b->data.mid(s.raw, s.rawSize), b->base + s.rva, 2000000, cancel);
            if (!code.isEmpty() && code.last().address + code.last().size != b->base + s.rva + s.rawSize)
                fail("Executable section exceeds the 2 million instruction decoding limit.");
            for (auto &i : code) {
                if (i.target)
                    b->xrefs.insert(i.target, i.address);
                if (i.call && i.target && b->fileOffset(i.target) >= 0 && !i.text.contains('[') &&
                    !functions.contains(i.target))
                    functions[i.target] = "call_target_" + QString::number(i.target - b->base, 16);
            }
            b->code += code;
        }
        for (quint32 j = 0; j < s.rawSize;) {
            if (cancel && *cancel)
                fail("Analysis canceled.");
            if (b->strings.size() >= 200000)
                fail("String discovery exceeds the 200,000-string analysis limit.");
            quint32 start = j;
            while (j < s.rawSize && uchar(b->data[s.raw + j]) >= 32 && uchar(b->data[s.raw + j]) < 127)
                j++;
            if (j - start >= 4)
                b->strings.push_back({b->base + s.rva + start,
                                      QString::fromLatin1(b->data.constData() + s.raw + start, j - start),
                                      "ASCII"});
            j++;
        }
        for (quint32 j = 0; j + 1 < s.rawSize;) {
            if (cancel && *cancel)
                fail("Analysis canceled.");
            if (b->strings.size() >= 200000)
                fail("String discovery exceeds the 200,000-string analysis limit.");
            quint32 start = j;
            while (j + 1 < s.rawSize && uchar(b->data[s.raw + j]) >= 32 && uchar(b->data[s.raw + j]) < 127 &&
                   b->data[s.raw + j + 1] == 0)
                j += 2;
            if (j - start >= 8) {
                QString text;
                for (quint32 k = start; k < j; k += 2)
                    text += QChar(uchar(b->data[s.raw + k]));
                b->strings.push_back({b->base + s.rva + start, text, "UTF-16LE (ASCII range)"});
            }
            j += 2;
        }
    }
    std::sort(b->code.begin(), b->code.end(), [](auto &a, auto &c) { return a.address < c.address; });
    for (auto it = functions.begin(); it != functions.end(); ++it)
        b->functions.push_back({it.key(), it.value(),
                                "Candidate: entry/export/unwind/direct call; boundaries may be incomplete"});
    return b;
}
QString blockSummary(const QVector<Instruction> &code) {
    if (code.isEmpty())
        return "No decoded instructions.";
    QSet<QString> reads, writes;
    int calls = 0, branches = 0;
    for (auto &i : code) {
        for (auto &r : i.reads)
            reads.insert(r);
        for (auto &r : i.writes)
            writes.insert(r);
        calls += i.call;
        branches += i.branch;
    }
    QStringList readNames(reads.values()), writeNames(writes.values());
    readNames.sort();
    writeNames.sort();
    return QString("Derived from %1 decoded instructions at %2–%3: %4 call(s), %5 branch(es).\nRegisters "
                   "read: %6\nRegisters written: %7\nUnknown: function intent, aliasing, indirect targets "
                   "and path feasibility. Linear sweep may include data; this is not decompilation.")
        .arg(code.size())
        .arg(hex(code.first().address), hex(code.last().address))
        .arg(calls)
        .arg(branches)
        .arg(readNames.join(", "), writeNames.join(", "));
}
QVector<QPair<quint64, quint64>> flowEdges(const QVector<Instruction> &code) {
    QVector<QPair<quint64, quint64>> edges;
    for (int n = 0; n < code.size(); n++) {
        auto &i = code[n];
        if (i.branch && i.target && !i.text.contains('['))
            edges.push_back({i.address, i.target});
        if (!i.terminal && n + 1 < code.size() && i.address + i.size == code[n + 1].address)
            edges.push_back({i.address, code[n + 1].address});
    }
    return edges;
}
bool conditionSyntax(const QString &s) {
    // Restrict to expression syntax. No debugger commands or side effects.
    return s.isEmpty() || (s.size() <= 512 &&
                           QRegularExpression("^[a-zA-Z0-9_@`xX ()<>=!&|+*/%~^-]+$").match(s).hasMatch() &&
                           !s.contains("++") && !s.contains("--") &&
                           !QRegularExpression("(?<![=!<>])=(?!=)").match(s).hasMatch());
}
} // namespace vnr
