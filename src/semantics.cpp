#include "semantics.h"
#include <Zydis/Zydis.h>
#include <algorithm>
#include <cstring>

namespace vnr {
namespace {
quint64 mask(int bits) {
    return bits >= 64 ? ~quint64(0) : (quint64(1) << bits) - 1;
}
QString regName(ZydisRegister r) {
    return QString::fromLatin1(ZydisRegisterGetString(r));
}
QString parent(ZydisRegister r) {
    return regName(ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, r));
}
int width(ZydisRegister r) {
    return ZydisRegisterGetWidth(ZYDIS_MACHINE_MODE_LONG_64, r);
}
int shift(ZydisRegister r) {
    return r == ZYDIS_REGISTER_AH || r == ZYDIS_REGISTER_BH || r == ZYDIS_REGISTER_CH ||
                   r == ZYDIS_REGISTER_DH
               ? 8
               : 0;
}
void merge(QVector<quint64> &a, const QVector<quint64> &b) {
    for (auto address : b)
        if (!a.contains(address))
            a << address;
}
struct Value {
    bool numeric = false, available = false, stack = false;
    quint64 number = 0;
    qint64 offset = 0;
    QString expression, callee;
    QVector<quint64> evidence;
};
Value constant(quint64 n) {
    Value v;
    v.numeric = v.available = true;
    v.number = n;
    v.expression = n ? hex(n) : "zero";
    return v;
}
QString show(const Value &v) {
    return v.expression.isEmpty() ? "an unknown value" : v.expression;
}
struct Parsed {
    ZydisDecodedInstruction d{};
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT]{};
    bool valid = false;
};
Parsed parse(const Instruction &i) {
    Parsed p;
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    p.valid = ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, i.bytes.data(), i.bytes.size(), &p.d, p.ops));
    return p;
}
struct Cell {
    int bits;
    Value value;
};
struct State {
    QMap<QString, Value> regs;
    QMap<qint64, Cell> stackCells;
    void reset() {
        regs.clear();
        stackCells.clear();
        Value sp;
        sp.stack = sp.available = true;
        sp.expression = "RSP at block entry";
        regs["rsp"] = sp;
    }
    Value reg(ZydisRegister r) const {
        auto v = regs.value(parent(r));
        if (!v.available) {
            v.expression = regName(r).toUpper();
            return v;
        }
        int bits = width(r);
        if (v.numeric) {
            v.number = (v.number >> shift(r)) & mask(bits);
            v.expression = v.number ? hex(v.number) : "zero";
        } else if (bits != 64) {
            v.expression = QString("%1-bit part of %2").arg(bits).arg(show(v));
            v.stack = false;
            v.callee.clear();
        }
        return v;
    }
    void write(ZydisRegister r, Value v, quint64 at) {
        QString key = parent(r);
        int bits = width(r);
        if (key.isEmpty() || key == "none")
            return;
        if (bits != 64 && bits != 32) {
            auto old = regs.value(key);
            if (!old.numeric || !v.numeric) {
                regs.remove(key);
                return;
            }
            quint64 m = mask(bits) << shift(r);
            v.number = (old.number & ~m) | ((v.number << shift(r)) & m);
            merge(v.evidence, old.evidence);
        } else if (bits == 32) {
            v.stack = false;
            v.callee.clear();
            if (v.numeric)
                v.number &= 0xffffffffULL;
        }
        if (v.numeric)
            v.expression = v.number ? hex(v.number) : "zero";
        if (!v.evidence.contains(at))
            v.evidence << at;
        if (v.available)
            regs[key] = v;
        else
            regs.remove(key);
    }
};
QString operandText(const Parsed &p, int n, quint64 address) {
    char buffer[256]{};
    ZydisFormatter fmt;
    ZydisFormatterInit(&fmt, ZYDIS_FORMATTER_STYLE_INTEL);
    ZydisFormatterFormatOperand(&fmt, &p.d, &p.ops[n], buffer, sizeof buffer, address, nullptr);
    return QString::fromLatin1(buffer);
}
Value effective(const ZydisDecodedOperand &o, const Instruction &i, const State &s, bool lea = false,
                int addressBits = 64) {
    Value v;
    // Address-size overrides need 32-bit wrapping; leave them unknown until modeled explicitly.
    if (addressBits != 64 || (o.mem.base != ZYDIS_REGISTER_NONE && width(o.mem.base) == 32) ||
        (o.mem.index != ZYDIS_REGISTER_NONE && width(o.mem.index) == 32))
        return v;
    if (!lea && (o.mem.segment == ZYDIS_REGISTER_FS || o.mem.segment == ZYDIS_REGISTER_GS))
        return v;
    auto b = o.mem.base == ZYDIS_REGISTER_RIP    ? constant(i.address + i.size)
             : o.mem.base == ZYDIS_REGISTER_NONE ? constant(0)
                                                 : s.reg(o.mem.base);
    auto x = o.mem.index == ZYDIS_REGISTER_NONE ? constant(0) : s.reg(o.mem.index);
    v.evidence = b.evidence;
    merge(v.evidence, x.evidence);
    if (x.numeric && b.numeric) {
        v = constant(b.number + x.number * o.mem.scale + quint64(o.mem.disp.value));
        v.evidence = b.evidence;
        merge(v.evidence, x.evidence);
    } else if (b.stack && x.numeric && x.number < 0x100000 && o.mem.disp.value > -0x100000 &&
               o.mem.disp.value < 0x100000) {
        v.stack = v.available = true;
        v.offset = b.offset + qint64(x.number * o.mem.scale) + o.mem.disp.value;
        v.expression = "block-entry RSP " + QString(v.offset < 0 ? "- " : "+ ") +
                       QString::number(qAbs(v.offset)) + " bytes";
    }
    return v;
}
QString importAt(const Binary *image, quint64 a) {
    if (image)
        for (auto &r : image->imports)
            if (r.address == a)
                return r.name;
    return {};
}
bool matchesApi(const Api &api, const QString &callee) {
    auto module = callee.section('!', 0, 0).toLower();
    if (module.endsWith(".dll"))
        module.chop(4);
    auto expected = api.symbol.section('!', 0, 0);
    bool forwarded = expected == "kernelbase" && (module == "kernel32" || module.startsWith("api-ms-win-") ||
                                                  module.startsWith("ext-ms-win-"));
    return api.symbol.section('!', 1) == callee.section('!', 1) && (module == expected || forwarded);
}
Value operand(const Parsed &p, int n, const Instruction &i, const State &s, const Binary *image) {
    const auto &o = p.ops[n];
    if (o.type == ZYDIS_OPERAND_TYPE_REGISTER)
        return s.reg(o.reg.value);
    if (o.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        auto v = constant(o.imm.value.u & mask(o.size));
        // Sign extension is encoded by the decoder's signed immediate operand.
        if (o.imm.is_signed)
            v = constant(quint64(o.imm.value.s));
        return v;
    }
    Value v;
    if (o.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        auto address = effective(o, i, s, false, p.d.address_width);
        if (address.stack && s.stackCells.contains(address.offset) &&
            s.stackCells[address.offset].bits == o.size) {
            v = s.stackCells[address.offset].value;
            merge(v.evidence, address.evidence);
            return v;
        }
        if (address.numeric) {
            v.callee = importAt(image, address.number);
            if (!v.callee.isEmpty()) {
                v.available = true;
                v.expression = "pointer from import " + v.callee;
                v.evidence = address.evidence;
                return v;
            }
        }
        v.expression = QString("%1-bit value at %2").arg(o.size).arg(operandText(p, n, i.address));
    }
    return v;
}
void store(State &s, const Value &address, int bits, Value value, quint64 at) {
    if (!address.stack) {
        s.stackCells.clear();
        return;
    }
    for (auto it = s.stackCells.begin(); it != s.stackCells.end();) {
        if (it.key() < address.offset + bits / 8 && it.key() + it->bits / 8 > address.offset)
            it = s.stackCells.erase(it);
        else
            ++it;
    }
    value.evidence << at;
    merge(value.evidence, address.evidence);
    if (value.available)
        s.stackCells.insert(address.offset, Cell{bits, value});
}
QString stringAt(const Binary *image, const Value &v, QString type) {
    if (!image || !v.numeric || !v.number || (type != "wstr" && type != "astr"))
        return {};
    auto bytes = image->bytesAt(v.number, 512);
    QString result;
    bool terminated = false;
    for (int n = 0; n < bytes.size(); n += type == "wstr" ? 2 : 1) {
        if (type == "wstr" && n + 1 >= bytes.size())
            break;
        ushort ch = type == "wstr" ? qFromLittleEndian<quint16>(bytes.data() + n) : uchar(bytes[n]);
        if (!ch) {
            terminated = true;
            break;
        }
        if (ch < 32 && ch != 9 && ch != 10 && ch != 13)
            return {};
        result += QChar(ch);
    }
    return result.isEmpty() ? QString()
                            : " \"" + result + "\" (static file bytes" + (terminated ? ")" : ", truncated)");
}
QString argumentValue(const Api &api, int n, Value v, const Binary *image) {
    if (!v.available)
        return "Unknown — not established in this basic block";
    auto arg = api.args[n].split(':');
    auto type = arg.value(1);
    if (v.numeric && (type == "uint" || type == "int" || type == "bool" || type == "flags"))
        v.number &= 0xffffffffULL;
    QString text = v.numeric ? hex(v.number) : show(v);
    if (v.numeric && (type == "uint" || type == "int" || type == "bool" || type == "size")) {
        text = type == "int" ? QString::number(qint32(v.number)) : QString::number(v.number);
        if (type == "size" || arg[0].contains("size", Qt::CaseInsensitive) ||
            arg[0].contains("bytes", Qt::CaseInsensitive) || arg[0] == "len")
            text += " bytes";
        if (type == "size" && v.number >= 1024 && v.number % 1024 == 0)
            text += " (" + QString::number(v.number / 1024) + " KiB)";
    }
    if (v.numeric && !v.number && (type == "ptr" || type == "wstr" || type == "astr"))
        text = "NULL";
    if (v.numeric && api.flags.contains(n)) {
        QStringList names;
        quint64 used = 0;
        auto flags = api.flags.value(n);
        for (auto it = flags.begin(); it != flags.end(); ++it)
            if (it.key() && (v.number & it.key()) == it.key()) {
                names << it.value();
                used |= it.key();
            }
        if (v.number & ~used)
            names << "unmodeled bits " + hex(v.number & ~used);
        text =
            names.isEmpty() ? (v.number ? hex(v.number) : QString("0 · no named flags")) : names.join(" | ");
    }
    if (v.numeric && api.enums.contains(n))
        text += " · " + api.enums.value(n).value(v.number, "unmodeled enum value");
    return text + stringAt(image, v, type);
}
struct Comparison {
    bool valid = false, test = false;
    Value left, right;
    quint64 at = 0;
};
QString condition(const Parsed &p, const Comparison &c, const State &s) {
    QString mn = QString::fromLatin1(ZydisMnemonicGetString(p.d.mnemonic));
    if (mn == "jrcxz" || mn == "jecxz")
        return show(s.reg(mn == "jrcxz" ? ZYDIS_REGISTER_RCX : ZYDIS_REGISTER_ECX)) + " is zero";
    if (!c.valid)
        return {};
    QString a = show(c.left), b = show(c.right);
    if (c.test && mn != "jz" && mn != "jnz")
        return {};
    if (mn == "jz" || mn == "jnz") {
        QString equality = mn == "jz" ? " equals " : " does not equal ";
        if (c.test) {
            if (a == b)
                return a + (mn == "jz" ? " is zero" : " is nonzero");
            return "(" + a + " AND " + b + ")" + equality + "zero";
        }
        return a + equality + b;
    }
    static const QMap<QString, QString> relations{{"jb", " < (unsigned) "},   {"jnb", " >= (unsigned) "},
                                                  {"jbe", " <= (unsigned) "}, {"jnbe", " > (unsigned) "},
                                                  {"jl", " < (signed) "},     {"jnl", " >= (signed) "},
                                                  {"jle", " <= (signed) "},   {"jnle", " > (signed) "}};
    return relations.contains(mn) ? a + relations[mn] + b : QString();
}
} // namespace

MeaningDocument analyzeMeaning(const QVector<Instruction> &input, const Binary *image) {
    MeaningDocument doc;
    const auto code = input.mid(0, 160);
    if (code.isEmpty())
        return doc;
    QSet<quint64> leaders{code.first().address};
    for (int n = 0; n < code.size(); ++n) {
        auto &i = code[n];
        if (i.branch && i.target)
            leaders.insert(i.target);
        if ((i.branch || i.terminal || !i.valid) && n + 1 < code.size())
            leaders.insert(code[n + 1].address);
    }
    State s;
    Comparison comparison;
    auto catalog = apiCatalog();
    for (int index = 0; index < code.size(); ++index) {
        const auto &i = code[index];
        auto p = parse(i);
        bool boundary = leaders.contains(i.address) ||
                        (index && code[index - 1].address + code[index - 1].size != i.address);
        if (boundary) {
            s.reset();
            comparison = {};
        }
        MeaningStep step;
        step.address = i.address;
        step.evidence = {i.address};
        step.boundary = boundary;
        step.title = "Instruction";
        step.summary = i.fact;
        auto mn = p.d.mnemonic;
        auto count = p.d.operand_count_visible;
        Value a, b, result;
        bool handledWrite = false, handledMemory = false;
        if (p.valid && count)
            a = operand(p, 0, i, s, image);
        if (p.valid && count > 1)
            b = operand(p, 1, i, s, image);
        if (!p.valid) {
            step.title = "Unmodeled bytes";
            s.reset();
            comparison = {};
        } else if (i.call) {
            step.call = true;
            step.title = "Call";
            QString callee = count ? a.callee : QString();
            if (callee.isEmpty() && i.target && p.ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
                callee = importAt(image, i.target);
            if (callee.isEmpty() && image && p.ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                for (auto &r : image->exports)
                    if (r.address == i.target)
                        callee = r.name;
            const Api *api = nullptr;
            for (auto &entry : catalog)
                if (!callee.isEmpty() && matchesApi(entry, callee)) {
                    api = &entry;
                    break;
                }
            step.summary = "Calls " +
                           (callee.isEmpty() ? (i.target && p.ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE
                                                    ? hex(i.target)
                                                    : "an unresolved target")
                                             : callee) +
                           ".";
            if (api) {
                step.title = "API request · " + api->symbol.section('!', 1);
                static const ZydisRegister args[]{ZYDIS_REGISTER_RCX, ZYDIS_REGISTER_RDX, ZYDIS_REGISTER_R8,
                                                  ZYDIS_REGISTER_R9};
                for (int n = 0; n < api->args.size(); ++n) {
                    Value value;
                    if (n < 4)
                        value = s.reg(args[n]);
                    else {
                        auto sp = s.reg(ZYDIS_REGISTER_RSP);
                        qint64 offset = sp.offset + 32 + (n - 4) * 8;
                        if (sp.stack && s.stackCells.contains(offset)) {
                            auto cell = s.stackCells[offset];
                            auto type = api->args[n].section(':', 1);
                            if (cell.bits == 64 || (cell.bits == 32 && (type == "uint" || type == "int" ||
                                                                        type == "bool" || type == "flags")))
                                value = cell.value;
                        }
                    }
                    QString source = n < 4 ? regName(args[n]).toUpper()
                                           : QString("[RSP+0x%1] before CALL").arg(32 + (n - 4) * 8, 0, 16);
                    step.arguments << MeaningArgument{api->args[n].section(':', 0, 0),
                                                      argumentValue(*api, n, value, image), source,
                                                      value.evidence};
                    merge(step.evidence, value.evidence);
                }
                if (api->symbol.endsWith("!VirtualAlloc")) {
                    auto size = s.reg(ZYDIS_REGISTER_RDX);
                    auto protection = s.reg(ZYDIS_REGISTER_R9);
                    QString permission =
                        protection.numeric && protection.number == 4   ? " with read/write access"
                        : protection.numeric && protection.number == 2 ? " with read-only access"
                                                                       : QString();
                    step.summary =
                        "Requests " +
                        (size.numeric ? QString::number(size.number) + " bytes of memory" : "memory") +
                        permission +
                        " through the VirtualAlloc import contract. Parameters are derived locally; "
                        "execution and success are unobserved.";
                } else
                    step.summary += " " + api->observation + " Execution and result are unobserved here.";
            } else
                step.summary += " Its effects and result are unknown.";
            merge(step.evidence, a.evidence);
            // Windows API contracts use the Windows x64 ABI. Unknown calls may use another convention.
            if (api) {
                for (const auto &r : {"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"})
                    s.regs.remove(r);
            } else {
                s.regs.clear();
            }
            s.stackCells.clear();
            comparison = {};
            if (api) {
                Value ret;
                ret.available = true;
                ret.expression = "return value of " + api->symbol.section('!', 1);
                ret.evidence = {i.address};
                s.regs["rax"] = ret;
            }
        } else if (i.conditional) {
            step.condition = true;
            step.title = "Choose a path";
            auto predicate = condition(p, comparison, s);
            if (!predicate.isEmpty()) {
                step.summary = "Branches to " + hex(i.target) + " if " + predicate +
                               "; otherwise continues at " + hex(i.address + i.size) + ".";
                if (comparison.valid && mn != ZYDIS_MNEMONIC_JRCXZ && mn != ZYDIS_MNEMONIC_JECXZ) {
                    step.evidence << comparison.at;
                    merge(step.evidence, comparison.left.evidence);
                    merge(step.evidence, comparison.right.evidence);
                }
            } else
                step.summary = "Conditional branch to " + hex(i.target) + ". " + i.fact +
                               " No safe link to a preceding comparison is established.";
        } else if (mn == ZYDIS_MNEMONIC_CMP || mn == ZYDIS_MNEMONIC_TEST) {
            if (b.numeric) {
                b.number &= mask(p.ops[0].size);
                b.expression = b.number ? hex(b.number) : "zero";
            }
            comparison = {true, mn == ZYDIS_MNEMONIC_TEST, a, b, i.address};
            step.title = mn == ZYDIS_MNEMONIC_CMP ? "Compare values" : "Test bits";
            step.summary =
                (mn == ZYDIS_MNEMONIC_CMP ? "Compares " : "Tests the bitwise AND of ") + show(a) + " and " +
                show(b) + QString(" (%1 bits); updates flags without storing the result.").arg(p.ops[0].size);
            merge(step.evidence, a.evidence);
            merge(step.evidence, b.evidence);
        } else if ((mn == ZYDIS_MNEMONIC_MOV || mn == ZYDIS_MNEMONIC_MOVZX || mn == ZYDIS_MNEMONIC_MOVSX ||
                    mn == ZYDIS_MNEMONIC_MOVSXD || mn == ZYDIS_MNEMONIC_LEA) &&
                   count >= 2) {
            result = mn == ZYDIS_MNEMONIC_LEA ? effective(p.ops[1], i, s, true, p.d.address_width) : b;
            if (mn == ZYDIS_MNEMONIC_MOVZX || mn == ZYDIS_MNEMONIC_MOVSX || mn == ZYDIS_MNEMONIC_MOVSXD) {
                if (result.numeric) {
                    int bits = p.ops[1].size;
                    result.number &= mask(bits);
                    if (mn != ZYDIS_MNEMONIC_MOVZX && (result.number & (quint64(1) << (bits - 1))))
                        result.number |= ~mask(bits);
                    result.expression = hex(result.number);
                } else if (result.available)
                    result.expression =
                        QString(mn == ZYDIS_MNEMONIC_MOVZX ? "zero-extended " : "sign-extended ") +
                        show(result);
            }
            step.title = mn == ZYDIS_MNEMONIC_LEA ? "Compute an address" : "Move a value";
            QString dest = operandText(p, 0, i.address);
            step.summary =
                (p.ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY ? "Stores " : "Sets " + dest + " to ") +
                show(result);
            if (p.ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                step.summary += " at " + dest;
                store(s, effective(p.ops[0], i, s, false, p.d.address_width), p.ops[0].size, result,
                      i.address);
                handledMemory = true;
            } else if (p.ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                s.write(p.ops[0].reg.value, result, i.address);
                handledWrite = true;
            }
            step.summary += QString(" (%1 bits).").arg(p.ops[0].size);
            if (mn == ZYDIS_MNEMONIC_LEA)
                step.summary += " This computes an address without reading memory.";
            if (p.ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER && p.ops[0].size == 32)
                step.summary +=
                    " The upper 32 bits of " + parent(p.ops[0].reg.value).toUpper() + " become zero.";
            step.preparation = p.ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER ||
                               effective(p.ops[0], i, s, false, p.d.address_width).stack;
            merge(step.evidence, result.evidence);
        } else if ((mn == ZYDIS_MNEMONIC_ADD || mn == ZYDIS_MNEMONIC_SUB || mn == ZYDIS_MNEMONIC_XOR ||
                    mn == ZYDIS_MNEMONIC_AND || mn == ZYDIS_MNEMONIC_OR) &&
                   count >= 2) {
            bool zero = mn == ZYDIS_MNEMONIC_XOR && p.ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                        p.ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                        p.ops[0].reg.value == p.ops[1].reg.value;
            if (zero)
                result = constant(0);
            else if (a.numeric && b.numeric) {
                quint64 n = mn == ZYDIS_MNEMONIC_ADD   ? a.number + b.number
                            : mn == ZYDIS_MNEMONIC_SUB ? a.number - b.number
                            : mn == ZYDIS_MNEMONIC_XOR ? a.number ^ b.number
                            : mn == ZYDIS_MNEMONIC_AND ? a.number & b.number
                                                       : a.number | b.number;
                result = constant(n & mask(p.ops[0].size));
                result.evidence = a.evidence;
                merge(result.evidence, b.evidence);
            } else if (a.stack && b.numeric && b.number < 0x100000 && p.ops[0].size == 64 &&
                       (mn == ZYDIS_MNEMONIC_ADD || mn == ZYDIS_MNEMONIC_SUB)) {
                result = a;
                result.offset += mn == ZYDIS_MNEMONIC_ADD ? qint64(b.number) : -qint64(b.number);
                result.expression = "block-entry RSP " + QString(result.offset < 0 ? "- " : "+ ") +
                                    QString::number(qAbs(result.offset)) + " bytes";
                merge(result.evidence, b.evidence);
            }
            step.title = zero ? "Clear a register" : "Update a value";
            QString operation = mn == ZYDIS_MNEMONIC_ADD   ? "Adds "
                                : mn == ZYDIS_MNEMONIC_SUB ? "Subtracts "
                                : mn == ZYDIS_MNEMONIC_AND ? "Bitwise AND of "
                                : mn == ZYDIS_MNEMONIC_OR  ? "Bitwise OR of "
                                                           : "Bitwise XOR of ";
            step.summary = zero ? "Sets " + operandText(p, 0, i.address) + " to zero."
                                : operation + show(b) +
                                      (mn == ZYDIS_MNEMONIC_SUB   ? " from "
                                       : mn == ZYDIS_MNEMONIC_ADD ? " to "
                                                                  : " and ") +
                                      show(a) + QString(" (%1 bits); updates flags.").arg(p.ops[0].size) +
                                      (result.available ? " Derived value: " + show(result) + "."
                                                        : " Result remains unknown.");
            if (p.ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER && p.ops[0].size == 32)
                step.summary +=
                    " The upper 32 bits of " + parent(p.ops[0].reg.value).toUpper() + " become zero.";
            if (p.ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                s.write(p.ops[0].reg.value, result, i.address);
                handledWrite = true;
            } else if (p.ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                store(s, effective(p.ops[0], i, s, false, p.d.address_width), p.ops[0].size, result,
                      i.address);
                handledMemory = true;
            }
            step.preparation = p.ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER;
            merge(step.evidence, result.evidence);
        } else if (mn == ZYDIS_MNEMONIC_PUSH && count) {
            auto sp = s.reg(ZYDIS_REGISTER_RSP);
            int bits = p.d.operand_width, bytes = bits / 8;
            if (sp.stack) {
                sp.offset -= bytes;
                store(s, sp, bits, a, i.address);
            } else
                s.stackCells.clear();
            s.write(ZYDIS_REGISTER_RSP, sp, i.address);
            handledWrite = handledMemory = true;
            step.title = "Save on the stack";
            step.summary = "Pushes " + show(a) + " onto the stack; decreases RSP by " +
                           QString::number(bytes) + " bytes.";
        } else if (mn == ZYDIS_MNEMONIC_POP && count && p.ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
            auto sp = s.reg(ZYDIS_REGISTER_RSP);
            Value value;
            if (sp.stack && s.stackCells.contains(sp.offset) && s.stackCells[sp.offset].bits == p.ops[0].size)
                value = s.stackCells[sp.offset].value;
            if (sp.stack)
                sp.offset += p.ops[0].size / 8;
            s.write(ZYDIS_REGISTER_RSP, sp, i.address);
            s.write(p.ops[0].reg.value, value, i.address);
            handledWrite = true;
            step.title = "Restore from the stack";
            step.summary = i.fact;
        } else if (mn == ZYDIS_MNEMONIC_RET) {
            step.title = "Return to the caller";
            step.summary = "Returns to the address on the stack. The destination and caller result are not "
                           "established statically.";
        } else if (i.branch) {
            step.title = "Continue elsewhere";
            step.summary =
                "Transfers control to " + (i.target ? hex(i.target) : QString("an unresolved target")) + ".";
        }
        if (p.valid && !i.call) {
            if (mn != ZYDIS_MNEMONIC_CMP && mn != ZYDIS_MNEMONIC_TEST && p.d.cpu_flags &&
                (p.d.cpu_flags->modified || p.d.cpu_flags->set_0 || p.d.cpu_flags->set_1 ||
                 p.d.cpu_flags->undefined))
                comparison = {};
            for (int n = 0; n < p.d.operand_count; ++n) {
                const auto &o = p.ops[n];
                if (!(o.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE))
                    continue;
                if (o.type == ZYDIS_OPERAND_TYPE_REGISTER && !handledWrite)
                    s.regs.remove(parent(o.reg.value));
                if (o.type == ZYDIS_OPERAND_TYPE_MEMORY && !handledMemory)
                    s.stackCells.clear();
            }
        }
        doc.steps << step;
    }
    // Group only transparent setup operations; never bury unknown effects in an API summary.
    for (int n = 0; n < doc.steps.size(); ++n) {
        const auto &step = doc.steps[n];
        MeaningUnit unit;
        unit.title = step.title;
        unit.summary = step.summary;
        unit.arguments = step.arguments;
        unit.steps = {n};
        unit.evidence = step.evidence;
        if (step.call || step.condition) {
            while (!doc.units.isEmpty()) {
                const auto &last = doc.units.last();
                bool absorb = true;
                for (int at : last.steps)
                    absorb &= step.call ? doc.steps[at].preparation
                                        : (doc.steps[at].title == "Compare values" ||
                                           doc.steps[at].title == "Test bits");
                int first = unit.steps.first();
                if (!absorb || doc.steps[first].boundary || unit.steps.size() + last.steps.size() > 24)
                    break;
                auto previous = doc.units.takeLast();
                unit.steps = previous.steps + unit.steps;
                merge(unit.evidence, previous.evidence);
                if (step.condition)
                    break;
            }
        }
        for (int at : unit.steps)
            doc.unitAt[doc.steps[at].address] = doc.units.size();
        doc.units << unit;
    }
    // Unit indices can change while folding setup into calls.
    doc.unitAt.clear();
    for (int n = 0; n < doc.units.size(); ++n)
        for (int at : doc.units[n].steps)
            doc.unitAt[doc.steps[at].address] = n;
    return doc;
}

std::optional<quint64> observedRegister(QString name, const QMap<QString, quint64> &values) {
    auto bytes = name.toLower().toLatin1();
    // Zydis has no string-to-register API. The supported GPR aliases are enumerated explicitly.
    static const QStringList parents{"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"};
    static const QStringList low32{"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"};
    static const QStringList low16{"ax", "cx", "dx", "bx", "sp", "bp", "si", "di"};
    static const QStringList low8{"al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil"};
    name = QString::fromLatin1(bytes);
    if (values.contains(name))
        return values[name];
    for (int n = 0; n < parents.size(); ++n) {
        int bits = name == low32[n] ? 32 : name == low16[n] ? 16 : name == low8[n] ? 8 : 0;
        if (bits && values.contains(parents[n]))
            return values[parents[n]] & mask(bits);
    }
    for (int n = 8; n <= 15; ++n) {
        auto key = "r" + QString::number(n);
        int bits = name == key + "d" ? 32 : name == key + "w" ? 16 : name == key + "b" ? 8 : 0;
        if (bits && values.contains(key))
            return values[key] & mask(bits);
    }
    int hi = QStringList{"ah", "ch", "dh", "bh"}.indexOf(name);
    if (hi >= 0 && values.contains(parents[hi]))
        return (values[parents[hi]] >> 8) & 255;
    return {};
}
QString observedOperands(const Instruction &i, const QMap<QString, quint64> &regs,
                         const std::function<QByteArray(quint64, int)> &memory) {
    auto p = parse(i);
    if (!p.valid)
        return {};
    QStringList lines;
    for (auto &name : i.reads)
        if (auto v = observedRegister(name, regs))
            lines << name.toUpper() + " = " + hex(*v);
    State s;
    for (auto it = regs.begin(); it != regs.end(); ++it)
        s.regs[it.key()] = constant(it.value());
    for (int n = 0; n < p.d.operand_count_visible; ++n)
        if (p.ops[n].type == ZYDIS_OPERAND_TYPE_MEMORY) {
            auto address = effective(p.ops[n], i, s, p.d.mnemonic == ZYDIS_MNEMONIC_LEA, p.d.address_width);
            if (!address.numeric) {
                lines << operandText(p, n, i.address) +
                             ": address unavailable (including segment base where needed)";
                continue;
            }
            QString text = operandText(p, n, i.address) + ": address " + hex(address.number);
            if (p.d.mnemonic == ZYDIS_MNEMONIC_LEA)
                text += " (address only; no memory read)";
            else if (p.ops[n].actions & ZYDIS_OPERAND_ACTION_MASK_READ) {
                int bytes = p.ops[n].size / 8;
                auto data = memory(address.number, bytes);
                text += data.size() == bytes ? " · captured bytes " + QString::fromLatin1(data.toHex(' '))
                                             : " · value not captured/readable in this snapshot";
            }
            lines << text;
        }
    return lines.join('\n');
}
QVector<MeaningArgument> recordedApiArguments(const Event &event) {
    QVector<MeaningArgument> result;
    for (const auto &api : apiCatalog()) {
        if (api.symbol.compare(event.api, Qt::CaseInsensitive) != 0)
            continue;
        auto fields = event.arguments;
        bool legacy = fields.isEmpty();
        if (legacy) {
            if (event.type != "Breakpoint hit")
                return {};
            auto capturedMemory = [&](quint64 address, int count) -> QByteArray {
                quint64 base = event.registers.value("rsp");
                if (address < base || address - base > quint64(event.stack.size()) || count < 0 ||
                    quint64(count) > quint64(event.stack.size()) - (address - base))
                    return {};
                return event.stack.mid(qsizetype(address - base), count);
            };
            // Older investigations have numeric register/stack evidence, but no structured string capture.
            describeApi(api, event.registers, capturedMemory, true, &fields);
        }
        for (int n = 0; n < api.args.size(); ++n) {
            auto name = api.args[n].section(':', 0, 0);
            auto field = std::find_if(fields.begin(), fields.end(),
                                      [&](const CapturedArgument &a) { return a.name == name; });
            if (field == fields.end())
                continue;
            QString value = field->value;
            auto number = QRegularExpression("^0x([0-9a-fA-F]+)").match(value);
            if (number.hasMatch()) {
                bool ok;
                auto raw = number.captured(1).toULongLong(&ok, 16);
                if (ok) {
                    value = argumentValue(api, n, constant(raw), nullptr);
                    auto type = api.args[n].section(':', 1);
                    if (type == "wstr" || type == "astr")
                        value += field->value.mid(number.capturedLength());
                }
            }
            result << MeaningArgument{name,
                                      value,
                                      field->source + (legacy ? " · saved registers/stack (legacy snapshot)"
                                                              : " · recorded at entry"),
                                      {event.ip}};
        }
        break;
    }
    return result;
}

} // namespace vnr
