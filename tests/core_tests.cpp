#include "semantics.h"
#include "types.h"
#include <QtTest>
#include <windows.h>
using namespace vnr;
static QString sample;
static QString library;
class CoreTests : public QObject {
    Q_OBJECT
  private slots:
    void pe() {
        auto b = analyze(sample);
        QVERIFY(b->base);
        QVERIFY(b->entry);
        QVERIFY(!b->dll);
        QVERIFY(!b->code.isEmpty());
        QVERIFY(b->instructionIndex(b->entry) >= 0);
        QVERIFY(!b->imports.isEmpty());
        QVERIFY(!b->functions.isEmpty());
        QVERIFY(b->hash.size() == 64);
        QVERIFY(b->bytesAt(b->entry, 16).size() == 16);
        QVERIFY(b->bytesAt(0, 16).isEmpty());
        QVERIFY(std::any_of(b->exports.begin(), b->exports.end(),
                            [](auto &r) { return r.name == "investigation_marker"; }));
    }
    void malformed() {
        QTemporaryFile f;
        QVERIFY(f.open());
        f.write("MZbad");
        f.flush();
        QVERIFY_EXCEPTION_THROWN(analyze(f.fileName()), std::runtime_error);
        auto b = analyze(sample);
        QByteArray bytes = b->data;
        auto dos = reinterpret_cast<IMAGE_DOS_HEADER *>(bytes.data());
        auto nt = reinterpret_cast<IMAGE_NT_HEADERS64 *>(bytes.data() + dos->e_lfanew);
        nt->FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
        f.resize(0);
        f.write(bytes);
        f.flush();
        QVERIFY_EXCEPTION_THROWN(analyze(f.fileName()), std::runtime_error);
    }
    void dll() {
        if (library.isEmpty())
            QSKIP("DLL fixture not supplied");
        auto b = analyze(library);
        QVERIFY(b->dll);
        QVERIFY(!b->exports.isEmpty());
        QVERIFY(std::any_of(b->exports.begin(), b->exports.end(),
                            [](const auto &r) { return r.name == "library_marker"; }));
    }
    void truncated() {
        auto b = analyze(sample);
        for (int n : {0, 1, 64, 128, 256, 512}) {
            QTemporaryFile f;
            QVERIFY(f.open());
            f.write(b->data.left(n));
            f.flush();
            QVERIFY_EXCEPTION_THROWN(analyze(f.fileName()), std::runtime_error);
        }
    }
    void semantics() {
        auto code = decode(QByteArray::fromHex("488d05010000004831c0c3"), 0x1000);
        QCOMPARE(code.size(), 3);
        QVERIFY(code[0].fact.contains("does not read"));
        QCOMPARE(code[0].target, quint64(0x1008));
        QVERIFY(code[1].writes.contains("rax"));
        QVERIFY(code[2].terminal);
        QVERIFY(blockSummary(code).contains("Unknown"));
        QVERIFY(!decode(QByteArray::fromHex("0f"), 0x2000)[0].valid);
        auto memory = decode(QByteArray::fromHex("488b449108"), 0x1000);
        QVERIFY(memory[0].reads.contains("rcx"));
        QVERIFY(memory[0].reads.contains("rdx"));
        QVERIFY(memory[0].writes.contains("rax"));
        auto address = decode(QByteArray::fromHex("488d449108"), 0x1000);
        QVERIFY(address[0].reads.contains("rcx"));
        QVERIFY(address[0].reads.contains("rdx"));
        QVERIFY(address[0].fact.contains("does not read"));
        auto segmented = decode(QByteArray::fromHex("65488b0501000000"), 0x1000);
        QCOMPARE(segmented[0].target, 0ULL);
        QVERIFY(segmented[0].reads.contains("gs"));
        QVERIFY(segmented[0].unknown.contains("segment base"));
        auto addressOnly = decode(QByteArray::fromHex("65488d0501000000"), 0x1000);
        QCOMPARE(addressOnly[0].target, 0x1009ULL);
        QVERIFY(!addressOnly[0].reads.contains("gs"));
    }
    void graph() {
        auto code = decode(QByteArray::fromHex("75029090c3"), 0x1000);
        auto edges = flowEdges(code);
        QVERIFY(edges.contains({0x1000, 0x1004}));
        QVERIFY(edges.contains({0x1000, 0x1002}));
        auto direct = decode(QByteArray::fromHex("eb029090c3"), 0x1000);
        auto jumps = flowEdges(direct);
        QVERIFY(!jumps.contains({0x1000, 0x1002}));
    }
    void highLevelApi() {
        Binary image;
        image.imports = {{0x2000, "KERNEL32.dll!VirtualAlloc", "IAT"}};
        auto setup = QByteArray::fromHex("31c9ba0010000041b80030000041b904000000");
        auto call = [&](QByteArray prefix) {
            auto displacement = qToLittleEndian<quint32>(quint32(0x2000 - (0x1000 + prefix.size() + 6)));
            prefix += QByteArray::fromHex("ff15");
            prefix.append(reinterpret_cast<const char *>(&displacement), 4);
            return prefix;
        };
        auto code = decode(call(setup) + QByteArray::fromHex("4885c07401c3c3"), 0x1000);
        auto doc = analyzeMeaning(code, &image);
        QVERIFY(doc.units[0].title.contains("VirtualAlloc"));
        QCOMPARE(doc.units[0].steps.size(), 5);
        QCOMPARE(doc.units[0].arguments.size(), 4);
        QVERIFY(doc.units[0].arguments[1].value.contains("4096 bytes"));
        QVERIFY(doc.units[0].arguments[2].value.contains("MEM_COMMIT"));
        QVERIFY(doc.units[0].arguments[3].value.contains("PAGE_READWRITE"));
        QVERIFY(doc.steps[6].summary.contains("return value of VirtualAlloc is zero"));
        QVERIFY(doc.steps[6].evidence.contains(code[4].address));
        // A write to DL invalidates the full previously unknown RDX; don't keep the old size.
        auto partial = analyzeMeaning(decode(call(setup + QByteArray::fromHex("0fa2b201")), 0x1000), &image);
        QVERIFY(partial.steps.last().arguments[1].value.contains("Unknown"));
        // Arithmetic wraps to the destination width, then zero-extends to RDX.
        auto wrap = analyzeMeaning(decode(call(QByteArray::fromHex("baffffffff83c201")), 0x1000), &image);
        QVERIFY(wrap.steps.last().arguments[1].value.contains("0 bytes"));
        // SIZE_T is 64 bits, not DWORD. Do not truncate a known 8 GiB request.
        auto large =
            analyzeMeaning(decode(call(QByteArray::fromHex("48ba0000000002000000")), 0x1000), &image);
        QVERIFY(large.steps.last().arguments[1].value.contains("8589934592 bytes"));
        image.imports[0].name = "custom.dll!VirtualAlloc";
        auto sameName = analyzeMeaning(decode(call(setup), 0x1000), &image);
        QVERIFY(sameName.steps.last().arguments.isEmpty());
    }
    void highLevelInvalidation() {
        auto doc = analyzeMeaning(decode(QByteArray::fromHex("4885c048ffc17401c3c3"), 0x1000));
        QVERIFY(doc.steps[2].summary.contains("No safe link")); // INC overwrote ZF.
        auto preserved = analyzeMeaning(decode(QByteArray::fromHex("4885c04889da7401c3c3"), 0x1000));
        QVERIFY(preserved.steps[2].summary.contains("RAX is zero")); // MOV preserves flags.
        auto join =
            analyzeMeaning(decode(QByteArray::fromHex("b901000000eb00ff1523000000"), 0x1000), nullptr);
        QVERIFY(join.steps.last().summary.contains("unresolved"));
        // A branch target resets block-local argument knowledge even if linear layout suggests a value.
        Binary image;
        image.imports = {{0x1030, "KERNEL32.dll!VirtualAlloc", "IAT"}};
        join = analyzeMeaning(decode(QByteArray::fromHex("b901000000eb00ff1523000000"), 0x1000), &image);
        QVERIFY(join.steps.last().arguments[0].value.contains("Unknown"));
        auto gap = decode(QByteArray::fromHex("b901000000"), 0x1000);
        gap += decode(QByteArray::fromHex("ff15eaffffff"), 0x1040); // slot 0x1030
        auto discontinuous = analyzeMeaning(gap, &image);
        QVERIFY(discontinuous.steps.last().arguments[0].value.contains("Unknown"));
    }
    void stackAndObservedValues() {
        Binary image;
        image.imports = {{0x2000, "KERNEL32.dll!CreateFileW", "IAT"}};
        QByteArray bytes = QByteArray::fromHex("4883ec3848c744242003000000ff15ed0f0000");
        auto doc = analyzeMeaning(decode(bytes, 0x1000), &image);
        QVERIFY(doc.steps.last().arguments[4].value.contains("OPEN_EXISTING"));
        QVERIFY(doc.steps.last().arguments[4].source.contains("before CALL"));
        // Unknown pointer stores can alias stack argument slots; invalidate them.
        auto unknown = QByteArray::fromHex("4883ec3848c744242003000000488908ff15ea0f0000");
        auto alias = analyzeMeaning(decode(unknown, 0x1000), &image);
        QVERIFY(alias.steps.last().arguments[4].value.contains("Unknown"));
        QMap<QString, quint64> r{{"rax", 0x123456789abcdeffULL}, {"rcx", 0x5000}};
        QCOMPARE(*observedRegister("eax", r), 0x9abcdeffULL);
        QCOMPARE(*observedRegister("ah", r), 0xdeULL);
        QVERIFY(!observedRegister("r8d", r));
        auto load = decode(QByteArray::fromHex("8b4108"), 0x1000)[0];
        auto observed = observedOperands(load, r, [](quint64 at, int count) {
            return at == 0x5008 && count == 4 ? QByteArray::fromHex("01000000") : QByteArray();
        });
        QVERIFY(observed.contains(hex(0x5008)));
        QVERIFY(observed.contains("01 00 00 00"));
        auto segmented = decode(QByteArray::fromHex("65488b01"), 0x1000)[0];
        QVERIFY(observedOperands(segmented, r, [](quint64, int) {
                    return QByteArray();
                }).contains("address unavailable"));
        auto lea = decode(QByteArray::fromHex("488d4108"), 0x1000)[0];
        bool read = false;
        QVERIFY(observedOperands(lea, r, [&](quint64, int) {
                    read = true;
                    return QByteArray();
                }).contains("no memory read"));
        QVERIFY(!read);
        Event entry;
        entry.api = "kernelbase!VirtualAlloc";
        entry.type = "Breakpoint hit";
        entry.ip = 0x1000;
        QMap<QString, quint64> args{
            {"rcx", 0}, {"rdx", 8589934592ULL}, {"r8", 0xffffffff00003000ULL}, {"r9", 4}};
        auto api = apiCatalog()[3];
        QCOMPARE(api.symbol, entry.api);
        entry.registers = args;
        entry.detail =
            describeApi(api, args, [](quint64, int) { return QByteArray(); }, true, &entry.arguments);
        entry.detail += "\nflProtect (r9): 0x0000000000000040 [PAGE_EXECUTE_READWRITE]";
        auto captured = recordedApiArguments(entry);
        QCOMPARE(captured.size(), 4);
        QCOMPARE(captured[0].value, QString("NULL"));
        QVERIFY(captured[1].value.contains("8589934592 bytes"));
        QVERIFY(captured[2].value.contains("MEM_COMMIT"));
        QVERIFY(!captured[2].value.contains("unmodeled bits"));
        QCOMPARE(captured[3].value, QString("PAGE_READWRITE"));
        entry.arguments
            .clear(); // Legacy data is reconstructed from saved registers, never parsed from log text.
        QCOMPARE(recordedApiArguments(entry)[3].value, QString("PAGE_READWRITE"));
    }
    void conditions() {
        QVERIFY(conditionSyntax("@rcx == 0n2"));
        QVERIFY(conditionSyntax("(@rax & 0x10) != 0"));
        QVERIFY(!conditionSyntax(".shell anything"));
        QVERIFY(!conditionSyntax("@rcx=1"));
        QVERIFY(!conditionSyntax("1;g"));
        QVERIFY(!conditionSyntax("@rax++"));
    }
    void cancellation() {
        auto cancel = std::make_shared<std::atomic_bool>(true);
        QVERIFY_EXCEPTION_THROWN(analyze(sample, cancel), std::runtime_error);
        QVERIFY_EXCEPTION_THROWN(decode(QByteArray::fromHex("90c3"), 0x1000, 100, cancel),
                                 std::runtime_error);
    }
    void api() {
        auto catalog = apiCatalog();
        auto it = std::find_if(catalog.begin(), catalog.end(),
                               [](auto &a) { return a.symbol == "kernelbase!VirtualAlloc"; });
        QVERIFY(it != catalog.end());
        QMap<QString, quint64> r{{"rcx", 0}, {"rdx", 4096}, {"r8", 0x3000}, {"r9", 4}};
        auto text = describeApi(*it, r, [](quint64, int) { return QByteArray(); });
        QVERIFY(text.contains("MEM_COMMIT"));
        QVERIFY(text.contains("PAGE_READWRITE"));
        QVERIFY(text.contains("does not imply"));
        auto send =
            std::find_if(catalog.begin(), catalog.end(), [](auto &a) { return a.symbol == "ws2_32!send"; });
        QVERIFY(send != catalog.end());
        r["r8"] = 0xffffffff;
        QVERIFY(describeApi(*send, r, [](quint64, int) { return QByteArray(); }).contains("(-1)"));
    }
    void persistence() {
        QTemporaryDir dir(QDir::currentPath() + "/core-case-XXXXXX");
        Workspace w;
        w.binary = sample;
        w.hash = "test";
        w.selected = 0xfffffffffffffff0ULL;
        w.notes = "Ω notes";
        w.comments[w.selected] = "comment";
        w.bookmarks[0x1000] = "bookmark";
        w.renames[0x2000] = "local_name";
        w.trail = {w.selected};
        Breakpoint b;
        b.expression = "module!fn";
        b.condition = "@rcx == 0n2";
        b.group = "Test";
        b.log = true;
        b.once = true;
        b.hits = 42;
        w.breakpoints << b;
        Event e;
        e.type = "test capture";
        e.address = w.selected;
        e.registers["rax"] = 0xffffffffffffffffULL;
        e.stack = QByteArray::fromHex("000102ff");
        e.ip = 0x1000;
        e.code = QByteArray::fromHex("4889c8c3");
        e.frames = {{0x1000, "fn", "frame"}};
        e.arguments = {{"lpFileName", "captured string\nflProtect (r9): fake parameter", "rcx"}};
        w.events << e;
        auto path = dir.filePath("case.venor");
        Workspace restored;
        try {
            saveWorkspace(path, w);
            restored = loadWorkspace(path);
        } catch (const std::exception &e) {
            QFAIL(e.what());
        }
        QCOMPARE(restored.selected, w.selected);
        QCOMPARE(restored.comments, w.comments);
        QCOMPARE(restored.renames, w.renames);
        QCOMPARE(restored.bookmarks, w.bookmarks);
        QCOMPARE(restored.notes, w.notes);
        QCOMPARE(restored.breakpoints[0].hits, 42ULL);
        QCOMPARE(restored.events[0].registers["rax"], 0xffffffffffffffffULL);
        QCOMPARE(restored.events[0].stack, e.stack);
        QCOMPARE(restored.events[0].ip, e.ip);
        QCOMPARE(restored.events[0].code, e.code);
        QCOMPARE(restored.events[0].frames[0].address, 0x1000ULL);
        QCOMPARE(restored.events[0].arguments[0].value, e.arguments[0].value);
        QCOMPARE(restored.breakpoints[0].status, QString("Pending"));
    }
};
int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    sample = QString::fromLocal8Bit(argv[1]);
    if (argc > 2)
        library = QString::fromLocal8Bit(argv[2]);
    CoreTests tests;
    return QTest::qExec(&tests, QStringList{"core_tests", "-o", "core-results.txt,txt"});
}
#include "core_tests.moc"
