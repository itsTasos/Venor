#include <cstdint>
#include <windows.h>
struct Record {
    int value;
    unsigned flags;
    const char *label;
};
#define EXPORTED extern "C" __declspec(dllexport) __attribute__((noinline))
EXPORTED int inspect_record(const Record *record, int limit) {
    if (!record || !record->label)
        return -1;
    int value = record->value;
    if ((record->flags & 1) != 0)
        value *= 2;
    return value > limit ? limit : value;
}
EXPORTED int summarize_records(const Record *records, unsigned count) {
    int total = 0;
    for (unsigned n = 0; n < count; ++n) {
        int value = inspect_record(&records[n], 100);
        if (value >= 0)
            total += value;
    }
    return total;
}
EXPORTED DWORD platform_probe() {
    HANDLE event = CreateEventW(nullptr, TRUE, FALSE, L"Venor benign decompiler test");
    if (!event)
        return GetLastError();
    SetEvent(event);
    DWORD result = WaitForSingleObject(event, 0);
    CloseHandle(event);
    return result;
}
#ifndef VENOR_TEST_DLL
int main(int argc, char **) {
    Record rows[]{{argc, 1, "first"}, {3, 0, "second"}, {-2, 1, "third"}};
    volatile int result = summarize_records(rows, 3);
    return platform_probe() == WAIT_OBJECT_0 && result >= 0 ? 0 : 1;
}
#endif
