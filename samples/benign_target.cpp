#include <cstdio>
#include <cstring>
#include <windows.h>
extern "C" {
alignas(8) __declspec(dllexport) volatile unsigned long long investigation_watch[4] = {};
}
extern "C" __declspec(dllexport) __attribute__((noinline)) int investigation_marker(int value) {
    investigation_watch[0] = investigation_watch[0] + value + 1;
    volatile int result = value + 7;
    return result;
}
DWORD WINAPI worker(void *) {
    Sleep(40);
    return 0;
}
extern "C" __declspec(dllexport) __attribute__((noinline)) void *meaning_allocation() {
    return VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
}
extern "C" __declspec(dllexport) __attribute__((noinline)) int recursive_marker(int depth) {
    if (depth <= 0)
        return 1;
    volatile int result = recursive_marker(depth - 1) + 1;
    return result;
}
LONG CALLBACK benignException(EXCEPTION_POINTERS *e) {
    return e->ExceptionRecord->ExceptionCode == 0xe0424242 ? EXCEPTION_CONTINUE_EXECUTION
                                                           : EXCEPTION_CONTINUE_SEARCH;
}
int main(int argc, char **argv) {
    if (argc > 1 && std::strcmp(argv[1], "--wait") == 0)
        Sleep(2000);
    if (argc > 1 && std::strcmp(argv[1], "--exception") == 0) {
        auto handler = AddVectoredExceptionHandler(1, benignException);
        RaiseException(0xe0424242, 0, 0, nullptr);
        if (handler)
            RemoveVectoredExceptionHandler(handler);
    }
    if (argc > 1 && std::strcmp(argv[1], "--recursive") == 0)
        std::printf("recursion %d\n", recursive_marker(3));
    if (argc > 1 && std::strcmp(argv[1], "--modules") == 0) {
        for (int n = 0; n < 2; n++) {
            HMODULE mod = LoadLibraryExW(L"version.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
            if (mod) {
                using Query = DWORD(WINAPI *)(LPCWSTR, LPDWORD);
                auto query = reinterpret_cast<Query>(GetProcAddress(mod, "GetFileVersionInfoSizeW"));
                DWORD ignored = 0;
                if (query)
                    query(L"C:\\Venor_nonexistent_test_file_092734.exe", &ignored);
                FreeLibrary(mod);
            }
        }
    }
    HANDLE t = CreateThread(nullptr, 0, worker, nullptr, 0, nullptr);
    void *page = meaning_allocation();
    for (int n = 0; n < 3; n++)
        std::printf("marker %d\n", investigation_marker(n));
    if (page)
        VirtualFree(page, 0, MEM_RELEASE);
    if (t) {
        WaitForSingleObject(t, 1000);
        CloseHandle(t);
    }
    return 0;
}
