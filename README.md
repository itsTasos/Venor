# Venor — native Windows x64 investigation workstation

Venor is the configurable working name. This is a native C++20/Qt 6 Widgets
application using Zydis and the Windows DbgEng engine. Windows 10 (1809+) or
Windows 11 x64 is required by this Qt build. All analysis, notes and
evidence stay on the local machine. No AI, inference services or uploads.

## Build

Windows x64, CMake 3.24+, Ninja, MinGW-w64 GCC 13 or later and Qt 6.8+ with
Widgets, Concurrent, Sql and Test. Dependencies must match the compiler ABI.
Zydis and Zycore source are pinned in `third_party/zydis`.
For a Git checkout, run `git submodule update --init --recursive` before building.

```powershell
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=C:/Qt/6.8.3/mingw_64
cmake --build build -j 4
$env:PATH = "C:/Qt/6.8.3/mingw_64/bin;C:/w64devkit/bin;" + $env:PATH
ctest --test-dir build --output-on-failure
./build/venor.exe
```

Use `-DVENOR_APP_NAME="Your working title"`, `VENOR_APP_TITLE`, or
`venor.exe --title "Your working title"` to change the displayed name.

## First investigation

1. Open an x64 PE EXE/DLL with Ctrl+O or drag it into the window. Opening never
   executes the target. Explore functions, imports, strings and metadata at left.
2. Start in **Meaning**: grouped operations explain API requests, locally known
   arguments and conditional paths. Click source addresses to synchronize
   **Assembly / Flow / Meaning**. The right inspector leads with a short summary,
   inputs and evidence; **Instruction details** expands the raw facts and bytes.
3. F9 adds a module+RVA breakpoint at a static selection, accounting for ASLR.
   Ctrl+B opens a custom editor. Ctrl+Shift+B opens searchable API presets with
   exact symbols, arguments, result contracts and limitations.
4. Ctrl+F5 explicitly starts the selected executable after a machine-choice
   warning. Use an isolated VM for unknown files. Ctrl+Alt+A attaches to a process
   you are allowed to debug. No automatic privilege elevation is attempted.
5. F5 continues; F6 pauses; F7/F8 step into/over; Shift+F8 steps out. Select a
   thread to change context. Registers, flags, stack, call stack and modules are
   actual DbgEng data. Hex/Memory reads static bytes or stopped process memory.
6. Captured breakpoint/exception events retain registers, stack bytes and stack
   frames. Timeline links are historical evidence, not a full instruction trace.
   API return observers pair the engine thread and expected stack pointer.
7. Add comments (`;`), names (`N`), bookmarks (Ctrl+D) and notes. Ctrl+S saves a
   local SQLite `.venor` investigation, including breakpoint policies, layout,
   navigation trail and evidence. Reopen checks the binary SHA-256 before binding
   evidence to code. Saved evidence does not recreate a live process.

Ctrl+G navigates; Ctrl+F searches symbols/strings/hex; Enter follows a resolved
operand; X shows xrefs; Alt+Left/Right navigates history; Ctrl+Shift+P opens the
command palette. View exposes every dock and Beginner/Analyst/Expert layouts
change density only. Dark/light themes and dock layouts persist locally.
Use View → Restore Current Workspace Layout to apply the new default proportions
when reopening an investigation with an older saved layout.
While paused, navigation can decode actual process bytes at arbitrary addresses
or DbgEng symbol expressions; Ctrl+I returns to the stopped instruction without
executing the target. Static function navigation uses the loaded module's base
when it is available. Investigations captured through attach can reopen saved
events and code snapshots even without an associated static binary.

## Debugger details and boundaries

Only x64 Windows user-mode PE is supported. Hardware breakpoints have four CPU
slots; data sizes are 1/2/4/8 bytes and require natural alignment. Read/write
watches both accesses; there is no read-only x64 watchpoint. Conditions use
DbgEng MASM expressions: `@rcx == 0n2` uses decimal 2; unprefixed numbers are hex.
Hit count includes nonqualifying hits; after-N is a threshold, one-shot disables
on the first qualifying hit, log-only records evidence and continues.

Symbols use local exports/local symbol files only. There is no symbol-server
download. Pending exports are resolved by DbgEng when modules load; errors and
hardware resource limits appear in the breakpoint table. The system DbgEng
version determines exact target and symbol support. Module names in custom
expressions must match the debugger's module names. Detach leaves a target alive.

Exceptions are recorded at first/second chance. Continue passes an outstanding
target exception unhandled by default; explicit Handled/Unhandled actions are in
Debug. API return values remain raw plus the documented contract; effects and
successful I/O are not inferred. Tail calls, exceptions, non-returning APIs or
unusual stacks can prevent return pairing; observers are capped at 256 per
session. String capture is bounded to 512 bytes and reports unreadable/truncated
data. Unicode string discovery currently covers UTF-16 ASCII-range characters.

Static code is a linear sweep of executable raw sections, not proof of
reachability; padding/data can decode as instructions. Function candidates come
from entry, exports, x64 unwind records and direct calls. Graph/readable windows
are capped at 160 instructions and 4 KiB; graph edges show decoded branches and
fallthrough, not complete control flow. Unknown operation semantics stay unknown.
Limits: 512 MiB file, 4 million executable raw bytes, 10,000 retained events,
5,000 trail addresses, 200,000 discovered strings, 2,000,000 instructions per
section and last 100 events in the relationship graph. Cancel is checked during
decoding, string discovery and between sections. The relationship graph links only captured event
order on the same thread; it does not assert causality or time travel.

The Meaning engine interprets a maximum of 160 instructions locally: GPR widths
and aliases, constants, supported arithmetic, relative stack slots, selected
loads/stores, import-derived API arguments, and comparison-to-branch links.
Knowledge is reset at block entries, joins, gaps and undecodable bytes;
unmodeled writes invalidate affected registers/stack facts, and calls invalidate
volatile state (all tracked registers for unknown calling conventions). General
memory loads are not treated as constants. Static string previews are labelled
file bytes; observed operands use only bytes actually present in that snapshot.
FS/GS bases and 32-bit address-size overrides are not resolved by this engine.
API contracts are matched to the expected Windows modules, not just a function
name. Known Windows API calls use the Windows x64 ABI; SIZE_T stays 64 bits.
The engine does not infer general function intent or follow data flow across
basic-block boundaries. Every grouped operation retains its source addresses. New API captures store
arguments as structured event fields, including strings containing newlines.
Legacy investigations recover inputs from their saved registers/stack, not by
parsing log text; missing string bytes stay unavailable.

## Starting a GitHub repository

`.gitignore` excludes local toolchains, builds, release packages, test captures,
process dumps, personal `.venor` investigations, local settings and `.env` files.
Internal plans, implementation reports, agent/skill instructions and design
references also stay local. Source, tests, build/release scripts, public
documentation, licenses and the application icon belong in the repository.
The pinned Zydis checkout is a submodule declared in `.gitmodules`; its Zycore
dependency is a nested upstream submodule. Keep `.gitmodules` and the Zydis
gitlink in your initial commit. The expected Zydis commit is
`a2278f1d254e492f6a6b39f6cb5d1f5d515659dc`.

After creating your GitHub repository, initialize/stage this folder and review
the staged changes before committing/pushing. Clone on other machines with
`git clone --recurse-submodules <your-repository-url>`; for an existing clone use
`git submodule update --init --recursive`. Qt/compiler installations remain
local and are configured using `CMAKE_PREFIX_PATH` as shown above. A `.gitignore`
does not remove files that you have already tracked in an existing repository.

The application is an initial implementation, not a claim of production
readiness. The boundaries above describe its supported behavior; the commands
below produce local test reports. Clean-machine portability and Windows 10
operation have not been verified. See THIRD_PARTY_NOTICES.md and licenses for
redistribution.

## Package and verify

The supplied `venor.ico` is embedded unchanged in both the Windows executable
resources (Explorer/shortcuts) and Qt resources (window icon). Replacing this
file and rebuilding updates both; no external icon file is needed at runtime.
`--check-runtime` also checks that the embedded Qt icon can be rendered.

Run `./tools/package.ps1` after both builds/tests complete. The release folder
contains `venor.exe`, Qt/runtime DLLs, platform and SQLite plugins, the harmless
target, tests, license texts, complete application/decoder source and evidence.
Extract the entire ZIP before running; keep the adjacent files together.
`./tools/verify-package.ps1` runs packaged tests with the developer Qt/compiler
directories removed from PATH and checks native application startup.
Packaging also requires the matching Qt source archive locally at
`third_party/qt-source/qtbase-everywhere-src-6.8.3.tar.xz` for redistribution.
This archive and the Qt/compiler installations are excluded from Git.

```powershell
./core_tests.exe ./benign_target.exe ./libbenign_library.dll
./debugger_tests.exe (Resolve-Path ./benign_target.exe)
$env:QT_QPA_PLATFORM = "offscreen"
./gui_tests.exe (Resolve-Path ./benign_target.exe)
```

Test reports are `core-results.txt`, `debugger-results.txt`, `gui-results.txt`
in the working directory. For native captures set `QT_QPA_PLATFORM=windows` and
`VENOR_QA_CAPTURES` to an output folder. Set `QT_SCALE_FACTOR=1.5` for application
scaling checks. GUI tests use Qt file dialogs for reproducible input; the normal
application uses the Windows native picker. These tests launch only the supplied
benign target. They do not establish clean-machine portability.
