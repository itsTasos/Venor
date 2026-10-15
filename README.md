# Venor

**Understand Windows binaries. Follow the evidence. Keep your investigation local.**

Venor is a native Windows x64 reverse-engineering workstation that combines static
analysis, live debugging and readable assembly explanations in one desktop app.
Explore an executable, understand supported instructions and Windows API calls,
set breakpoints, and save your findings for later.

Built with **C++20 · Qt 6 Widgets · Microsoft DbgEng · Zydis · SQLite**.
All analysis runs on your machine. **No AI, cloud inference or automatic uploads.**

[Get started](#get-started) · [Capabilities](#capabilities) ·
[First investigation](#your-first-investigation) · [Build from source](#build-from-source) ·
[Limitations](#scope-and-limitations)

## Capabilities

| Capability | What you can do |
| --- | --- |
| **Explore binaries** | Open x64 PE `.exe` and `.dll` files; inspect functions, imports, exports, strings, sections and metadata. |
| **Understand assembly** | Switch between synchronized **Assembly**, **Flow** and **Meaning** views. Read instruction explanations, supported API arguments, decoded flags and local data-flow clues, with links to the source instructions. |
| **Debug real processes** | Launch an executable or attach to an eligible process. Continue, pause and step through execution; inspect registers, flags, threads, modules, stack, call stack and memory. |
| **Choose useful breakpoints** | Use searchable API presets for process, memory, file and network operations, or create custom address/symbol breakpoints and hardware watchpoints. Add conditions, hit thresholds, groups, one-shot or log-only actions. |
| **Inspect captured evidence** | Review breakpoint and exception events in the timeline, follow saved snapshots back to code, and inspect supported API inputs and paired return values. |
| **Keep an investigation** | Save comments, renamed symbols, bookmarks, notes, breakpoints, navigation history, layout and captured evidence in a local `.venor` file. |
| **Work your way** | Search code and data, follow references, use the command palette, rearrange dock panels, and choose dark/light themes or Beginner/Analyst/Expert layouts. |

Explanations use deterministic rules and a curated API catalogue. Known facts,
local deductions and unavailable values are distinguished; Venor does not invent
source code or infer a program's intent.

## Get started

### Run a packaged build

1. Check the repository's [Releases](https://github.com/itsTasos/Venor/releases)
   for a Windows x64 ZIP. If no package is published, [build from source](#build-from-source).
2. Extract the **entire ZIP** into a writable folder.
3. Open the extracted folder and run **`venor.exe`**. Keep its adjacent DLLs and
   plugin folders together; the executable is not a standalone distribution.
4. Choose **Open Binary…** to inspect an x64 `.exe` or `.dll`.

The packaged build includes its Qt and compiler runtime libraries; users do not
need a development toolchain. The Qt build targets **Windows 10 1809+ / Windows 11
x64**. Windows 10 operation and clean-machine portability have not been verified.

> Opening a binary performs static inspection and does not execute it. **Start
> Debugging** and **Attach** act on real processes on the machine running Venor.
> Investigate unknown executables inside an isolated Windows VM.

### Your first investigation

1. **Open a binary.** Press `Ctrl+O` or drag a file into the window. For a safe
   first session, use the included **`benign_target.exe`** sample.
2. **Explore the code.** Pick a function, import or string in the left panel.
   Use **Meaning** for supported high-level operations, **Assembly** for exact
   instructions and **Flow** for decoded branches. Click an evidence address
   to navigate between views.
3. **Read the explanation.** The right inspector shows a summary, available
   inputs and their evidence. Expand **Instruction details** for operands,
   instruction bytes and lower-level facts. Static deductions and observed
   runtime values are labelled separately.
4. **Set a breakpoint.** Select an instruction and press `F9`, or open
   **Debug → Breakpoint Presets…** with `Ctrl+Shift+B`. Search for an API such as
   `VirtualAlloc` or `CreateFileW`, review its purpose and limitations, then
   install the preset. `Ctrl+B` opens the custom breakpoint editor.
5. **Start debugging.** Press `Ctrl+F5` and confirm the target and machine choice.
   Use `F5` to continue from a debugger stop. When a breakpoint hits, inspect the
   pause reason, registers, stack and available API arguments. `F7` steps into
   a call, `F8` steps over it and `Shift+F8` steps out of the current function.
6. **Record your findings.** Add a comment with `;`, rename a symbol with `N`,
   or bookmark an address with `Ctrl+D`. Review captured events in **Timeline**
   and add investigation notes.
7. **Save and return later.** Press `Ctrl+S` to save a `.venor` investigation.
   Reopen it through **File → Open Investigation…** (`Ctrl+Shift+O`). Keep the
   original binary available; Venor checks its SHA-256 before associating saved
   evidence with it. Saved snapshots do not restore a running process.

To debug an existing process, use **Debug → Attach to Process…** (`Ctrl+Alt+A`).
Attachment requires appropriate access and pauses a real process. **Detach**
(`Shift+F5`) leaves the target running.

### Find your way around

- **Left:** binary structure, functions, imports, strings and navigation.
- **Center:** synchronized code, flow, meaning and hex/memory views.
- **Right:** explanations, inputs, evidence and instruction details.
- **Bottom:** debugger state, breakpoints, threads, timeline and output.

Use the **View** menu to show a panel or restore the current workspace layout.
Beginner, Analyst and Expert layouts change density; they expose the same
capabilities. While paused, `Ctrl+I` returns to the actual stopped instruction
without executing anything.

### Keyboard essentials

| Action | Shortcut |
| --- | --- |
| Open binary / save investigation | `Ctrl+O` / `Ctrl+S` |
| Open investigation | `Ctrl+Shift+O` |
| Go to address or symbol / search | `Ctrl+G` / `Ctrl+F` |
| Follow operand / cross references | `Enter` / `X` |
| Back / forward | `Alt+Left` / `Alt+Right` |
| Toggle / custom / preset breakpoint | `F9` / `Ctrl+B` / `Ctrl+Shift+B` |
| Start target / attach | `Ctrl+F5` / `Ctrl+Alt+A` |
| Continue / pause | `F5` / `F6` |
| Step into / over / out | `F7` / `F8` / `Shift+F8` |
| Show current instruction / detach | `Ctrl+I` / `Shift+F5` |
| Comment / rename / bookmark | `;` / `N` / `Ctrl+D` |
| Command palette / help | `Ctrl+Shift+P` / `F1` |

## Build from source

### Requirements

- Windows x64.
- CMake **3.24+**, Ninja and Git, available on `PATH`.
- A compatible MinGW-w64 toolchain; the current build uses **GCC 13.1**.
- **Qt 6.8+** for the same compiler ABI, including Widgets, Concurrent, Sql and
  Test. The packaged configuration uses **Qt 6.8.3 MinGW 64-bit**.
- The pinned Zydis dependency and its nested Zycore submodule.

Run the following in PowerShell. Adjust the Qt/compiler paths to your installation:

```powershell
git clone --recurse-submodules https://github.com/itsTasos/Venor.git
cd Venor

$qtRoot = "C:/Qt/6.8.3/mingw_64"
$compilerRoot = "C:/Qt/Tools/mingw1310_64"
$env:PATH = "$compilerRoot/bin;$qtRoot/bin;" + $env:PATH

cmake -S . -B build-release -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="$qtRoot"
cmake --build build-release -j 4
ctest --test-dir build-release --output-on-failure

./build-release/venor.exe
```

For an existing checkout, initialize dependencies with
`git submodule update --init --recursive`. Zydis is pinned to commit
`a2278f1d254e492f6a6b39f6cb5d1f5d515659dc` (v4.1.1).

You can open a binary or saved investigation directly:

```powershell
./build-release/venor.exe ./build-release/benign_target.exe
./build-release/venor.exe "C:/Investigations/example.venor"
```

The displayed application title is configurable through the CMake option
`-DVENOR_APP_NAME="Your title"`, the `VENOR_APP_TITLE` environment variable,
or `venor.exe --title "Your title"`.

## Tests and release packaging

The test suites cover static analysis and persistence, real DbgEng debugging,
and GUI workflows using the supplied benign EXE/DLL fixtures. They launch real
local sample processes. Run `ctest` from the source-build instructions above.

For an additional Debug build, with the same environment:

```powershell
cmake -S . -B build-debug -G Ninja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_PREFIX_PATH="$qtRoot"
cmake --build build-debug -j 4
ctest --test-dir build-debug --output-on-failure
```

After building and testing **both** configurations, package the release:

```powershell
./tools/package.ps1 -Build build-release -Qt "$qtRoot" -Compiler "$compilerRoot"
./tools/verify-package.ps1
```

Packaging requires the matching Qt source archive at
`third_party/qt-source/qtbase-everywhere-src-6.8.3.tar.xz`, plus the Qt/compiler
license files used by the script. The archive and local toolchains stay outside
Git. See [third-party notices](THIRD_PARTY_NOTICES.md) for source and license details.

The output is `release/Venor-0.1.0-win64.zip`, containing the app, required runtime
libraries/plugins, sample target, tests, licenses, application/decoder source and
available local verification evidence. The verification script runs the packaged
tests and checks native startup with developer Qt/compiler directories removed
from `PATH`. This check does not establish clean-machine portability.

<details>
<summary>Test reports and visual checks</summary>

Test reports are `core-results.txt`, `debugger-results.txt` and `gui-results.txt`
in each test's working directory. You can also run the packaged suites from the
extracted package folder:

```powershell
./core_tests.exe ./benign_target.exe ./libbenign_library.dll
./debugger_tests.exe (Resolve-Path ./benign_target.exe)
$env:QT_QPA_PLATFORM = "offscreen"
./gui_tests.exe (Resolve-Path ./benign_target.exe)
```

For native GUI captures, set `QT_QPA_PLATFORM=windows` and `VENOR_QA_CAPTURES` to
an output folder. `QT_SCALE_FACTOR=1.5` exercises application scaling. GUI tests
use Qt file dialogs for reproducible input; normal use has the Windows native
picker. These checks do not establish OS-wide DPI or multi-monitor behavior.

</details>

## Scope and limitations

Venor currently supports **Windows x64 PE files and user-mode processes**.
It does not support 32-bit targets, other executable formats, kernel debugging,
emulation, full decompilation or time-travel debugging.

- **Explanations are bounded.** Meaning interprets supported operations locally
  within basic blocks; unknown values stay unknown. API coverage is curated,
  and an API entry hit describes a request, not proof of success or intent.
- **Static analysis is an approximation.** Linear decoding can include padding
  or data. Function discovery and graphs do not prove reachability or recover
  every function or control-flow edge.
- **Evidence is selective.** The timeline retains captured debug events and
  installed breakpoint hits, rather than a continuous instruction recording.
  Historical snapshots are separate from current process state.
- **Access and symbols depend on the host.** Protected processes may deny
  attachment. Symbols come from local files and exports; there are no automatic
  symbol-server downloads or privilege elevation.
- **Verification has limits.** Windows 11 builds, tests and desktop checks have
  been exercised locally. Clean-machine deployment and Windows 10 have not been
  verified. This is an initial implementation, not a production-readiness claim.

<details>
<summary>Detailed debugger and analysis boundaries</summary>

**Breakpoints and exceptions.** x64 hardware breakpoints have four CPU slots.
Data watch sizes are 1/2/4/8 bytes with natural alignment; read/write watches both
accesses, with no read-only hardware mode. Conditions use DbgEng MASM expressions:
`@rcx == 0n2` means decimal 2; unprefixed numbers are hexadecimal. Hit counts
include nonqualifying hits; after-N is a threshold, one-shot disables on the first
qualifying hit, and log-only captures evidence and continues. Static selection
breakpoints use module+RVA for relocation. Symbol breakpoints can remain pending
until a module loads; binding/resource errors appear in the breakpoint table.
Custom module expressions must match the debugger's module names.

Exceptions are captured at first/second chance. Continue passes an outstanding
target exception unhandled by default; explicit Handled/Unhandled actions are
available in Debug. Return observers pair thread and expected stack pointer;
tail calls, exceptions, non-returning APIs and unusual stacks can prevent pairing.
At most 256 return observers are retained per session. API outputs and successful
I/O are not inferred from entry hits or raw return values alone.

**Meaning and code recovery.** Graph/readable windows are capped at 160
instructions / 4 KiB. Function candidates come from the entry point, exports,
x64 unwind records and direct calls. Local interpretation covers supported GPR
widths/aliases, constants, arithmetic, relative stack slots, selected loads/stores,
import-derived API arguments and comparison-to-branch links. Facts are reset at
block entries, joins, gaps and undecodable bytes. Unmodeled writes invalidate
related facts; calls invalidate volatile state, or all tracked registers for
unknown conventions. General memory loads are not treated as constants. FS/GS
bases and 32-bit address-size overrides are not resolved. Windows API contracts
are matched to expected modules and use the Windows x64 ABI; SIZE_T stays 64-bit.

**Capture and storage.** Static string previews are labelled file bytes; observed
operands use bytes from the selected snapshot. API arguments are stored as
structured event fields. Legacy investigations recover numeric inputs from saved
registers/stack; missing string bytes remain unavailable. String capture is
bounded to 512 bytes, with unreadable/truncated data reported. Discovery covers
ASCII and ASCII-range UTF-16, not arbitrary multilingual strings. Snapshots retain
256 code bytes and 512 stack bytes, rather than a complete process dump. Stack
unwinding is capped at 64 frames and thread/module enumeration at 4,096 rows.
Attach investigations can reopen saved events/code without an associated binary.

**Capacity.** Limits include 512 MiB per file, 4,000,000 executable raw bytes,
2,000,000 decoded instructions per section, 200,000 discovered strings, 10,000
retained events and 5,000 navigation-trail addresses. The relationship graph
shows the last 100 events and links observed order on the same thread, not
causality. Cancellation is checked during decoding/string discovery and between
sections. Unreadable process memory is reported rather than replaced with static
file bytes. Exact debugger/target support depends on the system DbgEng version.

</details>

## License

Venor is released under the [MIT License](LICENSE). Dependencies retain their
own licenses; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

The supplied `venor.ico` is embedded in the Windows executable and Qt resources.
Replacing it and rebuilding updates both Explorer/shortcut and window icons;
no separate icon file is needed at runtime.
