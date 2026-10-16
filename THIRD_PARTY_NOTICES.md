# Dependencies

Qt 6.8.3 is dynamically linked under LGPL-3.0 (or your commercial license).
Qt source and license information: https://download.qt.io/archive/qt/6.8/6.8.3/
and https://doc.qt.io/qt-6/licensing.html . Users may replace the shipped Qt
libraries with ABI-compatible modified builds. No static Qt linking is used.
The release includes `licenses/qtbase-everywhere-src-6.8.3.tar.xz` with the
corresponding upstream source and its complete third-party licensing material.
Packaging includes Qt's license texts and this project's complete source/build
instructions. Qt's SQLite driver includes SQLite (public domain).

Zydis v4.1.1, commit a2278f1d254e492f6a6b39f6cb5d1f5d515659dc, and Zycore
commit 0b2432ced0884fd152b471d97ecf0258ff4d859f are MIT licensed. Full notices
are in third_party/zydis/LICENSE and third_party/zydis/dependencies/zycore/LICENSE.

Microsoft DbgEng is a Windows component, loaded from the installed operating
system. No Microsoft debugger engine DLLs are redistributed by this package.
The MinGW-w64 headers/import libraries and GCC runtime carry their respective
permissive notices and GCC runtime exception; runtime binaries, if required,
are shipped beside the application. See https://www.mingw-w64.org/license/
and https://gcc.gnu.org/onlinedocs/libstdc++/manual/license.html .

Optional provider networking uses Qt Network. TLS uses Windows Schannel;
identity-signature verification uses Windows CNG and credential encryption uses
Windows DPAPI. These Windows components are supplied by the operating system.
No model weights, OpenAI SDK, browser credentials or Codex authentication files
are included in the distribution.

Optional decompilation uses an external Ghidra installation through its headless
analyzer, DecompInterface and public program/decompiler APIs. Ghidra is licensed
under Apache-2.0 and includes dependencies under other licenses; obtain its full
distribution and notices from https://github.com/NationalSecurityAgency/ghidra/releases .
Ghidra, its native decompiler and a Java JDK are not redistributed by this package.
The Venor Java integration scripts are original project code and ship with Venor.
