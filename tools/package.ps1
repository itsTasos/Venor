param(
    [string]$Build = "build-release",
    [string]$Qt = ".tools/Qt/6.8.3/mingw_64",
    [string]$Compiler = ".tools/Qt/Tools/mingw1310_64"
)
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
function Resolve-ProjectInput([string]$Value) {
    $inputPath = if ([System.IO.Path]::IsPathRooted($Value)) { $Value } else { Join-Path $root $Value }
    return (Resolve-Path -LiteralPath $inputPath).Path
}
$buildPath = Resolve-ProjectInput $Build
$qtPath = Resolve-ProjectInput $Qt
$compilerPath = Resolve-ProjectInput $Compiler
$destination = Join-Path $root "release/Venor-0.2.0-win64"
New-Item -ItemType Directory -Force -Path $destination | Out-Null
$env:PATH = "$compilerPath/bin;$qtPath/bin;" + $env:PATH
cmake --install $buildPath --prefix $destination
if ($LASTEXITCODE -ne 0) { throw "CMake install failed" }
& "$qtPath/bin/windeployqt.exe" --release --compiler-runtime --no-translations --no-opengl-sw --no-system-d3d-compiler --no-system-dxc-compiler --skip-plugin-types generic,networkinformation,tls,sqldrivers "$destination/venor.exe"
if ($LASTEXITCODE -ne 0) { throw "Qt deployment failed" }
foreach ($name in 'libgcc_s_seh-1.dll','libstdc++-6.dll','libwinpthread-1.dll') {
    Copy-Item -LiteralPath "$compilerPath/bin/$name" -Destination $destination -Force
}
New-Item -ItemType Directory -Force -Path "$destination/sqldrivers","$destination/tls","$destination/licenses","$destination/source","$destination/evidence" | Out-Null
foreach ($test in 'core_tests.exe','debugger_tests.exe','gui_tests.exe','ai_tests.exe','ai_gui_tests.exe','libbenign_library.dll') {
    Copy-Item -LiteralPath "$buildPath/$test" -Destination $destination -Force
}
Copy-Item -LiteralPath "$qtPath/bin/Qt6Test.dll" -Destination $destination -Force
Copy-Item -LiteralPath "$qtPath/plugins/platforms/qoffscreen.dll" -Destination "$destination/platforms" -Force
Copy-Item -LiteralPath "$qtPath/plugins/sqldrivers/qsqlite.dll" -Destination "$destination/sqldrivers" -Force
Copy-Item -LiteralPath "$qtPath/plugins/tls/qschannelbackend.dll" -Destination "$destination/tls" -Force
Set-Content -LiteralPath "$destination/qt.conf" -Value "[Paths]`nPrefix=.`nPlugins=." -Encoding ascii
Copy-Item -Path "$root/third_party/licenses/*" -Destination "$destination/licenses" -Recurse -Force
Copy-Item -LiteralPath "$root/third_party/qt-source/qtbase-everywhere-src-6.8.3.tar.xz" -Destination "$destination/licenses" -Force
Copy-Item -LiteralPath "$root/third_party/zydis/LICENSE" -Destination "$destination/licenses/Zydis-MIT.txt" -Force
Copy-Item -LiteralPath "$root/third_party/zydis/dependencies/zycore/LICENSE" -Destination "$destination/licenses/Zycore-MIT.txt" -Force
Copy-Item -LiteralPath "$compilerPath/licenses/gcc" -Destination "$destination/licenses" -Recurse -Force
Copy-Item -LiteralPath "$compilerPath/licenses/mingw-w64" -Destination "$destination/licenses" -Recurse -Force
foreach ($folder in 'src','tests','samples','tools','resources') {
    Copy-Item -LiteralPath "$root/$folder" -Destination "$destination/source" -Recurse -Force
}
foreach ($file in 'CMakeLists.txt','README.md','LICENSE','THIRD_PARTY_NOTICES.md','.clang-format','.gitignore','.gitmodules','venor.ico') {
    Copy-Item -LiteralPath "$root/$file" -Destination "$destination/source" -Force
}
robocopy "$root/third_party/zydis" "$destination/source/third_party/zydis" /E /XD .git /XF .git /NFL /NDL /NJH /NJS | Out-Null
if ($LASTEXITCODE -ge 8) { throw "Source archive copy failed" }
Copy-Item -LiteralPath "$root/third_party/licenses" -Destination "$destination/source/third_party" -Recurse -Force
foreach ($configuration in 'build-debug','build-release') {
    $target = "$destination/evidence/$configuration"
    New-Item -ItemType Directory -Force -Path $target | Out-Null
    Copy-Item -Path "$root/$configuration/*-results.txt" -Destination $target -Force
    if (Test-Path "$root/$configuration/Testing/Temporary/LastTest.log") {
        Copy-Item -LiteralPath "$root/$configuration/Testing/Temporary/LastTest.log" -Destination $target -Force
    }
}
if (Test-Path "$root/evidence") { Copy-Item -Path "$root/evidence/*" -Destination "$destination/evidence" -Recurse -Force }
$archive = "$root/release/Venor-0.2.0-win64.zip"
Compress-Archive -LiteralPath $destination -DestinationPath $archive -Force
Get-FileHash -LiteralPath $archive -Algorithm SHA256 | Format-List
Write-Output "Packaged: $archive"
