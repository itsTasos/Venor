param([string]$Package = "release/Venor-0.1.0-win64")
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$packagePath = (Resolve-Path (Join-Path $root $Package)).Path
$oldPath = $env:PATH
$oldPlatform = $env:QT_QPA_PLATFORM
$oldPlugins = $env:QT_PLUGIN_PATH
$oldScale = $env:QT_SCALE_FACTOR
$oldPlatformPlugins=$env:QT_QPA_PLATFORM_PLUGIN_PATH
Push-Location $packagePath
try {
    $env:PATH = "$env:SystemRoot/System32;$env:SystemRoot"
    $env:QT_PLUGIN_PATH = $null
    $env:QT_QPA_PLATFORM_PLUGIN_PATH=$null
    $env:QT_SCALE_FACTOR = $null
    $env:QT_QPA_PLATFORM = "offscreen"
    $target = Join-Path $packagePath "benign_target.exe"
    & "$packagePath/core_tests.exe" $target "$packagePath/libbenign_library.dll"
    if ($LASTEXITCODE -ne 0) { Get-Content core-results.txt; throw "Packaged core tests failed" }
    & "$packagePath/debugger_tests.exe" $target
    if ($LASTEXITCODE -ne 0) { Get-Content debugger-results.txt; throw "Packaged live debugger tests failed" }
    & "$packagePath/gui_tests.exe" $target
    if ($LASTEXITCODE -ne 0) { Get-Content gui-results.txt; throw "Packaged GUI tests failed" }
    $env:QT_QPA_PLATFORM = "windows"
    $process = Start-Process -FilePath "$packagePath/venor.exe" -ArgumentList '--check-runtime' -WindowStyle Hidden -PassThru -Wait
    if ($process.ExitCode -ne 0) { throw "Packaged application startup failed: $($process.ExitCode)" }
    $evidence = Join-Path $root "evidence/package-clean-path"
    New-Item -ItemType Directory -Force -Path $evidence | Out-Null
    Copy-Item -Path "*-results.txt" -Destination $evidence -Force
    Set-Content -LiteralPath "$evidence/environment.txt" -Encoding utf8 -Value @"
Same Windows 11 host; not a clean virtual machine.
PATH=$env:PATH
QT_PLUGIN_PATH cleared; QT_SCALE_FACTOR cleared.
Core, real debugger and offscreen GUI tests returned 0.
Packaged venor.exe --check-runtime with native Windows Qt/SQLite backend returned 0.
"@
    Write-Output "Packaged tests and native startup passed with developer tools removed from PATH."
} finally {
    Pop-Location
    $env:PATH = $oldPath
    $env:QT_QPA_PLATFORM = $oldPlatform
    $env:QT_PLUGIN_PATH = $oldPlugins
    $env:QT_SCALE_FACTOR = $oldScale
    $env:QT_QPA_PLATFORM_PLUGIN_PATH=$oldPlatformPlugins
}
