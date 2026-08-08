# Prepare the official Schannel-flavoured MsQuic runtime for Windows builds.
#
# The Rust `msquic` crate's `find` feature expects a vcpkg-shaped directory.
# Microsoft's 2.5.3 x64 NuGet import library accidentally names msquic.sys,
# while the user-mode runtime it ships is msquic.dll. Regenerate the two-export
# import library from the DLL instead of shipping an unsafe .sys alias.

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$version = "2.5.3"
$packageSha256 = "c3b4ab7ea9260e30c265100709fac197b7ae5cfaddfd8e8e92d996d7f4daf2cb"
$dllSha256 = "31fc27c83463499b183dbe3b034bf88bde3827ae52bd713153ce609eae1212dd"
$pdbSha256 = "fc8f64d00f50fe71d44dae457306585742a18790ee0f71ed85e76dbe897c452d"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$tauriDir = (Resolve-Path (Join-Path $scriptDir "..\src-tauri")).Path
$work = Join-Path $tauriDir ".msquic"
$package = Join-Path $work "Microsoft.Native.Quic.MsQuic.Schannel.$version.nupkg"
$expanded = Join-Path $work "package-$version"
$vcpkg = Join-Path $work "vcpkg"
$triplet = Join-Path $vcpkg "installed\x64-windows"
$bin = Join-Path $triplet "bin"
$lib = Join-Path $triplet "lib"
$resourceDir = Join-Path $tauriDir "resources\windows"

New-Item -ItemType Directory -Force -Path $work, $bin, $lib, $resourceDir | Out-Null

if (-not (Test-Path $package) -or
    (Get-FileHash $package -Algorithm SHA256).Hash.ToLowerInvariant() -ne $packageSha256) {
    $uri = "https://api.nuget.org/v3-flatcontainer/microsoft.native.quic.msquic.schannel/$version/microsoft.native.quic.msquic.schannel.$version.nupkg"
    Write-Host "Downloading official MsQuic Schannel $version package"
    Invoke-WebRequest -UseBasicParsing -Uri $uri -OutFile $package
}
if ((Get-FileHash $package -Algorithm SHA256).Hash.ToLowerInvariant() -ne $packageSha256) {
    throw "MsQuic NuGet package SHA-256 mismatch"
}

$vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) { throw "Visual Studio vswhere.exe not found" }
$visualStudio = (& $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath).Trim()
if (-not $visualStudio) { throw "MSVC x64 tools are not installed" }
$libExe = Get-ChildItem (Join-Path $visualStudio "VC\Tools\MSVC\*\bin\Hostx64\x64\lib.exe") |
    Sort-Object FullName -Descending | Select-Object -First 1
if (-not $libExe) { throw "MSVC lib.exe not found" }
$dumpbinExe = Join-Path $libExe.Directory.FullName "dumpbin.exe"
if (-not (Test-Path $dumpbinExe)) { throw "MSVC dumpbin.exe not found" }

$runtimeDll = Join-Path $bin "msquic.dll"
$runtimePdb = Join-Path $bin "msquic.pdb"
$resourceDll = Join-Path $resourceDir "msquic.dll"
$importLibrary = Join-Path $lib "msquic.lib"
function Test-Hash([string]$path, [string]$expected) {
    return ((Test-Path $path) -and
        (Get-FileHash $path -Algorithm SHA256).Hash.ToLowerInvariant() -eq $expected
    )
}
$importText = if (Test-Path $importLibrary) {
    [System.Text.Encoding]::ASCII.GetString([System.IO.File]::ReadAllBytes($importLibrary))
} else { "" }
$layoutReady = ((Test-Hash $runtimeDll $dllSha256) -and
    (Test-Hash $resourceDll $dllSha256) -and
    (Test-Hash $runtimePdb $pdbSha256) -and
    $importText.Contains("msquic.dll") -and
    -not $importText.Contains("msquic.sys")
)

if (-not $layoutReady) {
    if (Test-Path $expanded) { Remove-Item -Recurse -Force $expanded }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($package, $expanded)
    $sourceDll = Join-Path $expanded "build\native\bin\x64\msquic.dll"
    $sourcePdb = Join-Path $expanded "build\native\bin\x64\msquic.pdb"
    if (-not (Test-Hash $sourceDll $dllSha256)) { throw "MsQuic DLL SHA-256 mismatch" }
    if (-not (Test-Hash $sourcePdb $pdbSha256)) { throw "MsQuic PDB SHA-256 mismatch" }
    Copy-Item -Force $sourceDll $runtimeDll
    Copy-Item -Force $sourcePdb $runtimePdb
    Copy-Item -Force $sourceDll $resourceDll

    $definition = Join-Path $work "msquic.def"
    @"
LIBRARY msquic.dll
EXPORTS
    MsQuicClose
    MsQuicOpenVersion
"@ | Set-Content -Encoding ASCII $definition
    & $libExe.FullName "/nologo" "/machine:x64" "/def:$definition" "/out:$importLibrary"
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $importLibrary)) {
        throw "failed to generate the corrected msquic.dll import library"
    }
} else {
    Write-Host "Reusing verified MsQuic Schannel $version layout"
}

foreach ($required in @(
    (Join-Path $bin "msquic.dll"),
    (Join-Path $bin "msquic.pdb"),
    $importLibrary
)) {
    $file = Get-Item $required -ErrorAction Stop
    if ($file.Length -eq 0) { throw "empty MsQuic build input: $required" }
    Write-Host "Verified $($file.FullName) ($($file.Length) bytes)"
}

$env:VCPKG_ROOT = $vcpkg
$env:DUMPBIN_EXE = $dumpbinExe
if ($env:GITHUB_ENV) {
    "VCPKG_ROOT=$vcpkg" | Add-Content -Encoding utf8 $env:GITHUB_ENV
    "DUMPBIN_EXE=$dumpbinExe" | Add-Content -Encoding utf8 $env:GITHUB_ENV
}
Write-Host "MsQuic ready: VCPKG_ROOT=$vcpkg"
