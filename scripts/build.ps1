param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"

Write-Host "Building XFS WinFsp filesystem..." -ForegroundColor Green

$releaseArgs = @()
if ($Configuration -eq "Release") {
    $releaseArgs += "--release"
}

cargo build -p fs-winfsp-glue --target x86_64-pc-windows-msvc @releaseArgs
if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed!" -ForegroundColor Red
    exit $LASTEXITCODE
}

$profileDir = if ($Configuration -eq "Release") { "release" } else { "debug" }
$source = Join-Path $PSScriptRoot "..\target\x86_64-pc-windows-msvc\$profileDir\xfs-mount.exe"
if (-not (Test-Path $source)) {
    Write-Host "Executable not found: $source" -ForegroundColor Red
    exit 1
}

$packageDir = Join-Path $PSScriptRoot "..\Package"
New-Item -ItemType Directory -Force -Path $packageDir | Out-Null
$destination = Join-Path $packageDir "xfs-mount.exe"
Copy-Item -Path $source -Destination $destination -Force

Write-Host "Build complete: $destination" -ForegroundColor Green
