# build.ps1
# Build script for the XFS WinFsp user-mode driver.

param(
    [string]$Configuration = "Release"
)

Write-Host "Building XFS WinFsp driver..." -ForegroundColor Green

# This project is a user-mode WinFsp filesystem, not a kernel .sys driver.
cargo build --release -p fs-winfsp-glue

if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed!" -ForegroundColor Red
    exit 1
}

$binary = "target\release\xfs-mount.exe"

if (-not (Test-Path $binary)) {
    Write-Host "Binary not found: $binary" -ForegroundColor Red
    exit 1
}

Write-Host "Build completed successfully: $binary" -ForegroundColor Green
Write-Host "Usage: $binary mount --image <image> --mount-point X:" -ForegroundColor Green
