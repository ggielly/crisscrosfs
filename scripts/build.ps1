# build.ps1
# Build script for XFS driver

param(
    [string]$Configuration = "Release"
)

Write-Host "Building XFS driver..." -ForegroundColor Green

# Build the driver
cargo build --release

if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed!" -ForegroundColor Red
    exit 1
}

Write-Host "Build completed successfully!" -ForegroundColor Green

# Copy the driver to the Package directory
$driverSrc = "target\x86_64-pc-windows-msvc\$Configuration\fs_driver_core.sys"
$driverDst = "Package\xfs_driver.sys"

if (Test-Path $driverSrc) {
    Copy-Item $driverSrc $driverDst
    Write-Host "Driver copied to Package directory" -ForegroundColor Green
} else {
    Write-Host "Driver file not found: $driverSrc" -ForegroundColor Red
    exit 1
}