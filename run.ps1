# NetShield Launcher for PowerShell
# Run as Administrator!

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  NetShield - VRChat Protection Shield" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[ERROR] Run this as Administrator!" -ForegroundColor Red
    Write-Host "Right-click -> Run as administrator" -ForegroundColor Yellow
    pause
    exit 1
}

# Navigate to script directory
Set-Location $PSScriptRoot

Write-Host "[*] Starting NetShield..." -ForegroundColor Green
Write-Host "[*] Press Ctrl+C to stop" -ForegroundColor Yellow
Write-Host ""

try {
    python -m netshield $args
} catch {
    Write-Host "[ERROR] $_" -ForegroundColor Red
} finally {
    Write-Host ""
    Write-Host "[*] NetShield stopped." -ForegroundColor Cyan
    pause
}
