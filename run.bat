@echo off
:: NetShield Launcher for Windows
:: Run as Administrator!

echo.
echo ========================================
echo   NetShield - VRChat Protection Shield
echo ========================================
echo.

:: Check admin
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Run this as Administrator!
    echo Right-click -^> Run as administrator
    pause
    exit /b 1
)

:: Navigate to script directory
cd /d "%~dp0"

echo [*] Starting NetShield...
echo [*] Press Ctrl+C to stop
echo.

python -m netshield %*

echo.
echo [*] NetShield stopped.
pause
