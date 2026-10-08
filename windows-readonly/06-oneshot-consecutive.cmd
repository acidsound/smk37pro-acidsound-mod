@echo off
REM SMK-37 Pro: consecutive loader-probe + dump in one session
REM Run as Administrator. Press Update button first, green LED off.
set "BUNDLE=%~dp0"
cd /d "%BUNDLE%"

echo [A] Loader probe...
py -3 smk37_wl82_readonly.py loader-probe --device "\\.\PHYSICALDRIVE5" --loader "assets\wl82loader.bin"
if errorlevel 1 (
    echo FAIL: loader probe
    pause
    exit /b 1
)

echo [B] Dump flash...
py -3 smk37_wl82_readonly.py dump --device "\\.\PHYSICALDRIVE5" --loader "assets\wl82loader.bin" --manifest "expected\m09-forced-recovery-manifest.json" --output-root "output"
if errorlevel 1 (
    echo FAIL: dump
    pause
    exit /b 1
)

echo.
echo ALL STEPS PASSED
echo Output: %BUNDLE%output\
pause
