@echo off
REM start_windows.bat - Start renewsn on Windows
REM
REM Usage:
REM   1. Install Python 3.6+ from https://www.python.org/
REM   2. Install requests: pip install requests
REM   3. Edit renewsn.ini with your DNSPod token and SN list
REM   4. Run this script or add to Task Scheduler for background operation

echo Starting renewsn...
echo Make sure you have edited renewsn.ini first!

python "%~dp0renewsn.py"

if %ERRORLEVEL% NEQ 0 (
    echo renewsn exited with error code %ERRORLEVEL%
    pause
)