@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
  py -3 server.py --selftest
) else (
  python server.py --selftest
)
pause
