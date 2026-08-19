@echo off
setlocal
cd /d "%~dp0"
echo ============================================================
echo  EyeToy Chat V008 - Verification DNS
echo ============================================================
for /f "tokens=2 delims=:" %%A in ('ipconfig ^| findstr /C:"IPv4"') do set IPPC=%%A
set IPPC=%IPPC: =%
echo IP PC detectee: %IPPC%
echo.
echo [1] EyeToy master DOIT pointer vers %IPPC%
nslookup eyetoychat-master.online.scee.com %IPPC%
echo.
echo [2] DNAS NE DOIT PAS pointer vers %IPPC%
echo     Il doit recevoir l'adresse fournie par le DNS PS2 communautaire.
nslookup gate1.eu.dnas.playstation.org %IPPC%
echo.
pause
