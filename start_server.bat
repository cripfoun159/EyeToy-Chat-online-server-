@echo off
setlocal
cd /d "%~dp0"
title EyeToy Chat PS2 - Local Server V029 - beta trust map + dual CA probes

net session >nul 2>&1
if %errorlevel% neq 0 (
  echo [V029] Relance en administrateur...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

echo ============================================================
echo  EyeToy Chat PS2 - Local Server V029 - beta trust map + dual CA probes
echo ============================================================
echo.
echo Garder la meme configuration reseau/ISO utilisee pour les tests precedents.
echo Policy 0x48 est verrouillee sur pad_before_287 ^(287 octets^).
echo V029 teste les deux ancres de confiance trouvees dans la beta sur TCP/10443.
echo.
echo Lignes importantes :
echo   UPDATE-TLS-CLIENTHELLO
echo   UPDATE-TLS-ALERT ou UPDATE-TLS-TRUST-ANCHOR-ACCEPTED
echo   UPDATE-TLS-HANDSHAKE-OK
echo   UPDATE-TLS-HTTP-RX / UPDATE-TLS-HTTP-TX
echo.

where py >nul 2>&1
if %errorlevel% equ 0 (
  py -3 server.py
) else (
  python server.py
)

echo.
pause
