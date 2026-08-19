@echo off
title DSH LAN Proxy (3081)
cd /d "%~dp0"

rem If port 3081 is already in use, tell the user instead of failing with EADDRINUSE
netstat -ano | findstr ":3081" >nul 2>&1
if %errorlevel%==0 (
    echo [INFO] Port 3081 is already in use - the proxy may already be running.
    echo        To restart it, close the old window or kill that process first.
    pause
    exit /b 0
)

echo ============================================
echo   Starting DSH LAN proxy ...
echo   URL: https://<this-machine-LAN-IP>:3081
echo   Close this window to stop the service.
echo ============================================
echo.
node server.js
echo.
echo Service stopped, or failed to start (see errors above).
pause