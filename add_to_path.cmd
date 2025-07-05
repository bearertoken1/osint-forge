@echo off
setlocal
set "CURPATH=%~dp0"
set "CURPATH=%CURPATH:~0,-1%"
echo.
echo [OSINT Forge] Adding this folder to your user PATH...
for /f "tokens=2*" %%A in ('reg query "HKCU\Environment" /v Path 2^>nul') do set "OLDPATH=%%B"
echo %OLDPATH% | find /I "%CURPATH%" >nul
if %errorlevel%==0 (
    echo [OSINT Forge] Already in PATH.
) else (
    setx PATH "%CURPATH%;%OLDPATH%"
    echo [OSINT Forge] Added to user PATH.
    echo [OSINT Forge] Please log out and log back in, or restart your computer, for changes to take effect.
)
endlocal
echo.
echo [OSINT Forge] If 'Forge' is still not recognized:
echo   - Make sure Forge.cmd exists in this folder.
echo   - Open a NEW terminal window after logging out/in or restarting.
echo   - In PowerShell, you may need to use '.\Forge' if running from this folder.
pause