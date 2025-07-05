@echo off
REM Fix common issues like missing dependencies

echo Installing required Python packages...
pip install -r "%~dp0requirements.txt"

echo Fixing PATH issues...
setx PATH "%~dp0;%PATH%"

echo All fixes applied. Please restart your terminal if needed.
