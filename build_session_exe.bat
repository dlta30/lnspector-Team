@echo off
setlocal
cd /d "%~dp0"
echo ==========================================
echo  3eN Inspect Team - Session EXE Builder
echo  by:ROITH
echo ==========================================
set /p SESSION_CODE=Paste the NEW one-time session code from the dashboard: 
if "%SESSION_CODE%"=="" (
  echo A session code is required.
  pause
  exit /b 1
)
echo %SESSION_CODE%| findstr /r /i "^[A-Z0-9][A-Z0-9]*$" >nul
if errorlevel 1 (
  echo Session code must contain only letters and numbers.
  pause
  exit /b 1
)
python -m pip install -r requirements.txt
if errorlevel 1 goto fail
python -m pip install pyinstaller
if errorlevel 1 goto fail
echo SESSION_CODE = "%SESSION_CODE%" > session_config.py
REM Use onedir instead of onefile: onefile self-extracting bundles are more likely to trigger heuristic false positives.
python -m PyInstaller --noconfirm --clean --onedir --windowed --name "3eN-Inspection-%SESSION_CODE%" --hidden-import session_config inspector_client.py
if errorlevel 1 goto fail
if exist session_config.py del session_config.py
echo.
echo BUILD COMPLETE:
echo dist\3eN-Inspection-%SESSION_CODE%\3eN-Inspection-%SESSION_CODE%.exe
 echo Keep the entire dist\3eN-Inspection-%SESSION_CODE% folder together when distributing.
echo Give this EXE only to the device owner for this session.
echo It shows the inspection scope and requires consent before scanning.
pause
exit /b 0
:fail
if exist session_config.py del session_config.py
echo Build failed. Read the error above.
pause
exit /b 1
