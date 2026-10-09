@echo off
rem Build the Windows installer -> installer\Output\Stenwatch-Setup-<version>.exe
rem Needs Python 3 and Inno Setup 6 (winget install JRSoftware.InnoSetup).
cd /d "%~dp0"
set ISCC=%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe
if not exist "%ISCC%" set ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe
if not exist "%ISCC%" (echo Inno Setup 6 not found & goto :fail)
if not exist .build\Scripts\python.exe py -3 -m venv .build || goto :fail
.build\Scripts\python -m pip install -q --require-hashes -r requirements.txt || goto :fail
.build\Scripts\python -m pip install -q pyinstaller || goto :fail
.build\Scripts\python test_pipeline.py >nul || goto :fail
.build\Scripts\python -m PyInstaller --noconfirm --clean stenwatch.spec || goto :fail
"%ISCC%" installer\stenwatch.iss || goto :fail
certutil -hashfile installer\Output\Stenwatch-Setup-0.1.0-beta.exe SHA256
exit /b 0
:fail
echo Build failed.
exit /b 1
