@echo off
rem Double-click to run Stenwatch. No admin, no PowerShell policy, no activation needed.
cd /d "%~dp0"

set PY=py -3
%PY% --version >nul 2>&1 || set PY=python
%PY% --version >nul 2>&1 || (
  echo Python not found. Install it from https://www.python.org/downloads/
  echo Choose "Install just for me" and tick "Add python.exe to PATH", then run this again.
  pause & exit /b 1
)

if not exist .venv\Scripts\python.exe %PY% -m venv .venv || goto :fail
set VPY=.venv\Scripts\python.exe
"%VPY%" -m pip install -q --require-hashes -r requirements.txt || goto :fail

if not exist profile.yaml (
  echo First run: trying the bundled Example Organisation...
  "%VPY%" run.py --example --since 2026-01-01 || goto :fail
  start "" out\example\dashboard.html
  echo.
  echo Done. To use your own data: copy the *.example.* files to profile.yaml, assets.csv, ... then run this again.
) else (
  echo Console at http://127.0.0.1:8765  ^(Ctrl+C to stop^)
  start "" http://127.0.0.1:8765
  "%VPY%" app.py
)
pause & exit /b 0

:fail
echo Something failed, see the message above.
pause & exit /b 1
