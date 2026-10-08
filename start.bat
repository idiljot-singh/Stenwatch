@echo off
rem Double-click to run Stenwatch. No admin, no PowerShell policy, no install needed.
rem Uses your Python if there is one, otherwise downloads a portable copy into .python\ (delete the folder to remove it).
cd /d "%~dp0"

set PY=py -3
%PY% --version >nul 2>&1 || set PY=python
%PY% --version >nul 2>&1 && goto :venv

rem --- no Python: portable embeddable build, SHA-256 pinned ---
set PYV=3.14.8
set PYSHA=a93abe456ab01bd96d7a085b3cdb6566b3063f4241360d114142fbdb07f0a310
set VPY=.python\python.exe
if exist %VPY% goto :deps
echo No Python found, downloading a portable copy ^(one time, ~11 MB^)...
curl.exe -fsSL -o python-embed.zip https://www.python.org/ftp/python/%PYV%/python-%PYV%-embed-amd64.zip || goto :fail
for /f "skip=1 delims=" %%h in ('certutil -hashfile python-embed.zip SHA256') do if not defined GOT set GOT=%%h
if /i not "%GOT%"=="%PYSHA%" (echo Download hash mismatch, aborting. & del python-embed.zip & goto :fail)
mkdir .python && tar -xf python-embed.zip -C .python || goto :fail
del python-embed.zip
rem enable site-packages and keep the project folder importable (embeddable Python ignores the script dir)
(echo python314.zip& echo .& echo ..& echo import site) > .python\python314._pth
curl.exe -fsSL -o .python\get-pip.py https://bootstrap.pypa.io/get-pip.py || goto :fail
%VPY% .python\get-pip.py --no-warn-script-location -q || goto :fail
goto :deps

:venv
if not exist .venv\Scripts\python.exe %PY% -m venv .venv || goto :fail
set VPY=.venv\Scripts\python.exe

:deps
%VPY% -m pip install -q --no-warn-script-location --require-hashes -r requirements.txt || goto :fail

if not exist profile.yaml (
  echo First run: trying the bundled Example Organisation...
  %VPY% run.py --example --since 2026-01-01 || goto :fail
  start "" out\example\dashboard.html
  echo.
  echo Done. To use your own data: copy the *.example.* files to profile.yaml, assets.csv, ... then run this again.
) else (
  echo Console at http://127.0.0.1:8765  ^(Ctrl+C to stop^)
  start "" http://127.0.0.1:8765
  %VPY% app.py
)
pause & exit /b 0

:fail
echo Something failed, see the message above.
pause & exit /b 1
