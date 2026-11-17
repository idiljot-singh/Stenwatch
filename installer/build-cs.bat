@echo off
rem Build the C# edition installer -> installer\Output\Stenwatch-Setup-0.7.0-beta.exe
rem Needs the .NET 8 SDK and Inno Setup 6 (winget install JRSoftware.InnoSetup).
cd /d "%~dp0.."
set ISCC=%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe
if not exist "%ISCC%" set ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe
if not exist "%ISCC%" (echo Inno Setup 6 not found & goto :fail)
dotnet test src\Stenwatch.Tests || goto :fail
if exist dist\StenwatchCS rmdir /s /q dist\StenwatchCS
dotnet publish src\Stenwatch.App -c Release -r win-x64 --self-contained true -o dist\StenwatchCS || goto :fail
dotnet publish src\Stenwatch.Cli -c Release -r win-x64 --self-contained true -o dist\StenwatchCS || goto :fail
"%ISCC%" installer\stenwatch-cs.iss || goto :fail
rem Signing: set STENWATCH_SIGN_THUMBPRINT to a code-signing certificate's thumbprint in your store; unset = unsigned (the Store build is the signed one)
if defined STENWATCH_SIGN_THUMBPRINT (signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /sha1 %STENWATCH_SIGN_THUMBPRINT% installer\Output\Stenwatch-Setup-0.7.0-beta.exe || goto :fail)
certutil -hashfile installer\Output\Stenwatch-Setup-0.7.0-beta.exe SHA256
exit /b 0
:fail
echo Build failed.
exit /b 1
