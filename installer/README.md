# installer/

Windows installers (Inno Setup 6, per-user, no admin rights). Build outputs go to `Output/` (git-ignored).

| File | What |
|---|---|
| `stenwatch-cs.iss` | Installer for the 0.2.0 beta desktop app. Self-contained: the .NET runtime is included. |
| `build-cs.bat` | Runs the tests, publishes the app and CLI, and builds the installer: `installer\build-cs.bat`. Needs the .NET 8 SDK and Inno Setup 6. |
| `readme-before.txt` | The "what to expect" page shown by the C# installer. |

Install location: `%LOCALAPPDATA%\Programs\Stenwatch2`. Your data lives in `%APPDATA%\Stenwatch` and survives updates; uninstalling asks before deleting it.
