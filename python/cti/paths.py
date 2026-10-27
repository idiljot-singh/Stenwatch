"""Where Stenwatch reads its own files (APP, EXAMPLES, GUIDES) and keeps the organisation's files (DATA).

From a checkout: python/ holds the code, examples/ the bundled Example Organisation, docs/guides/ the walkthrough, data/ your own files.
Installed: everything Stenwatch ships sits in the install folder, and your files live in %APPDATA%/Stenwatch."""
import os, shutil, sys
from pathlib import Path

VERSION = "0.1.0-beta"
FROZEN = getattr(sys, "frozen", False)  # True inside the installed program
APP = Path(sys._MEIPASS) if FROZEN else Path(__file__).resolve().parent.parent  # python/
REPO = APP.parent
EXAMPLES = APP if FROZEN else REPO / "examples"
GUIDES = APP if FROZEN else REPO / "docs" / "guides"
DATA = Path(os.environ["APPDATA"]) / "Stenwatch" if FROZEN else REPO / "data"  # survives updates and uninstall
DATA.mkdir(parents=True, exist_ok=True)


def find_browser():
    """Edge or Chrome, for app-mode windows and PDF printing."""
    return next((b for b in (shutil.which("msedge"), shutil.which("chrome"),
                             r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                             r"C:\Program Files\Google\Chrome\Application\chrome.exe") if b and Path(b).exists()), None)
