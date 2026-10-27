# PyInstaller: build with build.bat. Two programs share one folder: the windowless console and a console-mode script runner.
import os
P = SPECPATH                                  # python/
ROOT = os.path.dirname(P)                    # repository root
hidden = ["yaml", "requests", "stix2", "keyring", "cti.analyse", "cti.collect", "cti.process", "cti.disseminate", "cti.defender", "cti.llm", "cti.vault", "cti.paths", "keyring.backends.Windows", "unittest.mock"]
datas = [(f"{P}/cti/app.html", "cti"), (f"{P}/cti/dashboard.html", "cti"), (f"{P}/run.py", "."), (f"{P}/test_pipeline.py", "."),
         (f"{ROOT}/docs/guides/WALKTHROUGH.md", "."), (f"{ROOT}/docs/guides/WALKTHROUGH.pdf", "."),
         (f"{ROOT}/examples/profile.example.yaml", "."), (f"{ROOT}/examples/assets.example.csv", "."),
         (f"{ROOT}/examples/third_parties.example.csv", "."), (f"{ROOT}/examples/exceptions.example.csv", ".")]

a = Analysis([f"{P}/app.py"], pathex=[P], datas=datas, hiddenimports=hidden)
b = Analysis([f"{P}/cli.py"], pathex=[P], hiddenimports=hidden)
MERGE((a, "app", "Stenwatch"), (b, "cli", "stenwatch-cli"))
exe_a = EXE(PYZ(a.pure), a.scripts, [], exclude_binaries=True, name="Stenwatch", console=False)
exe_b = EXE(PYZ(b.pure), b.scripts, [], exclude_binaries=True, name="stenwatch-cli", console=True)
COLLECT(exe_a, a.binaries, a.datas, exe_b, b.binaries, b.datas, name="Stenwatch")
