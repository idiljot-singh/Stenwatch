# PyInstaller: build with build.bat. Two programs share one folder: the windowless console and a console-mode script runner.
hidden = ["yaml", "requests", "stix2", "keyring", "cti.analyse", "cti.collect", "cti.process", "cti.disseminate", "cti.defender", "cti.llm", "cti.vault", "cti.paths", "keyring.backends.Windows", "unittest.mock"]
datas = [("cti/app.html", "cti"), ("cti/dashboard.html", "cti"), ("run.py", "."), ("test_pipeline.py", "."),
         ("WALKTHROUGH.md", "."), ("WALKTHROUGH.pdf", "."), ("profile.example.yaml", "."), ("assets.example.csv", "."),
         ("third_parties.example.csv", "."), ("exceptions.example.csv", ".")]

a = Analysis(["app.py"], datas=datas, hiddenimports=hidden)
b = Analysis(["cli.py"], hiddenimports=hidden)
MERGE((a, "app", "Stenwatch"), (b, "cli", "stenwatch-cli"))
exe_a = EXE(PYZ(a.pure), a.scripts, [], exclude_binaries=True, name="Stenwatch", console=False)
exe_b = EXE(PYZ(b.pure), b.scripts, [], exclude_binaries=True, name="stenwatch-cli", console=True)
COLLECT(exe_a, a.binaries, a.datas, exe_b, b.binaries, b.datas, name="Stenwatch")
