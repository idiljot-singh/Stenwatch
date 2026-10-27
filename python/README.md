# python/: the Python edition (0.1, beta)

The original Stenwatch: a small CTI pipeline (`cti/`, one module per lifecycle stage) with a local browser console. It still works and is unchanged in behaviour. New development is in the C# edition under [`src/`](../src), which reproduces this edition's output exactly for the Example Organisation (a test) and adds the research pillars.

```
python/
  run.py            the pipeline: collect, match, score, report
  app.py            the local web console (127.0.0.1 only)
  cli.py            console-mode runner used by the installed app
  cti/              collect.py  process.py  analyse.py  disseminate.py  render.py  llm.py  defender.py  vault.py  paths.py
  test_pipeline.py  offline self-check, prints "ok"
  requirements.*    hash-pinned dependencies
  stenwatch.spec    PyInstaller recipe
  start.bat         double-click launcher (downloads a portable Python if needed)
  build.bat         builds the Python installer (see ../installer)
```

Run from the repository root:

```
pip install --require-hashes -r python/requirements.txt
python python/test_pipeline.py
python python/run.py --example --since 2026-01-01
python python/app.py
```

It reads the Example Organisation from `../examples` and keeps your files in `../data`.
