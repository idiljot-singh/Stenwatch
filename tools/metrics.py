"""Code metrics for the architecture diagrams: python tools/metrics.py   (prints a table, writes docs/diagrams/metrics.json)
Lines = non-blank, non-comment lines. Decisions = if, loops, case, catch, && and || (a rough count, same idea as McCabe but per file, not per method)."""
import json, re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
DECISION = re.compile(r"\b(if|for|foreach|while|case|catch)\b|&&|\|\||\?\?")
SKIP = ("obj", "bin")


def files(project):
    return sorted(p for p in (SRC / project).rglob("*.cs") if not set(p.parts) & set(SKIP))


def measure(path):
    lines = [l for l in path.read_text(encoding="utf-8-sig").splitlines() if l.strip() and not l.strip().startswith("//")]
    code = "\n".join(lines)
    return {"file": path.name, "project": path.relative_to(SRC).parts[0], "loc": len(lines), "decisions": len(DECISION.findall(code))}


def all_metrics():
    rows = [measure(p) for proj in ("Stenwatch.Core", "Stenwatch.App", "Stenwatch.Cli", "Stenwatch.Tests") for p in files(proj)]
    xaml = SRC / "Stenwatch.App" / "MainWindow.xaml"
    rows.append({"file": xaml.name, "project": "Stenwatch.App", "loc": sum(1 for l in xaml.read_text(encoding="utf-8-sig").splitlines() if l.strip()), "decisions": 0})
    return rows


def by_project(rows):
    return {p: {"loc": sum(r["loc"] for r in rows if r["project"] == p), "files": sum(1 for r in rows if r["project"] == p),
                "decisions": sum(r["decisions"] for r in rows if r["project"] == p)} for p in dict.fromkeys(r["project"] for r in rows)}


if __name__ == "__main__":
    rows = all_metrics()
    for p, v in by_project(rows).items():
        print(f"{p:20}{v['files']:>4} files{v['loc']:>7} lines{v['decisions']:>7} decisions")
    print("\nbusiest Core files:", sorted(((r["decisions"], r["file"]) for r in rows if r["project"] == "Stenwatch.Core"), reverse=True)[:8])
    out = ROOT / "docs" / "diagrams"; out.mkdir(parents=True, exist_ok=True)
    (out / "metrics.json").write_text(json.dumps(rows, indent=1), encoding="utf-8")
