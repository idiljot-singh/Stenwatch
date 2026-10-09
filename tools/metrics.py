"""Code metrics for the architecture diagrams: python tools/metrics.py   (prints a table, writes docs/diagrams/metrics.json)
Lines = non-blank, non-comment lines. Complexity = McCabe-style: 1 + decision points (if, loops, except, boolean operators, ternaries, comprehension filters)."""
import ast, json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FILES = ["run.py", "app.py", "cli.py", *sorted(str(p.relative_to(ROOT)).replace("\\", "/") for p in (ROOT / "cti").glob("*.py"))]
DECISIONS = (ast.If, ast.For, ast.While, ast.ExceptHandler, ast.IfExp, ast.Assert, ast.AsyncFor)


def complexity(node):
    n = 1
    for c in ast.walk(node):
        if isinstance(c, DECISIONS):
            n += 1
        elif isinstance(c, ast.BoolOp):
            n += len(c.values) - 1
        elif isinstance(c, ast.comprehension):
            n += 1 + len(c.ifs)
    return n


def measure(rel):
    src = (ROOT / rel).read_text(encoding="utf-8")
    tree = ast.parse(src)
    loc = sum(1 for l in src.splitlines() if l.strip() and not l.strip().startswith("#"))
    funcs = [(f.name, complexity(f), f.end_lineno - f.lineno + 1) for f in ast.walk(tree) if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef))]
    imports = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom) and n.module and (n.module == "cti" or n.module.startswith("cti.")):
            if n.module == "cti":
                imports |= {a.name for a in n.names}
            else:
                imports.add(n.module.split(".", 1)[1])
        elif isinstance(n, ast.Import):
            imports |= {a.name.split(".", 1)[1] for a in n.names if a.name.startswith("cti.")}
    top = max(funcs, key=lambda f: f[1], default=("-", 1, 0))
    module_level = complexity(ast.Module(body=[s for s in tree.body if not isinstance(s, (ast.FunctionDef, ast.ClassDef))], type_ignores=[])) - 1
    return {"file": rel, "loc": loc, "functions": len(funcs), "decisions": sum(f[1] - 1 for f in funcs) + module_level,
            "max_fn": top[0], "max_cc": top[1], "imports": sorted(imports - {Path(rel).stem}), "funcs": funcs}


if __name__ == "__main__":
    rows = [measure(f) for f in FILES]
    print(f"{'file':22}{'lines':>7}{'funcs':>7}{'decisions':>10}  most complex function")
    for r in rows:
        print(f"{r['file']:22}{r['loc']:>7}{r['functions']:>7}{r['decisions']:>10}  {r['max_fn']} (cc {r['max_cc']})   imports: {', '.join(r['imports']) or '-'}")
    print(f"{'TOTAL':22}{sum(r['loc'] for r in rows):>7}{sum(r['functions'] for r in rows):>7}{sum(r['decisions'] for r in rows):>10}")
    allf = sorted(((c, n, r["file"]) for r in rows for n, c, _ in r["funcs"]), reverse=True)[:10]
    print("\ntop functions by complexity:", allf)
    out = ROOT / "docs" / "diagrams"; out.mkdir(parents=True, exist_ok=True)
    (out / "metrics.json").write_text(json.dumps([{k: v for k, v in r.items() if k != "funcs"} | {"top": sorted(r["funcs"], key=lambda f: -f[1])[:3]} for r in rows], indent=1), encoding="utf-8")
