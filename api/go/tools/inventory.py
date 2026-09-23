#!/usr/bin/env python3
"""Inventory source contracts without importing Django or executing project code.

This is a declaration inventory, not a resolved OpenAPI schema. Dynamic routers,
includes, settings gates and inherited handlers remain explicit for review.
"""

import argparse
import ast
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2] / "tacticalrmm"
OUTPUT = Path(__file__).resolve().parents[1] / "contracts" / "inventory.json"
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


def name(node):
    return ast.unparse(node)


def scan(root):
    result = {"format": 1, "sources": {}, "routes": [], "handlers": [],
              "models": [], "tasks": [], "mcp_tools": [], "schedules": []}
    for path in sorted(root.rglob("*.py")):
        relative = path.relative_to(root)
        if any(part.startswith(".") or part in {"env", "venv", "__pycache__"}
               for part in relative.parts):
            continue
        source = path.read_bytes()
        result["sources"][str(relative)] = hashlib.sha256(source).hexdigest()
        tree = ast.parse(source, filename=str(relative))

        def record(node, **extra):
            return {"source": str(relative), "line": node.lineno, **extra}

        def visit_routes(nodes, conditions=()):
            for node in nodes:
                if isinstance(node, ast.If):
                    visit_routes(node.body, conditions + (name(node.test),))
                    visit_routes(node.orelse, conditions + (f"not ({name(node.test)})",))
                    continue
                for call in ast.walk(node):
                    if not isinstance(call, ast.Call):
                        continue
                    target = name(call.func)
                    if target in {"path", "re_path"} and len(call.args) >= 2:
                        result["routes"].append(record(
                            call, route=name(call.args[0]), target=name(call.args[1]),
                            kind=target, conditions=list(conditions)))
                    elif target.endswith(".register"):
                        result["routes"].append(record(
                            call, kind="router", declaration=name(call),
                            conditions=list(conditions)))

        if path.name == "urls.py":
            visit_routes(tree.body)
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                methods = [n.name.upper() for n in node.body
                           if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                           and n.name in HTTP_METHODS]
                if methods:
                    result["handlers"].append(record(node, name=node.name, methods=methods,
                        bases=[name(b) for b in node.bases]))
                if path.name == "models.py":
                    result["models"].append(record(node, name=node.name,
                        bases=[name(b) for b in node.bases]))
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                decorators = [name(d) for d in node.decorator_list]
                for category, predicate in (
                    ("tasks", lambda d: "shared_task" in d or d.startswith("app.task")),
                    ("mcp_tools", lambda d: ".tool(" in d),
                    ("handlers", lambda d: d.startswith("api_view")),
                ):
                    if any(predicate(d) for d in decorators):
                        result[category].append(record(node, name=node.name,
                            decorators=decorators))
            elif isinstance(node, ast.Assign):
                if any(name(t) == "app.conf.beat_schedule" for t in node.targets):
                    result["schedules"].append(record(node, declaration=name(node.value)))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Fail if source inventory has drifted")
    args = parser.parse_args()
    data = scan(ROOT)
    rendered = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != rendered:
            raise SystemExit("Source inventory changed; review and run tools/inventory.py")
    else:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(rendered)
    print(", ".join(f"{key}: {len(value)}" for key, value in data.items()
                    if isinstance(value, (list, dict))))


if __name__ == "__main__":
    main()
