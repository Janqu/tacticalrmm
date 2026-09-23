"""Pure differential checks: actual Python AST functions versus Go test bridge.

No Django setup, database, agent messaging, or production endpoint is used.
"""
import ast
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from types import SimpleNamespace
from typing import List


def source_functions():
    root = Path(__file__).resolve().parents[2] / "tacticalrmm"
    namespace = {"re": re, "json": json, "List": List,
                 "ScriptShell": SimpleNamespace(CMD="cmd", POWERSHELL="powershell"),
                 "DebugLogType": SimpleNamespace(SCRIPTING="scripting"),
                 "DebugLog": SimpleNamespace(error=lambda **kw: None)}
    script = ast.parse((root / "scripts/models.py").read_text())
    cls = next(node for node in script.body if isinstance(node, ast.ClassDef) and node.name == "Script")
    selected = {"replace_with_snippets", "parse_script_args", "parse_script_env_vars"}
    cls.bases = []
    cls.body = [node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name in selected]
    util = ast.parse((root / "tacticalrmm/utils.py").read_text())
    functions = [node for node in util.body if isinstance(node, ast.FunctionDef) and node.name in
                 {"replace_arg_db_values", "format_shell_array", "format_shell_bool"}]
    # The only omitted pieces are type annotations, imports, and DB resolution.
    for fn in functions:
        fn.returns = None
        for arg in fn.args.args + fn.args.kwonlyargs:
            arg.annotation = None
    module = ast.Module(body=functions + [cls], type_ignores=[])
    exec(compile(ast.fix_missing_locations(module), "<actual script source functions>", "exec"), namespace)
    return namespace


def fixtures():
    cases = []
    values = [None, "", False, True, 0, 42, 1.0, 0.00001, 1e16, "O'Brien", "ü😀", [], [",a", "b,"],
              {"b": "ü", "a": [1, False, None]}, r"C:\temp\name", r"C:\Windows\path", r"\1", r"\g<0>",
              r"\077", r"\400", r"\q x.y", "trailing\\", r"\&\$", "$literal",
              r"\g<00>", r"\08", r"\123", r"\777", r"\g<name>", r"\é", -0.0, 1e-4, 1e15]
    for shell in ("cmd", "powershell", "python", "bash", "nushell", "deno"):
        for value in values:
            for mode in ("args", "env"):
                items = ["x{{first}} y{{ second }}", "{{ second }}\n{{again}}", "before\n{{ second }}", "plain"]
                if mode == "env": items = ["KEY=" + item for item in items] + ["BAD", "A={{ second }}=lost", "B=a=b", "=empty-key"]
                cases.append({"mode": mode, "shell": shell, "items": items, "values": {" second ": value}})
    for code, snippets in [
        ("plain", {}), ("{{missing}}", {}), ("{{ one }}\n{{two}}", {"one": r"C:\a\b $x", "two": "{{one}}"}),
        ("{{one}} {{two}}", {"one}} {{two": "greedy"}),
        ("{{a.b}}\n{{axb}}", {"a.b": "matched", "axb": "second"}),
        ("{{(a)}}\n{{a}}", {"(a)": "capture", "a": "later"}),
        ("{{x}}\n{{x}}", {"x": "{{x}}!"}),
        ("{{line\nbreak}}", {"line\nbreak": "unused"}),
    ]:
        cases.append({"mode": "snippets", "code": code, "snippets": snippets})
    cases.extend([{"mode": "args", "shell": "cmd", "items": []},
                  {"mode": "env", "shell": "powershell", "items": []}])
    return cases


def reference(namespace, case):
    calls = []
    def resolve(*, string, instance=None):
        calls.append(string)
        return case.get("values", {}).get(string)
    namespace["get_db_value"] = resolve
    class Snippets:
        def filter(self, *, name):
            calls.append(name)
            return SimpleNamespace(exists=lambda: name in case.get("snippets", {}))
        def get(self, *, name):
            return SimpleNamespace(code=case["snippets"][name])
    namespace["ScriptSnippet"] = SimpleNamespace(objects=Snippets())
    script = namespace["Script"]
    if case["mode"] == "snippets": value = script.replace_with_snippets(case["code"])
    elif case["mode"] == "args": value = script.parse_script_args(None, case["shell"], case["items"])
    else: value = script.parse_script_env_vars(None, case["shell"], case["items"])
    return {"value": value, "calls": calls}


def run(*_unused):
    namespace = source_functions()
    cases = fixtures()
    expected = []
    for case in cases:
        try:
            expected.append(reference(namespace, case))
        except IndexError:
            # Named replacement group errors escape the source re.error
            # fallback; Go rejects them explicitly rather than returning code.
            expected.append({"unsupported": True, "calls": [" second "]})
    # Python-only regex constructs are explicitly rejected, not approximated.
    for name in ("(?=x)", r"\w+", "a{2}", "[[:alpha:]]", "a}}|x*|{{b"):
        cases.append({"mode": "snippets", "code": "{{" + name + "}}", "snippets": {name: "value"}})
        expected.append({"unsupported": True, "calls": [name]})
    directory = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="trmm-script-expansion-") as temporary:
        source, output = Path(temporary) / "input.json", Path(temporary) / "output.json"
        source.write_text(json.dumps(cases, ensure_ascii=True))
        env = dict(os.environ, TRMM_SCRIPT_EXPANSION_INPUT=str(source), TRMM_SCRIPT_EXPANSION_OUTPUT=str(output))
        subprocess.run(["go", "test", "./internal/httpapi", "-run", "^TestScriptExpansionContract$", "-count=1"], cwd=directory, env=env, check=True)
        actual = json.loads(output.read_text())
    assert len(actual) == len(expected)
    for index, (want, got) in enumerate(zip(expected, actual)):
        assert got == want, f"script expansion fixture {index} differs: expected {want!r}, actual {got!r}"
    print(f"Script expansion contracts: {len(cases)} comparisons passed")
    return len(cases)


if __name__ == "__main__":
    run()
