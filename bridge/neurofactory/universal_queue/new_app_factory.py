"""Isolated two-model generator for two new synthetic CLI applications.

No credentials, no private data, no dynamic command invocation.
Untrusted natural-language description determines only an allowlisted app kind.
"""
import ast
import hashlib
import json
import math
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import time
import urllib.request

WRITER = "qwen2.5-coder:1.5b"
REVIEWER = "qwen3:4b"
REPO = "DSLitvinov1/my_first_repo"
BRANCH = "neurofactory-public-lab-20261012"
API = "http://127.0.0.1:11434/api/generate"
OUTPUT = pathlib.Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "neurofactory_new_apps"
SAFE_AST = (ast.Module, ast.FunctionDef, ast.arguments, ast.arg, ast.Return,
            ast.BinOp, ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv,
            ast.Constant, ast.Name, ast.Load)
SPECS = {
    "temperature_converter": {
        "title": "Учебный конвертер температур",
        "modules": {
            "celsius_to_fahrenheit": {
                "args": ("celsius",), "formula": "celsius * 9 / 5 + 32",
                "tests": [((0,), 32), ((100,), 212), ((-40,), -40), ((20,), 68)],
            },
            "fahrenheit_to_celsius": {
                "args": ("fahrenheit",), "formula": "(fahrenheit - 32) * 5 / 9",
                "tests": [((32,), 0), ((212,), 100), ((-40,), -40), ((68,), 20)],
            }
        },
        "smoke": [("celsius_to_fahrenheit", (10,), 50), ("fahrenheit_to_celsius", (50,), 10)]
    },
    "fuel_trip_estimator": {
        "title": "Учебный расчёт расхода топлива в поездке",
        "modules": {
            "fuel_liters": {
                "args": ("distance_km", "consumption_per_100km"),
                "formula": "distance_km * consumption_per_100km / 100",
                "tests": [((100, 8), 8), ((250, 6), 15), ((0, 10), 0), ((50, 12), 6)],
            },
            "fuel_cost": {
                "args": ("liters", "price_per_liter"), "formula": "liters * price_per_liter",
                "tests": [((10, 55), 550), ((0, 70), 0), ((8, 50), 400), ((2.5, 60), 150)],
            }
        },
        "smoke": [("fuel_liters", (180, 5), 9), ("fuel_cost", (9, 60), 540)]
    }
}

def safe_id(task_id):
    if not re.fullmatch(r"NFQ-[0-9]{4}", task_id):
        raise ValueError("Unexpected synthetic queue ID")
    return task_id

def app_dir(task_id):
    return OUTPUT / safe_id(task_id)

def source_file(task_id, name):
    allowed = {"main.py", "test_app.py", "README.md", "verification-manifest.json"}
    for config in SPECS.values():
        allowed.update(k + ".py" for k in config["modules"])
    if name not in allowed:
        raise ValueError("Unexpected generated filename")
    root = app_dir(task_id)
    if root.is_symlink():
        raise ValueError("Output root symlink denied")
    root.mkdir(parents=True, exist_ok=True)
    path = root / name
    if path.is_symlink() or path.resolve().parent != root.resolve():
        raise ValueError("Output escape denied")
    return path

def ask(model, prompt, structured=False):
    if len(prompt) > 7000:
        raise ValueError("Model prompt exceeded limit")
    payload = {
        "model": model, "prompt": prompt, "stream": False, "think": False,
        "keep_alive": "0",
        "options": {"num_ctx": 1900, "num_predict": 230, "num_thread": 3,
                    "num_gpu": 0, "temperature": 0}
    }
    if structured:
        payload["format"] = "json"
    req = urllib.request.Request(API, data=json.dumps(payload).encode("utf-8"),
        method="POST", headers={"Content-Type": "application/json"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=230) as res:
        answer = json.load(res)
    if not answer.get("done"):
        raise ValueError("Incomplete local model response")
    return str(answer.get("response", "")).strip()

def extract(text, expected_name):
    lines = text.replace("\r", "").splitlines()
    for i, line in enumerate(lines):
        if re.match(r"^\s*def\s+" + re.escape(expected_name) + r"\(", line):
            first = line.strip()
            block = [first]
            if ":" in first and first.split(":", 1)[1].strip():
                return first + "\n"
            for item in lines[i + 1:]:
                if item.startswith(("    ", "\t")):
                    block.append(item)
                elif len(block) > 1:
                    break
            return "\n".join(block) + "\n"
    raise ValueError("Writer omitted the required function")

def verify(code, kind, module):
    spec = SPECS[kind]["modules"][module]
    tree = ast.parse(code)
    if len(tree.body) != 1 or type(tree.body[0]) is not ast.FunctionDef:
        raise ValueError("Only one pure function allowed")
    fn = tree.body[0]
    if (fn.name != module or [a.arg for a in fn.args.args] != list(spec["args"])
        or fn.decorator_list or len(fn.body) != 1 or type(fn.body[0]) is not ast.Return):
        raise ValueError("Incorrect signature, side effects or body shape")
    if any(type(node) not in SAFE_AST for node in ast.walk(tree)):
        raise ValueError("Unsafe generated syntax")
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id not in spec["args"]:
            raise ValueError("Unexpected identifier")
        if isinstance(node, ast.Constant):
            if type(node.value) not in (int, float) or abs(node.value) > 100:
                raise ValueError("Disallowed constant")
    env = {"__builtins__": {}}
    exec(compile(tree, "<verified-pure-function>", "exec"), env)
    func = env[module]
    for args, expected in spec["tests"]:
        actual = func(*args)
        if type(actual) not in (int, float) or not math.isclose(
                actual, expected, rel_tol=1e-9, abs_tol=1e-8):
            raise ValueError("Independent arithmetic check failed")
    return 4

def trusted_main(kind):
    spec = SPECS[kind]
    imports = "\n".join("from " + module + " import " + module for module in spec["modules"])
    signatures = ", ".join(repr(module) + ": (" + module + ", " + str(len(cfg["args"])) + ")"
                          for module, cfg in spec["modules"].items())
    return (imports + "\nimport argparse\n\n"
        "def main():\n"
        "    parser = argparse.ArgumentParser(description='Synthetic offline training app')\n"
        "    parser.add_argument('operation', choices=" + repr(list(spec["modules"])) + ")\n"
        "    parser.add_argument('values', nargs='+', type=float)\n"
        "    args = parser.parse_args()\n"
        "    mapping = {" + signatures + "}\n"
        "    fn, arity = mapping[args.operation]\n"
        "    if len(args.values) != arity:\n"
        "        parser.error('Incorrect argument count')\n"
        "    print(format(fn(*args.values), '.12g'))\n\n"
        "if __name__ == '__main__':\n    main()\n")

def trusted_tests(kind):
    # Acceptance tests are immutable trusted source; the model never writes or edits them.
    modules = SPECS[kind]["modules"]
    tests = ["import math, pathlib, subprocess, sys, unittest"]
    tests += ["from " + module + " import " + module for module in modules]
    tests += ["class IndependentAcceptance(unittest.TestCase):"]
    n = 0
    for module, cfg in modules.items():
        for args, expected in cfg["tests"]:
            n += 1
            tests += ["    def test_%02d_%s(self):" % (n, module),
                      "        self.assertTrue(math.isclose(%s(*%s), %r, rel_tol=1e-9, abs_tol=1e-8))"
                      % (module, repr(args), expected)]
    for operation, args, expected in SPECS[kind]["smoke"]:
        n += 1
        tests += ["    def test_%02d_cli(self):" % n,
                  "        result = subprocess.run([sys.executable, '-S', 'main.py', %r] + %r, "
                  "capture_output=True, text=True, timeout=6)" % (operation, [str(a) for a in args]),
                  "        self.assertEqual(result.returncode, 0, result.stderr)",
                  "        self.assertTrue(math.isclose(float(result.stdout.strip()), %r, "
                  "rel_tol=1e-9, abs_tol=1e-8))" % expected]
    assert n == 10
    tests += ["if __name__ == '__main__':", "    unittest.main(verbosity=2)"]
    return "\n".join(tests) + "\n"

def acceptance(kind, task_id):
    root = app_dir(task_id)
    env = {k: v for k, v in os.environ.items()
           if k in ("PATH", "HOME", "LANG", "TMPDIR")}
    result = subprocess.run([sys.executable, "-S", "test_app.py"],
        cwd=root, env=env, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, timeout=45)
    print("ACCEPTANCE:", task_id, result.stdout[-3200:], flush=True)
    if result.returncode != 0 or "Ran 10 tests" not in result.stdout or "\nOK" not in result.stdout:
        raise ValueError("Independent 10-test suite failed")
    return 10

def verify_published_candidate(kind, task_id):
    expected = set(SPECS[kind]["modules"])
    expected_files = {m + ".py" for m in expected} | {"main.py", "test_app.py", "README.md"}
    manifest = json.loads(source_file(task_id, "verification-manifest.json").read_text("utf-8"))
    if manifest.get("kind") != kind or manifest.get("task_id") != task_id:
        raise ValueError("Cross-task manifest")
    if (manifest.get("status") != "two_models_reviewed"
        or manifest.get("writer") != WRITER or manifest.get("reviewer") != REVIEWER
        or manifest.get("review_verdict") != "REVIEW_OK"
        or manifest.get("tests_passed") != 10):
        raise ValueError("Unapproved artifact")
    hashes = manifest.get("sha256", {})
    if set(hashes) != expected_files or len(set(hashes.values())) != len(hashes):
        raise ValueError("Duplicate or missing modules")
    for file, expected_digest in hashes.items():
        if hashlib.sha256(source_file(task_id, file).read_bytes()).hexdigest() != expected_digest:
            raise ValueError("Modified source")
    for module in expected:
        verify(source_file(task_id, module + ".py").read_text("utf-8"), kind, module)
    acceptance(kind, task_id)
    return manifest

def generate(kind, task_id):
    safe_id(task_id)
    if kind not in SPECS:
        raise ValueError("Missing approved independently-tested application category")
    if os.environ.get("GITHUB_REPOSITORY") != REPO or os.environ.get("NF_FREE_PUBLIC_CONFIRMED") != "yes":
        raise ValueError("Only public free isolated repository")
    if os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"):
        raise ValueError("Never send a GitHub access token into AI generation")
    started = time.monotonic()
    names = list(SPECS[kind]["modules"])
    source_file(task_id, "main.py").write_text(trusted_main(kind), "utf-8")
    source_file(task_id, "test_app.py").write_text(trusted_tests(kind), "utf-8")
    source_file(task_id, "README.md").write_text(
        "# " + SPECS[kind]["title"] + "\n\n"
        "Учебное офлайн-приложение на вымышленных данных; два вычислительных модуля "
        "созданы Qwen, проверены независимыми тестами и вторым агентом. "
        "Оболочка и тесты взяты из неизменяемого доверенного шаблона.\n", "utf-8")
    for module in names:
        cfg = SPECS[kind]["modules"][module]
        fixed = ("Return exactly one Python function in plain source, no markdown and no explanation. "
                 "This is an offline, pure arithmetic function. Name and args MUST match: "
                 + module + "(" + ", ".join(cfg["args"]) + "). "
                 "Return exactly the formula: " + cfg["formula"] + ". "
                 "Do not import, print, write files, define classes or call other functions. "
                 "Only numbers, parentheses, + - * / and the specified args are allowed. "
                 "Function starts with 'def'.")
        feedback = ""
        for attempt in range(3):
            try:
                response = ask(WRITER, fixed + feedback)
                code = extract(response, module)
                verify(code, kind, module)
                source_file(task_id, module + ".py").write_text(code, "utf-8")
                print("WRITER_OK:", task_id, module, "attempt", attempt + 1, flush=True)
                break
            except (ValueError, SyntaxError) as error:
                feedback = " Previous attempt rejected. Error: " + str(error)[:230]
                print("WRITER_RETRY:", task_id, module, feedback[:120], flush=True)
                if attempt == 2:
                    raise
    acceptance(kind, task_id)
    review = ("You are an independent reviewer. Check the exact two Python functions "
              "against these arithmetic specifications. Return JSON object with ONLY field verdict, "
              "equal to REVIEW_OK if both bodies match, or REVIEW_BAD otherwise. "
              "No other text.\n")
    for module in names:
        review += (module + " expected: " + SPECS[kind]["modules"][module]["formula"]
                   + "\nActual:\n" + source_file(task_id, module + ".py").read_text("utf-8") + "\n")
    answer = ask(REVIEWER, review, True)
    try:
        verdict = json.loads(answer).get("verdict")
    except (ValueError, AttributeError):
        verdict = None
    print("REVIEWER:", task_id, repr(verdict), flush=True)
    if verdict != "REVIEW_OK":
        raise ValueError("Second separate model rejected the source")
    files = [m + ".py" for m in names] + ["main.py", "test_app.py", "README.md"]
    proof = {"status": "two_models_reviewed", "task_id": task_id, "kind": kind,
             "writer": WRITER, "reviewer": REVIEWER, "review_verdict": verdict,
             "tests_passed": 10,
             "sha256": {name: hashlib.sha256(source_file(task_id, name).read_bytes()).hexdigest()
                        for name in files},
             "elapsed_seconds": round(time.monotonic() - started, 1)}
    source_file(task_id, "verification-manifest.json").write_text(
        json.dumps(proof, ensure_ascii=False, indent=2) + "\n", "utf-8")
    verify_published_candidate(kind, task_id)
    print("NEW_APP_SUCCESS:", json.dumps(proof, ensure_ascii=True), flush=True)
    return proof

if __name__ == "__main__":
    try:
        generate(sys.argv[1], sys.argv[2])
    except Exception as exc:
        print("NEW_APP_SAFE_STOP:", type(exc).__name__, str(exc)[:300], flush=True)
        sys.exit(1)
