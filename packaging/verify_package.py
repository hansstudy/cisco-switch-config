#!/usr/bin/env python3
"""The three release-gate scanners for the cisco-switch-config skill package.

    python packaging/verify_package.py --check imports        # AC7
    python packaging/verify_package.py --check unsafe-calls   # AC8
    python packaging/verify_package.py --check layout         # AC10
    python packaging/verify_package.py                        # all three

Exit 0 on a clean scan; exit 1 on any finding, printing "path:line: rule" for each - never file
content beyond the offending token. The frozen rule tables this script implements are described
below.

Stdlib only (this project's own no-third-party-runtime-dependency constraint applies to its
tooling too).

Scope and limits
-----------------------------------------------------------------
AC8 (`--check unsafe-calls`) is a **static AST guard on our own shipped code**, not a sandbox and
not a substitute for a manual pre-release security review. It is intra-procedural, has no lexical
scoping (one flat alias map per file) and no type inference. `packaging/tests/ac8-planted/`
carries all 27 shapes this scanner's self-test tree exercises - 7 that were already caught and 20
that were not - and this scanner closes every one of those 20 that a static resolver can
reasonably catch (run `python packaging/tests/ac8-planted/run_check.py` for the caught/total
counts, and see `PLANTED.md` there for the per-shape list). The following residual classes are
**out of reach for a single-pass AST scan without a real type/points-to analysis**, and are the
reason a manual pre-release security review exists as the backstop rather than a fourth scanner
pass:

1. **A name aliased through anything other than an import or a plain `name = name` assignment** -
   `funcs = {"p": print}; funcs["p"](...)`, `getattr(builtins, "open")(...)`, an alias built from a
   function return value, a class attribute, or a conditional branch the scanner cannot statically
   pick a single value for. The scanner *does* resolve a simple, single-hop-or-chained
   `target = source` name-to-name assignment (so `myprint = print; myprint(...)` and
   `a = print; b = a; b(...)` are both caught), which covers the shape this scanner's self-test
   tree actually plants, but a lookup through a container, attribute, or call return is not traced.
2. **Cross-scope name shadowing.** The alias map is one flat table per file, not a scope tree: a
   local variable that happens to share a name with a module-level import alias in a different
   function is not distinguished. This is a pre-existing property of the whole scanner, and it can
   misfire in both directions (a rare false positive from an unrelated
   local variable, or a false negative if a *denied* alias is shadowed by an unrelated safe value in
   an inner scope) - in practice this project's shipped code has no such shadowing, checked by hand.
3. **A loader object's `.exec_module()` / `.load_module()` call** - `importlib.util` and
   `importlib.machinery` attribute access is denied outright (any `importlib.*` call is unconditional
   AC8 territory now), but a loader instance returned from `importlib.util.module_from_spec(...)` is
   just a local variable by the time `.exec_module()` is called on it, indistinguishable at the AST
   level from an unrelated object's same-named method.
4. **A fully dynamic call target** - `getattr(os, "system")(cmd)`, `vars(os)["system"](cmd)`,
   `__dict__`-based dispatch - has no literal `.attr` access anywhere in the AST for this scanner to
   match against. `getattr`/`vars`/`__dict__` are not on any denial list; adding them would either
   need to deny all uses of extremely common builtins (mass false positives) or attempt to resolve
   their string-literal argument (which merely narrows, not closes, this class).
5. **Interprocedural data flow** - a mode string or command computed in one function and passed
   through several layers of parameters/returns before reaching `open`/`os.system`/etc. is invisible
   to this file-local, intra-procedural scan. A non-literal mode argument IS now flagged regardless
   (finding class "non-literal mode"), which converts this specific class from a silent miss into a
   forced manual read rather than leaving it silent.

None of the above is reachable from `skills/` today: the planted self-test tree described above is
reproduced under `packaging/tests/ac8-planted/`, and `check_unsafe_calls`/`check_imports` against
the real shipped tree separately scan at 0/0 (`python packaging/verify_package.py --check imports`
and `--check unsafe-calls`). The residual classes above are recorded so a future reviewer does not
mistake a clean AC8 run for a proof that no such call exists - that proof is what a manual
security review is for.
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from pathlib import Path

# --------------------------------------------------------------------------- paths

def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def skills_root(root: Path) -> Path:
    return root / "skills"


def python_files_under(base: Path) -> list[Path]:
    if not base.is_dir():
        return []
    return sorted(p for p in base.rglob("*.py") if "__pycache__" not in p.parts)


# --------------------------------------------------------------------------- AC7: imports

LOCAL_PACKAGES = {"ciscocheck", "ciscobaseline"}


def _handler_catches_import_error(handler: ast.ExceptHandler) -> bool:
    """True only when this handler names ImportError explicitly (alone or in a tuple).

    A bare `except:` or a catch-all `except Exception:`/`except BaseException:` is NOT an
    ImportError guard - it would let the AC7 exemption cover an import wrapped in a handler that
    also silently swallows unrelated bugs. Only an explicit ImportError (or a tuple containing it)
    counts.
    """
    if handler.type is None:
        return False  # bare `except:` never counts as an ImportError guard
    names = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
    for n in names:
        if isinstance(n, ast.Name) and n.id == "ImportError":
            return True
        if isinstance(n, ast.Attribute) and n.attr == "ImportError":
            return True
    return False


class ImportGuardVisitor(ast.NodeVisitor):
    """Finds Import/ImportFrom nodes and whether each sits in a try body guarded by
    an ImportError-catching except clause."""

    def __init__(self) -> None:
        self.findings: list[tuple[int, str]] = []
        self._try_guard_stack: list[bool] = []

    def _in_guarded_try(self) -> bool:
        return any(self._try_guard_stack)

    def visit_Try(self, node: ast.Try) -> None:
        guarded = any(_handler_catches_import_error(h) for h in node.handlers)
        self._try_guard_stack.append(guarded)
        for stmt in node.body:
            self.visit(stmt)
        self._try_guard_stack.pop()
        # orelse/finally/handlers are not "the try body" the exemption covers.
        self._try_guard_stack.append(False)
        for stmt in node.handlers:
            self.visit(stmt)
        for stmt in node.orelse:
            self.visit(stmt)
        for stmt in node.finalbody:
            self.visit(stmt)
        self._try_guard_stack.pop()

    def _check_root(self, root: str, node: ast.AST) -> None:
        if root in sys.stdlib_module_names or root in LOCAL_PACKAGES:
            return
        if self._in_guarded_try():
            return
        self.findings.append((node.lineno, f"import of '{root}' is not stdlib, not a local package, and not inside a try/except ImportError"))

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._check_root(alias.name.split(".")[0], node)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.level:
            return  # any relative import ('.', '..model', ...) stays within the local package tree
        if node.module:
            self._check_root(node.module.split(".")[0], node)
        self.generic_visit(node)


def check_imports(root: Path) -> list[str]:
    findings: list[str] = []
    for skill_dir in sorted((skills_root(root)).glob("*")):
        scripts_dir = skill_dir / "scripts"
        for py_file in python_files_under(scripts_dir):
            try:
                tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
            except SyntaxError as exc:
                findings.append(f"{py_file}:{exc.lineno}: does not parse as Python: {exc.msg}")
                continue
            visitor = ImportGuardVisitor()
            visitor.visit(tree)
            for lineno, rule in visitor.findings:
                findings.append(f"{py_file}:{lineno}: {rule}")
    return findings


# --------------------------------------------------------------------------- AC8: unsafe-calls

DENIED_IMPORT_ROOTS = {
    "subprocess", "ctypes", "pickle", "marshal", "shelve", "socket", "ssl", "http",
    "ftplib", "telnetlib", "smtplib", "asyncio", "requests", "httpx", "logging", "warnings",
    # Denied import roots with no legitimate use in shipped code - traceback (prints unmasked
    # exception detail), runpy (runs arbitrary modules), webbrowser (opens URLs/launches a
    # browser process), multiprocessing (spawns processes).
    "traceback", "runpy", "webbrowser", "multiprocessing",
}
DENIED_URLLIB_MODULES = {"urllib.request", "urllib.error", "urllib.robotparser"}

DENIED_BARE_CALLS = {"eval", "exec", "compile", "__import__"}

DENIED_OUTPUT_ATTR_CALLS = {
    "sys.stdout.write", "sys.stderr.write", "sys.stdout.buffer.write", "sys.stderr.buffer.write",
    "os.write",
    # The __stdout__/__stderr__ aliases (the original, un-redirected streams) and .writelines
    # are the same output row as .write - they bypass report.py's guard identically.
    "sys.__stdout__.write", "sys.__stderr__.write",
    "sys.__stdout__.buffer.write", "sys.__stderr__.buffer.write",
    "sys.stdout.writelines", "sys.stderr.writelines",
    "sys.__stdout__.writelines", "sys.__stderr__.writelines",
}
DENIED_WRITE_ATTR_CALLS = {"os.open", "os.fdopen"}
DENIED_WRITE_PREFIXES = ("tempfile.", "shutil.")
WRITE_METHOD_NAMES = {"write_text", "write_bytes", "unlink", "rename", "touch", "mkdir"}
# A bare `.writelines(...)` call whose base did not resolve (or resolved to something other than
# a known sys.stdout/stderr form) is still an output-shaped call; matched on the method name
# alone, same reasoning as WRITE_METHOD_NAMES.
OUTPUT_METHOD_NAMES = {"writelines"}

# Exact os.* destructive/process calls, and the process-execution family, denied
# unconditionally - no ciscocheck/report.py exemption, because these rows are the "no process
# execution" table row, not the "file writing" row. Also denied: os.startfile (Windows
# launcher), os.replace, os.makedirs.
DENIED_OS_EXACT_CALLS = {
    "os.system", "os.popen", "os.remove", "os.rename", "os.startfile", "os.replace", "os.makedirs",
}
DENIED_PROCESS_PREFIXES = ("subprocess.",)
# importlib.util / importlib.machinery loader construction (spec_from_file_location,
# module_from_spec, SourceFileLoader, ...) is as dangerous as import_module - denied by prefix
# instead of by an ever-growing exact-name list, unconditionally (dynamic-import capability has
# no legitimate use in report.py either).
DENIED_IMPORTLIB_PREFIX = "importlib."
DENIED_DYNAMIC_IMPORT_CALLS = {
    "builtins.__import__", "builtins.eval", "builtins.exec", "builtins.compile",
}
BUILTIN_OPEN_NAMES = {"open", "builtins.open", "io.open", "codecs.open"}
# The attribute form of print, and a resolved alias that reduces back to bare "print" (an
# import-as or a `myprint = print` assignment alias), is denied the same way and with the same
# report.py exemption as the bare `print` builtin caught directly in visit_Call.
DENIED_PRINT_EXACT = {"builtins.print", "print"}

FORBIDDEN_FIELD_NAMES = {"raw", "plaintext", "cleartext", "secret", "password", "unmasked", "digests"}
DIGESTS_CARVEOUT_FILE = Path("ciscocheck") / "mask.py"

TYPE7_NAME_RE = re.compile(r"(?i)(decrypt|decode|reveal|crack).*(7|type7)")
# The well-known Cisco "type 7" Vigenere key. Checked as 8-character sliding windows so any
# whole-or-partial transcription of it is caught.
VIGENERE_KEY = "dsfd;kfoA,.iyewrkldJKDHSUBsgvca69834ncxv9873254k;fg87"
VIGENERE_WINDOWS = {VIGENERE_KEY[i:i + 8] for i in range(len(VIGENERE_KEY) - 7)}


def _is_denied_output_or_write_file(rel_path: Path) -> bool:
    """True when this file IS the boundary writer (report.py), which is exempt from the
    output/file-writing rows only - every other row still applies to it."""
    return rel_path.name == "report.py" and rel_path.parent.name == "ciscocheck"


def _dotted(node: ast.AST, alias_map: dict[str, str]) -> str | None:
    """Best-effort resolution of a Name/Attribute chain to a dotted string, following
    import aliases at the base (module aliases resolve, per the AC8 scan rule)."""
    if isinstance(node, ast.Name):
        return alias_map.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value, alias_map)
        if base is None:
            return None
        return f"{base}.{node.attr}"
    return None


_MODE_SHAPE_RE = re.compile(r"^[rwaxbt+U]{1,3}$")


def _mode_contains_write(node: ast.AST) -> bool:
    """True only for a string constant that is actually shaped like a Python file-open mode
    (e.g. "w", "wb", "a+", "x") AND contains a write-indicating character. Checking the write
    characters alone against an arbitrary string false-positives on any ordinary string that
    happens to contain 'a', 'w', 'x' or '+' as a substring - e.g. `webbrowser.open("http://x")`
    - which would mislabel an unrelated call as a write-mode open. The mode-shape gate keeps the
    check precise without weakening it: a real write mode is always 1-3 characters drawn from
    r/w/a/x/b/t/+/U."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        value = node.value
        return bool(_MODE_SHAPE_RE.match(value)) and any(c in value for c in "wax+")
    return False


class UnsafeCallVisitor(ast.NodeVisitor):
    def __init__(self, rel_path: Path) -> None:
        self.rel_path = rel_path
        self.findings: list[tuple[int, str]] = []
        self.alias_map: dict[str, str] = {}
        self._is_boundary_writer = _is_denied_output_or_write_file(rel_path)
        self._is_mask_module = rel_path.as_posix() == DIGESTS_CARVEOUT_FILE.as_posix()
        self._class_stack: list[ast.ClassDef] = []

    # -- imports: build alias map, and flag denied roots --------------------
    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local = alias.asname or alias.name.split(".")[0]
            self.alias_map[local] = alias.name
            root = alias.name.split(".")[0]
            if root in DENIED_IMPORT_ROOTS:
                self.findings.append((node.lineno, f"import of denied module '{alias.name}'"))
            elif alias.name in DENIED_URLLIB_MODULES:
                self.findings.append((node.lineno, f"import of denied module '{alias.name}'"))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        root = module.split(".")[0] if module else ""
        denied = root in DENIED_IMPORT_ROOTS or module in DENIED_URLLIB_MODULES
        if denied:
            self.findings.append((node.lineno, f"import from denied module '{module}'"))
        for alias in node.names:
            local = alias.asname or alias.name
            resolved = f"{module}.{alias.name}" if module else alias.name
            self.alias_map[local] = resolved
            # `from urllib import request` has module == "urllib" (not denied, since bare
            # urllib.parse is fine) - the denial has to be checked per name, against the
            # fully-qualified form, not against the bare module root.
            if not denied and resolved in DENIED_URLLIB_MODULES:
                self.findings.append((node.lineno, f"import from denied module '{resolved}'"))
        self.generic_visit(node)

    # -- class bodies: forbidden dataclass field names -----------------------
    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for stmt in node.body:
            name = None
            if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                name = stmt.target.id
            elif isinstance(stmt, ast.Assign):
                for t in stmt.targets:
                    if isinstance(t, ast.Name) and t.id in FORBIDDEN_FIELD_NAMES:
                        name = t.id
            if name in FORBIDDEN_FIELD_NAMES and not (name == "digests" and self._is_mask_module):
                self.findings.append((stmt.lineno, f"forbidden field name '{name}' as a class attribute"))
        self.generic_visit(node)

    # -- attribute/name assignment: forbidden field names --------------------
    def visit_Assign(self, node: ast.Assign) -> None:
        for t in node.targets:
            if isinstance(t, ast.Attribute) and t.attr in FORBIDDEN_FIELD_NAMES:
                if not (t.attr == "digests" and self._is_mask_module):
                    self.findings.append((node.lineno, f"assignment to forbidden field name '.{t.attr}'"))
            # A plain `target = source` name-to-name assignment (e.g. a print alias) extends
            # the alias map the same way an import does, so `myprint = print;
            # myprint(...)` (and a transitive chain `a = print; b = a; b(...)`) resolve through
            # the same `_check_dotted_call` path a from-import binding already uses. Anything
            # more indirect than one bare Name on each side (a container lookup, an attribute, a
            # call return, a conditional) is out of reach for this intra-procedural, unscoped
            # pass - see the module docstring's "Scope and limits".
            if isinstance(t, ast.Name) and isinstance(node.value, ast.Name):
                self.alias_map[t.id] = self.alias_map.get(node.value.id, node.value.id)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        t = node.target
        if isinstance(t, ast.Attribute) and t.attr in FORBIDDEN_FIELD_NAMES:
            if not (t.attr == "digests" and self._is_mask_module):
                self.findings.append((node.lineno, f"assignment to forbidden field name '.{t.attr}'"))
        self.generic_visit(node)

    # -- name matching the type-7 recovery pattern ---------------------------
    def _check_type7_name(self, name: str, lineno: int) -> None:
        if TYPE7_NAME_RE.search(name):
            self.findings.append((lineno, f"name '{name}' matches the type-7 recovery pattern"))

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_type7_name(node.name, node.lineno)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_type7_name(node.name, node.lineno)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        self._check_type7_name(node.attr, node.lineno)
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str) and len(node.value) >= 8:
            for w in VIGENERE_WINDOWS:
                if w in node.value:
                    self.findings.append((node.lineno, "string literal contains an 8+ character slice of the type-7 Vigenere key constant"))
                    break
        self.generic_visit(node)

    # -- calls ----------------------------------------------------------------
    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Name):
            # A bare-name call bound by a from-import (`from os import system; system(...)`)
            # or a single-name alias must resolve to its real dotted origin before the denial
            # rules can see it.
            resolved = self.alias_map.get(func.id)
            if resolved and resolved != func.id:
                self._check_dotted_call(resolved, node)
            if func.id in DENIED_BARE_CALLS:
                self.findings.append((node.lineno, f"call to bare '{func.id}(...)'"))
            elif func.id == "open" and not resolved and not self._is_boundary_writer:
                self._check_open_mode(node, "open", mode_index=1)
            elif func.id == "print" and not self._is_boundary_writer:
                self.findings.append((node.lineno, "call to bare 'print(...)' outside ciscocheck/report.py"))
        elif isinstance(func, ast.Attribute):
            dotted = _dotted(func, self.alias_map)
            if dotted:
                self._check_dotted_call(dotted, node)
            elif not self._is_boundary_writer:
                # The base did not resolve to a Name/Attribute chain at all - typically an
                # attribute call on a CALL RESULT (`Path(p).write_text(...)`,
                # `pathlib.Path(p).open("w")`). Match on the method name alone; we cannot
                # type-infer the base statically.
                if func.attr in WRITE_METHOD_NAMES or func.attr in OUTPUT_METHOD_NAMES:
                    self.findings.append((node.lineno, f"call to '.{func.attr}(...)' (write/output-like method) outside ciscocheck/report.py"))
                elif func.attr == "open":
                    self._check_open_mode(node, ".open", mode_index=0)
        self.generic_visit(node)

    def _check_open_mode(self, node: ast.Call, label: str, mode_index: int) -> None:
        """`open(file, mode)` takes mode as arg 1; a `.open(mode)` METHOD (Path.open, a
        reopened file object, ...) takes it as arg 0 - conflating the two under-detects the
        method form, which is exactly the `pathlib.Path(p).open("w")` case.

        A mode that is present but not a string literal (`open(p, m)`), or a call that spreads
        unknown keywords in (`open(p, **kw)`), cannot be proven safe - either is flagged as its
        own finding class rather than silently passing (any non-constant open mode is treated
        as a finding)."""
        if any(kw.arg is None for kw in node.keywords):
            self.findings.append((node.lineno, f"'{label}(...)' called with **kwargs - a write mode cannot be ruled out statically"))
            return
        mode_arg = node.args[mode_index] if len(node.args) > mode_index else None
        mode_kw = next((kw.value for kw in node.keywords if kw.arg == "mode"), None)
        candidate = mode_kw if mode_kw is not None else mode_arg
        if candidate is None:
            return  # no mode given at all -> the 'r' default, safe
        if not (isinstance(candidate, ast.Constant) and isinstance(candidate.value, str)):
            self.findings.append((node.lineno, f"'{label}(...)' called with a non-literal mode - a write mode cannot be ruled out statically"))
            return
        if _mode_contains_write(candidate):
            self.findings.append((node.lineno, f"'{label}(...)' with a write-mode argument outside ciscocheck/report.py"))

    def _check_dotted_call(self, dotted: str, node: ast.Call) -> None:
        # No process execution, no dynamic import - denied everywhere, no boundary-writer
        # exemption (this is the "no process execution" AC8 row, not the "file writing" row).
        if dotted in DENIED_OS_EXACT_CALLS:
            self.findings.append((node.lineno, f"call to '{dotted}(...)'"))
            return
        for prefix in ("os.exec", "os.spawn", "os.fork"):
            if dotted.startswith(prefix):
                self.findings.append((node.lineno, f"call to '{dotted}(...)'"))
                return
        if dotted.startswith(DENIED_PROCESS_PREFIXES):
            self.findings.append((node.lineno, f"call to '{dotted}(...)' (process execution)"))
            return
        # The whole importlib.* surface (importlib.import_module was already denied;
        # importlib.util.spec_from_file_location / module_from_spec, importlib.machinery.*, and
        # importlib.reload are the same dynamic-import capability by another name) is denied by
        # prefix, unconditionally, rather than an exact-name list that a new loader helper falls
        # outside of.
        if dotted.startswith(DENIED_IMPORTLIB_PREFIX) or dotted == "importlib":
            self.findings.append((node.lineno, f"call to '{dotted}(...)' (dynamic import)"))
            return
        if dotted in DENIED_DYNAMIC_IMPORT_CALLS or dotted in (
            "socket.create_connection", "asyncio.open_connection", "asyncio.start_server",
        ):
            self.findings.append((node.lineno, f"call to '{dotted}(...)'"))
            return
        if dotted in BUILTIN_OPEN_NAMES and not self._is_boundary_writer:
            self._check_open_mode(node, dotted, mode_index=1)
            return
        if dotted in DENIED_PRINT_EXACT and not self._is_boundary_writer:
            self.findings.append((node.lineno, f"call to '{dotted}(...)' outside ciscocheck/report.py"))
            return
        if dotted in DENIED_OUTPUT_ATTR_CALLS and not self._is_boundary_writer:
            self.findings.append((node.lineno, f"output call '{dotted}(...)' outside ciscocheck/report.py"))
            return
        if dotted in DENIED_WRITE_ATTR_CALLS and not self._is_boundary_writer:
            self.findings.append((node.lineno, f"write call '{dotted}(...)' outside ciscocheck/report.py"))
            return
        if dotted.startswith(DENIED_WRITE_PREFIXES) and not self._is_boundary_writer:
            self.findings.append((node.lineno, f"call to '{dotted}(...)' outside ciscocheck/report.py"))
            return
        last = dotted.rsplit(".", 1)[-1]
        if last in WRITE_METHOD_NAMES and not self._is_boundary_writer:
            self.findings.append((node.lineno, f"call to '.{last}(...)' outside ciscocheck/report.py"))
            return
        if last in OUTPUT_METHOD_NAMES and not self._is_boundary_writer:
            self.findings.append((node.lineno, f"call to '.{last}(...)' outside ciscocheck/report.py"))
            return
        if last == "open" and not self._is_boundary_writer:
            self._check_open_mode(node, dotted, mode_index=0)

    def visit_Expr(self, node: ast.Expr) -> None:
        self.generic_visit(node)


def check_unsafe_calls(root: Path) -> list[str]:
    findings: list[str] = []
    base = skills_root(root)
    for py_file in python_files_under(base):
        rel_path = py_file.relative_to(base)
        # Drop the leading "<skill-name>/scripts/" so ciscocheck/mask.py etc. compare cleanly.
        parts = rel_path.parts
        if len(parts) >= 3 and parts[1] == "scripts":
            rel_for_rules = Path(*parts[2:])
        else:
            rel_for_rules = rel_path
        try:
            tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        except SyntaxError as exc:
            findings.append(f"{py_file}:{exc.lineno}: does not parse as Python: {exc.msg}")
            continue
        visitor = UnsafeCallVisitor(rel_for_rules)
        visitor.visit(tree)
        for lineno, rule in sorted(visitor.findings):
            findings.append(f"{py_file}:{lineno}: {rule}")
    return findings


# --------------------------------------------------------------------------- AC10: layout

TOKEN_RE = re.compile(r"\{\{[A-Z_]+\}\}")
HANS_PENDING_RE = re.compile(r"HANS-PENDING-[A-Z-]+")
SENTINEL_1 = "not a CIS Benchmark"
SENTINEL_2 = "not affiliated with or endorsed by"
RESERVED_WORDS = ("claude", "anthropic")
TIER2_FILES = (
    "SECURITY.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md",
    ".github/ISSUE_TEMPLATE/bug_report.yml", ".github/ISSUE_TEMPLATE/feature_request.yml",
    ".github/ISSUE_TEMPLATE/config.yml", ".github/PULL_REQUEST_TEMPLATE.md",
)

# Files this scanner treats as "shipped" for the token/backslash sweep: everything that ends up
# in the skill zip, plus the top-level docs/licensing files a human reads before installing.
SHIPPED_GLOB_DIRS = ("skills",)
SHIPPED_ROOT_FILES = ("README.md", "LICENSE", "NOTICE", "TRADEMARKS.md", "CHANGELOG.md")


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def _frontmatter(text: str) -> dict[str, str]:
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}
    out: dict[str, str] = {}
    for line in lines[1:]:
        if line.strip() == "---":
            break
        m = re.match(r"^([A-Za-z_]+):\s*(.*)$", line)
        if m:
            out[m.group(1)] = m.group(2).strip().strip('"').strip("'")
    return out


def check_layout(root: Path) -> list[str]:
    findings: list[str] = []
    skill_dir = skills_root(root) / "cisco-switch-config"
    skill_md = skill_dir / "SKILL.md"

    if not skill_md.is_file():
        findings.append(f"{skill_md}: does not exist yet")
    else:
        text = _read(skill_md) or ""
        fm = _frontmatter(text)
        name = fm.get("name", "")
        if name != skill_dir.name:
            findings.append(f"{skill_md}: frontmatter name '{name}' != directory name '{skill_dir.name}'")
        if any(w in name.lower() for w in RESERVED_WORDS):
            findings.append(f"{skill_md}: frontmatter name '{name}' contains a reserved word")
        description = fm.get("description", "")
        if not description:
            findings.append(f"{skill_md}: frontmatter description is empty")
        elif len(description) > 1024:
            findings.append(f"{skill_md}: frontmatter description is {len(description)} chars, over the 1024 limit")
        if "<" in description and ">" in description:
            findings.append(f"{skill_md}: frontmatter description appears to contain an XML/HTML tag")
        body_lines = [l for l in text.splitlines()]
        # Body = everything after the closing '---' of the frontmatter block.
        if body_lines and body_lines[0].strip() == "---":
            try:
                end = body_lines.index("---", 1)
                body = body_lines[end + 1:]
            except ValueError:
                body = body_lines
        else:
            body = body_lines
        if len(body) >= 500:
            findings.append(f"{skill_md}: body is {len(body)} lines, at or over the 500-line limit")
        for link in re.findall(r"\]\(([^)]+)\)", text):
            if link.startswith(("http://", "https://", "#")):
                continue
            target = (skill_md.parent / link).resolve()
            if not target.exists():
                findings.append(f"{skill_md}: markdown link target does not resolve: {link}")

    # Reference files: >100 lines needs a table of contents.
    references_dir = skill_dir / "references"
    if references_dir.is_dir():
        for ref in sorted(references_dir.glob("*.md")):
            text = _read(ref) or ""
            n = len(text.splitlines())
            if n > 100 and not re.search(r"(?im)^#+\s*(table of contents|contents)\b", text):
                findings.append(f"{ref}: {n} lines but no table-of-contents heading")

    # No backslash path separators in any shipped file's own text (a Windows-authored path
    # literal leaking into shipped content). Conservative: a backslash directly between two
    # path-ish characters, on either side of a slash-or-dot-bearing run, so escaped regex/
    # markdown characters and Windows CRLF are not false positives.
    BACKSLASH_PATH_RE = re.compile(r"[A-Za-z0-9_.]\\[A-Za-z0-9_][A-Za-z0-9_\\]*[/.]")
    if skill_dir.is_dir():
        for path in sorted(skill_dir.rglob("*")):
            if path.is_dir() or path.suffix not in (".md", ".py", ".json"):
                continue
            text = _read(path) or ""
            for lineno, line in enumerate(text.splitlines(), start=1):
                if BACKSLASH_PATH_RE.search(line):
                    findings.append(f"{path}:{lineno}: contains a backslash path separator")
                    break

    # Tier-1 files present and non-empty.
    for fname in ("LICENSE", "NOTICE", "TRADEMARKS.md"):
        p = root / fname
        if not p.is_file() or p.stat().st_size == 0:
            findings.append(f"{p}: missing or empty")

    # Both disclaimer sentinels, in both README.md and SKILL.md.
    for p in (root / "README.md", skill_md):
        text = _read(p) if p.is_file() else None
        if text is None:
            findings.append(f"{p}: missing, cannot check for disclaimer sentinels")
            continue
        if SENTINEL_1 not in text:
            findings.append(f"{p}: missing disclaimer sentinel: '{SENTINEL_1}'")
        if SENTINEL_2 not in text:
            findings.append(f"{p}: missing disclaimer sentinel: '{SENTINEL_2}'")

    # plugin.json / marketplace-entry.json agreement.
    plugin_json_path = root / ".claude-plugin" / "plugin.json"
    entry_path = root / "packaging" / "marketplace-entry.json"
    if plugin_json_path.is_file() and entry_path.is_file():
        try:
            plugin = json.loads(plugin_json_path.read_text(encoding="utf-8"))
            entry = json.loads(entry_path.read_text(encoding="utf-8"))
            for field in ("name", "version", "license", "description"):
                if plugin.get(field) != entry.get(field):
                    findings.append(
                        f"{entry_path}: field '{field}' ({entry.get(field)!r}) does not match "
                        f"{plugin_json_path} ({plugin.get(field)!r})"
                    )
        except json.JSONDecodeError as exc:
            findings.append(f"could not parse plugin.json/marketplace-entry.json: {exc}")
    else:
        if not plugin_json_path.is_file():
            findings.append(f"{plugin_json_path}: missing")
        if not entry_path.is_file():
            findings.append(f"{entry_path}: missing")

    # No surviving {{TOKEN}} template placeholder in any shipped file, and no HANS-PENDING-*
    # placeholder either - the latter is this project's release-blocking marker for
    # COPYRIGHT_HOLDER / SECURITY_CONTACT, deliberately checked here in addition to the
    # generic {{TOKEN}} sweep, so it is rejected the same way.
    shipped_paths: list[Path] = []
    if skill_dir.is_dir():
        shipped_paths.extend(p for p in skill_dir.rglob("*") if p.is_file())
    for fname in SHIPPED_ROOT_FILES:
        p = root / fname
        if p.is_file():
            shipped_paths.append(p)
    for extra in (root / ".claude-plugin" / "plugin.json", root / ".claude-plugin" / "marketplace.json",
                  root / "packaging" / "marketplace-entry.json"):
        if extra.is_file():
            shipped_paths.append(extra)

    for p in shipped_paths:
        text = _read(p)
        if text is None:
            continue
        for m in TOKEN_RE.finditer(text):
            findings.append(f"{p}: unresolved template token '{m.group(0)}'")
        for m in HANS_PENDING_RE.finditer(text):
            findings.append(f"{p}: release-blocking placeholder '{m.group(0)}' still present (Hans has not decided this value; see CHANGELOG.md)")

    # Manual SBOM component version must equal plugin.json's version.
    sbom_path = root / "packaging" / "sbom" / "cisco-switch-config.cdx.json"
    if plugin_json_path.is_file() and sbom_path.is_file():
        try:
            plugin = json.loads(plugin_json_path.read_text(encoding="utf-8"))
            sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
            components = sbom.get("components", [])
            sbom_version = components[0].get("version") if components else None
            if sbom_version != plugin.get("version"):
                findings.append(
                    f"{sbom_path}: component version ({sbom_version!r}) does not match "
                    f"{plugin_json_path} version ({plugin.get('version')!r})"
                )
        except (json.JSONDecodeError, IndexError, AttributeError) as exc:
            findings.append(f"{sbom_path}: could not compare version against plugin.json: {exc}")
    elif not sbom_path.is_file():
        findings.append(f"{sbom_path}: missing")

    # Tier-2 files must be absent at the repo root.
    for rel in TIER2_FILES:
        p = root / rel
        if p.exists():
            findings.append(f"{p}: tier-2 file must not be committed at the repo root (inherited from hansstudy/.github)")

    return findings


# --------------------------------------------------------------------------- main

CHECKS = {
    "imports": check_imports,
    "unsafe-calls": check_unsafe_calls,
    "layout": check_layout,
}


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", choices=sorted(CHECKS), default=None,
                         help="run one named scanner; omit to run all three")
    args = parser.parse_args(argv)

    root = repo_root()
    names = [args.check] if args.check else list(CHECKS)

    total_findings = 0
    for name in names:
        findings = CHECKS[name](root)
        print(f"--- {name} ({len(findings)} finding(s)) ---")
        for f in findings:
            print(f)
        if not findings:
            print("ok")
        total_findings += len(findings)

    return 1 if total_findings else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
