# AC8 planted-shape fixture tree

A planted tree of 27 code shapes (`skills/testskill/scripts/planted.py`) that exercises the
AST-level unsafe-calls/imports scanner in `packaging/verify_package.py`, so the scanner's coverage
of process-execution, filesystem-write, and dynamic-import constructs is provable and repeatable.
Run it with:

```
python packaging/tests/ac8-planted/run_check.py
```

This is not under `tests/` and is not shipped: `build_skill_zip.py` only ever zips
`skills/cisco-switch-config/**`, and this tree sits under `packaging/tests/` with a fake skill
name (`testskill`).

## Caught / total

| Scanner coverage | Caught | Total |
|---|---|---|
| Baseline (before this fixture tree's gaps were closed) | 7 | 27 |
| Current | 27 | 27 |

The real shipped tree (`skills/cisco-switch-config/**`) scans at 0 findings for both
`--check imports` and `--check unsafe-calls`, before and after - none of the 20 gaps below was
ever reachable from the code actually shipped; this fixture exists to prove the *scanner* closes
them, not to report a regression in the product.

## The 27 shapes

Shapes 1-7 were already caught by the baseline scanner. Shapes 8-27 were previously missed and
are now caught. "Anchor" is where the finding fires - for an import-level denial that is the
`import`/`from` statement, not the line that later uses it.

| # | Shape | Anchor | Fix |
|---|---|---|---|
| 1 | `os.open(p, os.O_WRONLY)` | call | already caught (exact dotted match) |
| 2 | `shutil.copy(a, b)` | call | already caught (`shutil.` prefix) |
| 3 | `tempfile.mkstemp()` | call | already caught (`tempfile.` prefix) |
| 4 | `import socket` | import | already caught (denied root) |
| 5 | `import smtplib` | import | already caught (denied root) |
| 6 | `import ftplib` | import | already caught (denied root) |
| 7 | `import http.client` | import | already caught (`http` denied root) |
| 8 | `open(p, m)` - mode is a variable | call | non-literal mode now flagged |
| 9 | `open(p, **kw)` - mode hidden in `**kwargs` | call | `**kwargs` spread now flagged |
| 10 | `io.open(p, "w")` | call | `io.open` added to the builtin-`open`-shaped set (mode at arg 1, not arg 0) |
| 11 | `codecs.open(p, "w")` | call | same fix as `io.open` |
| 12 | `sys.__stdout__.write(x)` | call | added to the denied output-attribute set |
| 13 | `sys.__stderr__.write(x)` | call | added to the denied output-attribute set |
| 14 | `sys.stdout.writelines([x])` | call | `.writelines` added alongside `.write` |
| 15 | `builtins.print(x)` | call | `builtins.print` added, same exemption as bare `print` |
| 16 | `myprint = print; myprint(x)` | call | a plain `name = name` assignment now extends the alias map, transitively |
| 17 | `import traceback` (then `traceback.print_exc()`) | import | `traceback` added to the denied import roots |
| 18 | `from urllib import request` | import | per-alias check against the fully-qualified form, not the bare `urllib` root |
| 19 | `import runpy` (then `runpy.run_module(...)`) | import | `runpy` added to the denied import roots |
| 20 | `importlib.util.spec_from_file_location(...)` | call | the whole `importlib.*` surface denied by prefix, not just `import_module` |
| 21 | `import webbrowser` (then `webbrowser.open(...)`) | import | `webbrowser` added to the denied import roots |
| 22 | `import multiprocessing` (then `multiprocessing.Process()`) | import | `multiprocessing` added to the denied import roots |
| 23 | `os.startfile(p)` | call | added to the exact os.* denial set |
| 24 | `os.replace(a, b)` | call | added to the exact os.* denial set |
| 25 | `os.makedirs(p)` | call | added to the exact os.* denial set |
| 26 | `Path(p).touch()` | call | `touch` added to the write-method-name set (call-on-call-result path) |
| 27 | `Path(p).mkdir()` | call | `mkdir` added to the write-method-name set (call-on-call-result path) |

## Files

- `skills/testskill/scripts/planted.py` - all 27 shapes, each tagged `# SHAPE: <n>` on its
  anchor line for shapes 8-27 (shapes 1-7 are located by a literal substring match instead, since
  they were already working and untagged in the original scanner).
- `skills/testskill/scripts/clean.py` - the safe equivalent of every category above (read modes,
  `Path` reads, a resolved alias to a *safe* function, a locally-defined function that happens to
  be named `system`), which must give 0 findings.
- `run_check.py` - loads `packaging/verify_package.py` by path and runs `check_unsafe_calls`/
  `check_imports` against this tree directly (no pytest dependency - this tree is outside `tests/`
  on purpose, see the note above).

## What is not fixed here, and why

See the "Scope and limits" section at the top of `packaging/verify_package.py`'s module docstring
for the residual classes a single-pass, intra-procedural, un-scoped AST scan cannot close (dynamic
dispatch through a container/`getattr`, cross-scope name shadowing, a loader object's
`.exec_module()`, and true interprocedural data flow). Those are why a manual pre-release security
review is the backstop, not a fourth scanner pass.
