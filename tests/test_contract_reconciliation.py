"""Cross-cutting contract reconciliation tests: checks that span both the catalogue and the
rule package, which neither half's own test file can verify alone.

Three contracts:

1. Remediation parameters (second static cross-check): for every catalogue id,
   `set(entry.params_required) <= set(registry.supplies_of(id))`. The catalogue names the
   `{name}` variables a remediation template needs; only the rule can supply them. A
   variable the rule never supplies renders as `<TODO:name>` plus a CSC-SELF-0002 note at run
   time, on configs no fixture happens to cover, so it is caught here statically instead.
2. Subject coverage: every `subject` token-prefix in the catalogue matches at least
   one line in at least one fixture, using the differ's own matching rule, so a subject list
   cannot silently rot the differ's `crosses_checks`.
3. Example reports: the reports shipped under `examples/reports/` are exactly what the
   finished engine produces from the example inputs beside them, so the skill never ships a
   hand-fabricated or stale report that Claude would read as ground truth.

Engine imports happen inside the tests (conftest's rule: a missing package fails, never skips).
"""

from __future__ import annotations

import importlib
import json

import pytest

from conftest import FIXTURES_DIR, SKILL_DIR, require_module_or_fail, run_cli

CATALOGUE_PATH = SKILL_DIR / "data" / "catalogue.json"
EXAMPLES_DIR = SKILL_DIR / "examples"
REPORTS_DIR = EXAMPLES_DIR / "reports"

# The frozen explicit import list of ciscocheck/rules/__init__.py.
_RULE_FAMILY_MODULES = ("mgt", "aaa", "vty", "snmp", "log", "ntp", "ssh", "stp", "l2", "dhcp",
                        "ifc", "res")

# Fixture files that are configuration text. `.raw` (ntc-templates show output) is included on
# purpose: the parser rejects it as not-a-config, which the test tolerates.
_FIXTURE_SUFFIXES = (".cfg", ".txt", ".raw")

# Subjects known to match no configuration line, each with the reason. The test pins this list
# EXACTLY: a new rotted subject fails it, and so does fixing one without deleting its row here,
# so the list can only shrink deliberately. Empty: the subjects once found rotted (IFC-0008,
# MGT-0014, RES-0005, RES-0006, RES-0007, STP-0008, STP-0009) were corrected in catalogue-src
# and the catalogue rebuilt.
KNOWN_ROTTED_SUBJECTS: dict[tuple[str, str], str] = {}


def _catalogue_checks() -> list[dict]:
    with CATALOGUE_PATH.open(encoding="utf-8") as fh:
        return json.load(fh)["checks"]


def _repopulate_registry():
    """Clear the registry and re-run every family module's decorators, exactly as
    test_catalogue_integrity.py::test_rule_binding does: other test modules register stubs and
    call `registry.clear()`, so the registry's state on entry is not ours to assume, and a bare
    `importlib.reload(rules_pkg)` would re-bind cached submodules without re-registering."""
    registry = require_module_or_fail("ciscocheck.registry")
    rules_pkg = require_module_or_fail("ciscocheck.rules")
    registry.clear()
    for name in _RULE_FAMILY_MODULES:
        importlib.reload(importlib.import_module(f"ciscocheck.rules.{name}"))
    importlib.reload(rules_pkg)
    return registry


# ---------------------------------------------------------------------------------------------
# 1. params_required <= supplies_of(id)
# ---------------------------------------------------------------------------------------------


def test_params_required_are_supplied_by_the_rule():
    registry = _repopulate_registry()
    checks = _catalogue_checks()

    registered = {cid for cid, _ in registry.rules()} | {cid for cid, _ in registry.extractors()}
    catalogue_ids = {c["id"] for c in checks}
    assert catalogue_ids == registered, (
        f"catalogue/registry id drift: missing rule {sorted(catalogue_ids - registered)}, "
        f"no catalogue entry {sorted(registered - catalogue_ids)}"
    )

    unsupplied = {}
    for c in checks:
        missing = set(c["params_required"]) - set(registry.supplies_of(c["id"]))
        if missing:
            unsupplied[c["id"]] = sorted(missing)
    assert not unsupplied, (
        "catalogue params_required not supplied by the bound rule (would render <TODO:name> "
        f"and emit CSC-SELF-0002): {unsupplied}"
    )


# ---------------------------------------------------------------------------------------------
# 2. Every subject token-prefix matches a fixture line
# ---------------------------------------------------------------------------------------------


def _fixture_line_tokens() -> list[tuple[str, tuple[str, ...], object]]:
    """(fixture name, lower-cased line tokens with a leading `no` stripped, the Line) for every
    parsed line in every configuration fixture, masked by the real ingest path."""
    parser = require_module_or_fail("ciscocheck.parser")
    out = []
    for path in sorted(FIXTURES_DIR.rglob("*")):
        if not path.is_file() or path.suffix not in _FIXTURE_SUFFIXES:
            continue
        text = path.read_bytes().decode("utf-8", errors="replace")
        try:
            cfg = parser.parse(text)
        except parser.NotACiscoConfigError:
            continue
        rel = path.relative_to(FIXTURES_DIR).as_posix()
        for node in cfg.walk():
            toks = tuple(t.lower() for t in node.line.tokens)
            if toks[:1] == ("no",):
                toks = toks[1:]
            out.append((rel, toks, node.line))
    return out


def test_every_catalogue_subject_matches_a_fixture_line():
    mask = require_module_or_fail("ciscocheck.mask")
    engine = require_module_or_fail("ciscocheck.engine")
    model = require_module_or_fail("ciscocheck.model")
    catalogue = model.Catalogue.load(CATALOGUE_PATH)
    lines = _fixture_line_tokens()
    assert lines, "no fixture lines parsed"

    uncovered = set()
    for entry in catalogue.entries:
        for subj in entry.subject:
            st = tuple(t.lower() for t in mask.tokenize(subj))
            assert st, f"{entry.id}: empty subject {subj!r}"
            hit = next((line for _, toks, line in lines if toks[:len(st)] == st), None)
            if hit is None:
                uncovered.add((entry.id, subj))
                continue
            # Same verdict as the differ itself, so this test cannot drift from the engine rule.
            assert entry.id in engine._subject_hits(hit, catalogue), (
                f"{entry.id} subject {subj!r} matched a fixture line by the documented rule but "
                "engine._subject_hits disagrees"
            )

    new_rot = sorted(uncovered - set(KNOWN_ROTTED_SUBJECTS))
    fixed = sorted(set(KNOWN_ROTTED_SUBJECTS) - uncovered)
    assert not new_rot, (
        f"catalogue subject token-prefixes that match no line in any fixture: {new_rot}. Either "
        "the subject is wrong (fix catalogue-src) or no fixture exercises it (add a line)."
    )
    assert not fixed, (
        f"subjects listed in KNOWN_ROTTED_SUBJECTS now match a fixture line; delete their rows: "
        f"{fixed}"
    )


# ---------------------------------------------------------------------------------------------
# 3. Shipped example reports equal a fresh run of the finished engine
# ---------------------------------------------------------------------------------------------

_EXAMPLE_REPORTS = (
    [("audit_config", f"configs/{p.name}", ["--format", "table"], f"{p.stem}.audit.txt")
     for p in sorted((EXAMPLES_DIR / "configs").glob("*.cfg"))]
    + [("gen_baseline", f"specs/{p.name}", ["--format", "cli"], f"{p.stem}.baseline.cfg")
       for p in sorted((EXAMPLES_DIR / "specs").glob("*.json"))]
)


def test_every_example_input_has_a_report():
    expected = {name for *_, name in _EXAMPLE_REPORTS}
    present = {p.name for p in REPORTS_DIR.glob("*")} if REPORTS_DIR.is_dir() else set()
    assert len(expected) >= 6
    assert expected == present, (
        f"examples/reports/ out of step with examples inputs: missing {sorted(expected - present)}, "
        f"orphaned {sorted(present - expected)}"
    )


@pytest.mark.parametrize("cli,rel_input,args,report", _EXAMPLE_REPORTS,
                         ids=[r[3] for r in _EXAMPLE_REPORTS])
def test_example_report_is_fresh(cli, rel_input, args, report):
    require_module_or_fail("ciscocheck.rules")
    result = run_cli(cli, [str(EXAMPLES_DIR / rel_input), *args])
    assert result.returncode == 0, f"{cli} exit {result.returncode}: {result.stderr[:500]}"
    committed = (REPORTS_DIR / report).read_text(encoding="utf-8")
    assert result.stdout == committed, (
        f"examples/reports/{report} is stale; regenerate it with scripts/{cli}.py "
        f"examples/{rel_input} {' '.join(args)} (LF line endings)"
    )
    assert "CANARY" not in committed
