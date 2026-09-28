"""Catalogue integrity tests: the committed catalogue.json, the build script that produces
it, and the rule/extractor registrations it must line up with.

Run with:
    PYTHONPATH=skills/cisco-switch-config/scripts python -m pytest -q \
        tests/test_catalogue_integrity.py -k "not rule_binding"

`test_build_freshness` (the byte-identity half of AC3) checks that the committed
catalogue.json stays byte-identical to a fresh build from catalogue-src/** via
packaging/build_catalogue.py.

`test_rule_binding` (the rule-binding half of AC3) needs ciscocheck.rules. Its import lives
INSIDE the test function, never at module top, so a missing rules package fails only this
one test (an honest error) rather than erroring the whole module at collection time. Do not
add a module-level `import ciscocheck.rules`.

`test_catalogue_text_passes_scrub` needs ciscocheck.mask. Its import is likewise inside the
function for the same reason.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parent.parent
CATALOGUE_PATH = ROOT / "skills" / "cisco-switch-config" / "data" / "catalogue.json"
SCHEMA_PATH = ROOT / "skills" / "cisco-switch-config" / "data" / "schema" / "catalogue.schema.json"
BUILD_SCRIPT = ROOT / "packaging" / "build_catalogue.py"
DEFAULTS_PATH = ROOT / "skills" / "cisco-switch-config" / "data" / "defaults.json"

PLACEHOLDER_RE = re.compile(r"(?<!\{)\{([a-zA-Z_][a-zA-Z0-9_]*)\}(?!\})")
CLOSED_VOCAB = {
    "interface", "vlan", "acl_name", "acl_number",
    "host", "group", "key_id", "line_range",
}
DUMMY_VALUES = {
    "interface": "GigabitEthernet1/0/1",
    "vlan": "100",
    "acl_name": "MGMT-ACL",
    "acl_number": "10",
    "host": "10.0.0.1",
    "group": "TAC-GROUP",
    "key_id": "1",
    "line_range": "0 4",
}


def _catalogue() -> dict:
    with CATALOGUE_PATH.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _schema() -> dict:
    with SCHEMA_PATH.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _checks() -> list[dict]:
    return _catalogue()["checks"]


# ---------------------------------------------------------------------------
# Schema and structural invariants
# ---------------------------------------------------------------------------

def test_schema():
    schema = _schema()
    validator_cls = jsonschema.validators.validator_for(schema)
    validator_cls.check_schema(schema)
    validator = validator_cls(schema)
    for check in _checks():
        errors = list(validator.iter_errors(check))
        assert not errors, f"{check.get('id')}: {[e.message for e in errors]}"


def test_no_duplicate_ids():
    ids = [c["id"] for c in _checks()]
    dupes = {i for i in ids if ids.count(i) > 1}
    assert not dupes, f"duplicate catalogue ids: {sorted(dupes)}"


def test_no_self_range():
    self_ids = [c["id"] for c in _checks() if c["id"].startswith("CSC-SELF-")]
    assert not self_ids, f"CSC-SELF- is reserved for engine notes, found: {self_ids}"


def test_cis_refs_have_version_and_no_title():
    for check in _checks():
        for ref in check.get("refs", []):
            if ref.get("authority") == "CIS":
                assert "title" not in ref, f"{check['id']}: CIS ref may not carry a title"
                assert ref.get("version"), f"{check['id']}: CIS ref requires a version"


# ---------------------------------------------------------------------------
# AC2 / AC4 ratio and size floors
# ---------------------------------------------------------------------------

def test_ratio():
    checks = _checks()
    total = len(checks)
    deterministic = sum(1 for c in checks if c["confidence"] == "deterministic")
    manual = sum(1 for c in checks if c["confidence"] == "manual-review")
    assert deterministic / total >= 0.80, f"deterministic ratio {deterministic}/{total} < 0.80"
    assert manual / total <= 0.10, f"manual-review ratio {manual}/{total} > 0.10"


def test_size_and_balance():
    checks = _checks()
    total = len(checks)
    reliability = sum(1 for c in checks if c["category"] == "reliability")
    assert total >= 90, f"total entries {total} < AC4 floor 90"
    assert total >= 110, f"total entries {total} < design floor 110"
    assert reliability >= 25, f"reliability entries {reliability} < AC4 floor 25"


# ---------------------------------------------------------------------------
# AC3, build-freshness half
# ---------------------------------------------------------------------------

def test_build_freshness():
    result = subprocess.run(
        [sys.executable, str(BUILD_SCRIPT), "--out", str(CATALOGUE_PATH), "--check"],
        cwd=str(ROOT), capture_output=True, text=True,
    )
    assert result.returncode == 0, (
        f"committed catalogue.json is not byte-identical to a fresh build:\n"
        f"stdout={result.stdout}\nstderr={result.stderr}"
    )


# ---------------------------------------------------------------------------
# First static cross-check for template variables
# ---------------------------------------------------------------------------

def test_template_vars():
    for check in _checks():
        lines = check.get("remediation") or []
        used: set[str] = set()
        for line in lines:
            used |= set(PLACEHOLDER_RE.findall(line))
        outside = used - CLOSED_VOCAB
        assert not outside, f"{check['id']}: remediation vars outside closed vocabulary: {outside}"
        required = set(check.get("params_required") or [])
        if lines:
            assert used == required, (
                f"{check['id']}: template vars {sorted(used)} != "
                f"params_required {sorted(required)}"
            )


# ---------------------------------------------------------------------------
# A remediation line must never hand the operator VLAN 1 as a destination
# ---------------------------------------------------------------------------

_VLAN_1_DESTINATION_RE = re.compile(r"\bvlan 1\b", re.IGNORECASE)


def test_no_check_suggests_vlan_1_as_a_destination():
    """VLAN 1 is the one VLAN every hardening check in this family exists to move traffic
    OFF of; no remediation line may hand it back as the fix. A check that cannot compute a
    genuinely unused VLAN from the config alone (CSC-L2-0001, CSC-L2-0005) already uses an
    explicit `<REPLACE-ME:...>` placeholder instead -- that is the only sanctioned way to
    leave the destination for the operator to fill in."""
    offenders = []
    for check in _checks():
        for line in check.get("remediation") or []:
            if _VLAN_1_DESTINATION_RE.search(line):
                offenders.append((check["id"], line))
    assert not offenders, f"remediation suggests VLAN 1 as a destination: {offenders}"


# ---------------------------------------------------------------------------
# defaults_key must name a real key in defaults.json
# ---------------------------------------------------------------------------

def test_defaults_key_exists():
    """Every non-null `defaults_key` must name a real key, for every platform the entry
    applies to, in defaults.json. `null` is the sanctioned value for a not-effectively-set
    entry with no matching key yet (e.g. an offered-algorithm-list check) and is skipped
    here, not flagged.

    defaults.json is read inside the test body rather than at module scope: this keeps the
    failure mode consistent with the rest of this module if it were ever missing (an honest
    error on this one test, not a collection-time failure for the whole file).
    """
    with DEFAULTS_PATH.open("r", encoding="utf-8") as fh:
        defaults = json.load(fh)
    platform_keys = {
        platform: set(pdata.get("keys", {}))
        for platform, pdata in defaults.get("platforms", {}).items()
    }

    missing = []
    for check in _checks():
        dk = check.get("defaults_key")
        if dk is None:
            continue
        for platform in check.get("platforms", []):
            keys = platform_keys.get(platform)
            if keys is None or dk not in keys:
                missing.append((check["id"], platform, dk))
    assert not missing, f"defaults_key not found in defaults.json (id, platform, key): {missing}"


# ---------------------------------------------------------------------------
# Catalogue text must never trip the egress guard
# ---------------------------------------------------------------------------

def test_catalogue_text_passes_scrub():
    """Every title, rationale and resolved remediation line yields zero mask.scrub()
    hits. `import ciscocheck.mask` is deliberately inside this function (see module
    docstring), so a missing module fails honestly rather than taking the module
    down at collection.
    """
    from ciscocheck import mask  # noqa: PLC0415 - intentional, see docstring

    hits = []
    for check in _checks():
        texts = [check["title"], check["rationale"]]
        for line in check.get("remediation") or []:
            resolved = PLACEHOLDER_RE.sub(
                lambda m: DUMMY_VALUES.get(m.group(1), m.group(0)), line
            )
            texts.append(resolved)
        for text in texts:
            found = mask.scrub(text)
            if found:
                hits.append((check["id"], text, found))
    assert not hits, f"scrub() hits in catalogue text (first 5): {hits[:5]}"


# ---------------------------------------------------------------------------
# AC3, rule-binding half
# ---------------------------------------------------------------------------

#: The frozen, explicit family-module import list from ciscocheck/rules/__init__.py.
#: Kept in sync with that file by hand; if a family module is ever added or renamed,
#: this tuple and the `__init__.py` list must be updated together.
_RULE_FAMILY_MODULES = (
    "mgt", "aaa", "vty", "snmp", "log", "ntp", "ssh", "stp", "l2", "dhcp", "ifc", "res",
)


def test_rule_binding():
    """Every check_id has exactly one registered rule or extractor, and every
    registered id exists in the catalogue. Both `ciscocheck.registry` and
    `ciscocheck.rules` are imported INSIDE this function, never at module top: at
    module scope a missing package would error the whole file at collection,
    taking test_build_freshness down with it.

    `importlib.reload(rules_pkg)` alone only re-executes rules/__init__.py, which re-binds
    the already-imported family submodules from sys.modules without re-running their
    `@rule`/`@extractor` decorators -- after `registry.clear()` that yields zero
    registrations, not 121. Each of the 12 frozen family submodules must be reloaded
    directly so their decorators re-run against the cleared registry; only then is the
    package `__init__` reloaded too (harmless -- it just re-binds names already reloaded).
    This must hold whether the test runs alone or inside the full suite: reload always
    fully repopulates from a clean `registry.clear()`, regardless of what any other test
    file already imported/registered earlier in the same session.
    """
    import importlib

    import ciscocheck.registry as registry
    import ciscocheck.rules as rules_pkg

    registry.clear()
    for name in _RULE_FAMILY_MODULES:
        family_mod = importlib.import_module(f"ciscocheck.rules.{name}")
        importlib.reload(family_mod)  # re-runs the @rule/@extractor decorators
    importlib.reload(rules_pkg)  # re-binds the package's own names; registration already done

    catalogue_ids = {c["id"] for c in _checks()}
    rule_ids = {check_id for check_id, _ in registry.rules()}
    extractor_ids = {check_id for check_id, _ in registry.extractors()}

    overlap = rule_ids & extractor_ids
    assert not overlap, f"registered as both rule and extractor: {sorted(overlap)}"

    registered = rule_ids | extractor_ids
    missing = catalogue_ids - registered
    extra = registered - catalogue_ids
    assert not missing, f"catalogue ids with no registered rule/extractor: {sorted(missing)}"
    assert not extra, f"registered ids not present in the catalogue: {sorted(extra)}"
    assert len(registered) == 121, f"expected all 121 catalogue ids bound, got {len(registered)}"
    assert catalogue_ids == registered, "registered ids must equal the catalogue ids exactly"
