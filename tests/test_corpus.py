"""AC5 and AC6: every fixture against its manifest, plus the two named AC6 assertions.

Manifests are deliberately tolerant (id sets and substring hints, never byte-exact golden
JSON -- "Expectation manifests"). This file loads every `tests/fixtures/manifests/*.json`,
runs `audit_config.py --format json` over the fixture it names, and checks the manifest's
assertions against the real findings. `require_module_or_fail` makes a missing
`ciscocheck.rules` package an honest failure, never a skip.
"""

from __future__ import annotations

import json

import pytest

import re

from conftest import all_manifests, fixture_path, require_module_or_fail, run_cli

# Matches the frozen canary vocabulary and any obvious derivative of it. Used below as a
# blanket, fixture-independent safety net: no finding's `evidence.text` may ever contain a
# raw canary value, because every secret is masked on ingest before any Finding exists. This
# is deliberately never loosened -- a manifest that expected a raw secret substring in
# evidence text was wrong under the frozen masking invariant, not a signal to relax this
# check.
_CANARY_RE = re.compile(r"CANARY[A-Za-z0-9\-]{2,}")


def _load_findings(fixture_relative: str, *, platform: str | None, role_map_path: str | None):
    argv = [str(fixture_path(fixture_relative)), "--format", "json"]
    if platform:
        argv += ["--platform", platform]
    if role_map_path:
        argv += ["--role-map", role_map_path]
    result = run_cli("audit_config", argv)
    if not result.stdout.strip():
        pytest.fail(
            f"audit_config produced no stdout for {fixture_relative} "
            f"(exit {result.returncode}); stderr: {result.stderr[:2000]}"
        )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        pytest.fail(f"audit_config JSON output for {fixture_relative} did not parse: {exc}\n"
                    f"stdout was: {result.stdout[:2000]!r}")


def _manifest_id():
    manifests = all_manifests()
    return [m["fixture"] for m in manifests]


@pytest.mark.parametrize("manifest", all_manifests(), ids=_manifest_id())
def test_fixture_matches_its_manifest(manifest):
    require_module_or_fail("ciscocheck.mask")
    doc = _load_findings(
        manifest["fixture"],
        platform=manifest.get("platform"),
        role_map_path=manifest.get("role_map"),
    )
    findings = doc.get("findings", [])
    notes = doc.get("notes", [])
    found_ids = {f["check_id"] for f in findings}
    noted_ids = {n["code"] for n in notes}
    counts = doc.get("counts", {})

    # Blanket masking-invariant check, independent of any manifest field: no finding's
    # evidence.text may ever carry a raw canary value. This is never relaxed to make a
    # manifest's evidence_hints pass -- a hint that named a raw secret substring was wrong,
    # and was corrected to name the `[REDACTED <class>, N chars]` token instead.
    for f in findings:
        text = f.get("evidence", {}).get("text", "") or ""
        leaked = _CANARY_RE.findall(text)
        assert not leaked, (
            f"{manifest['fixture']}: {f['check_id']} evidence.text carries a raw canary "
            f"value {leaked!r}: {text!r}"
        )

    for check_id in manifest.get("must_fire", []):
        assert check_id in found_ids, (
            f"{manifest['fixture']}: expected {check_id} to fire, but it did not "
            f"(fired: {sorted(found_ids)})"
        )
    for check_id in manifest.get("must_not_fire", []):
        assert check_id not in found_ids, (
            f"{manifest['fixture']}: expected {check_id} NOT to fire, but it did"
        )
    for code in manifest.get("must_note", []):
        assert code in noted_ids, (
            f"{manifest['fixture']}: expected note {code}, notes were {sorted(noted_ids)}"
        )

    evidence_hints = manifest.get("evidence_hints", {}) or {}
    for check_id, hints in evidence_hints.items():
        matches = [f for f in findings if f["check_id"] == check_id]
        if not matches:
            continue  # already covered by the must_fire assertion above if it was required
        evidence_texts = " ".join(m["evidence"]["text"] for m in matches)
        for hint in hints:
            assert hint in evidence_texts, (
                f"{manifest['fixture']}: expected evidence hint {hint!r} for {check_id} "
                f"somewhere in {evidence_texts!r}"
            )

    max_critical = manifest.get("max_critical")
    if max_critical is not None:
        assert counts.get("critical", 0) <= max_critical, (
            f"{manifest['fixture']}: critical count {counts.get('critical')} exceeds "
            f"manifest ceiling {max_critical}"
        )
    max_high = manifest.get("max_high")
    if max_high is not None:
        assert counts.get("high", 0) <= max_high, (
            f"{manifest['fixture']}: high count {counts.get('high')} exceeds "
            f"manifest ceiling {max_high}"
        )
    min_total = manifest.get("min_total_findings")
    if min_total is not None:
        assert counts.get("total", len(findings)) >= min_total, (
            f"{manifest['fixture']}: total findings {counts.get('total', len(findings))} "
            f"below manifest floor {min_total}"
        )
    min_security = manifest.get("min_security_findings")
    if min_security is not None:
        sec = sum(1 for f in findings if f.get("category") == "security")
        assert sec >= min_security
    min_reliability = manifest.get("min_reliability_findings")
    if min_reliability is not None:
        rel = sum(1 for f in findings if f.get("category") == "reliability")
        assert rel >= min_reliability


# ---------------------------------------------------------------------------------------
# AC6's two named assertions, stated directly (in addition to being covered by the
# hardened-reference / deliberately-bad manifests above, which use the tolerant
# max_critical/max_high/min_total_findings fields).
# ---------------------------------------------------------------------------------------


def test_ac6_hardened_reference_zero_critical_and_high():
    require_module_or_fail("ciscocheck.mask")
    doc = _load_findings("synthetic/hardened-reference.cfg", platform=None, role_map_path=None)
    counts = doc.get("counts", {})
    assert counts.get("critical", 0) == 0, f"hardened-reference.cfg has critical findings: {doc}"
    assert counts.get("high", 0) == 0, f"hardened-reference.cfg has high findings: {doc}"


def test_ac6_deliberately_bad_at_least_25_findings_both_categories():
    require_module_or_fail("ciscocheck.mask")
    doc = _load_findings("synthetic/deliberately-bad.cfg", platform=None, role_map_path=None)
    findings = doc.get("findings", [])
    counts = doc.get("counts", {})
    total = counts.get("total", len(findings))
    assert total >= 25, f"deliberately-bad.cfg produced only {total} findings, need >= 25"
    categories = {f.get("category") for f in findings}
    assert "security" in categories, "deliberately-bad.cfg produced no `security` findings"
    assert "reliability" in categories, "deliberately-bad.cfg produced no `reliability` findings"
