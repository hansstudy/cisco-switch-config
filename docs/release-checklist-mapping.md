# Release checklist mapping

Maps every gate in `docs/RELEASE-CHECKLIST.md` (checklist_version 3, 27 gates) to how
`cisco-switch-config` answers it. `artifact_kinds: [skl]` in `.github/release-config.yml` is the
authoritative scope: 25 gates apply (every `[all]` gate plus `G19-clean-install`). Two gates are
outside that scope:

- `G18-authenticode` is tagged `[bin]` `[mod]`. The checklist states it is N/A for `[skl]`, and the
  evidence file records it as `na` with that reason so the absence is explicit.
- `G24-authorized-use` is tagged `[prod]`. The skill never connects to a switch or any production
  system (`docs/threat-model.md`), so `[prod]` is not in `artifact_kinds`. The gate does not allow
  `na`, so it has no entry in the evidence file; the validator does not ask it for this scope.

"Planned status" is what the evidence file for the final tag is expected to record once every
action below has happened. It is not the evidence itself and not a claim about today; see
`docs/releases/<tag>/release-evidence.json` for the current, honest per-gate status.

## Release order

1. **Prerelease `v1.0.0-rc.1`.** `release.yml` builds, tests, publishes the SBOM, `SHA256SUMS` and
   the build attestation on a GitHub Release marked as a prerelease, and starts no channel (no
   marketplace validation run). `G11`, `G16` and `G25` are N/A for a prerelease, with the
   checklist's fixed wording. Every other applicable gate still needs `pass`.
2. **Final `v1.0.0`.** A new evidence file at `docs/releases/v1.0.0/release-evidence.json`
   (never a copy of the prerelease file; step 0 rejects a file whose `tag`/`version` do not
   match). The prerelease N/A entries become `pass` against the live landing page and the
   published release.

## Gate table

| Gate id | Tags | Applies to `[skl]` | Planned status | Evidence | Owner |
|---|---|---|---|---|---|
| G01-security-review | all | yes | pass | `docs/security-review.md` | Maintainer |
| G02-secret-scan | all | yes | pass | full-history `gitleaks detect --log-opts="--all"` output; secret scanning and push protection enabled | Maintainer |
| G03-threat-model | all | yes | pass | `docs/threat-model.md` | Maintainer |
| G04-dependency-alerts | all | yes | pass | Dependabot alerts, zero open High/Critical | Maintainer |
| G05-dependency-pinning | all | yes | pass | every `uses:` pinned to a 40-hex SHA; `requirements-dev.txt` exact pins; shipped skill is standard library only | Maintainer |
| G06-content-provenance | all | yes | pass | `docs/content-provenance.md`, `NOTICE` | Maintainer |
| G07-least-privilege | all | yes | pass | `README.md` "Requirements" | Maintainer |
| G08-redaction | all | yes | pass | redaction pass over every sample report and screenshot shown in `docs/` and `README.md` | Maintainer |
| G09-readme-complete | all | yes | pass | `README.md`, plus a clean-profile transcript of the install one-liner (needs the marketplace repository it names) | Maintainer |
| G10-changelog-entry | all | yes | pass | `CHANGELOG.md` dated section for the tag's exact version | Maintainer |
| G11-semver-consistent | all | yes | N/A on a prerelease (fixed reason); pass on final | tag, `.claude-plugin/plugin.json`, README badge, landing-page `version` | Maintainer |
| G12-screenshots-demo | all | yes | pass | current screenshots and demo GIF, lab data only | Maintainer |
| G13-docs-links | all | yes | pass | `https://hans.study/tools/cisco-switch-config/` returns 200; README and landing page link each other | site, Maintainer |
| G14-ci-built | all | yes | pass | the `release.yml` Actions run for the tag push | automated, Maintainer records |
| G15-sbom-published | all | yes | pass | `cisco-switch-config-<version>.cdx.json` on the GitHub Release | automated, Maintainer records |
| G16-sha256sums | all | yes | N/A on a prerelease (fixed reason); pass on final | `SHA256SUMS` on the release, values on the landing page | automated, site |
| G17-build-attestation | all | yes | pass | attestation bundle on the release; `gh attestation verify <zip> --owner hansstudy` output | automated, Maintainer records |
| G18-authenticode | bin, mod | no | N/A (not applicable to `[skl]`) | `docs/verify-downloads.md` | Maintainer |
| G19-clean-install | bin, mod, plg, skl, web | yes | pass | `claude plugin validate`, a clean-profile marketplace install, and the skill triggering on its intended prompt | Maintainer |
| G20-telemetry-policy | all | yes | pass | `README.md` "Telemetry" and the same statement on the landing page | Maintainer, site |
| G21-support-statement | all | yes | pass | `README.md` "Support" ("There is no SLA.") and the same statement on the landing page | Maintainer, site |
| G22-licence-trademark | all | yes | pass | `LICENSE` (Apache-2.0), `NOTICE`, `TRADEMARKS.md`, README disclaimer | Maintainer |
| G23-privacy-disclosure | all | yes | N/A (transmits nothing anywhere) | `README.md` "Requirements" and "Telemetry" | Maintainer |
| G24-authorized-use | prod | no | not asked (see above) | - | - |
| G25-landing-page-live | all | yes | N/A on a prerelease (fixed reason); pass on final | 200 for the landing page and a sitemap entry | site |
| G26-release-blog-post | all | yes | pass | the published launch post | Maintainer, site |
| G27-cross-post-preflight | all | yes | pass | dated sidebar-reading record per target community, or the recorded decision not to cross-post | Maintainer |

## Repository prerequisites

- A `release` environment with a required reviewer (`hansstudy`), limited to `v*` tags. It holds
  `validate-skill.yml`, which the final tag dispatches; a prerelease dispatches nothing.
- No repository variable is required: `RELEASE_CHECKLIST_PATH` is optional, and step 0 finds
  `docs/RELEASE-CHECKLIST.md` without it.
- The build command (`python3 packaging/build_skill_zip.py --out dist`) names the zip from the
  version in `.claude-plugin/plugin.json`, and the manual SBOM carries that version too. On a
  prerelease tag the zip is therefore named `cisco-switch-config-1.0.0.zip` while the SBOM file
  is named for the tag.
