# Install

`cisco-switch-config` installs unchanged into all three Agent Skills surfaces. It ships as one
directory (`skills/cisco-switch-config/`), rooted at its own `SKILL.md`, with no external
dependencies to install — the shipped engine is Python 3.11 standard library only.

## 1. Claude Code — plugin marketplace (recommended)

```
/plugin marketplace add hansstudy/claude-plugins
/plugin install cisco-switch-config@hansstudy-claude-plugins
```

This repository is also self-install-able as its own single-plugin marketplace, useful for
testing a specific tagged version directly from this repo rather than the aggregate marketplace:

```
/plugin marketplace add hansstudy/cisco-switch-config
/plugin install cisco-switch-config@hansstudy-cisco
```

## 2. Claude Code — personal or project skill (no plugin manager)

Download and extract a release `.zip` (see [`docs/verify-downloads.md`](verify-downloads.md) to
verify it first), then copy the `cisco-switch-config/` directory it contains into either:

- `~/.claude/skills/cisco-switch-config/` (personal, all your projects), or
- `<project>/.claude/skills/cisco-switch-config/` (project-scoped, committed or not, your choice).

Claude Code discovers a skill from its `SKILL.md` frontmatter automatically; no restart step
beyond starting a new session is required.

## 3. claude.ai — manual `.zip` upload

Download the release `.zip`, then in claude.ai: **Settings -> Capabilities -> Skills -> Upload
skill**, and select the downloaded `.zip` directly (do not re-zip or rename its contents — the
`SKILL.md` must sit at the zip's root, exactly as `packaging/build_skill_zip.py` produces it).

## 4. Claude API — `skills.create`

For the API's code-execution tool, upload the same release `.zip` via the `skills.create`
endpoint (or the equivalent SDK helper), then reference the skill's id in the request that uses
the code-execution tool. See the Claude API documentation for the current `skills.create` request
shape; this project's contribution is the `.zip` itself, produced identically for every surface.

## After installing, on any surface

Ask a question that names what the skill does — for example, "Audit this Cisco switch config for
security issues," or paste a `show running-config` fragment and ask "what's wrong with this?" See
`skills/cisco-switch-config/references/audit-workflow.md` (loaded by the skill itself once it
triggers) for the full operating guide: reading severities and confidences, building a
`--role-map`, choosing `--profile stig` vs the campus default, and reading SARIF output in CI.

## Verifying what you installed

Every release is built by CI from a signed tag, with a `SHA256SUMS` file and a Sigstore
build-provenance attestation. See [`docs/verify-downloads.md`](verify-downloads.md) before
trusting a downloaded `.zip` on a machine that matters.
