# Verify this download

This artifact is **not Authenticode-signed** — Authenticode is not applicable to a Claude skill
`.zip` in the way it applies to a Windows executable, and no code-signing certificate is held for
this project's downloadable artifacts in general (deferred until a tool shows traction). Every
release instead ships, next to the skill `.zip`:

- A `SHA256SUMS` file covering every release artifact, including the SBOM.
- A CycloneDX SBOM, `cisco-switch-config-<version>.cdx.json`.
- A [Sigstore](https://www.sigstore.dev/) build-provenance attestation
  (`actions/attest-build-provenance`), proving the artifact came out of a known GitHub Actions
  build of a known commit, not a hand-uploaded file. The attestation bundle is also attached to
  the release as `cisco-switch-config-<version>.intoto.jsonl`; it is not listed in `SHA256SUMS`,
  because it attests the files that `SHA256SUMS` covers.

## 1. Verify the checksum

Download `SHA256SUMS` from the same release as the file you downloaded, then:

```powershell
Get-FileHash -Algorithm SHA256 .\<file>
```

```sh
sha256sum <file>
```

Compare the printed hash against the matching line in `SHA256SUMS`. They must match exactly.

## 2. Verify the build provenance attestation

Requires the [GitHub CLI](https://cli.github.com/) (`gh`):

```sh
gh attestation verify <file> --owner hansstudy
```

A successful verification confirms the artifact was built by this repo's `release.yml` workflow,
from the tagged commit, and has not been modified since.

## Why gate G18 (Authenticode) is N/A for this artifact

Release gate `G18-authenticode` applies to `[bin]` (Windows EXE/MSI) and `[mod]` (PowerShell
module) artifacts. This project's artifact kind is `[skl]` (a Claude skill), for which the gate's
own tag list marks it not applicable. The evidence for that N/A is this document, per
`docs/RELEASE-CHECKLIST.md`'s gate-18 fixed reason: no code-signing certificate is held; deferred
until a tool shows traction; the release ships a Sigstore attestation, `SHA256SUMS`, and this
verify-by-hash instruction instead.

## Why this matters

Neither check replaces reading the skill's source before installing it (this repository is small
and readable end to end), but together they are a strong authenticity guarantee: they tie the
`.zip` you downloaded to the exact source commit and build log, not just to whoever uploaded a
file with the right name. See `https://github.com/hansstudy/cisco-switch-config/actions` for the
build log referenced by the attestation.
