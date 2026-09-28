# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

### Changed

### Fixed

### Security

## [1.0.0-rc.1] - 2026-09-28

Release candidate for 1.0.0, published as a GitHub prerelease only (no marketplace entry).

### Added

- Initial release. An offline audit engine for Cisco IOS and IOS-XE switch running-configurations:
  121 catalogue checks across AAA, SSH, VTY, SNMP, NTP, logging, management plane, DHCP snooping,
  Layer 2, spanning tree, interfaces and resilience. Every finding carries a severity, the masked
  evidence line, paste-ready remediation, and a citation to DISA STIG, NSA, CISA or Cisco
  guidance.
- `audit_config.py` output as a table, JSON, SARIF, or the whole configuration as masked text;
  `campus` and `stig` profiles, a severity floor, a security/reliability filter, an optional
  interface role map, and a `--fail-on` exit code for pipeline use.
- `gen_baseline.py`: generates a hardened baseline configuration from a short JSON spec, with
  placeholders instead of secrets.
- `diff_config.py`: compares two configurations and reports which hardening controls a change
  crossed.
- Credentials are masked on ingest, before any finding, diff or error message exists.
- Installs into Claude Code (plugin marketplace or personal/project skill), claude.ai (`.zip`
  upload) and the API's skills endpoint. Python 3.11+ standard library only: no dependencies, no
  network access, no telemetry.

### Fixed

- CSC-L2-0002, CSC-L2-0003 and CSC-L2-0009 no longer suggest VLAN 1, or the VLAN that was just
  flagged, as the fix; they now print a `<REPLACE-ME:vlan-id>` placeholder for the operator to
  fill in.

<!--
  On release: date the heading for the tag being released, then keep a fresh empty [Unreleased]
  section above it. release.yml reads the section for the tag being released to populate the
  GitHub Release notes - a missing section for the tag fails the release.
-->

[Unreleased]: https://github.com/hansstudy/cisco-switch-config/compare/v1.0.0-rc.1...HEAD
[1.0.0-rc.1]: https://github.com/hansstudy/cisco-switch-config/releases/tag/v1.0.0-rc.1
