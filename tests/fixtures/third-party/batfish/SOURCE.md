# Source: batfish

- Repository: https://github.com/batfish/batfish
- Licence: Apache-2.0 (`LICENSE` in this directory, fetched verbatim from the repository root)
- Commit pinned at retrieval: `5e8ecd02b080467470509710a7fe4be50b72bd46` (branch `master`)
- Retrieved: 2026-09-24
- Base path: `projects/batfish/src/test/resources/org/batfish/grammar/cisco/testconfigs/`

All files below are embedded **verbatim**, byte-for-byte, from the path shown. No text was
added, removed, or reworded. Every secret-shaped value already present in these files is
synthetic test data supplied by the batfish project (e.g. `MySecretKey1`, `psk1`, RFC-shaped
placeholder hex strings), not a real credential.

| File in this directory | Upstream path (relative to base path above) |
|---|---|
| `ios_banner.cfg` | `ios_banner` |
| `ios-line.cfg` | `ios-line` |
| `ios-aaa-group-server.cfg` | `ios-aaa-group-server` |
| `ios-crypto.cfg` | `ios-crypto` |
| `ios-ntp.cfg` | `ios-ntp` |
| `ios-snmp-community-string.cfg` | `ios-snmp-community-string` |

Used for: banner delimiter forms (single-line and multi-line `^C`), `line con/aux/vty`
constructs including type-7 passwords and transport keywords, AAA new-model with TACACS
server-group keys, ISAKMP/crypto keyring constructs, NTP configuration, and SNMP v2c
community-string lines. These exercise the masking construct table against
independently-authored, non-project config text.

Policy applied: embed verbatim with attribution.
