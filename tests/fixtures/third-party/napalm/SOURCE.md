# Source: NAPALM

- Repository: https://github.com/napalm-automation/napalm
- Licence: Apache-2.0 (`LICENSE` in this directory, fetched verbatim from the repository root)
- Commit pinned at retrieval: `d98ddfe746aff94bca41f51e1604266d4e181a7e` (branch `master`)
- Retrieved: 2026-09-24
- Upstream path: `test/ios/mocked_data/test_get_config/normal/show_running_config.txt`

Embedded **verbatim**, byte-for-byte. This is a full `show running-config` capture from an
IOS-XE CSR1000v lab device used by NAPALM's own test suite (`hostname CSR1`, `version 15.5`).
It is the best available structural template for what a real IOS-XE running-config dump looks
like end to end (paste banner, `!` spacing, comment placement, `end`).

The file contains `enable password cisco` and `username cisco privilege 15 password 0 cisco`
— NAPALM's own placeholder lab credentials on a well-known public test fixture, not a real
device's secrets. They are useful unmodified: the weak-default detector checks
against exactly the value `cisco`.

Used for: overall running-config structural shape (source router, so it carries no
switch-only L2 features — spanning-tree, port-security, storm-control, VTP, stacking, DHCP
snooping/DAI are absent here and covered by hand-authored `synthetic/` fixtures instead).

Policy applied: embed verbatim with attribution.
