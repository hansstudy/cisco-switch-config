# Source: ntc-templates

- Repository: https://github.com/networktocode/ntc-templates
- Licence: Apache-2.0 (`LICENSE` in this directory, fetched verbatim from the repository root;
  trust the LICENSE file text over GitHub's repo-level API classifier, which reports
  "Other/NOASSERTION" and does not reflect the actual license terms)
- Commit pinned at retrieval: `d86d09fa105ee2a432795022e7df04737c65dd28` (branch `master`)
- Retrieved: 2026-09-24
- Upstream path: `tests/cisco_ios/show_crypto_pki_certificates/cisco_ios_show_crypto_pki_certificates_1.raw`

Embedded **verbatim**, byte-for-byte, as `show_crypto_pki_certificates.raw`. This is `show`
command **operational output** (not config-mode text), used only for the field shapes of a
certificate/issuer/subject display (`cn=CommonName`, templated placeholder values throughout).
It is not parsed by `ciscocheck.parser` and carries no config-mode secret construct; it exists
to keep the corpus's PKI-adjacent fixtures grounded in a real vendor tool's field layout rather
than invented from scratch.

Policy applied: embed verbatim with attribution.
