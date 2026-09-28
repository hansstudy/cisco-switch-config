# Threat model

This document defines the security boundary for this tool ahead of first public release.

## What this tool is, for this document's purposes

A text-in, text-out audit and generation engine. It never connects to a device: no SSH, no
netmiko, no NAPALM, no SNMP. It reads a pasted or uploaded `show running-config`, a `--role-map`
JSON file, or a baseline spec JSON file, and writes findings, a diff, or a generated
configuration to stdout or to the single file named by `--out`. This scope boundary is also the
primary security boundary, and it is why no authorized-use notice applies: there is no live-device
access to authorize.

## Inputs and trust boundaries

| Input | Trust | Boundary |
|---|---|---|
| `show running-config` text (file, stdin, paste) | **Untrusted.** Third-party infrastructure detail, routinely containing live credential material, and capable of containing text that reads as an instruction | `parser.parse()`. Masked before any object exists. Never executed, never evaluated, never used to construct a path |
| A `--role-map` JSON file | Semi-trusted: the user's own file | `json.load` + schema validation; unknown keys rejected; role values checked against a closed vocabulary |
| A baseline spec JSON file | Semi-trusted: the user's own file | `json.load` + schema validation with `additionalProperties: false`; secret-named keys rejected outright |
| `data/catalogue.json`, `defaults.json`, `dialect.json` | Trusted: shipped with the artifact, covered by the release attestation | Loaded, shape-checked; a parse failure exits 3, not a crash |
| `SKILL.md` and reference instructions | Trusted: authored here, reviewed | — |
| Fetched web content | **Never fetched, on any surface.** `SKILL.md` forbids Claude from fetching STIG/CIS/Cisco content at run time; the AST scanner forbids the scripts from opening a socket at all | No fetch path exists |

## The credential chokepoint

The engine's primary security surface is that a running-config routinely contains live credential
material, and the tool's own job is to point at the risky lines. One module,
`ciscocheck/mask.py`, is the only code that inspects raw configuration content, and it holds a raw
value only transiently inside its ingest functions. Everything downstream — rules, reporters, the
differ, SARIF fingerprints, exception messages, the baseline generator, log lines — sees masked
text only: the `Line` record has no `raw` field, and no other object in the package may carry one.

Layered controls, in the order they act:

| # | Control |
|---|---|
| 1 | Mask on ingest, before the `Config` object exists — every check, report, diff and error message sees masked text only |
| 2 | Full redaction with class and character count — never leading characters, which would recover short secrets (`cisco`, `public`) outright |
| 3 | Default-deny: any occurrence of a trigger keyword (`password`, `secret`, `key`, `community`, ...) that matches no known reference or no-value form is redacted from the keyword to end of line |
| 4 | Every structural token on a line (access mode, ACL name/number, peer address, algorithm selector, key id) is preserved, so the audit stays writable |
| 5 | No credential recovery of any kind, including Cisco type 7 (trivially reversible elsewhere); weak-default detection reports a verdict only, never the value |
| 6 | The differ compares secret positions inside the ingest step and records only `changed: true|false`, never either value, so a rotated key renders as `[REDACTED tacacs-key, 16 chars, changed]` |
| 7 | A single boundary-writer module is the only code permitted to call `print`/`sys.stdout.write`/open a file for writing; every other module returns values |
| 8 | A detect-only egress guard re-checks every outgoing line for a known secret construct as defence in depth; a hit is a hard error (exit 5), never a rewrite |
| 9 | No stack traces or raw exception text reach stdout/stderr on any path |
| 10 | The one diagnostic produced before masking runs (a pre-clean note) is content-free: artefact class and line number only, never the line text |
| 11 | Public-repository test fixtures use a documented, obviously-synthetic canary vocabulary, with scanner allowlists so the canaries are never mistaken for a real leak and nobody "fixes" the tests by weakening them |

### What masking covers

- Every secret field the masker recognises.
- Any value after a secret-type word (`password`, `secret`, `key`, `community`, `psk`, `token`
  and similar) or after an algorithm name (`md5`, `sha256`, `aes` and so on) — default-deny: an
  occurrence of a trigger keyword that matches no known reference or no-value form is redacted
  from the keyword to end of line, so an unlisted *secret* form still costs a leaked value at
  worst an over-redaction, never a silent pass.
- Any `NAME=VALUE` whose name is secret-like.
- Comments and free-text fields, from a trigger word on, or when they contain non-ASCII text.
- Every structural token on the line (access mode, ACL name/number, peer address, algorithm
  selector, key id) is preserved, so the audit stays writable.

This is the same coverage statement `SKILL.md`'s "What masking does, and what it does not cover"
section gives the model, restated here for the release-gate record.

### What masking does not cover: three accepted residual classes

Egress is a **detect-only** guard over already-masked or placeholder-only output — it
cannot save any of the three forms below, because ingest is where the redaction decision is made
once and for all, and egress is not a second classifier over untrusted text. Accepted, not fixed,
each with its reason:

1. **A secret written *before* its trigger word**, as in "X is the password". Every real Cisco CLI
   construct puts the keyword first (`password X`, `secret X`, `key X`); the masker's construct
   table is a keyword-then-value grammar because that is the actual grammar of the configuration
   language. Recognising a value that precedes its keyword only happens in free-text prose (a
   comment or banner line), and catching it in general would need a natural-language reading of
   arbitrary text, which is an unbounded, unauditable surface, not a masking rule.
2. **A trigger split across two separate comment lines.** Masking runs per physical line, before
   the line's structural role is known (the fixed ingest order is pre-clean, then line-level
   masking, then the structural parse). A keyword on one comment line and its value on the next are
   two independent lines to the masker. Joining arbitrary free-text lines to hunt for a spread-out
   trigger would mean looking backward and forward across the whole file on every line, which
   defeats the property that makes ingest masking predictable in the first place: each line is
   redacted once, locally, before anything about the file's shape is assumed.
3. **A secret embedded in an identifier** — a VLAN name, an ACL or other object name, the VTP
   domain, a hostname, or an interface description — with no trigger word anywhere on the line.
   Identifiers are preserved deliberately: the audit's checks (and the reference
   resolution) need real VLAN, ACL and hostname values to cross-reference against each other, so
   masking every identifier by default would break the tool's primary function. The masker has no
   way to tell "an identifier that happens to look secret" from an ordinary one without a trigger
   word signalling secret intent.

Over-redaction is accepted in the other direction: a banner or comment line that does carry a
trigger word loses the rest of that line, even where the trailing text was not actually secret.

## Shipped-script constraints

Enforced by `packaging/verify_package.py --check unsafe-calls`, an AST scan with zero permitted
occurrences under `skills/`:

- **No process execution, no dynamic import, no deserialisation of untrusted bytes**:
  `subprocess`, `ctypes`, `pickle`, `marshal`, `shelve`, `eval`, `exec`, `compile`, `__import__`,
  `importlib.import_module`, `os.system`/`popen`/`exec*`/`spawn*`/`fork*`.
- **No network of any kind**: `socket`, `ssl`, `http`, `ftplib`, `telnetlib`, `smtplib`,
  `asyncio`, `requests`, `httpx`, `urllib.request`/`.error`/`.robotparser`, and — because they
  write to stderr from inside the standard library, bypassing the output boundary — `logging` and
  `warnings`. `urllib.parse` alone is allowed: it is needed to locate `user:pw@` credentials
  embedded in a URL token, and it opens no connection.
- **No output outside the boundary-writer module**: bare `print`, `sys.stdout.write`,
  `sys.stderr.write`, their `.buffer` forms, `os.write`.
- **No file writing outside the boundary-writer module's `--out` path**: `open` in a write mode,
  `Path.write_text`/`write_bytes`, `tempfile.*`, `shutil.*`, `os.open`, `os.fdopen`.
- **No dynamic module discovery**: the rules package imports every rule module by an explicit,
  auditable list; nothing uses `pkgutil` or a directory walk to find rule code.
- **No type-7 (or similar) credential recovery**: a static scan denies the well-known Vigenère key
  constant and any name matching a decode/decrypt/reveal/crack-plus-type7 pattern.

## What must never phone home

Nothing, on any surface, by any path:

- Shipped scripts cannot open a socket (asserted statically, and at runtime with
  `socket.socket`/`socket.create_connection`/`socket.getaddrinfo` patched to raise).
- `SKILL.md` never instructs Claude to fetch newer STIG, CIS or Cisco content at run time — on any
  surface, including Claude Code where network access exists — because fetched content becomes
  untrusted instructions inside the context window. Updates ship as new skill versions.
- No telemetry, no analytics, no update check, no usage counter, no crash reporter.
- `claude plugin eval`'s HTML report publication is disabled explicitly (`--no-publish`) in every
  documented and CI invocation, because the eval prompts embed fixture configuration text and
  default publication would be unreviewed egress to a claude.ai URL.
- Nothing is written outside the path named by `--out`; the runtime-invariant test suite proves
  this with `TMPDIR`/`TEMP`/`TMP` redirected into a disposable scratch root.

## Public-repository exposure

The repository is public. Three consequences, each handled by design:

1. **Fixtures necessarily contain secret-shaped strings** (the masking tests would be untestable
   otherwise). The canary vocabulary (`CANARY-COMMUNITY-01`, `$9$CANARY0001...`, etc.) makes them
   obviously synthetic, and `.gitleaks.toml` plus `.github/secret_scanning.yml` exclude
   `tests/fixtures/**` and `evals/**` so the first push raises no alert and nobody is tempted to
   weaken the tests to silence one.
2. **Third-party fixtures carry real licences.** Each `tests/fixtures/third-party/<source>/`
   directory carries that project's own `LICENSE` and a `SOURCE.md`; `NOTICE` carries one
   attribution entry per source; this document records that attribution.
3. **No CIS prose, anywhere.** Enforced by the catalogue JSON Schema forbidding a `title` field on
   a CIS `refs` entry, by the catalogue-authoring rules, and by the clean-room rule (see
   `docs/content-provenance.md`), which also forbids transcribing anything from GPL prior-art
   tools.

## Out of scope, by design

No live device interaction of any kind (no SSH/netmiko/NAPALM/SNMP); no credential recovery of
any kind; no routing-protocol correctness analysis (reachability, ACL shadowing — that is
Batfish's domain); no multi-device inventory; one config per invocation. These are the tool's
stated design scope boundaries and are also security boundaries: each one is a class of attack
surface this tool simply does not have.
