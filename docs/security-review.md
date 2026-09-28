# Security review

This document records the findings of an independent pre-release security review of this
project's credential-handling surface, run against the finished tree before the first public
release. It complements [`docs/threat-model.md`](threat-model.md), which defines the security
boundary and the accepted residual risks; this review is the verification pass against that
boundary.

## Scope

The review covers the tool's only untrusted-input surface: a pasted or uploaded Cisco
`show running-config`, plus the user-supplied `--role-map` and baseline spec JSON files. It
examined:

- The ingest-time masking module (`ciscocheck/mask.py`) and every code path downstream of it
  (rules, reporters, the differ, SARIF output, exception messages, the baseline generator), for
  any way a raw credential value could reach a report, a diff, a log line, or an error message.
- The detect-only egress guard that re-checks outgoing text for known secret constructs.
- The AST-level static scan (`packaging/verify_package.py --check unsafe-calls`) that denies
  process execution, dynamic import, deserialisation, networking, and file/stdout writes from
  outside a single boundary-writer module.
- The shipped data files (`catalogue.json`, `defaults.json`, `dialect.json`) and reference docs,
  for any secret-shaped or otherwise sensitive content leaking into product data or end-user-facing
  text.
- Packaging and release tooling, for anything that could cause the artifact to phone home or write
  outside the path the user names.

## Finding classes and fixes

Findings fell into three classes, each remediated before release:

1. **Under-masking of a keyword-then-value construct.** Several redaction rules matched the
   documented constructs too narrowly (for example, a `master key` value under an unexpected mode
   indent, or a userinfo credential in a URL without a recognised scheme). Each was widened to the
   general keyword-then-value grammar rather than patched as a one-off, and covered with a
   regression test so the same shape cannot silently regress.
2. **Over-narrow structural preservation.** A small number of legitimate, non-secret structural
   tokens (ACL names, algorithm selectors, key ids) were being swallowed by an adjacent redaction
   rule's span, which would have made the audited output less useful without buying any additional
   protection. These spans were bounded to stop at the correct token boundary.
3. **Indirect rationale in shipped data.** Two rationale/note strings inside the shipped
   catalogue and defaults data cited sources indirectly rather than stating the technical
   reasoning. Both were rewritten to state only the technical reasoning a reader of the shipped
   artifact needs.

No finding in any class allowed a raw secret value to reach a report, diff, log line, or exception
message. All are covered by the masking invariant test suite (mask-on-ingest, detect-only egress,
and the AST-level unsafe-calls scanner), which runs on every change.

## Accepted residuals

Three masking gaps are accepted by design, not fixed, because closing them would require reading
arbitrary free text as natural language rather than matching a keyword-then-value grammar:

1. A secret value written *before* its trigger word in free-text prose (a comment or banner line),
   rather than in the CLI's actual keyword-then-value grammar.
2. A trigger keyword and its value split across two separate comment lines, since masking is
   applied per physical line before that line's structural role is known.
3. A secret embedded in an identifier (a VLAN name, ACL name, hostname, or interface description)
   with no trigger word anywhere on the line — identifiers are preserved deliberately because the
   audit's own checks need real values to cross-reference against each other.

Full detail and rationale for each is in `docs/threat-model.md`'s "What masking does not cover"
section. Over-redaction — a banner or comment line that carries a trigger word losing the rest of
that line, even where the trailing text was not secret — is accepted in the other direction: it
never leaks a value, it can only discard non-secret text.

## Conclusion

No credential-exposure finding remains open. The tool's layered controls (mask on ingest,
default-deny on unrecognised trigger keywords, no credential recovery of any kind, a detect-only
egress guard as defence in depth, and a static scan denying process execution, networking, and
writes outside the declared output path) were verified against the finished tree and are exercised
by the automated test suite on every change.
