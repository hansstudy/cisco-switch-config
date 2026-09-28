"""The masking chokepoint.

This is the ONLY module that inspects raw configuration content, and the only module in
which a raw secret value is ever bound to a name. It masks on ingest (`mask_lines`,
`redact_line`) and detects - never rewrites - on egress (`scrub`).

Nothing in this module prints, logs or writes. No raw value is ever placed in an exception
message, a Note, a Redaction, a MaskedLine or a MaskedDocument.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Literal, Sequence

from .model import Extent, Note, Redaction

# --------------------------------------------------------------------------- errors

class EgressGuardError(Exception):
    """Raised by report.emit() when mask.scrub() finds an unmasked known secret.

    Carries the construct class and the token position only - NEVER the offending token or
    the offending line.
    """

    def __init__(self, cls: str, position: int) -> None:
        self.cls = str(cls)
        self.position = int(position)
        super().__init__(f"egress guard: unmasked {self.cls} detected at token "
                         f"{self.position}; output suppressed")


# --------------------------------------------------------------------------- records

@dataclass(frozen=True, slots=True)
class RedactResult:
    text: str
    redactions: tuple[Redaction, ...]
    digests: tuple[str, ...]          # parallel to redactions; NEVER stored on Line


@dataclass(frozen=True, slots=True)
class EgressHit:
    cls: str
    token_index: int


@dataclass(frozen=True, slots=True)
class MaskedLine:
    result: RedactResult
    indent: int
    head: str
    mode_path: tuple[str, ...]
    opaque: Literal["banner", "macro", "blob"] | None
    opaque_open: bool
    opaque_close: bool


@dataclass(frozen=True, slots=True)
class MaskedDocument:
    lines: tuple[MaskedLine, ...]
    nesting: Literal["indent", "exit-driven"]
    notes: tuple[Note, ...]


# --------------------------------------------------------------------------- token

REDACTION_RE = re.compile(
    r"\[REDACTED (?P<cls>[a-z0-9-]+), (?:(?P<chars>\d+) chars|span)(?P<changed>, changed)?\]")
_TOKEN_RE = re.compile(
    r"(?:\[REDACTED [a-z0-9-]+, (?:\d+ chars|span)(?:, changed)?\]|\S)+")
_PLACEHOLDER_RE = re.compile(r"<REPLACE-ME:[a-z0-9-]+>")
_TODO_RE = re.compile(r"<TODO:[A-Za-z0-9_-]+>")


def token(cls: str, length: int | None, *, changed: bool | None = None) -> str:
    """The frozen redaction-token spelling."""
    body = "span" if length is None else f"{int(length)} chars"
    return f"[REDACTED {cls}, {body}{', changed' if changed else ''}]"


def tokenize(text: str) -> tuple[str, ...]:
    """Split on whitespace, except that a REDACTION_RE match is one token."""
    return tuple(m.group(0) for m in _TOKEN_RE.finditer(text))


def _spans(text: str) -> list[tuple[int, int, str]]:
    return [(m.start(), m.end(), m.group(0)) for m in _TOKEN_RE.finditer(text)]


def is_placeholder(token: str) -> bool:
    return bool(_PLACEHOLDER_RE.fullmatch(token))


# --------------------------------------------------------------------------- vocabularies

_TYPE = frozenset({"0", "5", "6", "7", "8", "9"})
_ENC = frozenset({"ascii", "hex"})
_ALG = frozenset({
    # algorithm/type selector vocabulary (%ALG)
    "md5", "sha", "sha1", "sha-1", "sha2", "sha-2", "sha256", "sha-256", "des",
    "3des", "aes", "aes-cbc", "null", "hmac-sha1", "hmac-sha-1", "hmac-sha-256",
    "hmac-sha2-256", "cmac-aes-128",
    # the rest of the IOS / IOS-XE selector sets
    "sha224", "sha-224", "sha384", "sha-384", "sha512", "sha-512", "hmac-md5", "hmac-md5-96",
    "hmac-sha1-96", "hmac-sha-384", "hmac-sha-512", "hmac-sha2-384", "hmac-sha2-512",
    "cmac-aes-256", "aes-cmac", "aes128", "aes192", "aes256", "aes-128", "aes-192", "aes-256",
    "aes-128-cbc", "aes-192-cbc", "aes-256-cbc", "aes-gcm", "aes-gcm-128", "aes-gcm-256",
    "3des-cbc", "des-cbc",
    # key-size -cbc / -gcm forms
    "aes128-cbc", "aes192-cbc", "aes256-cbc", "aes128-gcm", "aes192-gcm", "aes256-gcm"})
_VOCAB = _TYPE | _ENC | _ALG

TRIGGER_KEYWORDS: frozenset[str] = frozenset({
    "password", "passwd", "secret", "key", "key-string", "pre-shared-key", "server-key",
    "community", "idtoken", "token", "psk", "authentication-key", "set-key", "auth", "priv",
    "pmk", "passphrase", "shared-secret", "ntp-shared-secret", "message-digest-key"})

# A multi-segment token (`-`/`_`) with one of these whole segments is a trigger
# too (`ACCOUNT-TOKEN`, `snmp_password`). `key`, `auth`, `pass`, `pw`, `ro`/`rw` and `community`
# are deliberately absent as segments: `key-chain`, `auth-port`, `pass-through` are structure.
_TRIGGER_SEGMENTS = frozenset({"password", "passwd", "secret", "token", "psk", "pmk", "passphrase",
                               "credential", "credentials"})
# The egress mirror covers the same vocabulary; `key`, `auth`, `priv`,
# `password`, `secret` and `community` are mirrored by their construct rows.
_EGRESS_TRIGGERS = frozenset({"pmk", "token", "passphrase", "shared-secret", "ntp-shared-secret",
                              "psk", "pre-shared-key", "message-digest-key", "authentication-key"})


def _is_trigger(norm: str) -> bool:
    if norm in TRIGGER_KEYWORDS:
        return True
    return _segment_trigger(norm)


def _segment_trigger(norm: str) -> bool:
    """A multi-segment name whose LAST segment is a secret noun (`account_token`,
    `snmp-password`). `secret-shaped`, `token-prefix`, `password-encryption` are not."""
    if "-" not in norm and "_" not in norm:
        return False
    segs = [x for x in re.split(r"[_-]+", norm) if x]
    return bool(segs) and segs[-1] in _TRIGGER_SEGMENTS

# Multi-word mode heads (3.5). Lowercased as a unit when building a mode_path element.
MULTIWORD_HEADS: tuple[tuple[str, ...], ...] = tuple(sorted((tuple(h.split()) for h in (
    "key chain", "aaa group server tacacs+", "aaa group server radius", "crypto ikev2 keyring",
    "crypto ikev2 profile", "aaa server radius dynamic-author", "event manager applet",
    "crypto pki certificate chain", "crypto pki trustpoint", "crypto key pubkey-chain rsa",
    "crypto keyring", "ip ssh pubkey-chain", "wireless mobility group", "tacacs server",
    "radius server", "parser view", "dot1x credentials", "kron policy-list",
    "ip access-list standard", "ip access-list extended", "interface range",
    "pnp profile")), key=len, reverse=True))

# Known-weak values (3.4.9). Compared by salted digest only; the verdict travels as a class.
_WEAK_VALUES = ("public", "private", "cisco", "cisco123", "password", "admin", "secret",
                "changeme", "snmp", "read", "write", "ro", "rw", "default", "community")
_WEAK_CLASSES = {"snmp-community": "snmp-community-weak",
                 "line-password": "line-password-weak",
                 "enable-password": "enable-password-weak"}

_SESSION_SALT = secrets.token_bytes(16)


def _digest(value: str) -> str:
    return hashlib.sha256(_SESSION_SALT + value.encode("utf-8")).hexdigest()


_WEAK_DIGESTS = frozenset(_digest(w) for w in _WEAK_VALUES)


# --------------------------------------------------------------------------- DSL

@dataclass(frozen=True, slots=True)
class _El:
    kind: str                       # lit optlit type enc alg num any opt rest group val url quoted body
    alts: frozenset[str] = frozenset()
    sub: tuple["_El", ...] = ()


def _compile(pattern: Sequence[str]) -> tuple[_El, ...]:
    out: list[_El] = []
    for p in pattern:
        if p.startswith("?(") and p.endswith(")"):
            out.append(_El("group", sub=_compile(p[2:-1].split())))
        elif p.startswith("?"):
            out.append(_El("optlit", alts=frozenset(a.lower() for a in p[1:].split("|"))))
        elif p == "%TYPE":
            out.append(_El("type"))
        elif p == "%ENC":
            out.append(_El("enc"))
        elif p == "%ALG":
            out.append(_El("alg"))
        elif p == "%NUM":
            out.append(_El("num"))
        elif p == "%ANY":
            out.append(_El("any"))
        elif p == "%OPT":
            out.append(_El("opt"))
        elif p == "%REST":
            out.append(_El("rest"))
        elif p == "$":
            out.append(_El("val"))
        elif p == "$URL":
            out.append(_El("url"))
        elif p == "$QUOTED":
            out.append(_El("quoted"))
        elif p == "$BODY":
            out.append(_El("body"))
        else:
            out.append(_El("lit", alts=frozenset(a.lower() for a in p.split("|"))))
    return tuple(out)


@dataclass(frozen=True, slots=True)
class Construct:
    cls: str
    mode: str
    pattern: tuple[str, ...]
    extent: Extent
    chain: bool = False
    ingest_only: bool = False
    # Rows whose value follows an optional algorithm/type selector fail
    # closed. `tail` is the only grammar allowed after the last bound value; anything else
    # means the slot bound the wrong token, and the line is redacted slot-to-end-of-line.
    backstop: bool = False
    tail: tuple[str, ...] = ()
    always_span: bool = False     # catch-all: unrecognised form, fail closed


def _extent_of(pattern: Sequence[str]) -> Extent:
    if "$BODY" in pattern:
        return "opaque-body"
    if "$URL" in pattern:
        return "embedded-substring"
    return "value-token"


# Legitimate structural tails after the last value, per row. Default: nothing.
_TAILS: dict[tuple[str, str], tuple[str, ...]] = {
    ("ntp-key", "ntp"): ("%TYPE",),
    ("snmpv3-auth", "snmp-server"): ("?(priv %ALG %OPT %ANY)", "?(access %REST)"),
    ("snmpv3-priv", "snmp-server"): ("?(access %REST)",),
    ("isakmp-psk", "crypto"): ("?(address|hostname %ANY %OPT)", "?no-xauth"),
    ("sip-password", "authentication|credentials"): ("?(realm %ANY)",),
    ("isis-password", "isis"): ("?level-1|level-2",),
    # `... shared-secret 0 S [protocol udp] [port N] [ip A | interface I]`
    ("energywise-secret", "energywise"): ("?(protocol %ANY)", "?(port %NUM)", "?(ip %ANY)",
                                          "?(interface %ANY)"),
}
_FHRP = frozenset({"hsrp-key", "vrrp-key", "glbp-key", "crypto-key-passphrase"})


def _is_backstop(cls: str, pattern: Sequence[str]) -> bool:
    if "$" not in pattern:
        return False
    last = len(pattern) - 1 - list(reversed(pattern)).index("$")
    return cls in _FHRP or any(p in ("%TYPE", "%ALG", "%ENC", "%OPT") for p in pattern[:last])


def _row(cls: str, mode: str, *pattern: str, chain: bool = False,
         always_span: bool = False) -> Construct:
    first = pattern[0]
    trigger_first = any(a.lower() in TRIGGER_KEYWORDS for a in first.lstrip("?").split("|"))
    ingest_only = first.startswith("%") or trigger_first or "$BODY" in pattern
    return Construct(cls=cls, mode=mode, pattern=tuple(pattern), extent=_extent_of(pattern),
                     chain=chain, ingest_only=ingest_only,
                     backstop=_is_backstop(cls, pattern), tail=_TAILS.get((cls, first), ()),
                     always_span=always_span)


_OSPFV3_PREFIXES = ((("ipv6", "ospf"), ""), (("ospfv3", "%OPT"), ""), (("area", "%ANY"), "router ospfv3"),
                    # `ospfv3 [pid] ipv4|ipv6 authentication ...`
                    (("ospfv3", "%OPT", "ipv4|ipv6"), ""),
                    # OSPFv3 virtual-link IPsec forms
                    (("area", "%ANY", "virtual-link", "%ANY"), ""))
_OSPFV3_SUFFIXES = (
    ("encryption", "ipsec", "spi", "%NUM", "esp", "null", "%ALG", "%TYPE", "$"),
    ("encryption", "ipsec", "spi", "%NUM", "esp", "%ANY", "%OPT", "%TYPE", "$", "%ALG", "%TYPE", "$"),
    ("authentication", "ipsec", "spi", "%NUM", "%ALG", "%TYPE", "$"),
)

# The construct table, in a frozen order. First match wins, except after a
# chain=True row. Every row is mandatory; rows may be added, never removed.
CONSTRUCTS: tuple[Construct, ...] = (
    # --- management plane and global
    _row("enable-password", "global", "enable", "password", "level", "%NUM", "%TYPE", "$"),
    _row("enable-password", "global", "enable", "password", "%TYPE", "$"),
    _row("enable-secret", "global", "enable", "secret", "level", "%NUM", "%TYPE", "$"),
    _row("enable-secret", "global", "enable", "secret", "%TYPE", "$"),
    _row("enable-secret", "global", "enable", "algorithm-type", "%ANY", "secret", "%TYPE", "$"),
    _row("local-user-password", "global", "username", "%ANY", "%REST", "password", "%TYPE", "$"),
    _row("local-user-secret", "global", "username", "%ANY", "%REST", "secret", "%TYPE", "$"),
    _row("local-user-secret", "global", "username", "%ANY", "%REST", "algorithm-type", "%ANY",
         "secret", "%TYPE", "$"),
    _row("local-user-secret", "global", "username", "%ANY", "%REST", "one-time", "secret",
         "%TYPE", "$"),
    _row("line-password", "line", "password", "%TYPE", "$"),
    _row("parser-view-secret", "parser view", "secret", "%TYPE", "$"),
    _row("master-key", "global", "key", "config-key", "password-encrypt", "$"),
    _row("snmp-community", "global", "snmp-server", "community", "$"),
    _row("snmp-community", "global", "snmp-server", "community-map", "$"),
    _row("snmp-community", "global", "snmp-server", "host", "%ANY", "?(vrf %ANY)",
         "?informs|traps", "?(version 1|2c)", "$"),
    _row("snmpv3-auth", "global", "snmp-server", "user", "%ANY", "%ANY", "%REST", "auth", "%ALG",
         "$", chain=True),
    _row("snmpv3-priv", "global", "snmp-server", "user", "%ANY", "%ANY", "%REST", "priv", "%ALG",
         "%OPT", "$"),
    _row("tacacs-key", "global", "tacacs-server", "key", "%TYPE", "$"),
    _row("tacacs-key", "global", "tacacs-server", "host", "%ANY", "%REST", "key", "%TYPE", "$"),
    _row("tacacs-key", "tacacs server", "key", "%TYPE", "$"),
    _row("radius-key", "global", "radius-server", "key", "%TYPE", "$"),
    _row("radius-key", "global", "radius-server", "host", "%ANY", "%REST", "key", "%TYPE", "$"),
    _row("radius-key", "radius server", "key", "%TYPE", "$"),
    _row("radius-pac-key", "radius server", "pac", "key", "%TYPE", "$"),
    _row("aaa-server-key", "aaa group server", "server-private", "%ANY", "%REST", "key", "%TYPE", "$"),
    _row("coa-server-key", "aaa server radius dynamic-author", "client", "%ANY", "%REST",
         "server-key", "%TYPE", "$"),
    _row("ntp-key", "global", "ntp", "authentication-key", "%NUM", "%ALG", "$"),
    _row("smart-idtoken", "global", "license", "smart", "trust", "idtoken", "$"),
    _row("ftp-password", "global", "ip", "ftp", "password", "%TYPE", "$"),
    _row("http-client-password", "global", "ip", "http", "client", "password", "%TYPE", "$"),
    _row("url-password", "", "ip", "http", "client", "proxy-server", "$URL"),
    _row("url-password", "", "boot", "system", "$URL"),
    _row("url-password", "archive", "path", "$URL"),
    _row("url-password", "kron policy-list", "cli", "%REST", "$URL"),
    _row("url-password", "call-home", "destination", "address", "http", "$URL"),
    _row("url-password", "call-home", "http-proxy", "$URL"),
    _row("url-password", "crypto pki trustpoint", "enrollment", "url", "$URL"),
    _row("ssh-pubkey-hash", "ip ssh pubkey-chain", "key-hash", "%ANY", "$"),
    _row("ssh-pubkey-body", "ip ssh pubkey-chain", "key-string", "$BODY"),
    _row("eem-cli-secret", "event manager applet", "action", "%ANY", "cli", "command", "$QUOTED"),
    _row("eem-env-secret", "global", "event", "manager", "environment", "%ANY", "$QUOTED"),
    # `action <n> set <var> <value>`, conditional on the variable name
    _row("eem-env-secret", "event manager applet", "action", "%ANY", "set", "%ANY", "$QUOTED"),
    # key export / import passphrase, the last token, with backstop
    _row("crypto-key-passphrase", "", "crypto", "key", "export", "%ANY", "%ANY", "pem", "terminal",
         "%ALG", "?exportable", "$"),
    _row("crypto-key-passphrase", "", "crypto", "key", "export", "%ANY", "%ANY", "pem", "url",
         "%ANY", "%ALG", "?exportable", "$"),
    _row("crypto-key-passphrase", "", "crypto", "key", "import", "%ANY", "%ANY",
         "?usage-keys|general-purpose|signature|encryption", "?exportable", "pem|der", "terminal",
         "?exportable", "$"),
    _row("crypto-key-passphrase", "", "crypto", "key", "import", "%ANY", "%ANY",
         "?usage-keys|general-purpose|signature|encryption", "?exportable", "pem|der", "url",
         "%ANY", "?exportable", "$"),
    # PKI export / import passphrases, the same shape as the key forms
    _row("crypto-key-passphrase", "", "crypto", "pki|ca", "export", "%ANY", "pem", "terminal",
         "%ALG", "?exportable", "$"),
    _row("crypto-key-passphrase", "", "crypto", "pki|ca", "export", "%ANY", "pem", "url", "%ANY",
         "%ALG", "?exportable", "$"),
    _row("crypto-key-passphrase", "", "crypto", "pki|ca", "export|import", "%ANY", "pkcs12",
         "%ANY", "?password", "$"),
    _row("crypto-key-passphrase", "", "crypto", "pki|ca", "export|import", "%ANY", "%REST", "$",
         always_span=True),
    # catch-all for forms the rows above do not recognise: keep type and label, redact the rest
    _row("crypto-key-passphrase", "", "crypto", "key", "export|import", "%ANY", "%ANY", "%REST",
         "$", always_span=True),
    _row("cts-sxp-password", "", "cts", "sxp", "default", "password", "%TYPE", "$"),
    _row("dot1x-password", "dot1x credentials", "password", "%TYPE", "$"),
    _row("sip-password", "sip-ua", "authentication|credentials", "username", "%ANY", "password",
         "%TYPE", "$"),
    _row("wsma-password", "", "wsma", "%REST", "password", "%TYPE", "$"),
    _row("pnp-password", "pnp profile", "%REST", "password", "%TYPE", "$"),
    # --- VLAN, layer 2, layer 3, tunnelling, crypto
    _row("vtp-password", "global", "vtp", "password", "$"),
    _row("ppp-chap-password", "", "ppp", "chap", "password", "%TYPE", "$"),
    _row("ppp-pap-password", "", "ppp", "pap", "sent-username", "%ANY", "password", "%TYPE", "$"),
    _row("key-chain-key", "key", "key-string", "%TYPE", "$"),
    _row("ospf-md-key", "", "ip", "ospf", "message-digest-key", "%NUM", "%ALG", "%TYPE", "$"),
    _row("ospf-auth-key", "", "ip", "ospf", "authentication-key", "%TYPE", "$"),
    # OSPF virtual-link / sham-link keys (router mode, any nesting)
    _row("ospf-md-key", "", "area", "%ANY", "virtual-link|sham-link", "%ANY", "%REST",
         "message-digest-key", "%NUM", "%ALG", "%TYPE", "$"),
    _row("ospf-auth-key", "", "area", "%ANY", "virtual-link|sham-link", "%ANY", "%REST",
         "authentication-key", "%TYPE", "$"),
    # TrustSec / MACsec SAP pairwise master key; mode-list etc. survive
    _row("sap-pmk", "", "sap", "pmk", "$"),
    # EnergyWise shared secrets (protocol / port / ip tails survive)
    _row("energywise-secret", "", "energywise", "%REST", "shared-secret|ntp-shared-secret",
         "%TYPE", "$"),
    *(_row("ospfv3-ipsec-key", mode, *prefix, *suffix)
      for prefix, mode in _OSPFV3_PREFIXES for suffix in _OSPFV3_SUFFIXES),
    _row("rip-key", "", "ip", "rip", "authentication", "key-string", "%TYPE", "$"),
    _row("eigrp-key", "af-interface", "authentication", "mode", "hmac-sha-256", "%TYPE", "$"),
    _row("isis-password", "", "isis", "password", "%TYPE", "$"),
    _row("isis-password", "router isis", "area-password|domain-password", "$"),
    _row("bgp-password", "router bgp", "neighbor", "%ANY", "password", "%TYPE", "$"),
    _row("ldp-password", "global", "mpls", "ldp", "neighbor", "%ANY", "password", "%TYPE", "$"),
    _row("msdp-password", "global", "ip", "msdp", "password", "peer", "%ANY", "%TYPE", "$"),
    _row("lisp-key", "", "authentication-key", "%TYPE", "$"),
    _row("hsrp-key", "", "standby", "%NUM", "authentication", "md5", "key-string", "%TYPE", "$"),
    _row("hsrp-key", "", "standby", "%NUM", "authentication", "text", "$"),
    _row("hsrp-key", "", "standby", "%NUM", "authentication", "$"),
    _row("vrrp-key", "", "vrrp", "%NUM", "authentication", "?text|md5", "?(key-string)", "%TYPE", "$"),
    _row("glbp-key", "", "glbp", "%NUM", "authentication", "?text|md5", "?(key-string)", "%TYPE", "$"),
    _row("nhrp-key", "", "ip", "nhrp", "authentication", "$"),
    _row("isakmp-psk", "global", "crypto", "isakmp", "key", "%TYPE", "$"),
    _row("isakmp-psk", "crypto keyring", "pre-shared-key", "address|hostname", "%ANY", "%REST",
         "key", "%TYPE", "$"),
    _row("ikev2-psk", "crypto ikev2 keyring", "pre-shared-key", "%OPT", "%TYPE", "$"),
    _row("ikev2-psk", "crypto ikev2 profile", "authentication", "local|remote", "pre-share", "key",
         "%TYPE", "$"),
    _row("pki-challenge", "crypto pki trustpoint", "password", "%TYPE", "$"),
    _row("pki-cert-body", "crypto pki certificate chain", "certificate", "%REST", "$BODY"),
    _row("pki-cert-body", "", "certificate", "self-signed", "%REST", "$BODY"),
    _row("rsa-key-body", "crypto key pubkey-chain rsa", "key-string", "$BODY"),
    _row("wlan-psk", "wlan", "security", "wpa", "psk", "set-key", "%ENC", "%TYPE", "$"),
    _row("ap-password", "", "ap", "dot1x", "username", "%ANY", "password", "%TYPE", "$"),
    _row("ap-password", "", "ap", "mgmtuser", "username", "%ANY", "password", "%TYPE", "$",
         "secret", "%TYPE", "$"),
    _row("mobility-key", "wireless mobility group", "keepalive|member", "%REST", "key", "%TYPE", "$"),
)
_COMPILED = tuple(_compile(c.pattern) for c in CONSTRUCTS)
_TAIL_COMPILED = tuple(_compile(c.tail) for c in CONSTRUCTS)
_ROW_INDEX = {id(c): i for i, c in enumerate(CONSTRUCTS)}

# Class used when redact_line() is called directly with in_opaque="blob" (the opener class is
# unknown there); mask_lines() always uses the opener row's class.
_BLOB_CLS = "opaque-blob"

CANARY_CLASSES: frozenset[str] = frozenset(
    {c.cls for c in CONSTRUCTS} | set(_WEAK_CLASSES.values())
    | {"unknown-secret", _BLOB_CLS, "alg-secret", "env-secret", "comment", "free-text"})


@dataclass(frozen=True, slots=True)
class _Exc:
    pattern: tuple[_El, ...]
    mode: str = ""
    mode_suffix: str | None = None    # element must also end with this token
    exact: bool = False               # the pattern must consume the whole line
    single: str | None = None         # this token may occur only once


def _exc(*pattern: str, mode: str = "", mode_suffix: str | None = None,
         exact: bool = False, single: str | None = None) -> _Exc:
    return _Exc(_compile(pattern), mode, mode_suffix, exact, single)


# `no-value` (step 1): a match leaves the line untouched.
NO_VALUE: tuple[_Exc, ...] = (
    _exc("service", "password-encryption"), _exc("no", "service", "password-encryption"),
    _exc("password", "encryption", "aes"), _exc("security", "passwords", "min-length", "%NUM"),
    _exc("login", "on-failure", "log"), _exc("login", "on-success", "log"),
    _exc("login", "block-for", "%REST"), _exc("login", "quiet-mode", "access-class", "%ANY"),
    _exc("aaa", "password", "restriction"), _exc("cryptographic-algorithm", "%ANY"),
    _exc("key", "chain", "%ANY", "macsec"), _exc("send-lifetime", "%REST"),
    _exc("accept-lifetime", "%REST"), _exc("authentication", "key-chain", "%REST"),
    _exc("ip", "ssh", "pubkey-chain"), _exc("ip", "ssh", "server", "algorithm", "%REST"),
    _exc("crypto", "key", "generate", "%REST"), _exc("crypto", "key", "zeroize", "%REST"),
    # `crypto key export|import` removed - the passphrase is the last token.
    # added: the mode opener of the rsa-key-body row; without it default-deny span-redacts the
    # opener (`key` is a trigger) and that row's mode gate can never match.
    _exc("crypto", "key", "pubkey-chain", "%REST"),
    _exc("snmp-server", "manager"),
    # `no snmp-server` is whole-line only: as a prefix it would pass `no snmp-server community X`.
    _exc("no", "snmp-server", exact=True),
    _exc("snmp-server", "group", "%ANY", "v3", "auth|noauth|priv", "%REST"),
    # never when an earlier `version` token is present
    _exc("snmp-server", "host", "%ANY", "%REST", "version", "3", "auth|noauth|priv", "%ANY", "%REST",
         single="version"),
    _exc("standby", "%NUM", "authentication", "md5", "key-chain", "%ANY"),
    _exc("vrrp", "%NUM", "authentication", "md5", "key-chain", "%ANY"),
    _exc("glbp", "%NUM", "authentication", "md5", "key-chain", "%ANY"),
    _exc("authentication", "open"), _exc("authentication", "port-control", "%ANY"),
    _exc("authentication", "host-mode", "%ANY"), _exc("authentication", "periodic"),
    _exc("dot1x", "pae", "%ANY"), _exc("aaa", "authentication", "%REST"),
    _exc("aaa", "authorization", "%REST"), _exc("aaa", "accounting", "%REST"),
    _exc("ppp", "authentication", "%REST"), _exc("isis", "authentication", "mode", "%ANY"),
)

# `reference` (step 3): the token after the keyword is an identifier and is preserved.
REFERENCE: tuple[_Exc, ...] = (
    _exc("ntp", "server", "%ANY", "key", "%NUM"), _exc("ntp", "peer", "%ANY", "key", "%NUM"),
    _exc("ntp", "server", "vrf", "%ANY", "%ANY", "key", "%NUM"),      # added: VRF form
    _exc("ntp", "peer", "vrf", "%ANY", "%ANY", "key", "%NUM"),        # added: VRF form
    _exc("ntp", "trusted-key", "%NUM"), _exc("ntp", "authenticate"),
    _exc("key", "chain", "%ANY"), _exc("key", "%NUM", mode="key chain"),
    _exc("key", "%ANY", mode="key chain", mode_suffix="macsec"),
    _exc("ip", "ospf", "authentication", "key-chain", "%ANY"),
    _exc("ipv6", "ospf", "authentication", "key-chain", "%ANY"),
    _exc("ip", "rip", "authentication", "key-chain", "%ANY"),
    _exc("ip", "authentication", "key-chain", "eigrp", "%NUM", "%ANY"),
    _exc("neighbor", "%ANY", "ao", "%ANY", "%REST"), _exc("mka", "policy", "%ANY"),
    _exc("mka", "pre-shared-key", "key-chain", "%ANY"), _exc("crypto", "ikev2", "keyring", "%ANY"),
    _exc("crypto", "keyring", "%ANY"), _exc("crypto", "pki", "trustpoint", "%ANY"),
    _exc("crypto", "pki", "certificate", "chain", "%ANY"), _exc("tacacs", "server", "%ANY"),
    _exc("radius", "server", "%ANY"), _exc("aaa", "group", "server", "tacacs+|radius", "%ANY"),
    _exc("dot1x", "credentials", "%ANY"), _exc("parser", "view", "%ANY"),
    _exc("snmp-server", "group", "%ANY", "%REST"), _exc("snmp-server", "engineid", "%REST"),
    _exc("snmp-server", "enable", "traps", "%REST"), _exc("snmp-server", "trap-source", "%ANY"),
    _exc("license", "smart", "%REST"), _exc("event", "manager", "applet", "%ANY", "%REST"),
    _exc("key", "config-key", "%REST"),
)


# --------------------------------------------------------------------------- matcher

_PUNCT = "()[]{},;:.!?`/'\""
_SCHEME_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://")
_BARE_USERINFO_RE = re.compile(r"([^:/@\s]+):([^@\s]+)@\S")


def _url_password(tok: str) -> tuple[int, int] | None:
    """(start, end) of a userinfo password inside a token, or None.

    `scheme://user:pw@host` anywhere in the token, and the scheme-less
    `user:pw@host` when the token has no `//`. The username is kept.
    """
    m = _SCHEME_RE.search(tok)
    if m:
        rest_start = m.end()
        at = tok.rfind("@", rest_start)
        if at < 0:
            return None
        userinfo = tok[rest_start:at]
        colon = userinfo.find(":")
        if colon < 0:
            return None
        s, e = rest_start + colon + 1, at
        return (s, e) if e > s else None
    if "//" in tok:
        return None
    lead = len(tok) - len(tok.lstrip("\"'(<[{"))
    b = _BARE_USERINFO_RE.match(tok, lead)
    if not b:
        return None
    return b.start(2), b.end(2)


def normalise(text: str) -> str:
    """NFKC, then drop Unicode format (Cf) and control (Cc) characters, except
    tab, line breaks and the 0x03 banner delimiter, so a glued zero-width or full-width
    character cannot split a keyword away from its exact-token match. Line breaks survive so
    a multi-line string handed to scrub() is never glued into one line."""
    # A combining mark (Mn/Mc/Me) glued to a keyword is dropped
    # BEFORE NFKC can compose it into a new letter; U+FFFD becomes a separator.
    text = "".join(" " if ch == "\ufffd" else ch for ch in text
                   if unicodedata.category(ch) not in ("Mn", "Mc", "Me"))
    text = unicodedata.normalize("NFKC", text)
    return "".join(ch for ch in text
                   if ch in "\t\n\r\x03" or unicodedata.category(ch) not in ("Cf", "Cc"))


class _Toks:
    """A tokenised line, with lowercase and (for egress) punctuation-normalised views."""

    __slots__ = ("toks", "low", "norm", "scrub")

    def __init__(self, toks: Sequence[str], scrub: bool) -> None:
        self.toks = list(toks)
        self.low = [t.lower() for t in self.toks]
        self.scrub = scrub
        # A solidus that NFKC leaves glued to a keyword (`community/`, from a
        # full-width U+FF0F) never hides it. Ingest strips only that, so prose punctuation in
        # comments (`password`, key,) keeps the exact-token rule; egress strips all edges.
        self.norm = ([t.strip(_PUNCT) or t for t in self.low] if scrub
                     else [t.strip("/\\") or t for t in self.low])


def _val_ok(t: _Toks, pos: int) -> bool:
    if t.norm[pos] in _VOCAB or t.low[pos] in _VOCAB:
        return False                      # `$` never binds a %TYPE/%ENC/%ALG token
    if t.scrub and not any(ch.isalnum() for ch in t.toks[pos]):
        return False
    if t.scrub and _is_trigger(t.norm[pos]):
        return False                      # egress: a trigger word is never the value itself
    if t.scrub and t.norm[pos] in ("is", "was", "are"):
        return False                      # egress: a connective ("secret is X") is not a value
    return True


def _match(els: tuple[_El, ...], i: int, t: _Toks, pos: int,
           binds: tuple) -> Iterator[tuple[tuple, int]]:
    if i == len(els):
        yield binds, pos
        return
    e = els[i]
    n = len(t.toks)
    k = e.kind
    if k == "lit":
        if pos < n and t.norm[pos] in e.alts:
            yield from _match(els, i + 1, t, pos + 1, binds)
    elif k in ("type", "enc", "alg", "optlit"):
        vocab = {"type": _TYPE, "enc": _ENC, "alg": _ALG}.get(k, e.alts)
        if pos < n and t.norm[pos] in vocab:
            yield from _match(els, i + 1, t, pos + 1, binds)
        yield from _match(els, i + 1, t, pos, binds)
    elif k == "num":
        if pos < n and t.norm[pos].isdigit():
            yield from _match(els, i + 1, t, pos + 1, binds)
    elif k == "any":
        if pos < n:
            yield from _match(els, i + 1, t, pos + 1, binds)
    elif k == "opt":
        if pos < n:
            yield from _match(els, i + 1, t, pos + 1, binds + (("opt", pos),))
        yield from _match(els, i + 1, t, pos, binds)
    elif k == "rest":
        for step in range(0, 13):
            if pos + step > n:
                break
            yield from _match(els, i + 1, t, pos + step, binds)
    elif k == "group":
        for sub_binds, newpos in _match(e.sub, 0, t, pos, ()):
            yield from _match(els, i + 1, t, newpos, binds + sub_binds)
        yield from _match(els, i + 1, t, pos, binds)
    elif k == "val":
        if pos < n and _val_ok(t, pos):
            yield from _match(els, i + 1, t, pos + 1, binds + (("val", pos),))
    elif k == "url":
        if pos < n:
            span = _url_password(t.toks[pos])
            if span is not None:
                yield from _match(els, i + 1, t, pos + 1, binds + (("url", pos, span),))
    elif k == "quoted":
        if pos < n:
            yield from _match(els, i + 1, t, n, binds + (("quoted", pos),))
    elif k == "body":
        yield from _match(els, i + 1, t, pos, binds + (("body",),))


def _mode_ok(mode: str, mode_path: tuple[str, ...], suffix: str | None = None) -> bool:
    if mode == "":
        return True
    if mode == "global":
        return not mode_path
    want = mode.lower().split()
    for element in reversed(mode_path):          # nearest ancestor first
        et = element.lower().split()
        if et[:len(want)] == want and (suffix is None or (et and et[-1] == suffix)):
            return True
    return False


_EEM_SECRET_SEGMENTS = frozenset({
    "ro", "rw", "comm", "community", "auth", "pass", "pw", "key", "secret", "token", "cred",
    "password", "passwd", "psk", "credential", "credentials"})


def _secret_name(var: str) -> bool:
    """Widened secret-variable-name test, whole `_`/`-` segments plus the
    original substring regex."""
    low = var.lower().strip("\"'")
    if any(seg in _EEM_SECRET_SEGMENTS for seg in re.split(r"[_\-]+", low) if seg):
        return True
    return bool(re.search(r"(pass|pw|key|secret|token|community|cred)", low))


def _quoted_end(text: str, s: int, end_of_line: int) -> int:
    """A quoted argument ends at its closing quote; an unquoted one at EOL."""
    if text[s:s + 1] == '"':
        q = text.find('"', s + 1)
        if 0 <= q < end_of_line:
            return q + 1
    return end_of_line


def _eem_condition(cls: str, t: _Toks, binds: tuple, text: str,
                   spans: list[tuple[int, int, str]] | None) -> bool:
    """The content-driven `event manager` rows."""
    qb = next((b for b in binds if b[0] == "quoted"), None)
    if qb is None:
        return True
    pos = qb[1]
    if cls == "eem-env-secret":
        return _secret_name(t.toks[pos - 1] if pos >= 1 else "")
    # eem-cli-secret (item 4a): a command argument is masked as a config line; anything that
    # does not start with a command head (a prompt answer) is redacted outright.
    if spans is not None:
        s = spans[pos][0]
        inner = text[s:_quoted_end(text, s, len(text.rstrip()))]
    else:
        inner = " ".join(t.toks[pos:])
    inner = inner.strip().strip('"').strip()
    if not inner:
        return False
    if inner.split()[0].lower().strip(_PUNCT) not in _eem_heads():
        return True
    reps, _body = _scan(inner, ())
    return bool(reps)


def _first_match(cls: str, els: tuple[_El, ...], t: _Toks, start: int, text: str,
                 spans: list[tuple[int, int, str]] | None, *,
                 check_cond: bool = True) -> tuple[tuple, int] | None:
    """The first accepted binding and the token index where the row's grammar ended."""
    for binds, end in _match(els, 0, t, start, ()):
        if check_cond and cls.startswith("eem-") and not _eem_condition(cls, t, binds, text, spans):
            continue
        return binds, end
    return None


def _first_binding(cls: str, els: tuple[_El, ...], t: _Toks, start: int, text: str,
                   spans: list[tuple[int, int, str]] | None, *,
                   check_cond: bool = True) -> tuple | None:
    m = _first_match(cls, els, t, start, text, spans, check_cond=check_cond)
    return m[0] if m is not None else None


_OPT_WORDS = frozenset({"local", "remote"})


def _opt_shape_ok(low: str) -> bool:
    """An optional qualifier before a value on a backstop row is a number (key length,
    process id), a local/remote qualifier or a known selector. Anything else means the
    optional element swallowed the real value."""
    return low.isdigit() or low in _OPT_WORDS or low in _VOCAB


def _tail_fits(tail: tuple[_El, ...], toks: Sequence[str], scrub: bool) -> bool:
    """True when `toks` (everything after the last bound value) is exactly the row's
    permitted structural tail. An empty tail permits nothing."""
    if not toks:
        return True
    if not tail:
        return False
    tt = _Toks(toks, scrub=scrub)
    return any(end == len(toks) for _b, end in _match(tail, 0, tt, 0, ()))


def _exc_match(exc: _Exc, t: _Toks, start: int, mode_path: tuple[str, ...] | None) -> bool:
    if mode_path is not None and not _mode_ok(exc.mode, mode_path, exc.mode_suffix):
        return False
    if exc.single is not None and t.norm[start:].count(exc.single) != 1:
        return False                      # malformed v3-host shape
    for _binds, end in _match(exc.pattern, 0, t, start, ()):
        if not exc.exact or end == len(t.toks):
            return True
    return False


# --------------------------------------------------------------------------- ingest

@dataclass(slots=True)
class _Rep:
    start: int
    end: int
    cls: str
    length: int | None
    extent: Extent
    value: str               # transient: consumed for the digest, then dropped


def _weak(cls: str, value: str) -> str:
    if cls in _WEAK_CLASSES and _digest(value.lower()) in _WEAK_DIGESTS:
        return _WEAK_CLASSES[cls]
    return cls


def _binding_valid(c: Construct, tail: tuple[_El, ...], t: _Toks, binds: tuple, end: int,
                    scrub: bool) -> bool:
    """A backstop row's binding is a full, well-formed parse: its optional qualifiers have the
    right shape and everything after the last value is the row's permitted tail."""
    if any(b[0] == "opt" and not _opt_shape_ok(t.norm[b[1]]) for b in binds):
        return False
    rest = t.toks[end:]
    if scrub:
        rest = [x for x in rest if any(ch.isalnum() for ch in x)]
    return _tail_fits(tail, rest, scrub=scrub)


def _pick(c: Construct, els: tuple[_El, ...], tail: tuple[_El, ...], t: _Toks, start: int,
          text: str, spans: list[tuple[int, int, str]] | None, scrub: bool
          ) -> tuple[tuple, int, bool] | None:
    """(binds, end, valid). A backstop row prefers the first well-formed parse; when none
    exists the first binding is returned with valid=False, and the caller fails closed."""
    first = None
    for n, (binds, end) in enumerate(_match(els, 0, t, start, ())):
        if n >= 256:
            break
        if c.cls.startswith("eem-") and not _eem_condition(c.cls, t, binds, text, spans):
            continue
        if first is None:
            first = (binds, end)
        if c.always_span:
            return binds, end, False
        if not c.backstop or _binding_valid(c, tail, t, binds, end, scrub):
            return binds, end, True
    if first is None:
        return None
    return first[0], first[1], False


def _unambiguous(c: Construct) -> bool:
    """Rows specific enough to apply whatever the mode_path - every row that is
    egress-eligible, plus ingest-only rows that open with three or more literals. Generic
    trigger-first rows (`key %TYPE $`) keep their mode gate; default-deny covers them."""
    if "$BODY" in c.pattern:
        return True          # only when the line is exactly the opener; see _steps
    if not c.ingest_only:
        return True
    lits = 0
    for p in c.pattern:
        if p.startswith(("%", "$", "?")):
            break
        lits += 1
    return lits >= 3


_UNAMBIGUOUS = tuple(_unambiguous(c) for c in CONSTRUCTS)


def _apply_row(c: Construct, binds: tuple, end: int, valid: bool, t: _Toks,
               spans: list[tuple[int, int, str]], text: str, end_of_line: int,
               reps: list[_Rep]) -> tuple[list[_Rep], str | None, bool]:
    """Replacements for one matched row. Returns (reps, body_cls, stop)."""
    slots = [b[1] for b in binds if b[0] == "val"]
    if c.backstop and slots and not valid:
        # Fail-closed backstop: no well-formed parse exists, so a slot bound the wrong
        # token. Redact from the first candidate slot (value or swallowed qualifier) to EOL.
        shifted = [b[1] for b in binds if b[0] == "opt" and not _opt_shape_ok(t.norm[b[1]])]
        s = spans[min(slots + shifted)][0]
        kept = [r for r in reps if r.end <= s]
        kept.append(_Rep(s, end_of_line, c.cls, None, "span", text[s:end_of_line]))
        return kept, None, True
    for b in binds:
        if b[0] == "body":
            return reps, c.cls, True
        if b[0] == "val":
            s, e, v = spans[b[1]]
            if is_placeholder(v) or REDACTION_RE.fullmatch(v):
                continue                     # 3.4.6 exemption / already masked
            reps.append(_Rep(s, e, _weak(c.cls, v), len(v), "value-token", v))
        elif b[0] == "url":
            s0 = spans[b[1]][0]
            ps, pe = b[2]
            v = spans[b[1]][2][ps:pe]
            if REDACTION_RE.fullmatch(v):
                continue
            reps.append(_Rep(s0 + ps, s0 + pe, c.cls, len(v), "embedded-substring", v))
        elif b[0] == "quoted":
            s = spans[b[1]][0]
            e = _quoted_end(text, s, end_of_line)
            v = text[s:e]
            if is_placeholder(v) or REDACTION_RE.fullmatch(v):
                continue
            reps.append(_Rep(s, e, c.cls, len(v), "value-token", v))
    return reps, None, not c.chain


def _steps(text: str, spans: list[tuple[int, int, str]], t: _Toks,
           mode_path: tuple[str, ...]) -> tuple[list[_Rep], str | None]:
    end_of_line = len(text.rstrip())
    # step 1: no-value
    for exc in NO_VALUE:
        if _exc_match(exc, t, 0, mode_path):
            return [], None
    # step 2: constructs, table order, first match wins except after a chain row. The mode gate
    # chooses between competing rows; when no gated row matches, an unambiguous row matches
    # whatever the mode_path, so a mode never turns a secret into an exemption.
    for gated in (True, False):
        reps: list[_Rep] = []
        matched = False
        for i, (c, els, tail) in enumerate(zip(CONSTRUCTS, _COMPILED, _TAIL_COMPILED)):
            if gated and not _mode_ok(c.mode, mode_path):
                continue
            if not gated and (not _UNAMBIGUOUS[i] or _mode_ok(c.mode, mode_path)):
                continue
            picked = _pick(c, els, tail, t, 0, text, spans, scrub=False)
            if picked is None:
                continue
            if not gated and "$BODY" in c.pattern and picked[1] != len(t.toks):
                continue         # `key-string 7 X` is a key, not a body opener
            matched = True
            reps, body, stop = _apply_row(c, picked[0], picked[1], picked[2], t, spans, text,
                                          end_of_line, reps)
            if body is not None:
                return reps, body
            if stop:
                break
        if matched:
            return reps, None
    # step 3: reference
    for exc in REFERENCE:
        if _exc_match(exc, t, 0, mode_path):
            return [], None
    # step 4: default-deny, first exact trigger token only (edge punctuation ignored)
    if t.toks and _free_text_at(t.toks) is not None:
        return [], None               # comments / free-text fields: _free_text_rep (items 11-12)
    for i, low in enumerate(t.norm):
        if low in TRIGGER_KEYWORDS or _segment_trigger(low):
            if i + 1 >= len(spans):
                return [], None
            s = spans[i + 1][0]
            v = text[s:end_of_line]
            if REDACTION_RE.fullmatch(v):
                return [], None
            return [_Rep(s, end_of_line, "unknown-secret", None, "span", v)], None
    return [], None


def _url_reps(spans: list[tuple[int, int, str]], reps: list[_Rep]) -> list[_Rep]:
    """Command-agnostic, mode-agnostic URL userinfo redaction, applied to every
    token not already covered, whatever steps 1-4 decided."""
    out = []
    for s0, e0, tok in spans:
        if any(r.start < e0 and s0 < r.end for r in reps):
            continue
        span = _url_password(tok)
        if span is None:
            continue
        v = tok[span[0]:span[1]]
        if REDACTION_RE.fullmatch(v):
            continue
        out.append(_Rep(s0 + span[0], s0 + span[1], "url-password", len(v), "embedded-substring", v))
    return out


_ALGNAME_RE = re.compile(
    r"^(aes|3des|des|chacha20|hmac|umac|ecdh|ecdsa|diffie-hellman|curve25519|rsa|ssh-|x509v3|"
    r"sha|md5|gcm|esp-|cmac|null)")
_KEY_LENGTHS = frozenset({"128", "192", "256", "384", "512", "1024", "2048", "3072", "4096"})
_STRUCT_WORDS = frozenset({
    "key-chain", "key-string", "key-hash", "keyring", "mode", "group", "hash", "encryption",
    "integrity", "prf", "lifetime", "exportable", "pem", "terminal", "url", "pkcs12", "der", "esp",
    "ah", "spi", "ipsec", "authentication", "message-digest", "hex", "ascii", "level", "priority",
    "version", "mode-list", "transform-set", "trustpoint", "signature", "access", "remote", "local",
    "vrf", "interval", "retransmit", "hello", "dead", "timeout", "in", "out", "both", "all", "none"})
_KV_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_.-]*)=(.+)")
_EDGE_QUOTES = "\"'`(<[{"


def _alg_skip(norm: str) -> bool:
    """A structural token after an algorithm word: more vocabulary, an algorithm name, a key
    length or an encryption-type digit."""
    return (norm in _VOCAB or bool(_ALGNAME_RE.match(norm)) or norm in _KEY_LENGTHS
            or (len(norm) == 1 and norm.isdigit()))


def _structural(norm: str) -> bool:
    return norm in _STRUCT_WORDS or norm in _eem_heads() or _is_trigger(norm)


def _alg_candidate(t: _Toks, i: int) -> int | None:
    """The value position after algorithm token i, or None when what follows
    is structure (value-slot logic: never vocabulary; command-head logic: never a keyword)."""
    j = i + 1
    while j < len(t.toks) and _alg_skip(t.norm[j]):
        j += 1
    if j >= len(t.toks) or _structural(t.norm[j]):
        return None
    return j


def _covered(reps: list[_Rep], s0: int, e0: int) -> bool:
    return any(r.start < e0 and s0 < r.end for r in reps)


# Comment lines fail closed. The vocabulary is the trigger set plus
# credential(s); matched case-insensitively on alphanumeric word boundaries, so quotes,
# backticks, brackets, `_` and `-` around the word never hide it (`API_KEY`, `` `password` ``).
_COMMENT_VOCAB = tuple(sorted(TRIGGER_KEYWORDS | {"credential", "credentials"}, key=len,
                              reverse=True))
_COMMENT_RE = re.compile(r"(?i)(?<![A-Za-z0-9])(" + "|".join(re.escape(w) for w in _COMMENT_VOCAB)
                         + r")(?![A-Za-z0-9])")
_NAME_EQ_RE = re.compile(r"(?<![A-Za-z0-9_.-])([A-Za-z_][A-Za-z0-9_.-]*)=")
_INERT_RE = re.compile(REDACTION_RE.pattern + "|" + _PLACEHOLDER_RE.pattern + "|" + _TODO_RE.pattern)


def _is_comment_line(first_token: str) -> bool:
    return first_token.startswith(("!", "#"))


def _comment_trigger_end(text: str, start: int = 0) -> int | None:
    """End offset of the first trigger in a comment (a vocabulary word, or the NAME of a
    secret-named NAME=VALUE). Redaction tokens and exact placeholders are inert: a trigger
    word inside `<REPLACE-ME:tacacs-key>` or `[REDACTED snmp-community, ...]` is not one."""
    inert = _INERT_RE.sub(lambda m: "\x01" * len(m.group(0)), text)
    ends = []
    m = _COMMENT_RE.search(inert, start)
    if m:
        ends.append((m.start(), m.end()))
    for km in _NAME_EQ_RE.finditer(inert, start):
        if _secret_name(km.group(1)):
            ends.append((km.start(), km.end(1)))
            break
    return min(ends)[1] if ends else None


# Free-text fields. The keyword stays visible; the text after it is treated
# like a comment body. (No dialect.json / parser marking exists, so the list lives here.)
_FREE_TEXT_FIELDS: tuple[tuple[str, ...], ...] = (
    ("macro", "description"), ("snmp-server", "location"), ("snmp-server", "contact"),
    ("description",), ("remark",), ("comment",))


def _free_text_at(toks: Sequence[str]) -> tuple[str, int] | None:
    """(class, index of the first body token) when the line is a comment ("comment", 0: the
    body starts inside token 0, after the `!`/`#` run) or a free-text field ("free-text", n)."""
    if not toks:
        return None
    if _is_comment_line(toks[0]):
        return "comment", 0
    low = [x.lower() for x in toks]
    i = 1 if low[0].isdigit() and len(low) > 1 and low[1] == "remark" else 0   # `10 remark ...`
    if low[0] == "access-list" and len(low) > 2 and low[2] == "remark":         # numbered ACL
        return "free-text", 3
    if low[0] == "alias" and len(low) > 3:                                      # alias body
        return "free-text", 3
    for field in _FREE_TEXT_FIELDS:
        if tuple(low[i:i + len(field)]) == field:
            return "free-text", i + len(field)
    return None


def _non_ascii_letter(text: str) -> bool:
    """A non-ASCII letter after normalise (IOS configs are ASCII), outside
    redaction tokens and placeholders. Catches cross-script homoglyphs with no confusables
    table: `pаssword` (Cyrillic а) is simply non-ASCII."""
    inert = _INERT_RE.sub("", text)
    return any(ord(ch) > 127 and ch.isalpha() for ch in inert)


def _free_text_rep(text: str, spans: list[tuple[int, int, str]],
                   where: tuple[str, int]) -> _Rep | None:
    """Comment and free-text handling at ingest. Non-ASCII body: redact all of it. Otherwise keep the first
    trigger word (or secret NAME of NAME=VALUE) and redact the rest. N counts from right after
    the `!`/`#` run or the field keyword."""
    cls, idx = where
    if cls == "comment":
        tok0 = spans[0][2]
        body_start = spans[0][0] + (len(tok0) - len(tok0.lstrip("!#")))
    elif idx < len(spans):
        body_start = spans[idx - 1][1]
    else:
        return None
    eol = len(text.rstrip())
    body = text[body_start:eol]
    if not body.strip() or REDACTION_RE.fullmatch(body.strip()):
        return None
    if _non_ascii_letter(body):
        ws = len(body) - len(body.lstrip())
        return _Rep(body_start + ws, eol, cls, len(body), "span", body)
    end = _comment_trigger_end(text, body_start)
    if end is None:
        return None
    rem = text[end:eol]
    if not rem.strip() or REDACTION_RE.fullmatch(rem.strip()):
        return None
    ws = len(rem) - len(rem.lstrip())
    return _Rep(end + ws, eol, cls, len(rem), "span", rem)


def _generic_reps(text: str, spans: list[tuple[int, int, str]], t: _Toks,
                  reps: list[_Rep]) -> list[_Rep]:
    """Shape-based rules that do not depend on the command.
    The table is an optimisation; these run on every line, whatever steps 1-4 decided."""
    out: list[_Rep] = []
    taken = list(reps)
    comment = spans[0][2].startswith("!")     # the shape rules target commands, not `!` prose
    for i, (s0, e0, tok) in enumerate(spans):
        # item 1: algorithm word followed by a value
        if not comment and t.norm[i] in _ALG:
            j = _alg_candidate(t, i)
            if j is not None:
                js, je, v = spans[j]
                if not _covered(taken, js, je) and not (is_placeholder(v) or REDACTION_RE.fullmatch(v)):
                    r = _Rep(js, je, "alg-secret", len(v), "value-token", v)
                    out.append(r)
                    taken.append(r)
        if _covered(taken, s0, e0):
            continue
        # item 3: NAME=VALUE with a secret-shaped name
        lead = len(tok) - len(tok.lstrip(_EDGE_QUOTES))
        core = tok[lead:]
        m = _KV_RE.fullmatch(core.lstrip("!"))
        if m and _secret_name(m.group(1)):
            lead += len(core) - len(core.lstrip("!"))
            vs, ve = lead + m.start(2), lead + m.end(2)
            if not (REDACTION_RE.fullmatch(tok[vs:ve]) or is_placeholder(tok[vs:ve])):
                while ve > vs and tok[ve - 1] in "\"'`)]},;":
                    ve -= 1
            v = tok[vs:ve]
            if v and not (is_placeholder(v) or REDACTION_RE.fullmatch(v)):
                r = _Rep(s0 + vs, s0 + ve, "env-secret", len(v), "embedded-substring", v)
                out.append(r)
                taken.append(r)
                continue
        # URL userinfo
        span = _url_password(tok)
        if span is not None:
            v = tok[span[0]:span[1]]
            if not REDACTION_RE.fullmatch(v):
                r = _Rep(s0 + span[0], s0 + span[1], "url-password", len(v), "embedded-substring", v)
                out.append(r)
                taken.append(r)
    return out


def _scan(text: str, mode_path: tuple[str, ...]) -> tuple[list[_Rep], str | None]:
    """Steps 1-4 of 3.4.4 over one line, then the shape-based generic rules, then (on a `!`
    comment) the comment rule. Returns replacements and, when a `$BODY` row matched, the
    class of the opaque body it opens."""
    spans = _spans(text)
    if not spans:
        return [], None
    t = _Toks([x[2] for x in spans], scrub=False)
    reps, body = _steps(text, spans, t, mode_path)
    where = _free_text_at([x[2] for x in spans])
    if where is not None:
        frep = _free_text_rep(text, spans, where)
        cut = frep.start if frep is not None else len(text)
        # comments keep only URL userinfo (the algorithm trigger stays off them: gen_baseline's
        # sha256 header); free-text fields keep every generic rule before the cut
        keep = [r for r in _generic_reps(text, spans, t, reps) if r.end <= cut
                and (where[0] == "free-text" or r.cls == "url-password")]
        return reps + keep + ([frep] if frep is not None else []), body
    reps = reps + _generic_reps(text, spans, t, reps)
    return reps, body


def _skeleton(masked: str) -> str:
    return REDACTION_RE.sub(lambda m: f"[{m.group('cls')}]", " ".join(tokenize(masked)))


def _finish(text: str, reps: list[_Rep], mode_path: tuple[str, ...]) -> RedactResult:
    """Apply replacements to `text` and build the Redaction records and digests."""
    text = text.rstrip()
    if not reps:
        return RedactResult(text=text, redactions=(), digests=())
    reps = sorted(reps, key=lambda r: r.start)
    out: list[str] = []
    cur = 0
    kept: list[_Rep] = []
    for r in reps:
        if r.start < cur:
            continue                              # overlapping replacement: first one wins
        out.append(text[cur:r.start])
        out.append(token(r.cls, r.length))
        cur = r.end
        kept.append(r)
    out.append(text[cur:])
    masked = "".join(out)
    skel = _skeleton(masked)
    prefix = "/".join(mode_path) + "|" + skel + "|"
    arg_indices: list[int] = []
    for idx, tok in enumerate(tokenize(masked)):
        arg_indices.extend([idx] * len(REDACTION_RE.findall(tok)))
    records = []
    digests = []
    for n, r in enumerate(kept):
        ai = arg_indices[n] if n < len(arg_indices) else -1
        records.append(Redaction(cls=r.cls, length=r.length, key=prefix + str(ai),
                                 extent=r.extent, changed=None))
        digests.append(_digest(r.value))
    return RedactResult(text=masked, redactions=tuple(records), digests=tuple(digests))


def redact_line(text: str, *, mode_path: tuple[str, ...], line_no: int,
                in_opaque: Literal["banner", "macro", "blob"] | None = None) -> RedactResult:
    """Mask one line (3.4.3-3.4.6). `line_no` is accepted for the frozen signature only."""
    if in_opaque == "blob":
        body = text.strip()
        indent = text[:len(text) - len(text.lstrip())]
        if not body:
            return RedactResult(text=text.rstrip(), redactions=(), digests=())
        skel = "/".join(mode_path) + "|" + f"[{_BLOB_CLS}]" + "|-1"
        return RedactResult(text=indent + token(_BLOB_CLS, len(body)),
                            redactions=(Redaction(_BLOB_CLS, len(body), skel, "opaque-body", None),),
                            digests=(_digest(body),))
    reps, _body = _scan(text, mode_path)
    return _finish(text, reps, mode_path)


# --------------------------------------------------------------------------- pre-pass

_BANNER_TYPES = frozenset({"motd", "login", "exec", "incoming", "slip-ppp",
                           "prompt-timeout", "config-save"})
_CTRL_C = "\x03"


def _indent_of(line: str) -> int:
    n = 0
    for ch in line:
        if ch == " ":
            n += 1
        elif ch == "\t":
            n += 8
        else:
            break
    return n


def _element(masked: str) -> str:
    """A mode_path element: lowercased head (multi-word where listed) + preserved remainder."""
    stripped = masked.strip()
    spans = _spans(stripped)
    if not spans:
        return ""
    low = [s[2].lower() for s in spans]
    width = 1
    for head in MULTIWORD_HEADS:
        if tuple(low[:len(head)]) == head:
            width = len(head)
            break
    head = " ".join(low[:width])
    remainder = stripped[spans[width - 1][1]:].strip()
    return head + (" " + remainder if remainder else "")


_DOC_CACHE: dict | None = None


def _defaults_doc() -> dict:
    """`data/defaults.json`, read-only and cached. An unreadable file disables exit-driven
    nesting and the global-pop rule; masking itself never depends on it except for the EEM
    head test, which then fails closed (every `cli command` argument is redacted)."""
    global _DOC_CACHE
    if _DOC_CACHE is None:
        path = Path(__file__).resolve().parent.parent.parent / "data" / "defaults.json"
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
            _DOC_CACHE = doc if isinstance(doc, dict) else {}
        except (OSError, ValueError):
            _DOC_CACHE = {}
    return _DOC_CACHE


_MODE_HEADS_CACHE: dict[str, tuple[str, ...]] | None = None
_GLOBAL_PREFIXES: tuple[tuple[str, ...], ...] | None = None
_EEM_HEADS: frozenset[str] | None = None


def _mode_heads() -> dict[str, tuple[str, ...]]:
    """`mode_heads`: mode-opening head -> permitted parent heads ("" = global)."""
    global _MODE_HEADS_CACHE
    if _MODE_HEADS_CACHE is None:
        raw = _defaults_doc().get("mode_heads", {}) or {}
        _MODE_HEADS_CACHE = {str(k).lower(): tuple(str(p).lower() for p in v)
                             for k, v in raw.items()}
    return _MODE_HEADS_CACHE


def _global_prefixes() -> tuple[tuple[str, ...], ...]:
    global _GLOBAL_PREFIXES
    if _GLOBAL_PREFIXES is None:
        _GLOBAL_PREFIXES = tuple(tuple(str(x).lower().split())
                                 for x in _defaults_doc().get("global_prefixes", []) or [])
    return _GLOBAL_PREFIXES


def _eem_heads() -> frozenset[str]:
    global _EEM_HEADS
    if _EEM_HEADS is None:
        doc = _defaults_doc()
        _EEM_HEADS = frozenset(str(h).lower() for h in
                               list(doc.get("cisco_heads", []) or []) +
                               list(doc.get("exec_heads", []) or []))
    return _EEM_HEADS


def _is_global_line(low: list[str]) -> bool:
    return any(tuple(low[:len(p)]) == p for p in _global_prefixes())


def _mode_head_of(low: list[str]) -> str | None:
    """The longest mode head the lowercased tokens start with (`%NUM` allowed in a head)."""
    best: str | None = None
    best_len = 0
    for head in _mode_heads():
        parts = head.split()
        if len(parts) <= best_len or len(parts) > len(low):
            continue
        ok = all((p == "%num" and low[i].isdigit()) or (p == "%any") or p == low[i]
                 for i, p in enumerate(parts))
        if ok:
            best, best_len = head, len(parts)
    return best


@dataclass(slots=True)
class _Frame:
    indent: int
    element: str
    head: str | None


def mask_lines(raw_lines: Sequence[str]) -> MaskedDocument:
    """Structural pre-pass plus masking of every line, in one pass.

    Yields only masked text, integers, lowercased heads of masked text and span flags; no raw
    text leaves this function.
    """
    raw_lines = [normalise(x) for x in raw_lines]       # NFKC + control-char normalisation
    n = len(raw_lines)
    out: list[MaskedLine | None] = [None] * n
    notes: list[Note] = []

    # --- flat-input detection (3.5): zero indented lines, >=1 exit, >=1 mode-opening head
    any_indented = False
    any_exit = False
    any_mode = False
    for ln in raw_lines:
        st = ln.strip()
        if not st:
            continue
        if _indent_of(ln) > 0:
            any_indented = True
            break
        low = [x.lower() for x in st.split()]
        if low[0] == "exit":
            any_exit = True
        elif _mode_head_of(low) is not None:
            any_mode = True
    nesting: Literal["indent", "exit-driven"] = (
        "exit-driven" if (not any_indented and any_exit and any_mode) else "indent")

    stack: list[_Frame] = []
    state: dict | None = None     # open opaque block

    def _close_blob(st: dict, terminated: bool) -> None:
        body_idx: list[int] = st["body"]
        total = sum(len(raw_lines[i].strip()) for i in body_idx)
        digest = _digest("\n".join(raw_lines[i].strip() for i in body_idx))
        mp = st["mp"]
        skel = "/".join(mp) + "|" + f"[{st['cls']}]" + "|-1"
        for k, i in enumerate(body_idx):
            ln = raw_lines[i]
            ind_str = ln[:len(ln) - len(ln.lstrip())]
            length = total if k == 0 else 0
            res = RedactResult(text=ind_str + token(st["cls"], length),
                               redactions=(Redaction(st["cls"], length, skel, "opaque-body", None),),
                               digests=(digest,))
            out[i] = MaskedLine(result=res, indent=_indent_of(ln),
                                head=tokenize(res.text)[0].lower(), mode_path=mp,
                                opaque="blob", opaque_open=False, opaque_close=False)
        if not terminated:
            notes.append(Note("CSC-SELF-0005", st["opener"] + 1,
                              f"unterminated blob block opened at line {st['opener'] + 1}"))

    def _seg(segment: str, mp: tuple[str, ...], offset: int) -> list[_Rep]:
        reps, _ = _scan(segment, mp)
        for r in reps:
            r.start += offset
            r.end += offset
        return reps

    def _find_closer(line: str, closers: tuple[str, ...], start: int) -> tuple[int, str] | None:
        best: tuple[int, str] | None = None
        for c in closers:
            q = line.find(c, start)
            if q >= 0 and (best is None or q < best[0]):
                best = (q, c)
        return best

    idx = 0
    while idx < n:
        line = raw_lines[idx].rstrip()
        ind = _indent_of(line)
        stripped = line.strip()

        # ---------------- inside an opaque block
        if state is not None:
            kind = state["kind"]
            mp = state["mp"]
            if kind == "banner":
                found = _find_closer(line, state["closers"], 0)
                inner_blob = state.get("blob")
                if found is None and inner_blob is not None:
                    # A blob inside a banner body is opaque through `quit`
                    if stripped.lower() == "quit":
                        state["blob"] = None
                        res = _finish(line, [], mp)
                    elif stripped:
                        ind_str = line[:len(line) - len(line.lstrip())]
                        skel = "/".join(mp) + "|" + f"[{inner_blob}]" + "|-1"
                        res = RedactResult(ind_str + token(inner_blob, len(stripped)),
                                           (Redaction(inner_blob, len(stripped), skel,
                                                      "opaque-body", None),),
                                           (_digest(stripped),))
                    else:
                        res = _finish(line, [], mp)
                    out[idx] = MaskedLine(res, ind, _first_low(res.text), mp, "banner", False, False)
                elif found is None:
                    reps = _seg(line, state["enc"], 0)
                    res = _finish(line, reps, mp)
                    out[idx] = MaskedLine(res, ind, _first_low(res.text), mp, "banner", False, False)
                    opener_cls = _body_opener(line)
                    if opener_cls is not None:
                        state["blob"] = opener_cls
                else:
                    q, c = found
                    if inner_blob is not None and line[:q].strip():
                        pre = line[:q]
                        reps = [_Rep(len(pre) - len(pre.lstrip()), len(pre.rstrip()), inner_blob,
                                     len(pre.strip()), "opaque-body", pre.strip())]
                    else:
                        reps = _seg(line[:q], state["enc"], 0)
                    reps += _seg(line[q + len(c):], state["enc"], q + len(c))
                    res = _finish(line, reps, mp)
                    out[idx] = MaskedLine(res, ind, _first_low(res.text), mp, "banner", False, True)
                    state = None
                idx += 1
                continue
            if kind == "macro":
                if stripped == "@":
                    res = _finish(line, [], mp)
                    out[idx] = MaskedLine(res, ind, "@", mp, "macro", False, True)
                    state = None
                else:
                    res = _finish(line, _seg(line, state["enc"], 0), mp)
                    out[idx] = MaskedLine(res, ind, _first_low(res.text), mp, "macro", False, False)
                idx += 1
                continue
            # blob. An `ip ssh pubkey-chain` key-string body also
            # closes on `exit`, or on a dedent below its opener (never in flat input)
            if state["cls"] == "ssh-pubkey-body" and stripped and (
                    stripped.lower() == "exit"
                    or (state["opener_indent"] > 0 and ind < state["opener_indent"]
                        and stripped.lower() != "quit")):
                _close_blob(state, terminated=True)
                if stripped.lower() == "exit":
                    res = _finish(line, [], mp)
                    out[idx] = MaskedLine(res, ind, "exit", mp, "blob", False, True)
                    state = None
                    idx += 1
                    continue
                state = None
                # dedent: fall through and process this line normally
            elif stripped.lower() == "quit":
                _close_blob(state, terminated=True)
                res = _finish(line, [], mp)
                out[idx] = MaskedLine(res, ind, "quit", mp, "blob", False, True)
                state = None
                idx += 1
                continue
            if state is not None and not stripped:
                out[idx] = MaskedLine(RedactResult("", (), ()), 0, "", mp, "blob", False, False)
                idx += 1
                continue
            elif state is not None:
                state["body"].append(idx)
                idx += 1
                continue

        # ---------------- ordinary line: structure first (from masked ancestors), then mask
        is_blank = not stripped
        is_comment = stripped.startswith("!")
        low_first = stripped.split()[0].lower() if stripped else ""
        is_exit = low_first.startswith("exit")
        push = False                      # does this line open a level?
        push_head: str | None = None
        if nesting == "indent":
            if is_blank or is_comment:
                mp = tuple(f.element for f in stack if f.indent < ind)
            elif low_first == "end" and ind == 0:
                stack.clear()
                mp = ()
            else:
                while stack and stack[-1].indent >= ind:
                    stack.pop()
                mp = tuple(f.element for f in stack)
                push = not is_exit
        else:
            mp = tuple(f.element for f in stack)
            if not (is_blank or is_comment):
                if low_first == "end":
                    stack.clear()
                    mp = ()
                elif not is_exit:
                    low_all = [x.lower() for x in stripped.split()]
                    head = _mode_head_of(low_all)
                    if head is not None:
                        ok = _mode_heads()[head]
                        if "" not in ok and not any((f.head or "") in ok for f in stack):
                            head = None          # no permitted ancestor: not a mode opener here
                    if head is None and _is_global_line(low_all):
                        # IOS falls back to global mode for a global command
                        stack.clear()
                        mp = ()
                    if head is not None:
                        # a mode-opening line first pops to the nearest ancestor allowed to
                        # contain it, then pushes (IOS's own rule)
                        parents_ok = _mode_heads()[head]
                        j = len(stack)
                        while j > 0 and (stack[j - 1].head or "") not in parents_ok:
                            j -= 1
                        if j > 0 or "" in parents_ok:
                            del stack[j:]
                            mp = tuple(f.element for f in stack)
                            push, push_head = True, head

        reps, body_cls = _scan(line, mp)
        opaque: Literal["banner", "macro", "blob"] | None = None
        opened = closed = False

        # banner opener (row a)
        spans = _spans(line)
        if (not is_blank and len(spans) >= 2 and spans[0][2].lower() == "banner"
                and spans[1][2].lower() in _BANNER_TYPES):
            p = spans[1][1]
            while p < len(line) and line[p] in " \t":
                p += 1
            if p < len(line):
                if line.startswith("^C", p):
                    closers, dl = ("^C", _CTRL_C), 2
                elif line[p] == _CTRL_C:
                    closers, dl = ("^C", _CTRL_C), 1
                else:
                    closers, dl = (line[p],), 1
                body_start = p + dl
                found = _find_closer(line, closers, body_start)
                if found is None:
                    reps = _seg(line[body_start:], mp, body_start)
                    opaque, opened = "banner", True
                    res = _finish(line, reps, mp)
                    state = {"kind": "banner", "closers": closers, "opener": idx, "enc": mp,
                             "mp": mp + (_element(res.text),)}
                else:
                    q, c = found
                    reps = (_seg(line[body_start:q], mp, body_start)
                            + _seg(line[q + len(c):], mp, q + len(c)))
                    opaque, opened, closed = "banner", True, True
                    res = _finish(line, reps, mp)
            else:
                res = _finish(line, reps, mp)
        elif not is_blank and len(spans) >= 2 and [s[2].lower() for s in spans[:2]] == ["macro", "name"]:
            res = _finish(line, reps, mp)
            opaque, opened = "macro", True
            state = {"kind": "macro", "opener": idx, "enc": mp, "mp": mp + (_element(res.text),)}
        else:
            res = _finish(line, reps, mp)
            if body_cls is not None:
                opaque, opened = "blob", True
                state = {"kind": "blob", "opener": idx, "opener_indent": ind, "cls": body_cls,
                         "body": [], "mp": mp + (_element(res.text),)}

        out[idx] = MaskedLine(result=res, indent=ind, head=_first_low(res.text), mode_path=mp,
                              opaque=opaque, opaque_open=opened, opaque_close=closed)

        # push after masking, so the element is built from the MASKED line
        if push:
            stack.append(_Frame(ind, _element(res.text), push_head))
        elif is_exit and nesting == "exit-driven" and stack:
            stack.pop()                   # `exit` pops one level
        idx += 1

    # EOF inside an opaque block: close at EOF, CSC-SELF-0005, continue
    if state is not None:
        if state["kind"] == "blob":
            _close_blob(state, terminated=False)
        else:
            o = state["opener"] + 1
            notes.append(Note("CSC-SELF-0005", o,
                              f"unterminated {state['kind']} block opened at line {o}"))
    # A fail-closed backstop redaction is a line the table could not classify
    # exactly; say so with a content-free literal (CSC-SELF-0004).
    for i, ml in enumerate(out):
        if ml is not None and any(r.extent == "span" and r.cls not in ("unknown-secret", "comment")
                                  for r in ml.result.redactions):
            notes.append(Note("CSC-SELF-0004", i + 1, "masking backstop applied"))
    notes.append(Note("CSC-SELF-0009", None, f"nesting={nesting}"))
    return MaskedDocument(lines=tuple(x for x in out if x is not None), nesting=nesting,
                          notes=tuple(notes))


def _body_opener(line: str) -> str | None:
    """The class of a `$BODY` row the line opens, with the mode gate ignored (banner bodies)."""
    spans = _spans(line)
    if not spans:
        return None
    t = _Toks([x[2] for x in spans], scrub=False)
    for c, els in zip(CONSTRUCTS, _COMPILED):
        if "$BODY" in c.pattern and _first_binding(c.cls, els, t, 0, line, spans) is not None:
            return c.cls
    return None


def _first_low(masked: str) -> str:
    toks = tokenize(masked)
    return toks[0].lower() if toks else ""


# --------------------------------------------------------------------------- egress

_JSON_ESCAPE_RE = re.compile(r'\\(["\\/bfnrt]|u[0-9a-fA-F]{4})')
# An escaped line break is a logical line break: JSON/SARIF text is scanned line by
# line exactly as table output is, so a row can never bind the next logical line's first word.
_ESC_MAP = {'"': '"', "\\": "\\", "/": "/", "b": " ", "f": " ", "n": "\n", "r": "\n", "t": " "}


def _unescape(text: str) -> str:
    def _sub(m: re.Match[str]) -> str:
        g = m.group(1)
        if g.startswith("u"):
            return chr(int(g[1:], 16))
        return _ESC_MAP[g]
    prev = None
    while prev != text:            # nested escaping (a JSON string inside a JSON string)
        prev = text
        text = _JSON_ESCAPE_RE.sub(_sub, text)
    return text


# Egress-eligible rows: command-literal-first rows plus the
# ingest-only rows that the mode-ignored pass can now reach (three or more leading literals).
_EGRESS = tuple((i, c, els) for i, (c, els) in enumerate(zip(CONSTRUCTS, _COMPILED))
                if _UNAMBIGUOUS[i] and "$BODY" not in c.pattern)


def _slot_clean(v: str) -> bool:
    """True when an egress value slot holds no secret: a redaction token, an exact
    placeholder, or an unsubstituted <TODO:...>."""
    core = v.strip(",;.:()\"'`")
    return bool(REDACTION_RE.fullmatch(core) or _PLACEHOLDER_RE.fullmatch(core)
                or _TODO_RE.fullmatch(core))


def _is_span_of(tok: str, cls: str) -> bool:
    m = REDACTION_RE.fullmatch(tok.strip(",;.:()\"'`"))
    return bool(m and m.group("cls") == cls and m.group("chars") is None)


def _span_at_first_slot(c: Construct, els: tuple[_El, ...], t: _Toks, start: int) -> int | None:
    """A same-class span token makes a row's slots structural only when it
    sits at that row's first value position (the ingest backstop's own output)."""
    # match only the row's grammar up to its first value: a backstop span collapses every later
    # value of a multi-value row into that one token
    first_val = next((k for k, e in enumerate(els) if e.kind == "val"), None)
    if first_val is None:
        return None
    for n, (binds, _end) in enumerate(_match(els[:first_val + 1], 0, t, start, ())):
        if n >= 256:
            break
        slots = [b[1] for b in binds if b[0] == "val"]
        if slots and _is_span_of(t.toks[slots[0]], c.cls):
            return slots[0]
    return None


def scrub(text: str) -> tuple[EgressHit, ...]:
    """Egress leak DETECTOR. Known constructs only, mode ignored, never default-deny,
    and it NEVER modifies `text`: it returns hits and the caller fails the run.

    Two scans, and a hit in either fails the run:
    - LOGICAL: JSON escapes decoded; a real or escaped line break separates logical lines, each
      scanned on its own, so a multi-line remediation is read line by line.
    - PHYSICAL: the unsplit text with every break turned into a space, so a keyword and a value
      joined by a literal backslash-n are still read as one construct.
    The physical scan does not report a value slot that begins right after a break AND is a
    command-head word (`enable`, `interface` ...): that is the next logical line's command,
    already scanned by the logical pass - the `no enable password\nenable ...` shape.
    Logical-line token indices count across the whole text."""
    decoded = normalise(_unescape(text))
    for q in ('"', "'", "`"):
        decoded = decoded.replace(q, " ")
    hits: list[EgressHit] = []
    offset = 0
    for logical in re.split(r"[\r\n]", decoded):
        toks = tokenize(logical)
        hits.extend(EgressHit(h.cls, h.token_index + offset) for h in _scrub_line(toks, logical))
        offset += len(toks)
    # physical pass: breaks become spaces; remember which tokens start right after one
    segments = re.split(r"[\r\n]", decoded)
    physical = " ".join(segments)
    starts, pos = set(), 0
    for seg in segments[:-1]:
        pos += len(seg) + 1
        starts.add(pos)
    ptoks, soft, breaks, prev_end = [], set(), set(), 0
    heads = _eem_heads()
    for i, (s0, e0, tok) in enumerate(_spans(physical)):
        after_break = any(prev_end <= b <= s0 for b in starts)
        if after_break:
            breaks.add(i)
            if tok.lower().strip(_PUNCT) in heads:
                soft.add(i)
        ptoks.append(tok)
        prev_end = e0
    seen = {(h.cls, h.token_index) for h in hits}
    for h in _scrub_line(tuple(ptoks), physical, soft=frozenset(soft), breaks=frozenset(breaks)):
        if (h.cls, h.token_index) not in seen:
            hits.append(h)
    return tuple(hits)


def _scrub_line(toks: tuple[str, ...], decoded: str, *,
                soft: frozenset[int] = frozenset(),
                breaks: frozenset[int] = frozenset()) -> tuple[EgressHit, ...]:
    """scrub() over one decoded line. Physical pass only: `soft` positions (the next logical
    line's command word) are never reported as a value, and a row's trailing-token checks stop
    at the next line break (`breaks`), so they never read the next logical line. A value slot
    that crosses a break is still checked in full."""
    if not toks:
        return ()

    def upto_break(first: int, row_start: int) -> range:
        # the row's own logical line ends at the first break after the row starts
        stop = next((b for b in sorted(breaks) if b > row_start), len(toks))
        return range(first, max(first, stop))
    t = _Toks(toks, scrub=True)
    hits: list[EgressHit] = []
    seen: set[int] = set()

    def hit(cls: str, pos: int) -> None:
        if pos not in seen and pos not in soft:
            seen.add(pos)
            hits.append(EgressHit(cls=cls, token_index=pos))

    comment_line = False                 # a `!` config comment, after any JSON key / prefix
    comment_at = 0
    free_at: tuple[str, int] | None = None
    for k in range(len(toks)):
        if _is_comment_line(toks[k]):
            comment_line, comment_at = True, k
            break
        if not any(ch.isalnum() for ch in toks[k]):
            continue                     # JSON punctuation, diff `+`/`-` markers
        if toks[k].endswith(":") or (k + 1 < len(toks) and toks[k + 1] == ":"):
            continue                     # JSON keys, `evidence:` / `fix:` prefixes
        if toks[k].isdigit() and not (k + 1 < len(toks) and toks[k + 1].lower() == "remark"):
            continue                     # masked line numbers, diff line columns
        if toks[k].lower() in ("added", "removed", "changed", "secret-rotated"):
            continue                     # diff-table change kinds
        f = _free_text_at(toks[k:])
        if f is not None:
            comment_at, free_at = k, f
        break
    if comment_line:
        free_at = ("comment", 0)
    prose_line = free_at is not None

    def row_hit(cls: str, pos: int) -> None:
        # On a `!` comment line a construct row reads prose ("`enable password` inside"), so
        # its value must also be secret-shaped; ingest already redacts a real comment secret.
        if not prose_line or _comment_shaped(toks[pos]):
            hit(cls, pos)

    covered_until = 0                   # leftmost match wins; no overlapping row matches
    for start in range(len(toks)):
        if t.norm[start] == "" or start < covered_until:
            continue
        vetoed: bool | None = None
        for ri, c, els in _EGRESS:
            first = els[0]
            if first.kind != "lit" or t.norm[start] not in first.alts:
                continue
            picked = _pick(c, els, _TAIL_COMPILED[ri], t, start, decoded, None, scrub=True)
            if picked is None:
                continue
            binds, end, valid = picked
            if vetoed is None:
                vetoed = any(_exc_match(x, t, start, None) for x in NO_VALUE)
            if vetoed:
                break
            # a clean quoted slot is one redaction token: the match covers only through it,
            # so a later construct on the same output line is still checked
            cover = end
            for b in binds:
                if b[0] == "quoted" and _slot_clean(t.toks[b[1]]):
                    cover = b[1] + 1
            covered_until = max(covered_until, cover)
            span_at = _span_at_first_slot(c, els, t, start) if c.backstop else None
            if span_at is not None:
                # the ingest backstop redacted slot-to-EOL: nothing raw may follow the span
                after = [k for k in upto_break(span_at + 1, start)
                         if any(ch.isalnum() for ch in toks[k]) and not _slot_clean(toks[k])]
                if after:
                    row_hit(c.cls, after[0])
                covered_until = max(covered_until, span_at + 1)
                if not c.chain:
                    break
                continue
            for b in binds:
                if b[0] in ("val", "quoted"):
                    pos = b[1]
                    slot = t.toks[pos]
                elif b[0] == "url":
                    pos = b[1]
                    ps, pe = b[2]
                    slot = t.toks[pos][ps:pe]
                else:
                    continue
                if not _slot_clean(slot):
                    row_hit(c.cls, pos)
            if c.backstop and not valid and any(b[0] == "val" for b in binds):
                # On egress: the same shape as the ingest backstop
                shifted = [b[1] for b in binds if b[0] == "opt"
                           and not _opt_shape_ok(t.norm[b[1]]) and not _slot_clean(t.toks[b[1]])]
                rest = [k for k in upto_break(end, start) if k not in soft
                        if any(ch.isalnum() for ch in toks[k]) and not _slot_clean(toks[k])]
                if shifted or rest:
                    row_hit(c.cls, (shifted + rest)[0])
            if not c.chain:
                break                     # same first-match-wins order as ingest (3.4.4)
    # A URL userinfo password anywhere, whatever the command
    for k, tok in enumerate(toks):
        span = _url_password(tok)
        if span is not None and not _slot_clean(tok[span[0]:span[1]]):
            hit("url-password", k)
    # The same shape-based rules on egress. A value must also be secret-shaped here, because egress
    # reads the tool's own English (titles, rationale): "MD5 rather than SHA1" is prose.
    if prose_line and not breaks:        # comment / free-text handling, mirrored (logical pass)
        cls, idx = free_at
        if cls == "comment":
            body_toks = [toks[comment_at].lstrip("!#")] + list(toks[comment_at + 1:])
        else:
            body_toks = list(toks[comment_at + idx:])
        ctext = " ".join(body_toks)
        if _non_ascii_letter(ctext):
            hit(cls, comment_at)                    # non-ASCII free text left in clear
        inert = _INERT_RE.sub(lambda m: "\x01" * len(m.group(0)), ctext)
        pos = 0
        while True:
            end = _comment_trigger_end(ctext, pos)
            if end is None:
                break
            rest = inert[end:].strip(" \t,;.:\"'`)]}")
            if rest and set(rest) - {"\x01", " ", ",", ";"}:
                hit(cls, comment_at)                # a trigger followed by clear text
                break
            pos = end
    for k in range(len(toks)):
        if k in soft:
            continue
        tok = toks[k]                                            # item 3: comments too
        lead = len(tok) - len(tok.lstrip(_EDGE_QUOTES + "!"))
        m = _KV_RE.fullmatch(tok[lead:])
        if m and _secret_name(m.group(1)):
            v = m.group(2)
            if not _slot_clean(v):
                v = v.rstrip("\"'`)]},;")
            if v and not _slot_clean(v):
                hit("env-secret", k)
        if comment_line:
            continue                     # items 1-2 target commands; comments have items 11-12
        norm = t.norm[k]
        if norm in _ALG:                                         # item 1
            j = _alg_candidate(t, k)
            if j is not None and not _slot_clean(toks[j]) and _secret_shaped(toks[j]):
                hit("alg-secret", j)
        if norm in _EGRESS_TRIGGERS or (norm not in TRIGGER_KEYWORDS and _segment_trigger(norm)):
            j = k + 1                                            # item 2
            while j < len(toks) and (t.norm[j] in _VOCAB or t.norm[j] in _KEY_LENGTHS):
                j += 1
            if (j < len(toks) and not _structural(t.norm[j]) and not _slot_clean(toks[j])
                    and _secret_shaped(toks[j])):
                hit("unknown-secret", j)
    return tuple(hits)


def _comment_shaped(tok: str) -> bool:
    """Stricter egress shape test for `!` comment prose, which capitalises for emphasis
    ("INSIDE") and at sentence starts ("Contains"): a digit, a symbol other than - _ ., 16+
    characters, or an uppercase letter after the first character alongside lowercase."""
    core = tok.strip(",;.:()[]{}\"'`")
    if len(core) < 4:
        return False
    return (any(c.isdigit() for c in core) or len(core) >= 16
            or any(not c.isalnum() and c not in "-_." for c in core)
            or (any(c.isupper() for c in core[1:]) and any(c.islower() for c in core)))


def _secret_shaped(tok: str) -> bool:
    """Egress-only plausibility test for the generic mirrors: a digit, mixed case, an
    all-capitals word of 6+, 16+ characters, or punctuation other than - _ . inside."""
    core = tok.strip(",;.:()[]{}\"'`")
    if len(core) < 4:
        return False
    has_upper = any(c.isupper() for c in core)
    has_lower = any(c.islower() for c in core)
    return (any(c.isdigit() for c in core) or (has_upper and has_lower)
            or (core.isupper() and len(core) >= 6) or len(core) >= 16
            or any(not c.isalnum() and c not in "-_." for c in core))
