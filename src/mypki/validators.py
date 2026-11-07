"""Every input rule in mypki, as pure functions that import nothing from FastAPI.

Why this module exists separately from `csr.py`: SAN and name validation is needed at three moments — while building
a CSR from a form, while validating a **foreign** CSR pasted into the sign page, and in unit tests that want to prove
one rule without constructing an X.509 object. Sharing one implementation is the only thing that keeps "the CSR I
generated" and "the CSR I accepted" meaning the same set of names. A SAN list that passes validation but lands in a
certificate differently from the one the operator typed is a mis-issuance, and mypki has no revocation to undo it.

Why classification happens **before** signature checks are trusted: `parse_and_validate_csr` orders its checks
signature-first (page-map §3), but this module must still be callable standalone — for the generate form, which has no
signature to check yet, and for tests that want a SAN rule without a keypair. The ordering guarantee therefore lives in
`csr.py`, not here; what lives here is the rule itself, so it cannot be skipped by forgetting the order somewhere else.

Why messages carry positions: `"server..local" is not a valid DNS name (empty label at position 7)` is actionable —
the operator can find that entry in a 40-line textarea. "invalid SAN" is not. Every message here names what was found,
where, and what would be acceptable instead (page-map §9).

Rejected alternative: validating by regex alone. `ipaddress` exists, classifies IPv4/IPv6 and their literals exactly,
and a regex that guesses at IPv6 will both accept invalid addresses and reject valid ones (`::1`, IPv4-mapped forms).
Classification is therefore "try `ipaddress`, else DNS", not pattern matching.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass, field

from .errors import CsrValidationError

log = logging.getLogger("mypki.validators")

#: RFC 1123 label: letters, digits and interior hyphens; no leading/trailing hyphen; ≤63 characters. Anchored so a
#: prefix match cannot smuggle trailing junk. (page-map §9)
_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")

_MAX_LABELS_LENGTH = 253
_MAX_LABEL_LENGTH = 63
_MAX_FIELD_LEN = 128
_MAX_CN_LEN = 253
_MAX_EMAIL_LEN = 254

__all__ = [
    "SanSet",
    "parse_sans",
    "validate_common_name",
    "validate_country",
    "validate_email",
    "validate_printable_field",
    "validate_san_entry",
    "validity_days",
]


@dataclass(frozen=True)
class SanSet:
    """Validated, deduplicated SANs in first-seen order, split by general-name type.

    The split is what the sign page displays and what `signing.py` copies into the certificate: DNS names and IP
    addresses are different general names in X.509 (`DNSName` / `IPAddress`) and a mixed list would let an ordering
    accident change a certificate's meaning. Dedupe happens here, once, so "same name typed twice" cannot become two
    SAN entries (page-map §9).

    `rejected` is deliberately *not* part of the equality: it carries diagnostics for the page, and comparing them as
    part of identity would make two identical name sets with different error text unequal.
    """

    dns: tuple[str, ...] = ()
    ips: tuple[str, ...] = ()
    rejected: tuple[tuple[int, str], ...] = field(default=(), compare=False)

    @property
    def empty(self) -> bool:
        return not self.dns and not self.ips

    def all_entries(self) -> tuple[str, ...]:
        """Every accepted entry, DNS first then IP — the display order on both pages."""
        return self.dns + self.ips

    def describe(self) -> str:
        """One-line summary for logs (names only; no PEM, no key material)."""
        parts = []
        if self.dns:
            parts.append(f"dns={len(self.dns)}")
        if self.ips:
            parts.append(f"ip={len(self.ips)}")
        return ", ".join(parts) if parts else "none"


def _is_ip_literal(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Classify a bare address, or None when the text is not an IP literal.

    `ipaddress.ip_address` accepts exactly what X.509 means by an IP general name and rejects the things browsers do
    not accept as hostnames — which is why a dotted-quad literal becomes an `IPAddress` here rather than a DNS name
    would then refuse to match (page-map §9). Leading-zero octets in a dotted quad are rejected on purpose:
    some resolvers read them as octal, so accepting one here would issue a certificate for an address the client means
    differently.
    """
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def validate_san_entry(entry: str, position: int = 0) -> tuple[str, str]:
    """Validate one SAN entry and classify it as ("dns", value) or ("ip", value).

    `position` is the zero-based index of the entry in the original textarea, used only to make the message findable.
    Raises `CsrValidationError` naming the reason: an empty label, a label over 63 characters, a leading/trailing
    hyphen, or a wildcard that is not the leftmost `*.` (page-map §9).
    """
    text = entry.strip()
    if not text:
        raise CsrValidationError(f"SAN entry at position {position} is empty", f"sans[{position}]")

    address = _is_ip_literal(text)
    if address is not None:
        return ("ip", str(address))

    # Four dot-separated numeric groups that `ipaddress` refused: almost certainly a mistyped IPv4 (a leading zero,
    # `192.168.1.256`), and every one of them is also a *legal* DNS name by RFC 1123 -- digits are allowed in labels.
    # Accepting them would classify the entry as a DNS general name, issuing a certificate for a name no client will
    # ever match against a socket address: silently mis-issued, and with no revocation here, permanently so. Rejecting
    # names the shape that was found rather than leaving the operator to guess why the certificate does not work.
    groups = text.split(".")
    if len(groups) == 4 and all(group.isdigit() for group in groups):
        raise CsrValidationError(
            f"{text!r} looks like an IPv4 address but is not a valid one; write it as a plain address "
            "(for example 10.0.0.1) so it becomes an IP general name",
            f"sans[{position}]",
        )

    if text.startswith("*."):
        # Wildcard is allowed only as the leftmost label, and only covering exactly one label: `*.a.b` is fine,
        # `a.*.b` and `*` alone are not (page-map §9). RFC 6125 §6.4.3 -- wildcards in a certificate are for the
        # leftmost label of a public suffix-shaped name and nothing else.
        rest = text[2:]
        if not rest or "*." in rest or "*" in rest:
            raise CsrValidationError(
                f"{text!r} is not a valid wildcard name (only the leftmost label may be `*`)",
                f"sans[{position}]",
            )
        base_type, base_value = validate_san_entry(rest, position)
        if base_type == "ip":
            raise CsrValidationError(
                f"{text!r} cannot wildcard an IP address",
                f"sans[{position}]",
            )
        return ("dns", f"*.{base_value}")

    if "*" in text:
        raise CsrValidationError(
            f"{text!r} is not a valid DNS name (a `*` may only appear as the leftmost label, e.g. `*.example.com`)",
            f"sans[{position}]",
        )

    if len(text) > _MAX_LABELS_LENGTH:
        raise CsrValidationError(
            f"{text!r} is {len(text)} characters; a DNS name may be at most {_MAX_LABELS_LENGTH}",
            f"sans[{position}]",
        )

    labels = text.split(".")
    for index, label in enumerate(labels):
        if not label:
            # The position named in the message is where the offending label starts inside the original string, which
            # is what an operator scanning a textarea actually looks for.
            offset = sum(len(labels[i]) + 1 for i in range(index))
            raise CsrValidationError(
                f"{text!r} is not a valid DNS name (empty label at position {offset})",
                f"sans[{position}]",
            )
        if not _LABEL_RE.match(label):
            reason = "not RFC 1123"
            if len(label) > _MAX_LABEL_LENGTH:
                reason = f"longer than {_MAX_LABEL_LENGTH} characters"
            elif label.startswith("-") or label.endswith("-"):
                reason = "begins or ends with a hyphen"
            raise CsrValidationError(
                f"{text!r} is not a valid DNS name (label {index + 1} {reason}: {label!r})",
                f"sans[{position}]",
            )

    # A single-label name ("localhost") is legal in X.509 and useful on a home lab; it is not an error here even
    # though resolvers treat it specially.
    return ("dns", text.lower())


def parse_sans(raw: str | None, max_entries: int) -> SanSet:
    """Split a textarea into validated, deduplicated SANs (page-map §2, §9).

    Separators are newline **or** comma, because operators paste from tools that use either. Entries are validated in
    the order typed so a position in a message maps to the line the operator can see. Rejected entries are collected
    rather than raised one at a time: fixing a 40-line list one error per page load is how an operator learns to hate
    a CA, so every problem is reported together and nothing partial is issued.

    The cap is checked against the *deduplicated* count, because "100 distinct names" is the limit's meaning; 300
    lines that collapse to 20 names is not a request for 300 names.
    """
    if not raw or not raw.strip():
        return SanSet()

    # (original_index, text) pairs. Keeping the original index is what makes a message usable: an operator reading
    # "position 3" counts down to line 3 of their textarea, and if blank or comma-split lines were dropped before
    # indexing,
    # every message after the first blank would point at the wrong entry -- a diagnostic that actively misleads.
    pieces: list[tuple[int, str]] = []
    index = 0
    for raw_line in raw.replace(",", "\n").splitlines():
        for piece in raw_line.split(","):
            stripped = piece.strip()
            if stripped:
                pieces.append((index, stripped))
            index += 1

    dns: list[str] = []
    ips: list[str] = []
    rejected: list[tuple[int, str]] = []
    seen: set[tuple[str, str]] = set()

    for index, piece in pieces:
        try:
            kind, value = validate_san_entry(piece, index)
        except CsrValidationError as exc:
            rejected.append((index, exc.reason))
            continue
        key = (kind, value)
        if key in seen:
            continue
        seen.add(key)
        (dns if kind == "dns" else ips).append(value)

    total = len(dns) + len(ips)
    if total > max_entries:
        raise CsrValidationError(
            f"{total} SANs submitted; the limit is {max_entries} (`MYPKI_MAX_SANS`).",
            "sans",
        )
    if rejected:
        listed = "; ".join(f"position {index}: {reason}" for index, reason in rejected)
        raise CsrValidationError(f"Some SAN entries were rejected — {listed}", "sans")

    log.info("validated %s", SanSet(tuple(dns), tuple(ips)).describe())
    return SanSet(tuple(dns), tuple(ips))


def validate_common_name(value: str | None) -> str:
    """Validate a certificate common name (page-map §2).

    Control characters are rejected outright rather than stripped: a CN containing a NUL or a newline is either a
    truncation in transit or an attempt to make a subject render as something it is not, and both belong on the page
    with the offending value quoted. When the CN *looks* like a hostname it is also checked as a DNS name, because a
    CN of `api..internal` is accepted by X.509 grammar and rejected by every client that has to match it against a
    URL -- catching it at issue time is the only place mypki can catch it.
    """
    text = (value or "").strip()
    if not text:
        raise CsrValidationError("common_name is required", "common_name")
    if len(text) > _MAX_CN_LEN:
        raise CsrValidationError(
            f"common_name is {len(text)} characters; the limit is {_MAX_CN_LEN}",
            "common_name",
        )
    if any(ord(char) < 0x20 or char == "\x7f" for char in text):
        raise CsrValidationError(
            "common_name contains control characters; it was probably truncated or pasted from a binary source",
            "common_name",
        )
    if "." in text and not text.startswith("*."):
        # Only checked when it looks like a host: "mypki Root CA" and "Acme Support Desk" are perfectly ordinary CNs.
        try:
            validate_san_entry(text)
        except CsrValidationError as exc:
            raise CsrValidationError(f"common_name {exc.reason}", "common_name") from exc
    return text


def validate_country(value: str | None) -> str | None:
    """Country must be exactly two letters after uppercasing (page-map §2).

    X.509's `C=` is a printable string of a country code, not free text: "USA", "Germany" and "DE " all encode fine
    and all fail the clients that interpret the field as ISO 3166-1 alpha-2. Rejecting at input time names the field;
    encoding it and letting a client complain is a support ticket.
    """
    text = (value or "").strip()
    if not text:
        return None
    upper = text.upper()
    if len(upper) != 2 or not upper.isalpha():
        raise CsrValidationError(
            f"country must be exactly two letters (got {value!r}); e.g. DE, US, GB",
            "country",
        )
    return upper


def validate_printable_field(value: str | None, field_name: str, max_length: int = _MAX_FIELD_LEN) -> str | None:
    """Optional subject attribute: printable, bounded, trimmed (page-map §2).

    The bound is not anti-DoS padding — a 10 KB `O=` in a certificate is copied into every client's trust store UI and
    some of them truncate it mid-attribute. 128 characters is longer than any real organisation name fits in and short
    enough that no display has to clip it.
    """
    text = (value or "").strip()
    if not text:
        return None
    if len(text) > max_length:
        raise CsrValidationError(
            f"{field_name} is {len(text)} characters; the limit is {max_length}",
            field_name,
        )
    if any(ord(char) < 0x20 or char == "\x7f" for char in text):
        raise CsrValidationError(f"{field_name} contains control characters", field_name)
    return text


def validate_email(value: str | None) -> str | None:
    """Optional email subject attribute: one `@`, printable, ≤254 (page-map §2).

    Deliberately not an RFC 5322 parser. A full parser would either reject addresses real people use or accept ones no
    mail system delivers, and mypki does not send mail to this address — it records it in a certificate. What has to be
    true is that the value cannot smuggle a second attribute into the subject or blow up a client's display.
    """
    text = (value or "").strip()
    if not text:
        return None
    if len(text) > _MAX_EMAIL_LEN:
        raise CsrValidationError(
            f"email is {len(text)} characters; the limit is {_MAX_EMAIL_LEN}",
            "email",
        )
    if text.count("@") != 1:
        raise CsrValidationError(f"email must contain exactly one @ (got {value!r})", "email")
    local, _, domain = text.partition("@")
    if not local or not domain:
        raise CsrValidationError("email needs a name before and after the @", "email")
    if any(ord(char) < 0x20 or char.isspace() for char in text):
        raise CsrValidationError("email contains whitespace or control characters", "email")
    try:
        validate_san_entry(domain)
    except CsrValidationError as exc:
        raise CsrValidationError(f"email domain {exc.reason}", "email") from exc
    return text


def validity_days(value: object, default: int, minimum: int, maximum: int) -> int:
    """Resolve the requested validity, rejecting out-of-range values naming the bound (page-map §3 step B).

    Never clamped. A request for 1000 days against a ceiling of 825 is an operator who believes this CA can issue a
    three-year certificate; silently issuing 825 leaves them believing they have 1000, which is the kind of
    misunderstanding that ends with a service failing on a date nobody wrote down. The refusal names the knob so the
    next request goes through `.env` rather than through guesswork (docs/REFERENCE.md gotcha 2).
    """
    raw = default if value is None or str(value).strip() == "" else str(value).strip()
    try:
        days = int(raw)
    except (TypeError, ValueError):
        raise CsrValidationError(
            f"validity_days must be a whole number of days (got {value!r})", "validity_days"
        ) from None
    if days < minimum:
        raise CsrValidationError(
            f"validity_days must be at least {minimum} (got {days})",
            "validity_days",
        )
    if days > maximum:
        raise CsrValidationError(
            f"validity_days may not exceed {maximum} (`MYPKI_VALIDITY_MAX_DAYS`); got {days}. "
            "mypki has no revocation, so validity is the only bound on a certificate that turns out to be wrong.",
            "validity_days",
        )
    return days
