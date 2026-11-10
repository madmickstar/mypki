"""Building mypki's CRL: one signed PEM artifact on disk, rebuilt from the record store (page-map §14).

Why this module exists separately from `store.py` and `app.py`: a CRL is a **signed statement about other
certificates**, which makes it the first artifact in this project whose correctness a third party can check. The store
knows which rows carry a revocation stamp; `ca.py` knows the key; only this module decides *what the CRL says* — which
serials are in it, what its two dates mean, and which extensions it carries. Keeping that decision in one file is what
lets `test_crl.py` assert the whole artifact without a web layer.

Why the entry set is derived rather than accumulated ----------------------------------------------------
Entries come from `IssuedStore.revoked_records()`: rows with `revoked_at_utc IS NOT NULL` **and** `not_after_utc > now`.
So a revoked certificate whose own validity has already lapsed is **dropped**. RFC 5280 §5.3.3 permits removing an entry
only when the CA asserts the certificate will no longer be considered valid, which is defensible here (the certificate
expires anyway) but reads wrong to a human: "removed from the CRL" sounds like "un-revoked". The honest sentence lives
on `/crl`, in page-map §14 and in docs/REFERENCE.md: *mypki drops a revoked serial from the CRL once that certificate
has expired;
there is no un-revoke, and the row stays in `issued.db` forever.*

Why `CRLNumber` comes from `count_revoked()` and never from `len(entries)`: entries can **shrink** (the rule above), and
RFC 5280 §5.2.1 requires the number to be monotonically increasing for a given CRL issuer. `len(entries)` after an
expired revoked certificate was dropped would be *smaller than the previous build's* value, which a strict client may
read as a retracted CRL. `count_revoked()` counts rows with a stamp — lifetime, monotone because this store has no
DELETE (`store.py`, page-map §5) — so the number can only stay level or grow. Asserted in tests across a rebuild that
*removed* an entry.

Why there is **no `IssuingDistributionPoint`** (measured, and the sharpest reason in this plan)
--------------------------------------------------------------------------------------------
An IDP scopes a CRL to a name and/or a subset of certificates. Measured with openssl 3.5.6 against a CRL carrying
`IDP(full_name=http://mypki.my.lab/revoke.crl, only_contains_user_certs=True, critical)`: `openssl verify -crl_check`
answers **`error 44 at 0 depth lookup: different CRL scope`, rc=2** for a *perfectly valid leaf that carries no CDP at
all* — i.e. every certificate of this CA carrying no pointer, and anything minted elsewhere against it. The plain-CRL
control verifies `OK` rc=0. Adding an IDP would therefore make `-crl_check` unusable on this CA's own history. Both
`IssuingDistributionPoint` and `DeltaCRLIndicator` are asserted absent in `test_crl.py`, and page-map §14 states the
`error 44` reason so nobody re-adds one "for completeness".

Why the two dates are constants rather than knobs: `next_update` = thisUpdate + 24 h. A knob would need a §11 row, a
presets entry, an empty-value rule and a story about what happens when it is shorter than a client's refresh interval —
for a value whose only sensible range is "often". OCSP's own `next_update` (4 h) sits in `ocsp_responder.py` for the
same reason.

Why PEM and not DER: mypki emits PEM everywhere else (`csr.py`, `ca.py`) and the artifact is meant to be pasted, emailed
and diffed by a human. A second DER spelling of the same object would be two implementations of one fact (page-map §1).

Why writing is atomic (temp file + `os.replace`): a half-written CRL is worse than an old one — a client that fetches a
truncated PEM gets a parse failure and cannot tell whether the CA revoked something or the disk lied mid-write. Same
posture as `settingsfile.py`'s write-then-chmod sequence.

What this module does **not** do: it does not read or write any key file (the caller hands it an already-loaded
`CaBundle`), and it does not decide *when* to rebuild (that is `app.py`: startup, after a stamping batch, and the GUI
Rebuild button).
"""

from __future__ import annotations

import contextlib
import datetime as dt
import logging
import os
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from .ca import CaBundle
from .errors import MypkiError
from .store import IssuedRecord

log = logging.getLogger("mypki.crl")

#: `nextUpdate` = thisUpdate + this. 24 hours: short enough that a client which polls daily learns about a revocation
#: the same day, long enough that an operator who leaves the box running for a weekend does not publish a CRL whose
#: stated freshness has already lapsed. A module constant on purpose — see the module docstring.
CRL_LIFETIME = dt.timedelta(hours=24)

#: The armour line `cryptography` and openssl agree on (`openssl crl -in <file> -noout -text` parses what
#: `load_pem_x509_crl` writes, and vice versa). Named here because the `/crl` page, `test_crl.py` and the harness's
#: §11 each assert this one spelling.
CRL_PEM_MARKER = "-----BEGIN X509 CRL-----"

__all__ = [
    "CRL_LIFETIME",
    "CRL_PEM_MARKER",
    "CrlFacts",
    "build_crl",
    "crl_pem",
    "read_crl_pem",
    "rebuild_crl",
    "summarise_crl",
    "write_crl_pem",
]


@dataclass(frozen=True)
class CrlFacts:
    """What a freshly built CRL actually says, for the `/crl` page and the rebuild confirmation (page-map §14).

    Carried as a value rather than re-read from the PEM by the handler because the page must show the same numbers the
    builder used. Re-parsing the artifact is what `test_crl.py` does to prove the round-trip; a template that recomputed
    entry counts from its own view of the store would be a second answer, and the two drift the first time an entry is
    dropped for expiry.
    """

    issuer: str
    this_update_utc: dt.datetime
    next_update_utc: dt.datetime
    crl_number: int
    entry_count: int
    pem: str

    @property
    def lifetime_hours(self) -> int:
        """`nextUpdate - thisUpdate` in whole hours, so the page states the interval rather than implying it."""
        return int((self.next_update_utc - self.this_update_utc).total_seconds() // 3600)


def build_crl(
    *,
    bundle: CaBundle,
    records: Sequence[IssuedRecord],
    crl_number: int,
    this_update_utc: dt.datetime | None = None,
) -> x509.CertificateRevocationList:
    """Sign a CRL for `records`, which must already be the filtered entry set (see `IssuedStore.revoked_records`).

    `crl_number` is a parameter rather than something computed here on purpose: the number's meaning ("how many
    revocations this CA has ever made") belongs to the store that counts rows, and a builder that derived it from
    `len(records)` would be one refactor away from the monotonicity bug described in the module docstring. The caller
    passes `store.count_revoked()`.

    `this_update_utc` defaults to now; tests pass a fixed instant so `nextUpdate` is assertable rather than "roughly a
    day ahead". Aware-UTC is required, and a naive value is converted rather than rejected — the same rule `store._iso`
    applies, because a CRL whose dates mean different things on different hosts is the exact bug this project avoids in
    its database too.

    An empty entry set is legal and signs fine (an empty CRL verifies with `is_signature_valid` True), so a
    CA that has never revoked anything still answers `/revoke.crl` with a valid, current, zero-entry artifact rather
    than a 404.

    No private key is read here; `bundle.key` must already be loaded by the caller (`ca.load_ca`, once at startup).
    """
    if bundle.key is None:
        raise MypkiError(
            "This CA has no private key loaded, so it cannot sign a CRL. Run `mypki init-ca`, or supply the "
            "passphrase if the existing key is encrypted."
        )

    now = _aware_utc(this_update_utc or dt.datetime.now(dt.timezone.utc))

    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(bundle.cert.subject)  # exactly the CA subject, same rule as signing.py §7
        .last_update(now)
        .next_update(now + CRL_LIFETIME)
    )

    for record in records:
        if record.revoked_at_utc is None:
            # Unreachable from `revoked_records()`, which filters on this column. Kept as a refusal rather than a skip:
            # silently dropping a row the caller asked to include would produce a CRL that disagrees with its own input,
            # and "the CRL omitted one of the serials you handed it" is not a failure an operator should discover at a
            # client.
            raise MypkiError(
                f"CRL build refused: record {record.serial_hex} carries no revocation stamp, so it is not a revoked "
                "certificate."
            )
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            # `int(hex, 16)` round-trips every serial this CA issues (all of them sampled, including the 101
            # of 200 that are 159-bit with the top bit set). The hex spelling is what `issued.db` stores and what
            # `/issued` displays, so it is also what a reader comparing this artifact to the page is matching on.
            .serial_number(int(record.serial_hex, 16))
            # Preserving the original stamp, not "now": the CRL entry must state when the decision was made, which is
            # the same principle `store.revoke()` protects by refusing to move an existing stamp.
            .revocation_date(_aware_utc(record.revoked_at_utc))
            # No `CRLReason` entry extension. RFC 5280 §5.3.1 defines an absent reason code as `unspecified`, which is
            # exactly what this responder answers in OCSP (`ocsp_responder.py`) — mypki's `revocation_reason` is prose,
            # prose, and encoding a code invented from prose would be a claim this CA cannot support.
            .build()
        )

    builder = builder.add_extension(x509.CRLNumber(crl_number), critical=False)
    # The one ignore in this module, and it names the same gap `signing.leaf_extensions` already carries: cryptography
    # types `AuthorityKeyIdentifier.from_issuer_public_key` as taking `CertificateIssuerPublicKeyTypes`, while
    # `Certificate.public_key()` returns the wider `CertificatePublicKeyTypes` (it also admits X25519/X448/MLKEM keys,
    # which cannot sign anything). mypki's CA policy refuses a non-RSA/EC root before this is reachable — `load_ca`
    # runs every loaded certificate through `keys.key_spec_for_public_key`.
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(bundle.cert.public_key()),  # type: ignore[arg-type]
        critical=False,
    )
    # No IssuingDistributionPoint, no DeltaCRLIndicator — deliberately absent, for the measured reason in the module
    # docstring (openssl `error 44 … different CRL scope` against every pre-0.7 certificate). Asserted in test_crl.py so
    # the absence is a checked fact rather than an opinion.

    crl = builder.sign(private_key=bundle.key, algorithm=hashes.SHA256())
    log.info(
        "built CRL (entries=%d, crl_number=%d, this_update=%s, next_update=%s)",
        len(records),
        crl_number,
        now.isoformat(),
        (now + CRL_LIFETIME).isoformat(),
    )
    return crl


def rebuild_crl(
    *,
    bundle: CaBundle,
    store: object,
    path: Path,
) -> CrlFacts:
    """Read the store, sign a fresh CRL, write it atomically, and report what it says.

    The one call site for all three build triggers (startup, after a stamping batch, the GUI Rebuild button), which is
    the point: three triggers that each assembled their own builder are three chances to disagree about the entry rule
    or the number. `store` is duck-typed (`revoked_records()` + `count_revoked()`) rather than typed as `IssuedStore` so
    this module does not import the SQLite layer for a signature — same posture as `paths.data_dir`'s `object | None`.

    Returns the facts rather than the path, because every caller renders them: `/crl` shows them, the rebuild
    confirmation names them, and startup logs them. A trigger that ignored the return value would be a trigger whose
    result nobody can confirm on the page.
    """
    records = list(store.revoked_records())  # type: ignore[attr-defined]
    crl_number = int(store.count_revoked())  # type: ignore[attr-defined]
    crl = build_crl(bundle=bundle, records=records, crl_number=crl_number)
    facts = summarise_crl(crl)
    write_crl_pem(path, facts.pem)
    return facts


def summarise_crl(crl: x509.CertificateRevocationList) -> CrlFacts:
    """The facts of a built CRL, read back **from the object** rather than from what the builder was told."""
    pem = crl.public_bytes(serialization.Encoding.PEM).decode("ascii")

    # `nextUpdate` is optional in DER (RFC 5280 §5.1.2.4 lets a CRL omit it) but not for mypki: `build_crl` always
    # calls `.next_update(now + CRL_LIFETIME)`, and `CrlFacts.lifetime_hours` subtracts this value from `thisUpdate`.
    # Narrowed here with a refusal rather than an ignore, because the artifact that could reach this branch is one
    # read back from disk by `_published_crl` — a hand-edited or truncated PEM — and a CRL with no stated expiry has
    # no freshness to report on the page.
    next_update = crl.next_update_utc
    if next_update is None:
        raise MypkiError("This CRL carries no nextUpdate, so this host cannot state how long it stays current.")

    return CrlFacts(
        issuer=crl.issuer.rfc4514_string(),
        this_update_utc=crl.last_update_utc,
        next_update_utc=next_update,
        crl_number=_crl_number(crl),
        entry_count=len(list(crl)),
        pem=pem,
    )


def crl_pem(crl: x509.CertificateRevocationList) -> str:
    """The PEM armour of a CRL, as text. `-----BEGIN X509 CRL-----` … (page-map §14)."""
    return crl.public_bytes(serialization.Encoding.PEM).decode("ascii")


def read_crl_pem(path: Path) -> x509.CertificateRevocationList:
    """Load `<data>/crl/revoke.crl` back as an object.

    Raises `FileNotFoundError` for a host that has not built one (the handler turns that into the page's "no CRL yet"
    state rather than a 500) and re-raises cryptography's parse failure for a truncated file — which is the case the
    atomic write exists to prevent, so it should never be seen in practice.
    """
    return x509.load_pem_x509_crl(path.read_bytes())


def write_crl_pem(path: Path, pem: str) -> None:
    """Write the PEM atomically: temp file in the same directory, `os.replace`, then the mode.

    Same directory on purpose — `os.replace` is atomic only within one filesystem, and a temp file on another would
    silently degrade to a copy that can be interrupted.

    Mode: ordinary permissions (0644 umask-respecting), following `ca_cert_path`'s precedent rather than
    `PRIVATE_FILE_MODE = 0o600`. Served to anyone by `GET /revoke.crl`, so owner-only mode would protect a secret this
    file is not. It still lives under `<data>/`, never inside a web-served directory (page-map §8, and the
    rule in `paths.py`'s docstring).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    # `mkstemp` rather than `NamedTemporaryFile(mode="wb")` because the mode has to be settable **before** the file
    # becomes visible under its real name: `tempfile` creates 0600, and a CRL written at 0600 then renamed is a public
    # artifact that only this user can read — which is invisible on the single-user box where it was written and breaks
    # the moment a second user (a fetch proxy running as its own account, a non-root collector) tries to read it.
    descriptor, temp_name = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(pem.encode("ascii"))
            handle.flush()
            os.fsync(handle.fileno())
        _make_publicly_readable(temp_name)
        os.replace(temp_name, path)
    except BaseException:
        # The temp file is the only thing that can be left behind; `path` itself is untouched until `os.replace` runs.
        with contextlib.suppress(OSError):
            os.unlink(temp_name)
        raise
    log.info("wrote CRL to %s (%d bytes)", path, len(pem))


def _make_publicly_readable(path: str) -> None:
    """0644 on POSIX. Stated as a no-op-with-a-caveat on Windows rather than pretended to work.

    Deliberately **not** `PRIVATE_FILE_MODE = 0o600` (`ca.py`): that constant protects `<data>/ca/ca_key.pem`, and this
    file is served to anyone by `GET /revoke.crl`. Owner-only mode here would protect nothing and break a reader that is
    not the mypki user.

    Windows: `os.chmod` can only toggle the read-only bit, so NTFS ACLs decide who actually reads — the same honest gap
    `ca.py` documents for the CA key (its `icacls` hardening exists because chmod does nothing there). No ACL work is
    done for this file on purpose: an artifact published over HTTP is not the thing to spend an `icacls` call on, and a
    failure mode where one is attempted (no `icacls`, partial grant) would add startup noise for no protection.
    """
    with contextlib.suppress(OSError):
        os.chmod(path, 0o644)


def _crl_number(crl: x509.CertificateRevocationList) -> int:
    """The CRL Number extension's value, or a refusal when it is missing.

    A CRL with no CRLNumber is not a defect in the library — it is a defect in *this* module, because the number is how
    a client detects that it has an outdated copy (RFC 5280 §5.2.1). Reading it back rather than trusting what was
    passed in is what makes `test_crl.py`'s monotonicity assertion about the artifact and not about a variable.
    """
    try:
        extension = crl.extensions.get_extension_for_class(x509.CRLNumber)
    except x509.ExtensionNotFound:  # pragma: no cover - build_crl always adds it; test_crl.py asserts its presence
        raise MypkiError(
            "This CRL carries no CRL Number extension, so a client cannot tell an old copy from a new one."
        ) from None
    return int(extension.value.crl_number)


def _aware_utc(value: dt.datetime) -> dt.datetime:
    """Naive in, UTC-aware out — the same conversion `store._iso` performs, for the same reason.

    A naive datetime reaching a CRL would be interpreted by cryptography as local time, and then two clients in
    different zones would disagree about whether this CRL is current. Converting (rather than rejecting) matches what
    this project already does with its database dates, and every value produced inside the app is already aware.
    """
    if value.tzinfo is None:
        return value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc)
