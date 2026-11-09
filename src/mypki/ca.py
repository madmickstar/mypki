"""Creating, loading and describing the one root CA this app is built around.

Why this module exists: everything mypki does is downstream of two files on disk, and the interesting decisions are
about *their* lifecycle rather than about X.509 itself — refusing to overwrite, archiving instead of deleting,
getting POSIX modes right and saying plainly that Windows has no equivalent, decrypting once at startup rather than
per request. Those rules are what make a single-operator CA survivable, and they belong in one module so the CLI and
the web app cannot disagree about them.

Why the key is loaded **once**, by `mypki serve`, and handed to the app as state: every signing request would
otherwise re-read and re-decrypt a PKCS#8 key — slow, and worse, it means the passphrase has to be reachable for the
whole lifetime of the process rather than during startup only. It also keeps the key out of the request path entirely:
no route takes a key path as a parameter, so there is no request-level way to ask for it (page-map §6).

Why `init_ca` refuses to overwrite instead of truncating: replacing a root CA silently invalidates every certificate
that clients have already installed. The refusal names the file and the flag that would override it, and `--force`
moves the old pair into `ca/archive/<UTC-timestamp>/` rather than deleting it — an archived mistake is recoverable,
a truncated one is not (page-map §6).

Rejected alternative: letting the GUI create the CA. It would mean a browser-reachable code path that writes a private
key, on an app whose entire security model is "no logins, so exposure is controlled by binding" — the one operation
that must stay behind a terminal command (page-map §6).
"""

from __future__ import annotations

import contextlib
import datetime as dt
import logging
import os
import platform
import shutil
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from . import paths
from .errors import CaAlreadyExistsError, CaNotFoundError, CaPassphraseError
from .keys import (
    KeySpec,
    describe_public_key,
    generate_key,
    key_spec_for_public_key,
    load_private_key_pem,
    private_key_pem,
)

log = logging.getLogger("mypki.ca")

#: POSIX mode for `<data>/ca/`: owner-only directory, so a world-readable home directory still does not expose the key.
CA_DIR_MODE = 0o700

#: POSIX mode for `ca_key.pem` and `instance/secret_key`. Verified by re-stat after writing (see
# `_assert_private_mode`).
PRIVATE_FILE_MODE = 0o600

__all__ = [
    "CaBundle",
    "InitCaResult",
    "describe_ca",
    "fingerprint_hex",
    "format_fingerprint",
    "init_ca",
    "load_ca",
    "secret_session_key",
]


@dataclass(frozen=True)
class CaBundle:
    """The CA as the running process sees it: certificate always, private key only if it could be loaded.

    `key is None` is a real state worth modelling rather than an error to crash on — a host can hold the public
    certificate (so `/` and `/ca/certificate` can answer) while the private key is absent or undecryptable. The home
    page reports that as the boolean "CA private key present on this host" (page-map §1), and signing refuses it
    explicitly instead of pretending to work.
    """

    cert: x509.Certificate
    key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | None
    cert_path: Path
    key_path: Path

    @property
    def key_present(self) -> bool:
        return self.key is not None


@dataclass(frozen=True)
class InitCaResult:
    """Public facts about a freshly created CA — the only thing `init-ca` is allowed to print (page-map §6)."""

    cert_path: Path
    key_path: Path
    subject: str
    serial_hex: str
    not_before_utc: dt.datetime
    not_after_utc: dt.datetime
    fingerprint_hex: str
    key_spec: str
    encrypted_key: bool
    archived_to: Path | None


def _is_posix() -> bool:
    """Whether POSIX permission semantics apply. Windows gets its own story (page-map §8), stated in REFERENCE
    "Key protection and the data directory"."""
    return os.name == "posix"


def _utc_stamp() -> str:
    """Filesystem-safe UTC timestamp for archive directory names.

    `%Y-%m-%dT%H:%M:%SZ` is the honest ISO form and an illegal Windows directory name: colons are reserved. The
    compact form sorts correctly, which is what makes `ca/archive/` readable as a history.
    """
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _assert_private_mode(path: Path) -> None:
    """Re-stat a freshly written private file and refuse it if group or other can read it.

    Deliberately not `chmod`-and-hope: umask, an existing file's mode, a filesystem that ignores chmod (FAT/exFAT),
    or an ACL inherited from a parent directory can all leave a 0600 request satisfied in form only. The assertion is
    the part that fails loudly at creation time rather than during the incident review afterwards. Skipped on Windows,
    where `os.chmod` toggles the read-only bit and this check would either pass meaninglessly or fail unhelpfully — the
    protection there is per-user `%LOCALAPPDATA%` plus optional `icacls` plus passphrase encryption (page-map §8).
    """
    if not _is_posix():
        return
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise RuntimeError(
            f"{path} is group/other-accessible (mode {mode:o}); expected {PRIVATE_FILE_MODE:o}. "
            f"Fix the directory's ownership or umask and run init-ca again."
        )


def _write_private_file(path: Path, data: bytes) -> None:
    """Write a private file with owner-only permissions from the moment it exists.

    `os.open` with the mode at creation matters: `path.write_bytes()` followed by `chmod` leaves a window where the
    file exists with the process umask's default mode (commonly 0644), which is enough for a local attacker with a
    polling loop, and long enough to show up in an audit log.
    """
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, PRIVATE_FILE_MODE)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    # Belt and braces: O_CREAT's mode is masked by umask, never *raised* by it, so set it explicitly too.
    os.chmod(str(path), PRIVATE_FILE_MODE)
    _assert_private_mode(path)


def _harden_with_icacls(key_path: Path) -> bool:
    """Optional Windows ACL hardening behind `--secure-acl` (page-map §8).

    Fixed argv array, no user-supplied component anywhere — the path comes from mypki's own resolver and every other
    element is a literal. That is the only `subprocess` call permitted in this project, it sits in the CLI path rather
    than the web layer, and it is skipped silently when `icacls` is absent rather than failing an otherwise healthy
    init. Returns whether hardening was applied so the CLI can say which happened.

    Inheritance removal (`/inheritance:r`) plus an explicit grant is what actually narrows a key file: adding
    `(M)` to the current user on top of inherited permissions only *adds*, and inherited access from
    `%LOCALAPPDATA%`'s parent chain is the thing worth removing.

    **On a real Windows host, and this is why the re-open below exists:** a `--secure-acl` run reported
    success (`icacls hardening applied to ...ca_key.pem`) and then the *same process* could not read that key --
    `PermissionError: [Errno 13] Permission denied`. Narrowing a DACL is exactly the operation that can lock out the
    account that asked for it, and mypki must find that out at init time rather than an operator finding it at
    `mypki serve`, where the only symptom is "the private key is not loadable". The mechanism on his machine was not
    determinable from Linux (which principal `USERNAME` resolved to, and how `(OI)(CI)` interacted with a leaf file),
    so what ships here is the detection, not a guess at the cause.
    """
    if platform.system() != "Windows":
        return False
    icacls = shutil.which("icacls")
    if icacls is None:
        log.info("icacls not found; skipping --secure-acl (per-user %%LOCALAPPDATA%% still applies)")
        return False
    user = os.environ.get("USERNAME") or os.environ.get("USER_NAME") or ""
    if not user:
        log.info("no username in the environment; skipping --secure-acl")
        return False
    grant = f"{user}:(OI)(CI)(F)"
    try:
        subprocess.run(
            [icacls, str(key_path), "/inheritance:r", "/grant:r", grant],
            check=True,
            capture_output=True,
            text=True,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        log.info("icacls hardening did not run (%s); continuing without it", exc)
        return False

    # A narrowing that locks out this process is a failed hardening, not a successful one. Re-opening the key for read
    # is the only check that answers the question mypki actually cares about: can the CA still use its own key? If it
    # cannot, saying "icacls hardening applied" would be a lie, and leaving the pair in place without saying anything
    # would hand the operator a CA they discover is unusable only when they try to serve it.
    try:
        with key_path.open("rb") as handle:
            handle.read(1)
    except OSError as exc:
        log.warning(
            "icacls ran but left %s unreadable by this process (%s); the CA was created but --secure-acl did not "
            "succeed. Repair the ACL (e.g. `icacls '%s' /reset`) or re-run without --secure-acl.",
            key_path,
            exc,
            key_path,
        )
        return False
    return True


def _subject_builder(
    common_name: str,
    organization: str | None,
    organizational_unit: str | None,
    country: str | None,
) -> x509.Name:
    """Build the CA subject from the CLI's four identity flags (page-map §6).

    Attributes are added only when supplied: an empty `O=` or `C=` in a root certificate is noise that every client
    then displays, and some strict validators treat a zero-length attribute as malformed.
    """
    attributes = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    if organization:
        attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
    if organizational_unit:
        attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit))
    if country:
        attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country.upper()))
    return x509.Name(attributes)


def init_ca(
    data_root: Path,
    *,
    common_name: str,
    organization: str | None = None,
    organizational_unit: str | None = None,
    country: str | None = None,
    spec: KeySpec,
    days: int,
    passphrase: bytes | None = None,
    force: bool = False,
    secure_acl: bool = False,
) -> InitCaResult:
    """Create the root CA pair on disk. The only code path that ever writes a private key (page-map §6).

    Raises `CaAlreadyExistsError` (CLI maps it to exit 2) when either file exists and `force` is False — no silent
    truncation, ever, because replacing a root silently invalidates every certificate clients already trust.
    """
    cert_path = paths.ca_cert_path(data_root)
    key_path = paths.ca_key_path(data_root)
    ca_directory = paths.ca_dir(data_root)

    existing = [p for p in (cert_path, key_path) if p.exists()]
    if existing and not force:
        raise CaAlreadyExistsError(existing[0])

    archived_to: Path | None = None
    if existing:
        # `--force` archives rather than deletes. The archive name is collision-proof by appending a counter, so two
        # forced re-inits in the same second cannot merge two CA histories into one directory.
        stamp = _utc_stamp()
        archive = paths.ca_archive_dir(data_root, stamp)
        suffix = 1
        while archive.exists():
            archive = paths.ca_archive_dir(data_root, f"{stamp}-{suffix}")
            suffix += 1
        archive.mkdir(parents=True, exist_ok=False)
        for path in existing:
            shutil.move(str(path), str(archive / path.name))
        archived_to = archive
        log.info("archived existing CA pair to %s", archive)

    # Directory first, with the owner-only mode requested. mkdir(mode=...) is umask-masked, so chmod after creation is
    # what makes 0700 a promise rather than an intention.
    ca_directory.mkdir(parents=True, exist_ok=True)
    if _is_posix():
        os.chmod(str(ca_directory), CA_DIR_MODE)

    key = generate_key(spec)
    _write_private_file(key_path, private_key_pem(key, passphrase))

    subject = _subject_builder(common_name, organization, organizational_unit, country)
    not_before = dt.datetime.now(dt.timezone.utc)
    not_after = not_before + dt.timedelta(days=days)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)  # self-signed root: issuer is exactly the subject (page-map §7)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        # pathLength:0, not None: caps the chain at one level, so a leaf that somehow gets marked CA cannot mint
        # another CA beneath it (page-map §7; RFC 5280 §4.2.1.9).
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        # No AKI on a self-signed root: an authority key id pointing at itself carries no information and some
        # validators treat a self-referencing AKI as a chain-building hint (RFC 5280 §4.2.1.1).
    )
    cert = builder.sign(private_key=key, algorithm=hashes.SHA256())

    # Public certificate: ordinary file permissions are fine here; this is the artifact meant to be copied everywhere.
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    if secure_acl and _harden_with_icacls(key_path):
        log.info("icacls hardening applied to %s", key_path)

    fingerprint = cert.fingerprint(hashes.SHA256())
    result = InitCaResult(
        cert_path=cert_path,
        key_path=key_path,
        subject=cert.subject.rfc4514_string(),
        serial_hex=f"{cert.serial_number:x}",
        not_before_utc=cert.not_valid_before_utc,
        not_after_utc=cert.not_valid_after_utc,
        fingerprint_hex=fingerprint.hex(),
        key_spec=describe_public_key(key.public_key()),
        encrypted_key=passphrase is not None,
        archived_to=archived_to,
    )
    log.info(
        "created CA %s serial=%s validity=%s..%s key=%s",
        result.subject,
        result.serial_hex,
        result.not_before_utc.date().isoformat(),
        result.not_after_utc.date().isoformat(),
        result.key_spec,
    )
    return result


def load_ca(
    data_root: Path,
    *,
    passphrase: bytes | None = None,
    passphrase_env: str = "MYPKI_CA_PASSPHRASE",
) -> CaBundle:
    """Load the CA certificate and (best-effort) its private key. Called once at startup, never per request.

    Raises `CaNotFoundError` (exit 3 / the page-map §1 notice) when the certificate is absent, and
    `CaPassphraseError` when the key is encrypted and this process cannot decrypt it — naming the env var rather than
    the secret, because a wrong-passphrase failure is the log line most likely to be read by someone other than the
    operator (page-map §8).
    """
    cert_path = paths.ca_cert_path(data_root)
    key_path = paths.ca_key_path(data_root)
    if not cert_path.exists():
        raise CaNotFoundError(cert_path)

    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())

    key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | None = None
    if key_path.exists():
        raw = key_path.read_bytes()
        encrypted = b"ENCRYPTED PRIVATE KEY" in raw
        if encrypted and passphrase is None:
            raise CaPassphraseError(passphrase_env)
        try:
            key = load_private_key_pem(raw, passphrase)
        except (TypeError, ValueError) as exc:
            # `load_pem_private_key` raises TypeError for a passphrase mismatch ("Password must be bytes...") and
            # ValueError for a wrong-but-well-formed one; both mean the same operator-facing thing (a refusal).
            log.error("CA private key at %s could not be decrypted (%s)", key_path, type(exc).__name__)
            raise CaPassphraseError(passphrase_env) from exc
        if not key_matches_certificate(key, cert):
            log.warning(
                "CA key at %s does not match the public key in %s; signing will fail chain checks",
                key_path,
                cert_path,
            )
    else:
        log.warning("CA certificate present but private key missing at %s", key_path)

    log.info(
        "loaded CA %s serial=%s key=%s (key_present=%s)",
        cert.subject.rfc4514_string(),
        f"{cert.serial_number:x}",
        describe_public_key(cert.public_key()),
        key is not None,
    )
    return CaBundle(cert=cert, key=key, cert_path=cert_path, key_path=key_path)


def key_matches_certificate(
    key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | None,
    cert: x509.Certificate,
) -> bool:
    """True when a loaded private key corresponds to the CA certificate's public key.

    Compared as SubjectPublicKeyInfo DER rather than by any identity shortcut: two `RSAPublicKey` objects holding the
    same modulus are not `==` in cryptography, so the only honest comparison is over their serialised form. The failure
    this catches is an archive/restore mix-up -- a `ca_key.pem` from one init sitting next to a `ca_cert.pem` from
    another,
    which would otherwise produce signatures that fail chain verification on every client (see docs/REFERENCE.md
    gotcha 1).

    `None` is part of the parameter type because `CaBundle.key` is Optional by design (page-map §1): "this host has no
    key" is an answer this function can give directly, rather than an AttributeError it would have to swallow. The
    spelling is the same union `CaBundle.key` and `keys.load_private_key_pem` use, which is what lets `load_ca` pass
    what it holds without a cast.
    """
    if key is None:
        return False

    try:
        private_der = key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        cert_der = cert.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    except Exception:  # pragma: no cover - defensive; cryptography-specific serialisation surprises
        return False
    return private_der == cert_der


def describe_ca(cert: x509.Certificate) -> dict[str, object]:
    """Public facts about a CA certificate, for the home card and `mypki info` (page-map §1, §6).

    Reads only what is public by construction — subject, validity, serial, fingerprint, key spec, BasicConstraints.
    There is no parameter here that could ask for something private, which is why this function is safe to call from
    a request handler.
    """
    subject = cert.subject
    basic: x509.BasicConstraints | None = None
    with contextlib.suppress(x509.ExtensionNotFound):
        basic = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    return {
        "subject": subject.rfc4514_string(),
        "common_name": _one(subject, NameOID.COMMON_NAME),
        "organization": _one(subject, NameOID.ORGANIZATION_NAME),
        "organizational_unit": _one(subject, NameOID.ORGANIZATIONAL_UNIT_NAME),
        "country": _one(subject, NameOID.COUNTRY_NAME),
        "not_before_utc": cert.not_valid_before_utc,
        "not_after_utc": cert.not_valid_after_utc,
        "serial_hex": f"{cert.serial_number:x}",
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "key_type": describe_public_key(cert.public_key()),
        "key_spec": key_spec_for_public_key(cert.public_key()),
        "basic_constraints": None
        if basic is None
        else f"CA:{'TRUE' if basic.ca else 'FALSE'} pathLength:{basic.path_length}",
    }


def _one(name: x509.Name, oid: x509.ObjectIdentifier) -> str | None:
    """First value of one subject attribute, as text, or None when the CA was created without it.

    The decode arm exists because cryptography types `NameAttribute.value` as `str | bytes`, not `str`: the ASN.1 string
    type varies by OID (UTF8String for `CN=`, PrintableString for `C=`, and OCTET/BIT STRING for a couple of the rarer
    OIDs), so mypy is right that this cannot promise text. Every attribute *mypki* writes is a `str`
    (`_subject_builder`), but `describe_ca` also runs on a CA loaded from somewhere else, and a template rendering a
    `bytes` prints `b'...'` to an operator.
    """
    attributes = name.get_attributes_for_oid(oid)
    if not attributes:
        return None
    value = attributes[0].value
    if isinstance(value, bytes):  # pragma: no cover - defensive; only a foreign cert can encode an attribute as bytes
        return value.decode("utf-8", "replace")
    return value


def fingerprint_hex(cert: x509.Certificate) -> str:
    """SHA-256 fingerprint as a plain hex string.

    `cert.fingerprint(hashes.SHA256()) -> bytes` is the API on cryptography 50.0.2; the newer-looking
    `cert.fingerprints.sha256` raises `AttributeError` on the pinned build, so this one call site is where that trap is
    kept out of every page and CLI output.
    """
    return cert.fingerprint(hashes.SHA256()).hex()


def format_fingerprint(hex_string: str) -> str:
    """Colon-grouped fingerprint for display, so a human can compare it against a client's UI two characters at
    a time."""
    upper = hex_string.upper()
    return ":".join(upper[i : i + 2] for i in range(0, len(upper), 2))


def secret_session_key(data_root: Path, configured: str | None = None) -> str:
    """Session signing key: use the configured one, else load or create `<data>/instance/secret_key` (0600).

    Persisting it is what makes sessions survive a restart; `secrets.token_urlsafe(32)` for 256 bits of entropy. An
    existing file is used as-is rather than regenerated, because silently rotating the session key would invalidate
    every in-flight two-step signing (page-map §3) on an unrelated restart.
    """
    import secrets

    if configured:
        return configured
    target = paths.secret_key_path(data_root)
    if target.exists():
        value = target.read_text(encoding="utf-8").strip()
        if value:
            return value
    target.parent.mkdir(parents=True, exist_ok=True)
    value = secrets.token_urlsafe(32)
    _write_private_file(target, value.encode("utf-8"))
    log.info("generated session secret at %s", target)
    return value
