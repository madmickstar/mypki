"""Issuing leaf certificates: fixed extension profiles, random serials, UTC validity.

Why this module exists and why its extensions are **constants**: a leaf's meaning is entirely in its extensions, and the
only trustworthy source for them is the CA's own policy. Copying anything from the CSR — even something as benign-
looking as KeyUsage or ExtendedKeyUsage — means whoever wrote the CSR decides what this CA certified, which is how an
end-entity request asks for `CA:TRUE` and walks out holding a signing certificate. So `server`, `client` and `both` are
three hard-coded profiles here and **SAN is the single value copied from the request** (page-map §7). The CSR chooses
*which names*; this module decides *what the certificate is*.

Why the profile comes from a server-side `cert_type` radio rather than an inference about the CSR: inferring ("it has a
DNS SAN, so it must be a TLS server") makes the issued certificate depend on input mypki does not control, and leaves no
way to issue a client certificate for the same name. The operator chooses; the profile follows.

Why EC leaves drop `keyEncipherment`: that bit authorises the key to *wrap other keys*, which only RSA key-transport key
encipherment actually does. An EC public key cannot, so setting it on an EC leaf certifies a capability the key does not
have, and profile-strict validators treat that as an error (RFC 5280 §4.2.1.3). The test suite pins both halves — True
for RSA server, False for EC — because "we handled EC" is not a fact you can assert without asserting it.

Why validity is computed from tz-aware UTC and written through `not_valid_before`/`not_valid_after` with aware
datetimes: the naive accessors read and write *local* time, so a CA started in a mis-set container timezone would issue
certificates whose expiry means something different on every client. On the pinned builder:
`not_valid_before_utc`/`not_valid_after_utc` return `+00:00`-aware datetimes and the builder accepts aware inputs, so
UTC is what this module both computes and stores.

Operator-edited subject and SANs ---------------------------------------- `issue_certificate` now takes
`subject=` and `sans=`, which the sign page's confirm step passes when the operator edits the fields shown after
validation. That is a deliberate loosening of "the certificate says what the request said", so the boundary has to be
exact:

  * **Still from the CSR: the public key.** `details.public_key` is used unconditionally, and it is the only part of the
    output a CSR proves possession of. Editing who a certificate is *named for* while signing the key the request
    presented is an ordinary CA act; substituting a different key would not be a certificate for that request at all.
  * **Still never from the CSR: every extension.** `leaf_extensions` is unchanged and remains the only place a leaf's
    extensions are decided. An edited form cannot smuggle a KeyUsage because the form has no such field.
  * **What must be re-validated first:** an edited SAN list is operator input again, so it goes through
    `validators.parse_sans` / `validate_common_name` upstream (page-map §9), exactly like the generate
    form's. This module does not validate subject strings — it takes validated values and refuses a profile
    mismatch (a `server` leaf with no SANs).
  * **What the UI owes the operator in return:** when what was issued differs from what was requested, the
    page names the fields (page-map §3). An edit that silently drops `O=` is a mis-issuance nobody noticed,
    and walking it back needs a client that consults this CA's CRL or OCSP — which leaves certificates that
    give no pointer to, so the page's disclosure remains the primary defence.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import logging
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, NameOID

from .ca import CaBundle
from .csr import CsrDetails
from .errors import CsrValidationError, MypkiError
from .keys import KeySpec, key_spec_for_public_key
from .validators import SanSet

log = logging.getLogger("mypki.signing")

#: The three profiles this CA knows (page-map §7). Anything outside this set is refused rather than defaulted:
#: defaulting to `server` would issue a TLS-server certificate for a request that asked for something else.
CERT_TYPES: tuple[str, ...] = ("server", "client", "both")

#: Plain-language descriptions of the three profiles, rendered by the sign page (page-map §3, §7).
#:
#: They live next to the profiles they describe rather than in a template because `CERT_TYPES` and this mapping are one
#: fact: a profile added to `CERT_TYPES` without an entry here renders a radio button with no explanation, which is how
#: a
#: CA page ends up offering an option nobody can choose knowingly. The wording is deliberately non-technical -- what you
#: would use it for, and what it will not do -- because the two mistakes this prevents (a client certificate pasted onto
#: a web server, a server certificate accepted as a login credential) both come from not knowing which side the
#: certificate authenticates.
CERT_PROFILE_HELP: dict[str, str] = {
    "server": (
        "For a service people connect to: a website, an HTTPS API, a reverse proxy, an internal dashboard. The names "
        "under SAN are what a browser or client matches the URL against, so those names have to be exactly the ones "
        "your users type. This is the web-server profile. It does NOT authenticate a person or device logging in."
    ),
    "client": (
        "For proving who is connecting, rather than what they are connecting to: a VPN client (OpenVPN, WireGuard with "
        "TLS auth), a smartcard or badge, mutual-TLS where your laptop presents a certificate, code-signing-style "
        "identities. Your service checks this certificate to decide who the caller is. It will NOT make a browser "
        "trust a web site -- for that you want `server`."
    ),
    "both": (
        "One certificate usable in either direction: a host or device that serves TLS *and* authenticates as a client, "
        "like a lab box doing mutual-TLS to another service while also hosting an endpoint. Convenient when one "
        "machine plays both roles; stricter environments prefer the two kept separate, because a leaked `both` "
        "certificate is trusted for both jobs."
    ),
}

__all__ = ["CERT_PROFILE_HELP", "CERT_TYPES", "IssuedCert", "issue_certificate", "leaf_extensions", "signing_hash"]


@dataclass(frozen=True)
class IssuedCert:
    """A signed leaf plus everything the UI and the record store need from it.

    `chain_pem` is **leaf then CA** in that order (page-map §3 step B): a client importing the file expects the
    certificate it authenticates first, and reversing the two yields a chain most TLS stacks reject with an error about
    the trust anchor rather than about the ordering.
    """

    cert: x509.Certificate
    pem: str
    chain_pem: str
    serial_hex: str
    not_before_utc: dt.datetime
    not_after_utc: dt.datetime
    fingerprint_sha256: str
    cert_type: str
    common_name: str
    sans: SanSet

    @property
    def summary(self) -> str:
        """Log-safe one-liner: identity and expiry only, never a PEM body (page-map §0)."""
        return (
            f"serial={self.serial_hex} type={self.cert_type} cn={self.common_name} sans={self.sans.describe()} "
            f"not_after={self.not_after_utc.date().isoformat()}"
        )


def signing_hash(leaf_public_key: object) -> hashes.SHA256 | hashes.SHA384:
    """Hash used to sign this leaf: SHA-384 for a P-384 key, SHA-256 otherwise (page-map §7).

    The two concrete classes rather than `hashes.HashAlgorithm`: `CertificateBuilder.sign` declares its algorithm as
    cryptography's `_AllowedHashTypes`, a union of eight concrete hashes that does **not** include the abstract base, so
    annotating this as `HashAlgorithm` makes the one call site in `issue_certificate` an arg-type error even though both
    values returned here are exactly what the builder accepts.
    """
    if isinstance(leaf_public_key, ec.EllipticCurvePublicKey) and leaf_public_key.curve.key_size >= 384:
        return hashes.SHA384()
    return hashes.SHA256()


def _key_usage(cert_type: str, spec: KeySpec) -> x509.KeyUsage:
    """KeyUsage per profile, with `keyEncipherment` present only for RSA (see module docstring).

    `client` gets digitalSignature alone: a client certificate authenticates its holder, it does not encipher traffic,
    and asking for keyEncipherment on one is how a smartcard certificate starts looking like a TLS-server certificate to
    every policy checker in the chain.
    """
    if cert_type == "client":
        return x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,  # never on a leaf (page-map §7)
            crl_sign=False,  # never on a leaf
            encipher_only=False,
            decipher_only=False,
            key_encipherment=False,
        )
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
        key_encipherment=spec.algorithm == "rsa",
    )


def _extended_key_usage(cert_type: str) -> list[x509.ObjectIdentifier]:
    """EKU per profile.

    Marked non-critical on purpose: RFC 5280 §4.2.2.9 defines EKU as non-critical for end-entity certificates, and a
    critical EKU makes a client that cannot parse the extension reject a certificate it could otherwise honour.
    """
    if cert_type == "server":
        return [ExtendedKeyUsageOID.SERVER_AUTH]
    if cert_type == "client":
        return [ExtendedKeyUsageOID.CLIENT_AUTH]
    return [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]


def leaf_extensions(
    cert_type: str,
    spec: KeySpec,
    sans: SanSet,
    leaf_public_key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey,
    ca_public_key: CertificatePublicKeyTypes,
    crl_base_url: str,
) -> list[tuple[x509.ExtensionType, bool]]:
    """The exact extension set for one profile, as `(extension, critical)` pairs.

    Exposed separately from `issue_certificate` so `test_signing.py` can assert a profile as data — no CA, no keypair,
    no signature. An extension table is exactly the kind of claim that should be checkable without a cryptographic
    side effect (page-map §7).

    `CA:FALSE` with `path_length=None`: an explicit 0 would mean "no certificates may follow this one", which happens to
    be true of a leaf but is not the conventional spelling clients expect to read (RFC 5280 §4.2.1.9). AKI comes from
    the **issuer's** key, which is what lets a client pick the right anchor when several roots are installed (§4.2.1.1).

    What changed for these two pointers -----------------------------------------------------------
    `CRLDistributionPoints` and `AuthorityInfoAccess` **do** appear here now, both non-critical, both spelled from the
    one configured base (`crl_base_url`, validated in `config.py` to start with `http://` or `https://`). The sentence
    this docstring used to carry — "no CRLDistributionPoints, no AuthorityInfoAccess appear here at all" — was true
    until those pointers existed, so it is rewritten in the same commit as the behaviour rather than left as a
    comfortable lie.

    What has **not** changed: this function remains the only place a leaf's extensions are decided, so "never copied
    from the CSR" is still enforced by construction rather than by a filter someone must remember downstream. A request
    carrying its own `CRLDistributionPoints` is still classified ignorable by `csr.py` and still dropped — the CA adds
    its own pointer — and the confirm form has no field that could smuggle either extension in.

    Both are non-critical for the same reason EKU is: a critical extension makes a client that cannot parse it reject a
    certificate it could otherwise honour. Both land only on certificates issued after this change — no migration, no
    re-issue — so older leaves keep carrying nothing, which `/crl` says plainly.
    """
    extensions: list[tuple[x509.ExtensionType, bool]] = [
        (x509.BasicConstraints(ca=False, path_length=None), True),
        (_key_usage(cert_type, spec), True),
        (x509.ExtendedKeyUsage(_extended_key_usage(cert_type)), False),
    ]
    if not sans.empty:
        names: list[x509.GeneralName] = [x509.DNSName(name) for name in sans.dns]
        names += [x509.IPAddress(ipaddress.ip_address(value)) for value in sans.ips]
        extensions.append((x509.SubjectAlternativeName(names), False))
    extensions.append((x509.SubjectKeyIdentifier.from_public_key(leaf_public_key), False))
    # The one ignore in this module, and it names a real gap in cryptography's own stubs rather than a looseness here:
    # `AuthorityKeyIdentifier.from_issuer_public_key` wants `CertificateIssuerPublicKeyTypes`, while the value callers
    # hand us comes from `Certificate.public_key()`, which is typed as the wider `CertificatePublicKeyTypes` (it also
    # admits X25519/X448/MLKEM keys, which cannot sign anything). mypki's CA policy refuses a non-RSA/EC root before
    # this is reachable -- `load_ca` runs every loaded certificate through `keys.key_spec_for_public_key`, and the CLI
    # only ever generates RSA-2048/3072/4096 or P-256/P-384 -- so the extra union members cannot arrive here.
    authority_key_id = x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_public_key)  # type: ignore[arg-type]
    extensions.append((authority_key_id, False))
    # The two pointers. Spelled here rather than handed in pre-assembled: `/crl.pem` and `/ocsp` are routes
    # `app.py` registers, so a caller free to pass an arbitrary URL is a caller that can bake a pointer to a path this
    # app does not serve. One base, two suffixes, one spelling each (plan §3).
    extensions.append(
        (
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier(f"{crl_base_url}/crl.pem")],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]
            ),
            False,
        )
    )
    extensions.append(
        (
            x509.AuthorityInformationAccess(
                [
                    x509.AccessDescription(
                        AuthorityInformationAccessOID.OCSP,
                        x509.UniformResourceIdentifier(f"{crl_base_url}/ocsp"),
                    )
                ]
            ),
            False,
        )
    )
    return extensions


def issue_certificate(
    bundle: CaBundle,
    details: CsrDetails,
    *,
    cert_type: str,
    validity_days: int,
    max_sans: int,
    key_spec: KeySpec | None = None,
    subject: x509.Name | None = None,
    sans: SanSet | None = None,
    crl_base_url: str,
) -> IssuedCert:
    """Sign a validated CSR's key into a leaf certificate using mypki's own profile.

    Assumes `parse_and_validate_csr` already ran (page-map §3 step A): the signature, hash and CA-privilege questions
    are settled there. What this function checks itself are the *profile's* requirements — a CA key able to sign, and a
    non-empty SAN set for `server`/`both` — because those describe what mypki will issue, not what was requested.

    `key_spec` is derived from the CSR's public key unless supplied; taking it as a parameter is how `test_signing.py`
    pins the EC-vs-RSA KeyUsage rule without generating three keypairs per assertion.

    `subject` and `sans` replace what the CSR states, for the confirm step where the operator edited those
    fields; both default to None, which means "issue exactly what the request says" and is still the path every unedited
    signing takes. They arrive validated (`csr.subject_from_fields` / `validators.parse_sans` ran upstream — see the
    module docstring for where that boundary sits), and neither can reach an extension: `leaf_extensions` never reads a
    subject.
    """
    if cert_type not in CERT_TYPES:
        raise CsrValidationError(f"cert_type must be one of {', '.join(CERT_TYPES)} (got {cert_type!r})", "cert_type")

    if bundle.key is None:
        # Missing capability, not invalid input: this host holds the certificate but not the key that signs with it.
        raise MypkiError(
            "This CA has no private key loaded, so it cannot sign. Run `mypki init-ca`, or supply the passphrase if "
            "the existing key is encrypted."
        )

    leaf_public_key = details.public_key
    if not isinstance(leaf_public_key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
        # Unreachable for CSRs this app parsed (`key_spec_for_public_key` already rejected other key types), but the
        # guard is what makes `CsrDetails.public_key` typed as an object safe to hand to the builder.
        raise CsrValidationError(
            f"The confirmed CSR carries a {type(leaf_public_key).__name__}, which mypki cannot certify.",
            "csr_pem",
        )

    spec = key_spec if key_spec is not None else key_spec_for_public_key(leaf_public_key)
    # The two editable values resolve once, here, so the rest of the function has one answer to "which names are being
    # certified" instead of `details.sans` in some places and an override in others. That kind of split is how a limit
    # check ends up counting one set while the certificate carries another.
    issued_sans = details.sans if sans is None else sans
    sans_count = len(issued_sans.dns) + len(issued_sans.ips)

    if cert_type in ("server", "both") and issued_sans.empty:
        # A TLS server certificate with no SAN is rejected by every current browser (name matching ignores CN), so
        # issuing one would produce a certificate that cannot be used for anything. Refusing names the profile rule.
        raise CsrValidationError(
            f"A {cert_type} certificate requires at least one SAN; this CSR has none. Add SANs to the request, or "
            "issue it as `client`.",
            "sans",
        )
    if sans_count > max_sans:
        raise CsrValidationError(
            f"The confirmed CSR carries {sans_count} SANs; the limit is {max_sans} (`MYPKI_MAX_SANS`).",
            "sans",
        )

    not_before = dt.datetime.now(dt.timezone.utc)
    not_after = not_before + dt.timedelta(days=validity_days)

    builder = (
        x509.CertificateBuilder()
        # Subject exactly as the CSR states it: the certificate is for that entity, and rewriting a subject attribute
        # here would make mypki's output disagree with the request it says it signed.
        # Subject exactly as the CSR states it *unless the operator edited it* (page-map §3 step B): an edit is allowed
        # only when it was made visibly, on the confirmation page that displayed the request's own values.
        .subject_name(details.subject_name if subject is None else subject)
        .issuer_name(bundle.cert.subject)  # exactly the CA subject (page-map §7)
        .public_key(leaf_public_key)
        # Random serial, not a counter: sequential serials let anyone who sees one certificate predict the next, which
        # turns this CA's issue rate into observable information (RFC 5280 §7.1 says explicitly "do not do this").
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    for extension, critical in leaf_extensions(
        cert_type, spec, issued_sans, leaf_public_key, bundle.cert.public_key(), crl_base_url
    ):
        builder = builder.add_extension(extension, critical=critical)

    cert = builder.sign(private_key=bundle.key, algorithm=signing_hash(leaf_public_key))

    pem = cert.public_bytes(Encoding.PEM).decode("ascii")
    ca_pem = bundle.cert.public_bytes(Encoding.PEM).decode("ascii")
    issued = IssuedCert(
        cert=cert,
        pem=pem,
        chain_pem=pem + ca_pem,
        serial_hex=f"{cert.serial_number:x}",
        not_before_utc=cert.not_valid_before_utc,
        not_after_utc=cert.not_valid_after_utc,
        fingerprint_sha256=cert.fingerprint(hashes.SHA256()).hex(),
        cert_type=cert_type,
        # The subject actually issued, not the one requested: `IssuedCert.common_name` feeds the log line, the DB row
        # and
        # `/issued`, so an edited CN would otherwise be recorded — and later revoked by serial — under a name the
        # certificate does not carry.
        common_name=_common_name_of(subject if subject is not None else details.subject_name, details),
        sans=issued_sans,
    )
    log.info("issued %s", issued.summary)
    return issued


def _common_name_of(name: x509.Name, details: CsrDetails) -> str:
    """The CN of the subject actually issued, falling back to the CSR's when that name carries none.

    A fallback is needed rather than assumed: a CSR with no CN at all is legal (only SANs matter for TLS matching), and
    a `Name` rebuilt from edited fields can legitimately omit one. Falling back to `details.subject` keeps such a
    certificate describable in the list instead of showing an empty Common name column.
    """
    attributes = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not attributes:
        return details.subject.get("common_name") or ""
    value = attributes[0].value
    # The same `str | bytes` reality `csr._subject_dict` documents: the ASN.1 string type behind an attribute varies by
    # OID, and a `bytes` value reaching a template prints as `b'...'` to an operator.
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)
