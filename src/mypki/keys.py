"""Key generation, key specs and PEM serialisation -- the only place that decides what a "usable key" is.

Why this module exists separately from `ca.py` and `csr.py`: the same key rules are enforced in three different
places with three different callers -- the CLI (`--key-type/--key-size/--curve`), the generate-CSR form (the
`key_type` allow-list string, e.g. `rsa-3072`), and the sign page (the policy check applied to a **foreign** CSR's
public key). If each site wrote its own `if size >= 2048`, they would drift, and the drift would be invisible until
the day the form accepts something the signer refuses. So one spec type is parsed from a string, validated once,
and both generation and policy checks read it (page-map §3 rule 5, §7).

Why an allow-list of *named specs* rather than free `size` + `curve` numbers: a page that accepts arbitrary sizes
invites 1024-bit RSA and P-224 EC through a form field or a crafted request body. Here the accepted set is a tuple
of names, and anything else fails at parse time with the allowed list in the message.

Rejected alternative: `cryptography`'s own "generate then check" ordering -- generate the key, then discover it was
a bad choice. Generation is the expensive step; validation happens first so a rejected spec never allocates a key.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)

from .errors import KeyPolicyError

log = logging.getLogger("mypki.keys")

#: The only key specs mypki will generate or accept, as form/CLI strings (page-map §2, §3 rule 5).
#: RSA floors at 2048 because that is the boundary current guidance treats as no longer conservative; the default
#: is 3072 so the common case has margin. EC offers P-256 and P-384 only: P-224 and P-521 are omitted on purpose --
#: P-224 is weak, P-521 is not widely deployed enough to trust a client with, and an allow-list that needs a
#: "usually" in it is not an allow-list.
ALLOWED_KEY_SPECS: tuple[str, ...] = ("rsa-2048", "rsa-3072", "rsa-4096", "ec-p256", "ec-p384")

#: Human-readable version of the same list, for error messages. Built from ALLOWED_KEY_SPECS so it cannot drift.
ALLOWED_KEY_SPECS_TEXT = ", ".join(sorted(ALLOWED_KEY_SPECS))

#: RSA public exponent. 65537 is the value every verifier expects; smaller exponents (3, 17) have a history of
#: implementation-specific attacks and larger ones cost verification time for no benefit (FIPS 186-5 D.2.1).
RSA_PUBLIC_EXPONENT = 65537

_MIN_RSA_BITS = 2048

_CURVES: dict[str, ec.EllipticCurve] = {"p256": ec.SECP256R1(), "p384": ec.SECP384R1()}

# Curves accepted when inspecting a *foreign* key (a pasted CSR's public key), keyed by the curve class mypki
# actually recognises. P-224 is absent here too, so a CSR cannot sneak in a curve the generator refuses to issue.
_ALLOWED_EC_CURVES: dict[str, tuple[ec.EllipticCurve, str]] = {
    "secp256r1": (ec.SECP256R1(), "P-256"),
    "secp384r1": (ec.SECP384R1(), "P-384"),
}

__all__ = [
    "ALLOWED_KEY_SPECS",
    "ALLOWED_KEY_SPECS_TEXT",
    "KeySpec",
    "describe_private_key",
    "describe_public_key",
    "generate_key",
    "key_spec_for_public_key",
    "load_private_key_pem",
    "private_key_pem",
]


@dataclass(frozen=True)
class KeySpec:
    """A validated key specification: algorithm + size (RSA bits or curve name).

    Frozen because a key spec that can be mutated after validation is a validated value with a hole in it: the
    sign page checks a spec, then hands it to the builder, and a mutable spec lets something between those two
    steps change what was checked. `from_string` is the only way one comes into existence (page-map §2).
    """

    algorithm: str  # "rsa" | "ec"
    size: int  # RSA modulus bits; EC key.size in bits (256/384)
    curve_name: str | None  # "P-256"/"P-384" for EC, None for RSA

    @property
    def name(self) -> str:
        """Canonical spec string, reproducing an entry of `ALLOWED_KEY_SPECS` byte for byte.

        This is not cosmetic. The allow-list is compared against `.name` elsewhere in the app (and by tests), so an EC
        spec that canonicalises to `ec-256` instead of `ec-p256` is accepted by the form and then refused by
        anything that
        re-parses its own name -- the CA rejecting its own output. The `p` is part of the name, not decoration.
        """
        if self.algorithm == "ec":
            return f"ec-{_curve_key(self.curve_name or '')}"
        return f"rsa-{self.size}"

    @property
    def label(self) -> str:
        """Display form: `RSA 3072` / `EC P-384`."""
        return f"RSA {self.size}" if self.algorithm == "rsa" else f"EC {self.curve_name}"

    @classmethod
    def from_string(cls, value: str) -> KeySpec:
        """Parse an allow-listed spec string. Anything else raises `KeyPolicyError` naming the allowed set."""
        key = (value or "").strip().lower()
        if key not in {s.lower() for s in ALLOWED_KEY_SPECS}:
            raise KeyPolicyError(f"{value!r} is not a known key type", ALLOWED_KEY_SPECS_TEXT)
        algorithm, _, rest = key.partition("-")
        if algorithm == "rsa":
            return cls(algorithm="rsa", size=int(rest), curve_name=None)
        return cls(
            algorithm="ec", size=256 if rest == "p256" else 384, curve_name="P-256" if rest == "p256" else "P-384"
        )

    def signature_hash_name(self) -> str:
        """Hash mypki uses to sign *with* or *for* a key of this spec (page-map §7).

        SHA-256 everywhere except P-384 leaves, where the hash matches the curve strength rather than being lifted
        to SHA-384 for its own sake -- a P-256 leaf signed with SHA-384 buys nothing and confuses auditors.
        """
        return "sha384" if self.curve_name == "P-384" else "sha256"


def _curve_key(name: str) -> str:
    """Normalise any spelling of a curve name to `_CURVES`'s key form: `P-256`, `p256`, `P256` -> `p256`.

    Removing every non-alphanumeric rather than stripping a known prefix is what makes this total. An earlier
    version did
    `name.lower().removeprefix("p")`, which turned "P-256" into "-256", found nothing, and made EC key generation
    fail for
    every EC spec the parser had just accepted -- unusable EC support with every parse-time test still green.
    """
    return "".join(char for char in name.lower() if char.isalnum())


def _curve_for(name: str) -> ec.EllipticCurve:
    curve = _CURVES.get(_curve_key(name))
    if curve is None:  # pragma: no cover - KeySpec.from_string already rejects unknown curves
        raise KeyPolicyError(f"curve {name!r} is not supported", "P-256, P-384")
    return curve


def generate_key(spec: KeySpec) -> rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey:
    """Generate a private key for a validated spec.

    Validation happens in `KeySpec.from_string`, before this function is reachable, so the expensive call is never
    made for a spec that will be refused (see module docstring).
    """
    if spec.algorithm == "rsa":
        log.info("generating %s private key", spec.label)
        return rsa.generate_private_key(public_exponent=RSA_PUBLIC_EXPONENT, key_size=spec.size)
    log.info("generating %s private key", spec.label)
    return ec.generate_private_key(_curve_for(spec.curve_name or "P-256"))


def private_key_pem(
    key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    passphrase: bytes | None = None,
) -> bytes:
    """Serialise a private key to PKCS#8 PEM, encrypted when a passphrase is given.

    `PrivateFormat.PKCS8` + `BestAvailableEncryption` is the pair that produces
    `-----BEGIN ENCRYPTED PRIVATE KEY-----`. Two traps this avoids:
    `serialization.Encryption` does not exist on that version, and PKCS#1 (`PrivateFormat.TraditionalOpenSSL`)
    emits `BEGIN RSA PRIVATE KEY`, which is not encryptable at all -- an encryption request that silently
    returns an unencrypted key is the worst possible failure mode for this function.
    """
    encryption: BestAvailableEncryption | NoEncryption = (
        BestAvailableEncryption(passphrase) if passphrase else NoEncryption()
    )
    return key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=encryption)


def load_private_key_pem(
    data: bytes, passphrase: bytes | None = None
) -> rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey:
    """Reload a mypki-generated key PEM (encrypted or not).

    Kept here so the encryption format and its loader live in one module: a change to `private_key_pem` that does
    not also change this function is caught by `test_keys.py`'s round-trip rather than at a client's install time.

    Supplying a passphrase for an **unencrypted** key raises
    `TypeError: Password was given but private key is not encrypted`. That mismatch is a normal operator state --
    the key
    was created without `--encrypt` while `MYPKI_CA_PASSPHRASE` is still exported in the shell or systemd unit --
    so it is
    handled here by retrying without the passphrase and logging that it was unnecessary. Two things that retry must not
    become: (a) swallowing a *wrong* passphrase, which raises on an encrypted key and is re-raised unchanged by `ca.py`,
    and (b) pretending the key was protected. The log line says plainly that the file is unencrypted, because an
    operator
    who believes they have an encrypted CA key and does not have one is exactly the misunderstanding this project cannot
    afford.
    """
    try:
        key = load_pem_private_key(data, password=passphrase)
    except TypeError as exc:
        if passphrase is None or "not encrypted" not in str(exc):
            raise
        log.warning(
            "a passphrase was supplied but %s-style key material is unencrypted; loading it without one", "PRIVATE KEY"
        )
        key = load_pem_private_key(data, password=None)
    if not isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):  # pragma: no cover - defensive
        raise KeyPolicyError(
            f"loaded key is a {type(key).__name__}, not RSA or EC",
            ALLOWED_KEY_SPECS_TEXT,
        )
    return key


def describe_public_key(public_key: object) -> str:
    """One-line description of a public key for display (`RSA 3072`, `EC P-256`)."""
    spec = key_spec_for_public_key(public_key)
    return spec.label


def key_spec_for_public_key(public_key: object) -> KeySpec:
    """Classify an arbitrary public key against mypki's policy, or raise `KeyPolicyError`.

    This is the function behind step A rule 5 of the sign page (page-map §3): it answers "would mypki issue a
    certificate for this key?" for a key that came from *outside* the app, so the classification has to be built
    from what cryptography reports about the key (`key_size`, `curve.name`) rather than from a spec string someone
    typed.
    """
    if isinstance(public_key, rsa.RSAPublicKey):
        bits = public_key.key_size
        if bits < _MIN_RSA_BITS:
            raise KeyPolicyError(f"RSA-{bits}", f"RSA {_MIN_RSA_BITS}, RSA 3072, RSA 4096")
        return KeySpec(algorithm="rsa", size=bits, curve_name=None)
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        known = _ALLOWED_EC_CURVES.get(public_key.curve.name.lower())
        if known is None:
            raise KeyPolicyError(f"EC {public_key.curve.name}", "EC P-256, EC P-384")
        return KeySpec(algorithm="ec", size=public_key.curve.key_size, curve_name=known[1])
    raise KeyPolicyError(type(public_key).__name__, ALLOWED_KEY_SPECS_TEXT)


def describe_private_key(key: object) -> str:
    """Describe a private key mypki holds, without any key material -- algorithm and size only.

    The fallbacks are the point of this function rather than an afterthought: it is called on whatever a caller is
    holding (`object`), and a *description* must never be able to break the code that only wanted a label. Two
    branches, both exercised by `test_keys.py`: a `public_key()` that raises, and an object with no `public_key` at all.

    Why `except Exception` and not a tuple of cryptography exceptions:
    `cryptography.exceptions` exports no common base -- `dir()` yields UnsupportedAlgorithm, AlreadyFinalized,
    AlreadyUpdated, NotYetFinalized, InvalidTag, InvalidSignature, InternalError, InvalidKey and nothing named
    `CryptographyError`. Enumerating the concrete set here would drift with the library and silently stop catching the
    day a new one appears, which is worse than the broad arm in a function whose entire contract is "never raise".
    """
    public = getattr(key, "public_key", None)
    if callable(public):
        try:
            return describe_public_key(public())
        except Exception:  # broad on purpose -- see the docstring: describing a key must not break its caller
            log.warning("could not describe a %s; reporting the type name only", type(key).__name__)
    return type(key).__name__
