"""Key specs, generation and PEM encryption round-trips.

Why these are asserted at the key layer rather than only through the pages: the same allow-list is consulted by the CLI
(`--key-type/--key-size/--curve`), the generate form (`key_type`) and the sign page (the policy applied to a foreign
CSR's public key). A hole in `keys.py` is therefore reachable from three directions at once, and testing it through any
one of them proves only that one direction.

Every negative case here mutates **one** thing: an accepted spec becomes a rejected one by changing the size or
the curve
and nothing else (STYLE §8). That is what makes "1024 is refused" a fact about the size check rather than a fact about
this particular keypair being unlucky.
"""

from __future__ import annotations

import dataclasses

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from mypki.errors import KeyPolicyError
from mypki.keys import (
    ALLOWED_KEY_SPECS,
    RSA_PUBLIC_EXPONENT,
    KeySpec,
    describe_private_key,
    describe_public_key,
    generate_key,
    key_spec_for_public_key,
    load_private_key_pem,
    private_key_pem,
)

# --------------------------------------------------------------------------------- the allow-list itself


@pytest.mark.parametrize("spec_name", ALLOWED_KEY_SPECS)
def test_every_listed_spec_parses_and_round_trips_to_its_own_name(spec_name: str) -> None:
    """Each entry of `ALLOWED_KEY_SPECS` parses, generates, and reports itself back identically.

    Round-tripping through `.name` is the assertion that matters: a spec whose canonical form does not reproduce
    an entry
    of the allow-list would be accepted by the form and then rejected by anything that re-parses its own name --
    which is
    how a page starts refusing its own output.
    """
    spec = KeySpec.from_string(spec_name)
    assert spec.name == spec_name
    key = generate_key(spec)
    assert key_spec_for_public_key(key.public_key()).name == spec_name


def test_rsa_sizes_2048_3072_and_4096_are_accepted_with_matching_bit_lengths() -> None:
    for name in ("rsa-2048", "rsa-3072", "rsa-4096"):
        spec = KeySpec.from_string(name)
        key = generate_key(spec)
        assert isinstance(key, rsa.RSAPrivateKey)
        assert key.key_size == spec.size


def test_rsa_1024_is_rejected_naming_the_allowed_set() -> None:
    """1024-bit RSA is refused at parse time, before any key is generated.

    The ordering is the point: `generate_key` is the expensive step, so a spec that will be refused must never reach it.
    Asserting only "KeyPolicyError" would also pass if the code generated the key first and rejected it afterwards.
    """
    with pytest.raises(KeyPolicyError) as excinfo:
        KeySpec.from_string("rsa-1024")
    assert "rsa-1024" in str(excinfo.value)
    assert "2048" in str(excinfo.value)  # the message names what *is* allowed, not just what is not


def test_ec_p256_and_p384_are_accepted() -> None:
    for name in ("ec-p256", "ec-p384"):
        spec = KeySpec.from_string(name)
        key = generate_key(spec)
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        assert spec.curve_name in {"P-256", "P-384"}
        assert key.curve.key_size == spec.size


def test_ec_p224_is_rejected() -> None:
    """P-224 is absent from the allow-list on purpose (see keys.py), and stays absent.

    A curve that is "weakish but common" is the easiest thing to accidentally add back during a refactor, because it
    looks like a harmless generalisation of the EC branch.
    """
    with pytest.raises(KeyPolicyError):
        KeySpec.from_string("ec-p224")


def test_an_arbitrary_curve_is_rejected_rather_than_defaulted() -> None:
    for name in ("ec-p521", "ec-secp256k1", "ec-"):
        with pytest.raises(KeyPolicyError):
            KeySpec.from_string(name)


def test_unknown_algorithm_string_is_rejected() -> None:
    for name in ("dsa-2048", "ed25519", "", "  ", "rsa-abc"):
        with pytest.raises(KeyPolicyError):
            KeySpec.from_string(name)


def test_spec_parsing_is_case_insensitive_but_the_canonical_name_is_lowercase() -> None:
    """`RSA-3072` from a form or a CLI typo is accepted; what it *becomes* is the allow-list spelling.

    Accepting case variants is usability. Canonicalising them is what keeps `ALLOWED_KEY_SPECS` comparable against a
    parsed spec elsewhere in the app without every comparison needing its own `.lower()`.
    """
    spec = KeySpec.from_string("RSA-3072")
    assert spec.name == "rsa-3072"
    assert spec.name in ALLOWED_KEY_SPECS


def test_generated_rsa_keys_use_exponent_65537() -> None:
    key = generate_key(KeySpec.from_string("rsa-2048"))
    assert key.public_key().public_numbers().e == RSA_PUBLIC_EXPONENT


def test_signature_hash_follows_the_curve_sha384_only_for_p384() -> None:
    """SHA-384 for P-384 leaves, SHA-256 for everything else (page-map §7).

    The "everything else" half matters as much as the first: a P-256 leaf signed with SHA-384 buys nothing and
    reads to an
    auditor as a policy statement the CA never intended.
    """
    assert KeySpec.from_string("ec-p384").signature_hash_name() == "sha384"
    for name in ("ec-p256", "rsa-2048", "rsa-3072", "rsa-4096"):
        assert KeySpec.from_string(name).signature_hash_name() == "sha256"


def test_key_spec_is_immutable_after_validation() -> None:
    """`KeySpec` is frozen: a validated value with a mutable body is a validated value with a hole in it.

    The sign page validates a spec and then hands it to the builder. If anything between those two steps could change
    `size`, the check and the issued certificate would describe different keys.
    """
    spec = KeySpec.from_string("rsa-2048")
    with pytest.raises(dataclasses.FrozenInstanceError):
        spec.size = 1024  # type: ignore[misc]


# --------------------------------------------------------------------------------------------- PEM round-trips


def test_unencrypted_key_pem_reloads_without_a_passphrase() -> None:
    key = generate_key(KeySpec.from_string("rsa-2048"))
    pem = private_key_pem(key)
    assert b"-----BEGIN PRIVATE KEY-----" in pem
    assert b"ENCRYPTED" not in pem

    reloaded = load_private_key_pem(pem)
    assert reloaded.public_key().public_numbers() == key.public_key().public_numbers()


def test_encrypted_key_pem_carries_the_pkcs8_encrypted_header() -> None:
    """`PrivateFormat.PKCS8` + `BestAvailableEncryption` produces `ENCRYPTED PRIVATE KEY` (MEASURED, 50.0.2).

    The header *is* the assertion. PKCS#1 (`TraditionalOpenSSL`) emits `BEGIN RSA PRIVATE KEY` and cannot be encrypted
    at all, so an encryption request that quietly returns a PKCS#1 body is the worst possible failure mode here -- it
    looks like success and stores the key in the clear.
    """
    key = generate_key(KeySpec.from_string("rsa-2048"))
    pem = private_key_pem(key, b"a-passphrase-that-is-long")
    assert b"-----BEGIN ENCRYPTED PRIVATE KEY-----" in pem


def test_encrypted_key_reloads_with_the_right_passphrase() -> None:
    key = generate_key(KeySpec.from_string("ec-p256"))
    pem = private_key_pem(key, b"correct-horse-battery")
    reloaded = load_private_key_pem(pem, b"correct-horse-battery")
    # Compared as SubjectPublicKeyInfo DER: two key objects holding the same curve point are not `==` in cryptography,
    # so serialised form is the only honest comparison available here.
    assert reloaded.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    ) == key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


def test_encrypted_key_with_the_wrong_passphrase_fails_rather_than_returning_a_different_key() -> None:
    """A wrong passphrase raises; it never yields *some* key.

    A library that returned a usable key for a wrong password would make `ca.load_ca`'s success path meaningless, so the
    failure has to be proven to be a failure at this layer rather than assumed from documentation.
    """
    key = generate_key(KeySpec.from_string("rsa-2048"))
    pem = private_key_pem(key, b"right-passphrase-here")
    with pytest.raises((TypeError, ValueError)):
        load_private_key_pem(pem, b"wrong-passphrase-here")


def test_encrypted_key_cannot_be_loaded_as_if_it_were_plaintext() -> None:
    key = generate_key(KeySpec.from_string("rsa-2048"))
    pem = private_key_pem(key, b"right-passphrase-here")
    with pytest.raises((TypeError, ValueError)):
        load_private_key_pem(pem)


def test_a_passphrase_supplied_for_an_unencrypted_key_still_loads_it() -> None:
    """A leftover `MYPKI_CA_PASSPHRASE` against an unencrypted key must not break startup.

    MEASURED: cryptography raises `TypeError: Password was given but private key is not encrypted`. That is a normal
    operator state -- the CA was created without `--encrypt` while the variable is still exported from an old
    systemd unit
    or shell profile -- so `keys.load_private_key_pem` retries without the passphrase instead of failing.

    The pair that makes this test worth having is `test_encrypted_key_with_the_wrong_passphrase_fails...`: unencrypted +
    any passphrase loads, encrypted + wrong passphrase raises. Collapsing those two into one code path is how a CA
    ends up
    silently accepting an unprotected key file on a host whose operator believes it is protected.
    """
    key = generate_key(KeySpec.from_string("rsa-2048"))
    pem = private_key_pem(key)
    assert b"ENCRYPTED" not in pem

    reloaded = load_private_key_pem(pem, b"unused-but-harmless")
    assert reloaded.public_key().public_numbers() == key.public_key().public_numbers()


def test_an_unencrypted_key_still_loads_with_no_passphrase_at_all() -> None:
    """The common case: no passphrase was ever set, and none is needed."""
    key = generate_key(KeySpec.from_string("rsa-2048"))
    pem = private_key_pem(key)
    assert load_private_key_pem(pem) is not None


def test_encrypted_and_unencrypted_pems_of_the_same_key_differ() -> None:
    """A passphrase actually changes the artifact.

    Trivially true, but it is the assertion behind docs/REFERENCE.md gotcha 1: if `--encrypt` produced byte-identical
    output, the
    operator would believe the key file was protected when it was not.
    """
    key = generate_key(KeySpec.from_string("rsa-2048"))
    assert private_key_pem(key) != private_key_pem(key, b"some-passphrase-here")


# ---------------------------------------------------------------------------- foreign-key classification


def test_foreign_rsa_1024_public_key_is_rejected_by_policy() -> None:
    """The policy check applies to a key that came from *outside* mypki, not only to specs typed into a form.

    This is the code path behind `/csr/sign` step A rule 5 (page-map §3): the CSR's own public key is classified, so a
    request generated by someone else's openssl cannot bring in a key size this CA would refuse to generate itself.
    """
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    with pytest.raises(KeyPolicyError) as excinfo:
        key_spec_for_public_key(weak.public_key())
    assert "1024" in str(excinfo.value)


def test_foreign_ec_p224_public_key_is_rejected_by_policy() -> None:
    weak = ec.generate_private_key(ec.SECP224R1())
    with pytest.raises(KeyPolicyError) as excinfo:
        key_spec_for_public_key(weak.public_key())
    assert "secp224r1" in str(excinfo.value).lower()


def test_ed25519_public_key_is_rejected_as_unsupported_not_weak() -> None:
    """An algorithm mypki does not handle is refused naming the type, rather than crashing later in the builder."""
    from cryptography.hazmat.primitives.asymmetric import ed25519

    key = ed25519.Ed25519PrivateKey.generate()
    with pytest.raises(KeyPolicyError) as excinfo:
        key_spec_for_public_key(key.public_key())
    assert "Ed25519" in str(excinfo.value)


def test_a_non_key_object_is_rejected_rather_than_raising_typeerror() -> None:
    with pytest.raises(KeyPolicyError):
        key_spec_for_public_key("not a key")  # type: ignore[arg-type]


# ------------------------------------------------------------------------------------------- descriptions


def test_describe_public_key_names_algorithm_and_size_only() -> None:
    """`RSA 2048` / `EC P-256`: enough to display, and nothing that could be mistaken for key material.

    These strings reach the home page, the confirmation panel and `mypki info`, so "contains no key bytes" is a property
    worth pinning on the function itself rather than re-checking at every call site.
    """
    rsa_label = describe_public_key(generate_key(KeySpec.from_string("rsa-3072")).public_key())
    ec_label = describe_public_key(generate_key(KeySpec.from_string("ec-p384")).public_key())
    assert rsa_label == "RSA 3072"
    assert ec_label == "EC P-384"
    for label in (rsa_label, ec_label):
        assert "PRIVATE KEY" not in label
        assert len(label) < 32


def test_describe_private_key_reports_the_spec_and_not_the_key() -> None:
    key = generate_key(KeySpec.from_string("ec-p256"))
    description = describe_private_key(key)
    assert description == "EC P-256"
    assert "PRIVATE KEY" not in description


def test_allowed_specs_text_is_derived_from_the_allow_list() -> None:
    """The human-readable list is built from the same tuple the parser checks.

    A hand-written second copy of "what is allowed" is a second source of truth, and it drifts the first time
    someone adds
    a spec to one place and not the other -- leaving an error message that lies about what the app accepts.
    """
    from mypki.keys import ALLOWED_KEY_SPECS_TEXT

    for name in ALLOWED_KEY_SPECS:
        assert name in ALLOWED_KEY_SPECS_TEXT
