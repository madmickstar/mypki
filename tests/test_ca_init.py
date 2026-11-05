"""The CA lifecycle on disk: create, refuse to overwrite, archive instead of delete, load, describe.

Why these are asserted here rather than only through the CLI: `init_ca` is the one code path in this project that ever
writes a private key, and every rule page-map §6 states about it (refuse rather than truncate, archive rather than
delete, 0700 directory, 0600 key re-stat'd after writing, passphrase never in argv) is a filesystem promise that has to
hold for the CLI *and* for anything else that ever calls this function.

Each negative case mutates **one** thing (STYLE §8): an existing cert file, an existing key file, a `force` flag, a
mismatched key. That is what makes "the refusal works" a fact about the check rather than about this particular
directory being unlucky. No test here touches an operator's real data dir -- `conftest.py`'s autouse fixtures redirect
the data root into `tmp_path` before any `Settings` is built.
"""

from __future__ import annotations

import datetime as dt
import logging
import os
import re
import stat
import subprocess
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from mypki import ca as ca_module
from mypki import paths
from mypki.ca import (
    CA_DIR_MODE,
    PRIVATE_FILE_MODE,
    CaBundle,
    describe_ca,
    fingerprint_hex,
    format_fingerprint,
    init_ca,
    key_matches_certificate,
    load_ca,
    secret_session_key,
)
from mypki.errors import CaAlreadyExistsError, CaNotFoundError, CaPassphraseError
from mypki.keys import KeySpec

POSIX = os.name == "posix"


def _init(data_root: Path, **overrides: object):
    """`init_ca` with the defaults this file cares about, so each test changes exactly one thing."""
    options: dict[str, object] = {
        "common_name": "mypki Test CA",
        "organization": "mypki tests",
        "country": "xx",
        "spec": KeySpec.from_string("rsa-2048"),
        "days": 3650,
    }
    options.update(overrides)
    return init_ca(data_root, **options)  # type: ignore[arg-type]


# --------------------------------------------------------------------------------------------- creation (§7 root
# profile)


def test_init_creates_exactly_the_documented_files(data_root: Path) -> None:
    """`ca_key.pem` + `ca_cert.pem`, and nothing else.

    The "and nothing else" half is the assertion: an `init-ca` that also wrote a database row, or a leftover `.key.tmp`,
    would make the CLI's promise "writes nothing to the DB" (page-map §6) false in a way no reader would notice.
    """
    result = _init(data_root)

    assert paths.ca_key_path(data_root).is_file()
    assert paths.ca_cert_path(data_root).is_file()
    files = sorted(p.relative_to(data_root).as_posix() for p in data_root.rglob("*") if p.is_file())
    assert files == ["ca/ca_cert.pem", "ca/ca_key.pem"], files
    assert result.cert_path == paths.ca_cert_path(data_root)
    assert result.key_path == paths.ca_key_path(data_root)


def test_result_prints_only_public_facts(data_root: Path) -> None:
    """`InitCaResult` is what `init-ca` is allowed to print (page-map §6), so it must not carry key material.

    Asserted structurally: the dataclass has no field whose value could be a PEM body or a passphrase, and
    `encrypted_key` is a boolean rather than "here is how it was encrypted".
    """
    result = _init(data_root, passphrase=b"a-passphrase-not-a-real-one")

    assert set(result.__dataclass_fields__) == {
        "cert_path",
        "key_path",
        "subject",
        "serial_hex",
        "not_before_utc",
        "not_after_utc",
        "fingerprint_hex",
        "key_spec",
        "encrypted_key",
        "archived_to",
    }
    assert result.encrypted_key is True
    assert result.archived_to is None
    for value in (result.subject, result.serial_hex, result.fingerprint_hex, result.key_spec):
        assert "PRIVATE KEY" not in str(value)
    assert result.key_spec == "RSA 2048"


def test_root_certificate_carries_the_profile_page_map_promises(data_root: Path) -> None:
    """`CA:TRUE pathLength:0` critical, keyCertSign+crlSign critical, SKI present, **no** AKI, self-signed.

    `path_length == 0` and not `None` is the load-bearing assertion (page-map §7): `None` would let a leaf that somehow
    got marked CA mint another CA beneath this one. The missing AKI matters for the same reason in miniature -- a
    self-referencing authority key id is read by some validators as a chain-building hint.
    """
    result = _init(data_root)
    cert = load_ca(data_root).cert

    # The certificate on disk is the one `init-ca` reported: same fingerprint, computed rather than copied.
    assert cert.fingerprint(hashes.SHA256()).hex() == result.fingerprint_hex

    basic = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert basic.ca is True
    assert basic.path_length == 0
    usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert (usage.key_cert_sign, usage.crl_sign) == (True, True)
    assert usage.digital_signature is True
    assert usage.key_encipherment is True

    types = {type(extension.value).__name__ for extension in cert.extensions}
    assert "SubjectKeyIdentifier" in types
    assert "AuthorityKeyIdentifier" not in types
    assert "ExtendedKeyUsage" not in types

    assert cert.subject == cert.issuer  # self-signed root: issuer is exactly the subject
    assert cert.signature_hash_algorithm.name == "sha256"
    critical_names = {type(extension.value).__name__ for extension in cert.extensions if extension.critical}
    assert critical_names == {"BasicConstraints", "KeyUsage"}


def test_subject_attributes_are_added_only_when_supplied(data_root: Path) -> None:
    """An empty `O=` or `C=` is not written at all (page-map §7's subject builder).

    Two runs, differing in one thing each: with the attributes and without them. A zero-length attribute copied into a
    root certificate shows up in every client's certificate viewer, so "absent" has to mean absent.
    """
    minimal = _init(data_root, organization=None, organizational_unit=None, country=None)
    facts = describe_ca(load_ca(data_root).cert)
    assert facts["organization"] is None
    assert facts["organizational_unit"] is None
    assert facts["country"] is None
    assert facts["common_name"] == "mypki Test CA"

    (data_root / "ca").mkdir(parents=True, exist_ok=True)
    minimal.cert_path.unlink()
    minimal.key_path.unlink()
    _init(data_root, organization="Acme", organizational_unit="Board", country="de")
    filled = describe_ca(load_ca(data_root).cert)
    assert filled["organization"] == "Acme"
    # `OU=` is the one subject attribute no other test in this file had ever supplied, so its branch in
    # `_subject_builder` was untested -- and a dropped `OU=` is invisible unless you ask for it by name.
    assert filled["organizational_unit"] == "Board"
    assert filled["country"] == "DE", "country is uppercased before it reaches the certificate"


def test_validity_span_is_the_requested_number_of_days(data_root: Path) -> None:
    """`days` means days, measured on tz-aware UTC accessors.

    The tolerance is a minute rather than zero because `not_before` is sampled from the clock; what must not drift is
    the *span*, which is why the assertion is about `not_after - not_before` and not about either endpoint.
    """
    result = _init(data_root, days=40)
    span = result.not_after_utc - result.not_before_utc
    assert abs(span - dt.timedelta(days=40)) < dt.timedelta(minutes=1)
    assert result.not_before_utc.tzinfo is not None
    assert result.not_after_utc.utcoffset() == dt.timedelta(0)


# --------------------------------------------------------------------------------------------- refusal and archiving


def test_re_init_is_refused_and_names_the_flag_that_would_override_it(data_root: Path) -> None:
    """Exit-2 material: the refusal names the file **and** `--force` (page-map §6).

    Nothing on disk changes when a CA already exists. That half is the point -- a refusal that refused *after*
    truncating the key would be indistinguishable from a successful re-init to anyone not watching closely.
    """
    first = _init(data_root)
    before = {p: p.read_bytes() for p in (first.cert_path, first.key_path)}

    with pytest.raises(CaAlreadyExistsError) as excinfo:
        _init(data_root)

    message = str(excinfo.value)
    assert "--force" in message
    assert str(paths.ca_cert_path(data_root)) in message or str(paths.ca_key_path(data_root)) in message
    assert {p: p.read_bytes() for p in (first.cert_path, first.key_path)} == before
    assert not list(data_root.rglob("archive"))


def test_refusal_also_covers_a_half_written_pair(data_root: Path) -> None:
    """A key without a certificate is still "something exists here" and is refused.

    This is the archive/restore mistake in its mildest form: one file restored by hand. Silently generating a *new*
    certificate next to that key would produce a CA whose public half does not match its private half, which every
    client discovers and this host discovers late.
    """
    first = _init(data_root)
    first.cert_path.unlink()

    with pytest.raises(CaAlreadyExistsError):
        _init(data_root)


def test_force_archives_the_old_pair_and_deletes_nothing(data_root: Path) -> None:
    """`--force` moves, it does not truncate (page-map §6).

    Asserted by content, not by directory listing: the archived bytes must be byte-identical to what was there before,
    and the new pair must differ from them. "Nothing was deleted" is only honest if the old bytes are still readable
    somewhere.
    """
    first = _init(data_root)
    old_cert = first.cert_path.read_bytes()
    old_key = first.key_path.read_bytes()

    second = _init(data_root, force=True)

    assert second.archived_to is not None
    assert (second.archived_to / "ca_cert.pem").read_bytes() == old_cert
    assert (second.archived_to / "ca_key.pem").read_bytes() == old_key
    assert paths.ca_cert_path(data_root).read_bytes() != old_cert
    assert paths.ca_key_path(data_root).read_bytes() != old_key
    assert second.archived_to.parent == paths.ca_dir(data_root) / "archive"


def test_two_forced_re_inits_do_not_share_one_archive_directory(
    data_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Archive names get a counter when the timestamp collides.

    The stamp is pinned to one fixed value so the collision is *constructed* rather than hoped for: two forced re-inits
    inside the same second are exactly an operator retrying a command that "did not seem to work", and without the
    counter the second move either fails outright or lands on top of the first history -- which makes page-map §6's
    "nothing is ever deleted" a statement of intent rather than behaviour.
    """
    monkeypatch.setattr("mypki.ca._utc_stamp", lambda: "20260101T000000Z")

    _init(data_root)
    second = _init(data_root, force=True)
    third = _init(data_root, force=True)

    archives = sorted(p.name for p in (paths.ca_dir(data_root) / "archive").iterdir())
    assert archives == ["20260101T000000Z", "20260101T000000Z-1"], archives
    assert second.archived_to != third.archived_to
    assert all((paths.ca_dir(data_root) / "archive" / name / "ca_cert.pem").is_file() for name in archives)


def test_archive_directory_name_is_legal_on_windows(data_root: Path) -> None:
    """The archive stamp contains no colon and sorts as a string.

    `%Y-%m-%dT%H:%M:%SZ` is the honest ISO-8601 spelling and an illegal Windows directory name; the compact form used
    here sorts correctly, which is what makes `ca/archive/` readable as a history rather than names to decode. The shape
    is asserted rather than a specific timestamp because the value *is* a timestamp.
    """
    _init(data_root)
    archived = _init(data_root, force=True)
    name = (archived.archived_to or Path("none")).name

    assert ":" not in name
    assert re.fullmatch(r"\d{8}T\d{6}Z(-\d+)?", name), name


# --------------------------------------------------------------------------------------------- permissions (§8)


@pytest.mark.skipif(not POSIX, reason="POSIX mode bits do not exist on Windows (page-map §8)")
def test_key_file_and_ca_directory_modes_are_owner_only(data_root: Path) -> None:
    """0600 on the key, 0700 on `ca/`, re-stat'd rather than chmod-and-hope.

    `_assert_private_mode` is what turns a umask or an inherited ACL from a silent exception into a startup failure, so
    the assertion here is the same one the production code makes -- and it is asserted *after* creation, because the
    window between "written" and "protected" is where a polling attacker lives.
    """
    result = _init(data_root)
    key_mode = stat.S_IMODE(result.key_path.stat().st_mode)
    dir_mode = stat.S_IMODE(paths.ca_dir(data_root).stat().st_mode)

    assert key_mode == PRIVATE_FILE_MODE, oct(key_mode)
    assert dir_mode == CA_DIR_MODE, oct(dir_mode)
    assert not key_mode & 0o077
    assert not dir_mode & 0o077


def test_private_mode_assertion_is_skipped_where_mode_bits_do_not_exist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`_assert_private_mode` returns immediately when POSIX semantics do not apply.

    The same file that passes the POSIX check is *not* protected on a Windows host -- `os.chmod` there toggles a single
    read-only bit, so re-statting it would either pass meaninglessly or fail unhelpfully and abort an init that is
    otherwise fine (page-map §8). What this test pins is the deliberate skip: a 0644-looking file raises nothing when
    `_is_posix()` is False. Without the early return, the same file on a Windows host would raise `RuntimeError` and no
    operator could create a CA at all.
    """
    key = tmp_path / "ca_key.pem"
    key.write_bytes(b"not a real key")
    key.chmod(0o644)

    monkeypatch.setattr(ca_module, "_is_posix", lambda: False)
    ca_module._assert_private_mode(key)  # must not raise

    monkeypatch.undo()
    if POSIX:
        with pytest.raises(RuntimeError):
            ca_module._assert_private_mode(key)


def test_public_certificate_uses_ordinary_permissions(data_root: Path) -> None:
    """The certificate is the artifact meant to be copied everywhere; it is not secret.

    One mutation relative to the previous test: the same init, a different file. If `ca_cert.pem` were written with the
    private-file path's mode, an operator copying it to a shared machine would find it unreadable for a reason with no
    diagnostic in it.
    """
    result = _init(data_root)
    mode = stat.S_IMODE(result.cert_path.stat().st_mode)
    assert not mode & 0o100, "not executable"


# --------------------------------------------------------------------------------------------- loading and passphrase


def test_load_ca_returns_a_bundle_with_the_key(throwaway_ca: CaBundle) -> None:
    """The normal case, through the fixture every other file uses."""
    assert throwaway_ca.key_present is True
    assert throwaway_ca.key is not None
    assert key_matches_certificate(throwaway_ca.key, throwaway_ca.cert)


def test_load_without_a_key_file_is_a_state_not_a_crash(data_root: Path) -> None:
    """`key is None` is modelled deliberately (page-map §1): the host can still show its public CA card.

    `load_ca` succeeds here rather than raising, because `/` and `/ca/certificate` can answer truthfully from the public
    certificate alone. What must not happen is a bundle that claims a key it does not have.
    """
    result = _init(data_root)
    result.key_path.unlink()

    bundle = load_ca(data_root)
    assert bundle.key_present is False
    assert bundle.key is None
    assert describe_ca(bundle.cert)["subject"] == result.subject


def test_missing_certificate_is_a_named_error(data_root: Path) -> None:
    """`CaNotFoundError` (CLI exit 3) rather than a `FileNotFoundError` traceback."""
    with pytest.raises(CaNotFoundError) as excinfo:
        load_ca(data_root)
    assert "init-ca" in str(excinfo.value)
    assert excinfo.value.path == paths.ca_cert_path(data_root)


def test_encrypted_key_without_a_passphrase_names_the_env_var_not_the_secret(data_root: Path) -> None:
    """The message a wrong-passphrase failure may safely produce (page-map §8).

    The key is encrypted, no passphrase is supplied, and the refusal must name `MYPKI_CA_PASSPHRASE` while repeating
    nothing from the key file. "It could not be decrypted" plus the variable to set is the whole useful answer.
    """
    _init(data_root, passphrase=b"a-passphrase-not-a-real-one")

    with pytest.raises(CaPassphraseError) as excinfo:
        load_ca(data_root)
    assert "MYPKI_CA_PASSPHRASE" in str(excinfo.value)
    assert "PRIVATE KEY" not in str(excinfo.value)


def test_wrong_passphrase_raises_the_same_named_error(data_root: Path) -> None:
    """A wrong-but-well-formed passphrase is refused, not retried away.

    One mutation from the previous test: a passphrase *is* supplied, and it is the wrong one.
    `keys.load_private_key_pem`
    retries only the "passphrase given for an unencrypted key" case (MEASURED `TypeError`), so a real wrong
    passphrase on
    an encrypted key must still surface as `CaPassphraseError`.
    """
    _init(data_root, passphrase=b"the-real-passphrase-not-a-one")

    with pytest.raises(CaPassphraseError):
        load_ca(data_root, passphrase=b"wrong-but-well-formed-value")


def test_passphrase_round_trip_loads_the_same_key(data_root: Path) -> None:
    """An encrypted CA is usable, not merely storable."""
    passphrase = b"a-passphrase-not-a-real-one"
    _init(data_root, passphrase=passphrase)

    bundle = load_ca(data_root, passphrase=passphrase)
    assert bundle.key_present is True
    assert key_matches_certificate(bundle.key, bundle.cert)


def test_no_key_at_all_is_a_mismatch_rather_than_an_attribute_error(throwaway_ca: CaBundle) -> None:
    """`key_matches_certificate(None, cert)` is False, not a crash.

    `CaBundle.key` is Optional by design (page-map §1), and this function is called with whatever the bundle holds.
    Before the explicit `None` arm existed, mypy flagged it and any future caller passing a key-less bundle would get
    an AttributeError from inside what should be a boolean question.
    """
    assert key_matches_certificate(None, throwaway_ca.cert) is False


def test_key_from_a_different_init_does_not_match_the_certificate(data_root: Path) -> None:
    """The archive/restore mix-up `key_matches_certificate` exists to catch (page-map §8).

    A foreign key placed next to this CA's certificate: `load_ca` still loads both (the host can show its public facts),
    and the mismatch is detectable rather than latent. Signing with that pair produces signatures every client rejects,
    so the check has to be observable from the bundle alone.
    """
    first = _init(data_root)
    foreign = _init(data_root.parent / "other", common_name="Foreign CA")
    foreign_key_bytes = foreign.key_path.read_bytes()

    first.key_path.write_bytes(foreign_key_bytes)
    first.key_path.chmod(PRIVATE_FILE_MODE)

    bundle = load_ca(data_root)
    assert bundle.key is not None
    assert key_matches_certificate(bundle.key, bundle.cert) is False


# --------------------------------------------------------------------------------------------- description and secret


def test_describe_ca_reports_public_facts_only(data_root: Path) -> None:
    """The dict behind the home card and `mypki info` (page-map §1).

    Asserted against the certificate itself rather than against expected strings, so the test cannot drift into a
    snapshot of one release: fingerprint matches `cert.fingerprint`, serial matches `cert.serial_number`, key spec
    matches what cryptography says about the public key.
    """
    _init(data_root)
    cert = load_ca(data_root).cert
    facts = describe_ca(cert)

    assert facts["serial_hex"] == f"{cert.serial_number:x}"
    assert facts["fingerprint_sha256"] == cert.fingerprint(hashes.SHA256()).hex()
    assert facts["key_type"] == "RSA 2048"
    assert facts["basic_constraints"] == "CA:TRUE pathLength:0"
    assert facts["not_after_utc"] == cert.not_valid_after_utc

    rendered = " ".join(str(value) for value in facts.values())
    assert "PRIVATE KEY" not in rendered


def test_fingerprint_helpers_agree_with_cryptography(data_root: Path) -> None:
    """`fingerprint_hex` is the single call site for `cert.fingerprint(...)` (cryptography 50.0.2 has no
    `cert.fingerprints`), and `format_fingerprint` only reformats its output."""
    _init(data_root)
    cert = load_ca(data_root).cert
    plain = fingerprint_hex(cert)

    assert plain == cert.fingerprint(hashes.SHA256()).hex()
    grouped = format_fingerprint(plain)
    assert grouped.replace(":", "") == plain.upper()
    assert all(len(part) == 2 for part in grouped.split(":"))


def test_secret_session_key_is_persisted_once_and_reused(data_root: Path) -> None:
    """Sessions survive a restart because the secret is stored, not regenerated (page-map §10).

    The second call must return the same value; silently rotating it would invalidate every in-flight two-step signing
    on an unrelated restart.
    """
    first = secret_session_key(data_root)
    second = secret_session_key(data_root)

    assert first == second
    target = paths.secret_key_path(data_root)
    assert target.read_text(encoding="utf-8").strip() == first
    assert len(first) >= 32


def test_configured_secret_wins_and_is_never_written_to_disk(data_root: Path) -> None:
    """`MYPKI_SECRET_KEY` is how sessions stay valid across hosts; it does not get copied into the data dir."""
    value = secret_session_key(data_root, configured="an-explicit-secret-not-a-real-one")

    assert value == "an-explicit-secret-not-a-real-one"
    assert not paths.secret_key_path(data_root).exists()


@pytest.mark.skipif(not POSIX, reason="POSIX mode bits do not exist on Windows (page-map §8)")
def test_generated_session_secret_is_owner_only(data_root: Path) -> None:
    _init(data_root)
    secret_session_key(data_root)
    mode = stat.S_IMODE(paths.secret_key_path(data_root).stat().st_mode)
    assert mode == PRIVATE_FILE_MODE, oct(mode)


# --------------------------------------------------------------------------------- Windows `icacls` hardening
#
# `_harden_with_icacls` is the only `subprocess` call in this project and it is guarded by `platform.system()`, so on
# this Linux runner every line of its body is unreachable by accident. These tests make the platform decision itself
# the thing under test: `platform.system`, `shutil.which` and `subprocess.run` are replaced, and what is asserted is
# which branch mypki takes and what it tells the operator. Scope matters here: these tests DO execute the function body
# (on any OS, because the platform is faked), but no test has ever driven a REAL `icacls` subprocess. The real thing was
# measured outside the suite, on a Windows 10 host, and that measurement is what found the lock-out bug recorded under
# 0.2.0 Fixed in CHANGELOG.md.


def _fake_icacls(
    monkeypatch: pytest.MonkeyPatch,
    *,
    found: str | None,
    username: str | None,
    raiser: Exception | None = None,
) -> list[list[str]]:
    """Put `_harden_with_icacls` on a pretend Windows host and record the argv it would have run.

    Four separate knobs because the function has four independent decisions (platform, binary present, username
    present, subprocess result), and STYLE §8 says one mutation per case. `raiser` is what `subprocess.run` raises
    instead of succeeding.
    """
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **kwargs: object) -> None:
        calls.append(list(argv))
        if raiser is not None:
            raise raiser

    monkeypatch.setattr(ca_module.platform, "system", lambda: "Windows")
    monkeypatch.setattr(ca_module.shutil, "which", lambda name: found)
    monkeypatch.setattr(ca_module.subprocess, "run", fake_run)
    for name in ("USERNAME", "USER_NAME"):
        monkeypatch.delenv(name, raising=False)
    if username is not None:
        monkeypatch.setenv("USERNAME", username)
    return calls


def test_icacls_hardening_is_skipped_on_a_non_windows_host(monkeypatch: pytest.MonkeyPatch) -> None:
    """The guard is `platform.system()`, not "we are on Linux": a macOS or AIX host takes the same exit.

    Nothing is consulted on this path -- no `which`, no `subprocess` -- which is what keeps a POSIX init from paying
    for a Windows-only feature it cannot use.

    The platform is faked rather than inherited from the runner. **MEASURED:** the previous version read the real host,
    so on a Windows machine it ran the *real* `icacls` against a relative path and passed only because that call failed.
    A test named "skipped on a non-Windows host" must not depend on which host it happens to be running on.
    """
    monkeypatch.setattr(ca_module.platform, "system", lambda: "Linux")

    assert ca_module._harden_with_icacls(Path("ca_key.pem")) is False


def test_secure_acl_grants_inheritance_removal_and_full_control(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The success arm: fixed argv, `/inheritance:r`, and one `(OI)(CI)(F)` grant for the current user.

    Asserted as the exact argv list because this is the project's only `subprocess` call and every element of it is a
    literal except the path mypki resolved itself. If someone later adds a shell string or interpolates an operator's
    text into these arguments, this test is where it fails.
    """
    calls = _fake_icacls(monkeypatch, found=r"C:\Windows\System32\icacls.exe", username="ALICE")
    # The key file exists here because `_harden_with_icacls` is only ever called after `init_ca` has written it, and the
    # function now re-opens that file to confirm the narrowing did not lock out this very process (see the Windows
    # finding in its docstring). A path that does not exist would take that failure arm instead.
    key_path = tmp_path / "ca" / "ca_key.pem"
    key_path.parent.mkdir(parents=True)
    key_path.write_bytes(b"-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n")

    assert ca_module._harden_with_icacls(key_path) is True
    assert calls == [
        [r"C:\Windows\System32\icacls.exe", str(key_path), "/inheritance:r", "/grant:r", "ALICE:(OI)(CI)(F)"]
    ]


def test_secure_acl_falls_back_to_user_name_when_username_is_absent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """`USERNAME` or `USER_NAME`: the second spelling is what a non-standard Windows shell exports."""
    calls = _fake_icacls(monkeypatch, found="icacls", username=None)
    monkeypatch.setenv("USER_NAME", "BOB")
    key_path = tmp_path / "ca_key.pem"
    key_path.write_bytes(b"-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n")

    assert ca_module._harden_with_icacls(key_path) is True
    assert calls[0][-1] == "BOB:(OI)(CI)(F)"


def test_missing_icacls_is_reported_and_init_continues(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """`icacls` absent (Home SKU, a stripped image): skip, say so in the log, and do not fail the init.

    `subprocess.run` is never reached, which is asserted by the empty argv list: the point of this arm is that an
    operator who passed `--secure-acl` on a host without the binary gets a working CA *and* a sentence explaining why
    the ACL part did not happen.
    """
    calls = _fake_icacls(monkeypatch, found=None, username="ALICE")
    with caplog.at_level(logging.INFO, logger="mypki.ca"):
        assert ca_module._harden_with_icacls(tmp_path / "ca_key.pem") is False

    assert calls == []
    assert any("icacls not found" in record.getMessage() for record in caplog.records)


def test_no_username_in_the_environment_skips_hardening(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A Windows process with neither `USERNAME` nor `USER_NAME` cannot be given a named grant.

    Refusing to guess (a `whoami` call, or `Everyone`) is the point: `(F)` granted to the wrong principal is worse than
    no hardening at all.
    """
    calls = _fake_icacls(monkeypatch, found="icacls", username=None)
    with caplog.at_level(logging.INFO, logger="mypki.ca"):
        assert ca_module._harden_with_icacls(tmp_path / "ca_key.pem") is False

    assert calls == []
    assert any("no username" in record.getMessage() for record in caplog.records)


@pytest.mark.parametrize(
    ("raiser", "expected_in_message"),
    [
        (subprocess.CalledProcessError(1, ["icacls"]), "icacls hardening did not run"),
        (OSError(13, "Permission denied"), "icacls hardening did not run"),
    ],
    ids=["nonzero-exit", "os-error"],
)
def test_icacls_failure_is_logged_and_never_propagates(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    raiser: Exception,
    expected_in_message: str,
) -> None:
    """A failing `icacls` is a sentence in the log and an init that still succeeds.

    Two different exception families because they come from different failures (the binary refused vs. the binary could
    not be executed), and both are swallowed for the same reason: an operator who asked for optional hardening should
    not lose a healthy CA because the optional step broke. The message names what did *not* happen rather than claiming
    success.
    """
    _fake_icacls(monkeypatch, found="icacls", username="ALICE", raiser=raiser)
    with caplog.at_level(logging.INFO, logger="mypki.ca"):
        assert ca_module._harden_with_icacls(tmp_path / "ca_key.pem") is False

    messages = [record.getMessage() for record in caplog.records]
    assert any(expected_in_message in message for message in messages)


@pytest.mark.skipif(not POSIX, reason="asserts a POSIX-only claim (page-map §8)")
def test_secure_acl_true_on_a_posix_host_logs_no_hardening_claim(
    data_root: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """`init_ca(secure_acl=True)` on Linux writes a working CA and never claims ACL hardening.

    This is the line an operator actually reaches for (`mypki init-ca --secure-acl` on the wrong platform, or in a
    copy-pasted runbook) and it must be harmless: page-map §8 promises `icacls` is skipped when absent, not that the
    command fails. The assertion that matters is the negative one -- no "icacls hardening applied" line was logged,
    because claiming it would be a lie about the ACLs on that key file.
    """
    with caplog.at_level(logging.INFO, logger="mypki.ca"):
        result = _init(data_root, secure_acl=True)

    assert paths.ca_key_path(data_root).read_bytes() == result.key_path.read_bytes()
    messages = [record.getMessage() for record in caplog.records]
    assert not any("icacls" in message for message in messages)


class _UnreadableKey:
    """A path-shaped stand-in whose `open()` always fails, so the lock-out arm runs on any OS.

    Needed because there is no portable way to make a file unreadable to its own owner: `chmod 000` denies the read on
    POSIX (MEASURED here: `PermissionError: [Errno 13]`) but on Windows `os.chmod` toggles only the read-only bit and
    the owner keeps reading it. Faking the OS instead would fake the very thing under test -- the re-open is what has
    to fail -- so the file object is what gets replaced. `_harden_with_icacls` uses exactly two members of its argument,
    `str()` and `open()`, and both are provided faithfully.
    """

    def __init__(self, path: Path) -> None:
        self._path = path

    def __str__(self) -> str:
        return str(self._path)

    def open(self, mode: str = "r", **kwargs: object) -> None:  # never returns; always raises
        raise PermissionError(13, "Permission denied", str(self._path))


def test_icacls_that_locks_out_this_process_is_reported_as_failed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """`icacls` succeeding is not the same as hardening working -- the re-open decides which happened.

    This is the arm that a real Windows 10 run proved was needed: `--secure-acl` reported
    `icacls hardening applied to ...ca_key.pem`, and the next read of that file raised
    `PermissionError: [Errno 13] Permission denied`. Returning True there would print a success claim about a key the
    CA can no longer use, and the operator would meet the problem later as "the private key is not loadable".
    """
    calls = _fake_icacls(monkeypatch, found="icacls", username="ALICE")
    unreadable = _UnreadableKey(tmp_path / "ca_key.pem")

    with caplog.at_level(logging.INFO, logger="mypki.ca"):
        assert ca_module._harden_with_icacls(unreadable) is False  # type: ignore[arg-type]

    assert len(calls) == 1, "icacls should have run -- the failure is what happens *after* it"
    messages = [record.getMessage() for record in caplog.records]
    assert any("unreadable by this process" in message for message in messages), messages
    assert not any("icacls hardening applied" in message for message in messages), messages


def test_icacls_success_is_reported_by_init_ca(
    data_root: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """When hardening really did run, `init_ca` says so -- and only then.

    The pair of tests this one completes is the log line itself: a silent success would leave an operator unable to
    tell "hardened" from "skipped because icacls was missing", which is exactly the ambiguity page-map §8's
    `Returns whether hardening was applied` exists to remove. `_harden_with_icacls` is replaced with a recorder here
    rather than driving the fake-Windows argv again -- that is the previous tests' job (STYLE §8).
    """
    monkeypatch.setattr(ca_module, "_harden_with_icacls", lambda key_path: True)
    with caplog.at_level(logging.INFO, logger="mypki.ca"):
        _init(data_root, secure_acl=True)

    messages = [record.getMessage() for record in caplog.records]
    applied = [m for m in messages if "icacls hardening applied" in m]
    assert len(applied) == 1, messages
    assert str(paths.ca_key_path(data_root)) in applied[0]
