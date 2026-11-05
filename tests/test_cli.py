"""The command line itself: `mypki init-ca`, `mypki serve`, `mypki info`, and the exit codes they promise.

Why a dedicated file for the CLI when `test_ca_init.py` already covers `init_ca`: the two layers make different
promises, and only one of them is a *contract*. `ca.py` promises X.509 and filesystem semantics; `cli.py` promises an
argv grammar, four exit codes (0/1/2/3 plus 130), warnings printed before a bind, and "no traceback for an expected
condition". A wrapper script or a systemd unit reads exactly those, and nothing in the module-level tests can catch the
day a refusal starts exiting 1 instead of 2.

This file is also where the CLI-only bugs live. **MEASURED:** writing it found that `mypki init-ca --key-type ec` had
never worked — `_ec_candidate("P-256")` produced `ec-256`, which is not in `ALLOWED_KEY_SPECS`, so every EC init failed
with exit 1 while all 349 existing tests stayed green. Nothing else in the suite drove that flag pair, because
everything else calls `KeySpec.from_string` directly. That is the argument for testing a CLI as a CLI: the bug was in
the translation layer between an operator's spelling and the policy module's spelling.

Hermeticity (STYLE §8): every test runs through `cli.main([...])` **in-process** with `MYPKI_DATA_DIR`,
`MYPKI_LOG_FILE`, `XDG_*` and `HOME` pointed at `tmp_path` by `conftest.py` plus the autouse fixture below. No test
spawns a subprocess, binds a port, or reads a developer's real data dir. `serve` never reaches a socket because
`uvicorn.Server` is replaced with a recorder — see `test_serve_happy_path`.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import io
import os
import stat
from pathlib import Path
from typing import Any

import pytest

from mypki import __version__, cli, csr, paths
from mypki.ca import CA_DIR_MODE, PRIVATE_FILE_MODE, InitCaResult, init_ca
from mypki.keys import KeySpec

POSIX = os.name == "posix"

#: A passphrase that satisfies `init-ca`'s own 12-character floor. Not a secret: it appears in no file this suite
#: writes outside `tmp_path`, and never in an assertion about program output.
PASSPHRASE = "a-cli-test-passphrase-not-a-real-one"


class RunResult:
    """One in-process CLI run: exit code plus both streams, captured rather than printed to the test log.

    `stdout`/`stderr` are kept separate on purpose. Half of the CLI's contract is *which* stream a message goes to —
    refusals and usage errors belong on stderr so `mypki info | grep subject` stays parseable, and the CA facts belong
    on stdout because page-map §6 says they are the output. A single combined buffer cannot assert either half.
    """

    def __init__(self, code: int, stdout: str, stderr: str) -> None:
        self.code = code
        self.stdout = stdout
        self.stderr = stderr

    @property
    def output(self) -> str:
        return self.stdout + self.stderr


def _expired_ca(data_root: Path, *, common_name: str) -> None:
    """Write a genuinely expired root CA to disk, as a real certificate with past dates.

    `init_ca(days=-4000)` cannot produce one: cryptography's builder refuses `notAfter <= notBefore` (MEASURED --
    ValueError "The not valid after date must be after the not valid before date"), and `init-ca --days` refuses 0 and
    below anyway. So the expired state has to be built by hand, which is also how an operator actually gets one: a root
    that simply aged in place. Only the dates are synthetic; the key and the signature are real.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID

    from mypki.keys import KeySpec, generate_key

    key = generate_key(KeySpec.from_string("ec-p256"))
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    retired = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=4000)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(retired - dt.timedelta(days=365))
        .not_valid_after(retired)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(private_key=key, algorithm=hashes.SHA256())
    )
    paths.ca_dir(data_root).mkdir(parents=True, exist_ok=True)
    paths.ca_cert_path(data_root).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    paths.ca_key_path(data_root).write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


@pytest.fixture(autouse=True)
def _cli_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """CLI-specific hermeticity on top of `conftest.py`'s fixtures.

    Two things `conftest.py` deliberately does not do for other files: pin `MYPKI_LOG_FILE` (its default is the
    relative `logs/mypki.log`, which would make every CLI test write into the repository's own `logs/` directory), and
    clear `MYPKI_CA_PASSPHRASE` *again* after any test that set it, so a passphrase cannot leak into the next run.
    """
    monkeypatch.setenv("MYPKI_LOG_FILE", str(tmp_path / "cli-logs" / "mypki.log"))
    monkeypatch.delenv("MYPKI_CA_PASSPHRASE", raising=False)
    monkeypatch.delenv("MYPKI_PORT", raising=False)
    monkeypatch.delenv("MYPKI_HOST", raising=False)
    monkeypatch.delenv("MYPKI_CA_CN", raising=False)


def _run(*argv: str) -> RunResult:
    """`cli.main(list(argv))` with both streams captured, and argparse's SystemExit folded into the same code space.

    `main()` returns an int; `--version` and a missing subcommand exit through `SystemExit` instead (MEASURED: no
    subcommand raises `SystemExit(2)` from argparse itself). Treating both as one integer is what lets a test assert
    "argparse's usage error is 2, mypki's refusal is 2, mypki's missing state is 3" without special-casing the plumbing.
    """
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main(list(argv))
        except SystemExit as exc:  # argparse's own exits land here
            code = 0 if exc.code is None else int(exc.code)
    return RunResult(code, out.getvalue(), err.getvalue())


def _init_ec(data_root: Path, **overrides: Any) -> InitCaResult:
    """A throwaway EC root written straight through `ca.init_ca`.

    EC rather than the RSA-3072 `throwaway_ca` fixture because this file creates a CA in most of its tests and P-256
    generation measures 0.002 s against 0.146 s for RSA-3072 (MEASURED on this box): same X.509 semantics, a fraction
    of the runtime, and `init-ca`'s EC flag pair is itself one of the things under test here.
    """
    options: dict[str, Any] = {
        "common_name": "mypki CLI Test CA",
        "organization": "mypki tests",
        "country": "XX",
        "spec": KeySpec.from_string("ec-p256"),
        "days": 3650,
    }
    options.update(overrides)
    return init_ca(data_root, **options)


#: One backslash. The doubled-separator tests need a path whose separators are *literally* doubled, and building them
#: by concatenation says that plainly instead of depending on how this file's own string literals get read.
BACKSLASH = "\\"


def _server_pair(tmp_path: Path, *, mismatch: bool = False, chain: bool = False) -> tuple[Path, Path]:
    r"""A **real** PEM certificate/key pair in `tmp_path`, for the TLS tests that now read file contents.

    0.4.0's TLS tests wrote `b"not a real certificate"` because `cli._tls_file_problem` only asked whether a path
    existed. 0.5.0 also parses what is inside, so the passing tests need material that actually parses and the failing
    tests need material that fails in one named way rather than in whichever way garbage happens to fail. EC P-256 for
    the same reason `_init_ec` exists: measured 0.002 s against 0.146 s for RSA-3072 on this box.

    `mismatch=True` writes a certificate whose public key belongs to a **different** key next to that other key -- the
    pair OpenSSL reports as `[X509: KEY_VALUES_MISMATCH]`. `chain=True` appends a second certificate after the leaf,
    because a leaf-plus-issuer in one file is ordinary and must still be accepted.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID

    from mypki.keys import generate_key, private_key_pem

    spec = KeySpec.from_string("ec-p256")
    key = generate_key(spec)
    other = generate_key(spec) if mismatch else key
    now = dt.datetime.now(dt.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "cli-tls-test.example")])

    def issued(signer: Any, subject_key: Any) -> bytes:
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(subject_key)
            .serial_number(11)
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=30))
            .sign(private_key=signer, algorithm=hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.PEM)

    body = issued(key, key.public_key())
    if chain:
        # A second certificate from the same key: ordinary leaf-plus-issuer bundling, which the content check must
        # tolerate rather than refuse as "two certificates where one was expected".
        body += issued(key, key.public_key())

    cert_path = tmp_path / "server.crt"
    key_path = tmp_path / "server.key"
    cert_path.write_bytes(body)
    key_path.write_bytes(private_key_pem(other))
    return cert_path, key_path


@pytest.fixture
def recording_server(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    """Replace `uvicorn.Server` with a recorder so `serve` can be tested without binding a port.

    Patching `uvicorn.Server` (and not `uvicorn.Config`) keeps the real config object under test: the assertion that
    matters is *what mypki hands uvicorn* — host, port, the numeric log level, `log_config=None`, and whether the TLS
    pair made it through. A fake Config would assert nothing at all, because those arguments are the whole point of
    `cmd_serve`. The real `Server.run()` is a blocking loop; leaving it live would hang the suite.
    """
    import uvicorn

    built: list[Any] = []

    class RecordingServer:
        def __init__(self, config: Any) -> None:
            self.config = config
            built.append(config)

        def run(self) -> None:
            return None

    monkeypatch.setattr(uvicorn, "Server", RecordingServer)
    return built


def _server_raising(monkeypatch: pytest.MonkeyPatch, error: BaseException) -> None:
    """A `serve` whose server fails at `run()`, for the two exits that depend on a bind failing."""
    import uvicorn

    class FailingServer:
        def __init__(self, config: Any) -> None:
            self.config = config

        def run(self) -> None:
            raise error

    monkeypatch.setattr(uvicorn, "Server", FailingServer)


# --------------------------------------------------------------------------------------------- init-ca: creation


def test_init_ca_creates_the_pair_and_exits_zero(tmp_path: Path) -> None:
    """The happy path, asserted as the operator sees it: exit 0 and a printed CA card (page-map §6)."""
    root = tmp_path / "data"
    result = _run("init-ca", "--data-dir", str(root), "--key-type", "ec")

    from mypki.config import get_settings

    assert result.code == cli.EXIT_OK
    assert "Created root CA." in result.stdout
    # The subject printed is `Settings.ca_cn`, read back from the model rather than written out here: a test that
    # hard-codes "mypki Root CA" is asserting a copy of a default it does not control (the same rule
    # tools/e2e_harness.py §3 follows for the version number).
    assert f"CN={get_settings().ca_cn}" in result.stdout
    assert "EC P-256" in result.stdout
    for name in ("ca_cert.pem", "ca_key.pem"):
        assert name in result.stdout


def test_init_ca_prints_only_public_facts(tmp_path: Path) -> None:
    """page-map §6: subject, serial, validity, fingerprint, key spec and paths -- and nothing else.

    Asserted against the certificate on disk rather than against fixed strings, so the test cannot drift into a copy
    of the output that stops matching reality. The negative half is the point: no PEM armour, no key bytes.
    """
    root = tmp_path / "data"
    _init_ec(root)

    result = _run("info", "--data-dir", str(root))
    cert_bytes = paths.ca_cert_path(root).read_bytes()

    assert result.code == cli.EXIT_OK
    assert "BEGIN CERTIFICATE" not in result.output
    assert "PRIVATE KEY" not in result.output
    assert cert_bytes.splitlines()[0].decode() not in result.output
    for label in ("subject", "serial", "valid (UTC)", "sha256 fingerprint", "key", "basic constraints"):
        assert label in result.stdout


def test_init_ca_reports_the_ec_curve_the_operator_asked_for(tmp_path: Path) -> None:
    """`--curve P-384` must reach the certificate, not merely parse.

    The measured bug this file was written to catch: `--key-type ec` formatted `ec-256`, which the allow-list does not
    contain, so the CLI refused its own accepted flag pair with exit 1. Asserting the *label* on stdout is what keeps
    the fix from regressing into a spec that parses but issues the wrong curve.
    """
    result = _run("init-ca", "--data-dir", str(tmp_path / "data"), "--key-type", "ec", "--curve", "P-384")

    assert result.code == cli.EXIT_OK
    assert "EC P-384" in result.stdout
    assert "ec-p256" not in result.output


def test_init_ca_accepts_the_rsa_sizes_the_allow_list_advertises(tmp_path: Path) -> None:
    """`--key-size 2048` is legal and must be reported as the key that was made."""
    result = _run("init-ca", "--data-dir", str(tmp_path / "data"), "--key-size", "2048")

    assert result.code == cli.EXIT_OK
    assert "RSA 2048" in result.stdout


def test_init_ca_writes_nothing_to_the_database(tmp_path: Path) -> None:
    """page-map §6: `init-ca` writes the key pair and *only* the key pair.

    A CA creation that also opened the issued-certificate database would make `init-ca` depend on SQLite and leave an
    empty `issued.db` behind on a host that never signed anything -- two things a backup script has to reason about,
    neither of them asked for.
    """
    root = tmp_path / "data"
    _run("init-ca", "--data-dir", str(root))

    assert not paths.db_path(root).exists()


# --------------------------------------------------------------------------------- init-ca: refusals and exits


def test_init_ca_refuses_to_overwrite_and_names_the_flag(tmp_path: Path) -> None:
    """Exit **2**, on stderr, quoting the existing file and `--force` (page-map §6, README exit codes).

    The exit code is the contract a wrapper script reads: "already there" must be distinguishable from "broke", and
    the message has to carry the override rather than make the operator guess at one.
    """
    root = tmp_path / "data"
    _init_ec(root)
    first = paths.ca_cert_path(root).read_bytes()

    result = _run("init-ca", "--data-dir", str(root))

    assert result.code == cli.EXIT_REFUSED
    assert "refused:" in result.stderr
    assert "--force" in result.stderr
    assert paths.ca_cert_path(root).name in result.stderr
    assert paths.ca_cert_path(root).read_bytes() == first, "nothing was overwritten"


def test_init_ca_refuses_when_only_the_key_exists(tmp_path: Path) -> None:
    """Half a CA is still a refusal.

    One mutation from the previous test: the certificate is gone and the key is not. The pair is what makes a CA, so
    silently minting a new certificate next to an orphaned key would produce a host whose `load_ca` fails chain checks
    later (README gotcha 1).
    """
    root = tmp_path / "data"
    _init_ec(root)
    paths.ca_cert_path(root).unlink()

    result = _run("init-ca", "--data-dir", str(root))

    assert result.code == cli.EXIT_REFUSED
    assert paths.ca_key_path(root).name in result.stderr


def test_force_archives_the_old_pair_instead_of_deleting_it(tmp_path: Path) -> None:
    """`--force` moves the pair into `ca/archive/<UTC-stamp>/`; nothing is destroyed (page-map §6)."""
    root = tmp_path / "data"
    _init_ec(root, common_name="Original CLI CA")
    old_cert = paths.ca_cert_path(root).read_bytes()
    old_key = paths.ca_key_path(root).read_bytes()

    result = _run("init-ca", "--data-dir", str(root), "--force", "--common-name", "Replacement CLI CA")

    assert result.code == cli.EXIT_OK
    archives = list(paths.ca_dir(root).joinpath("archive").iterdir())
    assert len(archives) == 1, archives
    archived = archives[0]
    assert (archived / "ca_cert.pem").read_bytes() == old_cert
    assert (archived / "ca_key.pem").read_bytes() == old_key
    assert paths.ca_cert_path(root).read_bytes() != old_cert, "a new pair was created"
    assert "archived to" in result.stdout and "nothing was deleted" in result.stdout


def test_two_forced_inits_in_the_same_second_do_not_merge(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The archive name carries a counter, so two forced re-inits stay two histories.

    The stamp has second resolution (page-map §6), and a real pair of `--force` runs usually lands in *different*
    seconds -- which is why this test pins `_utc_stamp` to one constant value instead of racing the clock. Without the
    collision the counter branch never executes and the test would pass while proving nothing; with it, the second
    archive has to be named `<stamp>-1`, because two CA histories cannot share one directory: `shutil.move` would
    overwrite the first archived key with the second, and an archive that quietly loses a key is worse than no archive.
    """
    from mypki import ca as ca_module

    monkeypatch.setattr(ca_module, "_utc_stamp", lambda: "20300101T000000Z")
    root = tmp_path / "data"
    _init_ec(root, common_name="First CA")
    first_key = paths.ca_key_path(root).read_bytes()

    _run("init-ca", "--data-dir", str(root), "--force", "--common-name", "Second CA")
    second_key = paths.ca_key_path(root).read_bytes()
    _run("init-ca", "--data-dir", str(root), "--force", "--common-name", "Third CA")

    archives = sorted(name.name for name in paths.ca_dir(root).joinpath("archive").iterdir())
    assert archives == ["20300101T000000Z", "20300101T000000Z-1"], archives
    archived = paths.ca_dir(root).joinpath("archive")
    keys = sorted((archived / name / "ca_key.pem").read_bytes() for name in archives)
    assert keys == sorted([first_key, second_key]), "neither archived key was overwritten"


@pytest.mark.skipif(not POSIX, reason="POSIX mode bits do not exist on Windows (page-map §8)")
def test_init_ca_leaves_the_key_owner_only_on_posix(tmp_path: Path) -> None:
    """0600 on the key, 0700 on `ca/` -- measured after the CLI ran, not asserted from the source."""
    root = tmp_path / "data"
    _run("init-ca", "--data-dir", str(root))

    key_mode = stat.S_IMODE(paths.ca_key_path(root).stat().st_mode)
    dir_mode = stat.S_IMODE(paths.ca_dir(root).stat().st_mode)
    assert key_mode == PRIVATE_FILE_MODE, oct(key_mode)
    assert dir_mode == CA_DIR_MODE, oct(dir_mode)


@pytest.mark.skipif(not POSIX, reason="POSIX mode bits do not exist on Windows (page-map §8)")
def test_init_ca_maps_a_world_readable_key_to_exit_one(tmp_path: Path) -> None:
    """`ca.py`'s mode assertion is a usage error to the CLI, not a traceback (page-map §6).

    Synthetic by necessity: `_write_private_file` chmods to 0600 and re-stats, so a normal filesystem cannot produce a
    group-readable key here. Replacing that one helper with a version that writes 0644 is the mutation that reaches the
    `except (OSError, RuntimeError)` arm in `cmd_init_ca`, which is what an operator on a FAT/exFAT data dir hits.
    """
    from mypki import ca as ca_module

    def sloppy_write(path: Path, data: bytes) -> None:
        """A `_write_private_file` whose chmod did not stick, then the module's own re-stat.

        Writing 0644 is only half the state worth reproducing -- what `ca.py` guards against is a filesystem that
        ignores `os.chmod` (FAT/exFAT) or an ACL inherited from the parent directory. Running `_assert_private_mode`
        afterwards is what turns that state into the `RuntimeError` `cmd_init_ca` has to map, rather than into a
        silently world-readable key every later test would still pass on.
        """
        path.write_bytes(data)
        os.chmod(str(path), 0o644)
        ca_module._assert_private_mode(path)

    monkey = pytest.MonkeyPatch()
    monkey.setattr(ca_module, "_write_private_file", sloppy_write)
    try:
        result = _run("init-ca", "--data-dir", str(tmp_path / "data"))
    finally:
        monkey.undo()

    assert result.code == cli.EXIT_USAGE
    assert "group/other-accessible" in result.stderr
    assert "Traceback" not in result.stderr


@pytest.mark.skipif(not POSIX, reason="POSIX mode bits do not exist on Windows (page-map §8)")
def test_init_ca_reports_an_unwritable_data_dir_as_exit_one(tmp_path: Path) -> None:
    """A read-only data dir is a fixable operator problem: exit 1, one line, no traceback."""
    root = tmp_path / "data"
    root.mkdir()
    os.chmod(str(root), 0o500)  # r-x: mkdir under it raises PermissionError
    try:
        result = _run("init-ca", "--data-dir", str(root))
    finally:
        os.chmod(str(root), 0o700)

    assert result.code == cli.EXIT_USAGE
    assert "error:" in result.stderr
    assert "Traceback" not in result.stderr


def test_init_ca_rejects_a_key_size_outside_the_allow_list(tmp_path: Path) -> None:
    """`--key-size 1024` fails with the accepted list, before any key is generated (page-map §2)."""
    result = _run("init-ca", "--data-dir", str(tmp_path / "data"), "--key-size", "1024")

    assert result.code == cli.EXIT_USAGE
    assert "rsa-1024" in result.stderr
    for allowed in ("rsa-2048", "rsa-3072", "ec-p256"):
        assert allowed in result.stderr
    assert not paths.ca_key_path(tmp_path / "data").exists(), "no key was generated for a rejected spec"


def test_init_ca_rejects_a_zero_day_validity(tmp_path: Path) -> None:
    """`--days 0` is refused naming the floor, rather than producing an already-expired root."""
    result = _run("init-ca", "--data-dir", str(tmp_path / "data"), "--days", "0")

    assert result.code == cli.EXIT_USAGE
    assert "--days must be at least 1" in result.stderr


def test_init_ca_rejects_a_three_letter_country(tmp_path: Path) -> None:
    """`C=` is ISO 3166-1 alpha-2; "DEU" encodes fine and every client that reads it disagrees (page-map §2)."""
    result = _run("init-ca", "--data-dir", str(tmp_path / "data"), "--country", "DEU")

    assert result.code == cli.EXIT_USAGE
    assert "exactly two letters" in result.stderr


def test_init_ca_uppercases_a_two_letter_country(tmp_path: Path) -> None:
    """`--country xx` is accepted and lands in the certificate as `C=XX`."""
    root = tmp_path / "data"
    result = _run("init-ca", "--data-dir", str(root), "--key-type", "ec", "--country", "xx")

    assert result.code == cli.EXIT_OK
    assert "C=XX" in result.stdout


def test_init_ca_reports_a_bad_log_level_as_a_config_error(tmp_path: Path) -> None:
    """The logging flags exist on every subcommand, and a typo is a startup error (page-map §11).

    `MYPKI_LOG_LEVEL=INFP` or `--log-level INFD` must not produce a CA that quietly logs nothing at the level the
    operator asked for -- that is discovered during an incident rather than at startup.
    """
    result = _run("init-ca", "--data-dir", str(tmp_path / "data"), "--log-level", "INFD")

    assert result.code == cli.EXIT_USAGE
    assert "config error" in result.stderr
    assert "log_level must be one of" in result.stderr


def test_log_level_reaches_init_ca_and_not_only_serve(tmp_path: Path) -> None:
    """`--log-level` on `init-ca` changes what `init-ca` logs; the same flag exists on all three commands.

    Wiring the logging flags only to `serve` would make them unreachable exactly when they are needed -- a failing
    `init-ca` is the command an operator runs when something is already wrong. Asserted by suppression rather than by
    looking for DEBUG output: mypki emits no DEBUG lines today (MEASURED: no `log.debug` call exists in `src/`), so
    "DEBUG produces a DEBUG line" would be an assertion about nothing. `--log-level ERROR` silences the INFO startup
    line, which is observable, and the default run right after it proves the silence was caused by the flag.
    """
    quiet = _run("init-ca", "--data-dir", str(tmp_path / "quiet"), "--key-type", "ec", "--log-level", "ERROR")
    loud = _run("init-ca", "--data-dir", str(tmp_path / "loud"), "--key-type", "ec")

    assert quiet.code == cli.EXIT_OK
    assert loud.code == cli.EXIT_OK
    assert "INFO" not in quiet.stderr, "the flag did not reach the root logger"
    assert "INFO" in loud.stderr


# ------------------------------------------------------------------------------------ init-ca: passphrase rules


def _encrypted_ca(root: Path, monkeypatch: pytest.MonkeyPatch, passphrase: str = PASSPHRASE) -> None:
    """Create an encrypted throwaway CA through the CLI, with the passphrase supplied by the named env var.

    Env-var rather than prompt because tests that then run `serve`/`info` need a *known number of
    remaining prompts*; exhausting a fake `getpass` iterator raises StopIteration inside the code under
    test and reads as a crash in `cli.py` rather than as a fixture running out.
    """
    monkeypatch.setenv("MYPKI_CA_PASSPHRASE", passphrase)
    created = _run("init-ca", "--data-dir", str(root), "--key-type", "ec", "--encrypt")
    assert created.code == cli.EXIT_OK
    assert b"ENCRYPTED PRIVATE KEY" in paths.ca_key_path(root).read_bytes()


def test_encrypt_reads_the_passphrase_from_the_named_env_var(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`--encrypt --passphrase-env NAME` produces an encrypted key and says where the passphrase came from.

    The message names the variable and nothing else -- never the value, and not even its length (page-map §6).
    """
    monkeypatch.setenv("MYPKI_TEST_CA_PASS", PASSPHRASE)
    root = tmp_path / "data"

    result = _run(
        "init-ca",
        "--data-dir",
        str(root),
        "--key-type",
        "ec",
        "--encrypt",
        "--passphrase-env",
        "MYPKI_TEST_CA_PASS",
    )

    assert result.code == cli.EXIT_OK
    assert "$MYPKI_TEST_CA_PASS" in result.stdout
    assert PASSPHRASE not in result.output
    assert b"ENCRYPTED PRIVATE KEY" in paths.ca_key_path(root).read_bytes()
    assert "(encrypted with a passphrase)" in result.stdout


def test_encrypted_key_never_contains_the_passphrase_as_plain_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The file on disk is PKCS#8-encrypted; the passphrase is not recoverable by reading it.

    A cheap check with a high value: if `--encrypt` ever regressed to emitting a plain key while *reporting* an
    encrypted one, this fails on the bytes rather than on the message (README gotcha 1).
    """
    monkeypatch.setenv("MYPKI_CA_PASSPHRASE", PASSPHRASE)
    root = tmp_path / "data"
    _run("init-ca", "--data-dir", str(root), "--key-type", "ec", "--encrypt")

    raw = paths.ca_key_path(root).read_bytes()
    assert b"ENCRYPTED PRIVATE KEY" in raw
    assert PASSPHRASE.encode() not in raw


def test_a_short_prompted_passphrase_is_refused_naming_the_floor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Under `PASSPHRASE_MIN_LENGTH` is refused rather than accepted into a barely-protected file.

    The floor is 8 as of 0.2.0 and the CLI imports it from `csr.py` rather than restating it (cli._passphrase_for_init):
    the web form and this prompt are one rule in two surfaces, and a test that hard-coded "12" would be a third copy of
    a number this project already decided once. Both numbers appear in the refusal because the operator has to know what
    is enforced *and* what is better.
    """
    answers = iter(["short"])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(answers))

    result = _run("init-ca", "--data-dir", str(tmp_path / "data"), "--key-type", "ec", "--encrypt")

    assert result.code == cli.EXIT_USAGE
    assert f"at least {csr.PASSPHRASE_MIN_LENGTH} characters" in result.stderr
    assert f"{csr.PASSPHRASE_RECOMMENDED_LENGTH} or more is better" in result.stderr
    # Refused means nothing was written: no half-encrypted key sitting in the data dir.
    assert not paths.ca_key_path(tmp_path / "data").exists()


def test_a_prompted_passphrase_between_the_floor_and_the_recommendation_warns_and_succeeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """9 characters creates the CA **and** prints the 12-or-more advisory (csr.passphrase_advisory).

    The pair of facts is the point: mypki enforces 8 and recommends 12, so a 9-character passphrase must not be refused
    (that would make the floor a lie) and must not pass silently either (that would make the recommendation a lie). The
    advisory names the *length* and never the value, which is asserted here because this is the surface where an
    operator typed the value into a terminal and a careless message would repeat it back into the shell's scrollback.
    """
    short = "123456789"  # above the floor, below the recommendation
    assert csr.PASSPHRASE_MIN_LENGTH <= len(short) < csr.PASSPHRASE_RECOMMENDED_LENGTH

    answers = iter([short, short])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(answers))

    result = _run("init-ca", "--data-dir", str(tmp_path / "data"), "--key-type", "ec", "--encrypt")

    assert result.code == cli.EXIT_OK, result.output
    assert f"warning: A {len(short)}-character passphrase is accepted" in result.stderr
    assert f"{csr.PASSPHRASE_RECOMMENDED_LENGTH} or more is better" in result.stderr
    # The advisory names a length and not a value.
    assert short not in result.stderr
    assert paths.ca_key_path(tmp_path / "data").exists()


def test_an_env_passphrase_below_the_recommendation_warns_without_naming_its_length(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The `MYPKI_CA_PASSPHRASE` path warns with a fixed sentence, because naming the length would leak it.

    Deliberately different from the prompted path (cli.py explains why): on a prompt the operator just typed the value
    in front of themselves, so its length is already public information in their own terminal. An env-sourced secret's
    length is not — printing "that passphrase is 9 characters" puts a fact about a secret into stdout/stderr, and
    therefore into whatever captured this command's output (a CI log, a support transcript). The warning is the same
    advice with the number of the *recommendation* in it rather than the number of the secret.
    """
    short = "123456789"
    monkeypatch.setenv("MYPKI_CA_PASSPHRASE", short)

    result = _run("init-ca", "--data-dir", str(tmp_path / "data"), "--key-type", "ec", "--encrypt")

    assert result.code == cli.EXIT_OK, result.output
    assert f"shorter than {csr.PASSPHRASE_RECOMMENDED_LENGTH} characters" in result.stderr
    # The length of the env value never reaches either stream, and neither does the value itself.
    assert f"{len(short)}-character" not in result.output
    assert short not in result.output
    assert paths.ca_key_path(tmp_path / "data").exists()


def test_two_mismatched_prompted_passphrases_are_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The confirmation prompt is a real check, and its failure names itself."""
    answers = iter([PASSPHRASE, PASSPHRASE + " but not the same"])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(answers))

    result = _run("init-ca", "--data-dir", str(tmp_path / "data"), "--key-type", "ec", "--encrypt")

    assert result.code == cli.EXIT_USAGE
    assert "do not match" in result.stderr
    assert not paths.ca_key_path(tmp_path / "data").exists()


def test_prompted_passphrase_round_trips_through_the_cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A CA created by prompting is usable by the same CLI -- the encryption is not a one-way door.

    `init-ca` prompts (no env var set); `info` then decrypts using the env var. Both halves are asserted in one test
    because the pair *is* the feature: an encrypted CA nobody can load is a worse outcome than an unencrypted one,
    since it looks like a lost key.
    """
    answers = iter([PASSPHRASE, PASSPHRASE])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(answers))
    root = tmp_path / "data"

    created = _run("init-ca", "--data-dir", str(root), "--key-type", "ec", "--encrypt")
    assert created.code == cli.EXIT_OK
    assert b"ENCRYPTED PRIVATE KEY" in paths.ca_key_path(root).read_bytes()

    monkeypatch.setenv("MYPKI_CA_PASSPHRASE", PASSPHRASE)
    info = _run("info", "--data-dir", str(root))

    assert info.code == cli.EXIT_OK
    assert "private key        " in info.stdout
    assert "(present)" in info.stdout


def test_wrong_passphrase_exits_three_and_names_the_env_var(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Exit **3** for undecryptable state, with the variable to fix and no secret quoted (page-map §6, §8)."""
    root = tmp_path / "data"
    _encrypted_ca(root, monkeypatch)

    monkeypatch.setenv("MYPKI_CA_PASSPHRASE", "wrong-but-well-formed-passphrase-value")
    result = _run("info", "--data-dir", str(root))

    assert result.code == cli.EXIT_MISSING_STATE
    assert "MYPKI_CA_PASSPHRASE" in result.stderr
    assert PASSPHRASE not in result.output


def test_info_does_not_prompt_for_an_unencrypted_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """No prompt when there is nothing to decrypt -- `info` on an ordinary CA must never block.

    A prompt that fires unconditionally turns `mypki info` in a cron job into a process that waits forever for input
    it will never receive.
    """
    called: list[str] = []
    monkeypatch.setattr("getpass.getpass", lambda prompt="": called.append(prompt) or "")

    root = tmp_path / "data"
    _init_ec(root)
    result = _run("info", "--data-dir", str(root))

    assert result.code == cli.EXIT_OK
    assert called == []


def test_info_prompts_for_an_encrypted_key_when_no_env_var_is_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The interactive route for the encrypted case: `info` asks rather than failing (page-map §6)."""
    root = tmp_path / "data"
    _encrypted_ca(root, monkeypatch)
    monkeypatch.delenv("MYPKI_CA_PASSPHRASE")
    monkeypatch.setattr("getpass.getpass", lambda prompt="": PASSPHRASE)

    result = _run("info", "--data-dir", str(root))

    assert result.code == cli.EXIT_OK
    assert "(present)" in result.stdout


# ------------------------------------------------------------------------------------------------------ serve


def test_serve_exits_three_when_there_is_no_ca(tmp_path: Path) -> None:
    """page-map §6: "run `mypki init-ca` first", exit 3, and nothing bound."""
    result = _run("serve", "--data-dir", str(tmp_path / "nope"), "--port", "8443")

    assert result.code == cli.EXIT_MISSING_STATE
    assert "cannot serve" in result.stderr
    assert "init-ca" in result.stderr


def test_serve_exits_three_when_the_key_is_undecryptable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The CA is there and this host cannot use it -- also exit 3, with a different sentence.

    Distinct from "no CA": the certificate exists, so `/` could answer, but nothing could be signed. The message says
    which of the two fixes applies (`--force`, or supply the passphrase).
    """
    root = tmp_path / "data"
    _encrypted_ca(root, monkeypatch)
    monkeypatch.delenv("MYPKI_CA_PASSPHRASE")
    # `serve` finds an encrypted key with no env var and prompts (page-map §6); this is the wrong answer to that prompt.
    monkeypatch.setattr("getpass.getpass", lambda prompt="": "wrong-but-well-formed-passphrase-value")

    result = _run("serve", "--data-dir", str(root), "--port", "8443")

    assert result.code == cli.EXIT_MISSING_STATE
    assert "could not be decrypted" in result.stderr


def test_serve_exits_three_when_the_key_file_is_absent(tmp_path: Path) -> None:
    """A CA with no key at all is refused by `serve`, even though the pages could render."""
    root = tmp_path / "data"
    _init_ec(root)
    paths.ca_key_path(root).unlink()

    result = _run("serve", "--data-dir", str(root), "--port", "8443")

    assert result.code == cli.EXIT_MISSING_STATE
    assert "private key is not loadable" in result.stderr


def test_serve_data_dir_precedence_flag_then_env_then_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`--data-dir` > `MYPKI_DATA_DIR` > OS default, proven by which path the refusal names (page-map §8).

    Run three times against three *different* empty directories: the failure message carries the resolved certificate
    path, so the precedence is observable without a CA in any of them and without a port being bound. The default arm
    resolves through `XDG_DATA_HOME`, which `conftest.py` pins at `tmp_path` -- on an unpinned machine this test would
    be asserting against a developer's real data dir, which is the definition of a non-hermetic test.
    """
    flag_dir = tmp_path / "flag"
    env_dir = tmp_path / "env"
    xdg_home = tmp_path / "xdg-data"
    monkeypatch.setenv("XDG_DATA_HOME", str(xdg_home))
    monkeypatch.setenv(paths.DATA_DIR_ENV, str(env_dir))

    with_flag = _run("serve", "--data-dir", str(flag_dir), "--port", "8443")
    assert str(paths.ca_cert_path(flag_dir)) in with_flag.stderr
    assert str(env_dir) not in with_flag.stderr

    from_env = _run("serve", "--port", "8443")
    assert str(paths.ca_cert_path(env_dir)) in from_env.stderr

    from mypki.config import get_settings

    monkeypatch.delenv(paths.DATA_DIR_ENV)
    # `get_settings()` is `lru_cache`d for the lifetime of the process (config.py), and this test changes
    # `MYPKI_DATA_DIR` *inside* one test. Clearing it is what lets the third arm read the environment again; without
    # the clear the run would reuse the Settings object the second arm built -- precisely the "a CLI override became
    # global state" behaviour `settings_with_cli_overrides` documents as undesirable. A real operator gets one Settings
    # per process, so this is a test-only necessity, and naming it here keeps it from looking like production advice.
    get_settings.cache_clear()
    from_default = _run("serve", "--port", "8443")
    # The default arm is OS-specific by design (page-map §8): XDG on POSIX, %LOCALAPPDATA% on Windows. conftest.py
    # pins *both* spellings inside tmp_path, so the assertion names whichever one this host legitimately resolves.
    # **MEASURED on a real Windows 10 host:** the previous version hardcoded the XDG path while mypki correctly
    # resolved `%LOCALAPPDATA%\\mypki` -- the test was wrong about the machine it ran on, not the resolver.
    expected_default = xdg_home if POSIX else tmp_path / "localappdata"
    assert str(paths.ca_cert_path(expected_default / paths.APP_DIR_NAME)) in from_default.stderr


def test_serve_treats_an_empty_data_dir_env_as_unset(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`MYPKI_DATA_DIR=` is an operator asking for the default, not for the current directory (page-map §8).

    The failure this prevents is the exact one `paths.py` exists to prevent: an empty value becoming `Path("")`, which
    resolves to cwd and would put a CA key inside whatever directory the service happens to run from.
    """
    xdg_home = tmp_path / "xdg-data"
    monkeypatch.setenv("XDG_DATA_HOME", str(xdg_home))
    monkeypatch.setenv(paths.DATA_DIR_ENV, "   ")
    result = _run("serve", "--port", "8443")

    assert result.code == cli.EXIT_MISSING_STATE
    expected_default = xdg_home if POSIX else tmp_path / "localappdata"
    assert str(paths.ca_cert_path(expected_default / paths.APP_DIR_NAME)) in result.stderr
    # The assertion is about the *data dir* line, not about every appearance of the cwd: `configure_logging` prints
    # `cwd=...` on purpose (page-map §11). What must never appear is a data dir resolved to the current directory.
    assert f"data dir {Path.cwd()}" not in result.stderr


def test_serve_happy_path_builds_uvicorn_config_from_settings(tmp_path: Path, recording_server: list[Any]) -> None:
    """The bind-free `serve`: banner printed, app built, and uvicorn handed exactly what mypki promises.

    `log_config is None` is asserted because it is load-bearing (see `logsetup.py` measured behaviour 2): uvicorn's own
    dictConfig sets `propagate=False` on the `uvicorn` logger, so every server line would skip the rotating file. A
    refactor that "tidies up" that argument fails here rather than in a log that is missing lines.
    """
    root = tmp_path / "data"
    _init_ec(root)

    result = _run("serve", "--data-dir", str(root), "--host", "127.0.0.1", "--port", "8443")

    assert result.code == cli.EXIT_OK
    assert f"mypki {__version__} serving http://127.0.0.1:8443" in result.stdout
    assert str(root) in result.stdout
    assert len(recording_server) == 1
    config = recording_server[0]
    assert config.host == "127.0.0.1"
    assert config.port == 8443
    assert config.log_config is None
    assert config.log_level == "info"
    assert config.is_ssl is False


def test_serve_warns_in_plain_http_and_not_at_all_with_tls(tmp_path: Path, recording_server: list[Any]) -> None:
    """The plain-HTTP warning appears exactly when TLS is absent (page-map §0, §6)."""
    root = tmp_path / "data"
    _init_ec(root)

    plain = _run("serve", "--data-dir", str(root), "--port", "8443")
    assert "WARNING: plain HTTP" in plain.stdout
    assert "session cookie cannot be Secure" in plain.stdout

    # The banner's advice is asserted because it is a claim about how to deploy this honestly. Until 0.5.0 it ended
    # 'run nginx/Caddy/IIS in front of this localhost-only origin', which was true only of the default bind and hid the
    # consequence: with TLS terminated at a proxy, `tls_enabled` is False here, so `https_only` is False and Secure has
    # to be set at the proxy. `.env.example` says the same thing above the two knobs it documents, and STYLE §1's
    # single-source rule makes a banner that contradicts it a defect rather than a wording preference.
    assert "terminate TLS there" in plain.stdout
    assert "localhost-only" not in plain.stdout

    # Real PEM material from 0.5.0 on: `_tls_file_problem` parses the pair, so a banner test can no longer hand it
    # junk and still expect to reach the banner.
    cert, key = _server_pair(tmp_path)
    secure = _run("serve", "--data-dir", str(root), "--port", "8443", "--ssl-cert", str(cert), "--ssl-key", str(key))

    assert secure.code == cli.EXIT_OK
    assert "WARNING: plain HTTP" not in secure.stdout
    assert "https://127.0.0.1:8443" in secure.stdout
    assert recording_server[-1].ssl_certfile == str(cert)
    assert recording_server[-1].ssl_keyfile == str(key)


def test_serve_warns_about_half_configured_tls(tmp_path: Path, recording_server: list[Any]) -> None:
    """`--ssl-cert` without `--ssl-key` is *not* TLS: the plain-HTTP warning must still print.

    `Settings.tls_enabled` requires both files (see `config.py`). Accepting half a TLS configuration would make the
    banner and the session cookie's `https_only` disagree about which mode the process is in, and uvicorn would fail at
    bind time with an error that reads like a file-permission problem.
    """
    root = tmp_path / "data"
    _init_ec(root)
    cert = tmp_path / "server.crt"
    cert.write_bytes(b"not a real certificate")

    result = _run("serve", "--data-dir", str(root), "--port", "8443", "--ssl-cert", str(cert))

    assert result.code == cli.EXIT_OK
    # `Settings.tls_enabled` requires **both** files (config.py), so mypki still calls this plain HTTP and says so.
    # uvicorn's own `Config.is_ssl` is True on a certfile alone (MEASURED on 0.54.0), which is exactly why the half set
    # must be judged here rather than handed to uvicorn to interpret; `ssl_keyfile is None` is what actually reached it.
    assert "WARNING: plain HTTP" in result.stdout
    # `Settings.tls_enabled` requires **both** files (config.py), and `cmd_serve` forwards the pair to uvicorn only when
    # both are set -- so a cert without a key reaches uvicorn as *no TLS at all*. That is deliberate: uvicorn's own
    # `Config.is_ssl` is True on a certfile alone (MEASURED on 0.54.0), which is exactly why the half set must be judged
    # here rather than handed downstream for interpretation.
    assert recording_server[-1].ssl_certfile is None
    assert recording_server[-1].ssl_keyfile is None


def test_serve_refuses_a_missing_tls_cert_naming_the_knob_and_path(tmp_path: Path, recording_server: list[Any]) -> None:
    """A TLS path that does not exist is exit 1 naming the knob, not a bind error (0.4.0 pre-flight).

    **MEASURED before this check existed** (reproduced on Linux at /tmp/sslprobe, and reported from a real Windows 10
    host): with both knobs set and a path that does not exist, uvicorn raised `FileNotFoundError` while building its SSL
    context, the bind never happened, and `cmd_serve`'s `except OSError` printed
    `error: cannot bind 0.0.0.0:8443: [Errno 2] No such file or directory`. The operator was sent looking for a process
    holding the port. Here the message names the knob and the path instead, and uvicorn is never reached at all.
    """
    root = tmp_path / "data"
    _init_ec(root)
    missing = tmp_path / "www" / "server.crt"

    result = _run(
        "serve",
        "--data-dir",
        str(root),
        "--port",
        "8443",
        "--ssl-cert",
        str(missing),
        "--ssl-key",
        str(tmp_path / "server.key"),
    )

    assert result.code == cli.EXIT_USAGE
    assert "MYPKI_SSL_CERTFILE" in result.stderr
    assert str(missing) in result.stderr
    assert "does not exist" in result.stderr
    # The misleading sentence this check exists to replace.
    assert "cannot bind" not in result.stderr
    assert "never bound" not in result.stderr
    assert recording_server == []


def test_serve_refuses_a_missing_tls_key_naming_the_knob_and_path(tmp_path: Path, recording_server: list[Any]) -> None:
    """The key half gets the same treatment as the cert half: which knob, and which path."""
    root = tmp_path / "data"
    _init_ec(root)
    cert = tmp_path / "server.crt"
    cert.write_bytes(b"not a real certificate")
    missing = tmp_path / "www" / "server.key"

    result = _run(
        "serve",
        "--data-dir",
        str(root),
        "--port",
        "8443",
        "--ssl-cert",
        str(cert),
        "--ssl-key",
        str(missing),
    )

    assert result.code == cli.EXIT_USAGE
    assert "MYPKI_SSL_KEYFILE" in result.stderr
    assert str(missing) in result.stderr
    assert "MYPKI_SSL_CERTFILE" not in result.stderr
    assert recording_server == []


def test_serve_names_doubled_separators_written_on_the_command_line(
    tmp_path: Path, recording_server: list[Any]
) -> None:
    r"""The doubled-separator hint is judged on the **text the operator wrote**, never on a `Path`.

    This replaces a test that could only ever pass on POSIX. The old one built
    `tmp_path / "doubled\\path.crt"`, which on POSIX is a filename holding two literal backslashes, so `str(path)`
    contained a doubled separator and the hint fired. On Windows pathlib *collapses* doubled separators before anything
    can look at them -- MEASURED on this box (/tmp/probe5.py): `str(PureWindowsPath("C:\\root_apps\\server.crt"))` is
    `C:\root_apps\server.crt`, while `PurePosixPath` of the same string keeps them doubled -- so the hint was
    unreachable on the OS where the mistake is actually made. Doubled forward slashes were never reachable either:
    MEASURED, `str(PurePosixPath("/tmp//d//x.crt"))` is `/tmp/d/x.crt`. Either way the old assertion measured
    pathlib's POSIX flavour rather than anything mypki does.

    The fix lives in `config.Settings._keep_raw_ssl_spellings`, which records the configured text before `Path` gets
    it, and `cli._separator_hint` reads that. This doubled path is spelled identically on both platforms and resolves
    to a file that exists on neither.
    """
    root = tmp_path / "data"
    _init_ec(root)
    doubled = "C:" + BACKSLASH * 2 + "root_apps" + BACKSLASH * 2 + "mypki-data" + BACKSLASH * 2 + "www"
    doubled += BACKSLASH * 2 + "server.crt"

    result = _run(
        "serve",
        "--data-dir",
        str(root),
        "--port",
        "8443",
        "--ssl-cert",
        doubled,
        "--ssl-key",
        str(tmp_path / "server.key"),
    )

    assert result.code == cli.EXIT_USAGE
    assert "MYPKI_SSL_CERTFILE" in result.stderr
    assert "does not exist" in result.stderr
    assert "doubled separators" in result.stderr
    assert "forward slashes" in result.stderr
    # The spelling the operator typed is quoted back to them, because on Windows the resolved path printed just above
    # it is a *different* string containing no doubled separator at all. That extra line only appears when pathlib has
    # actually rewritten something, which is why the assertion is conditional rather than unconditional: asserting it
    # here would be another POSIX-shaped test.
    assert doubled in result.stderr
    if doubled != str(Path(doubled)):
        assert "You configured it as" in result.stderr
    assert "cannot bind" not in result.stderr
    assert recording_server == []


@pytest.mark.parametrize(
    "knob, value",
    [
        # The spelling an operator actually produces: a saved `/settings` line or an exported variable, doubled by an
        # escaping layer. Both knobs and both separator flavours are covered.
        (
            "MYPKI_SSL_CERTFILE",
            "C:" + BACKSLASH * 2 + "root_apps" + BACKSLASH * 2 + "www" + BACKSLASH * 2 + "server.crt",
        ),
        (
            "MYPKI_SSL_KEYFILE",
            "C:" + BACKSLASH * 2 + "root_apps" + BACKSLASH * 2 + "www" + BACKSLASH * 2 + "server.key",
        ),
        ("MYPKI_SSL_CERTFILE", "C://root_apps//www//server.crt"),
    ],
)
def test_a_doubled_separator_from_the_environment_is_named_not_bound(
    knob: str, value: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recording_server: list[Any]
) -> None:
    r"""The environment route is how this mistake really arrives, and it reaches the hint on **both** platforms.

    MEASURED (/tmp/probe5.py): a dotenv line `MYPKI_SSL_CERTFILE=C:\\root_apps\\server.crt` reaches pydantic verbatim
    -- doubled separators intact -- and so does a real environment variable; the wrap validator sees both before
    `Path` rewrites them. A **quoted** dotenv value (`KEY="C:\\root_apps\\server.crt"`) is the one case that arrives
    *un* doubled, because dotenv honours `\` as an escape inside double quotes: MEASURED, single separators. That is
    why README and `.env.example` tell operators to use forward slashes or single backslashes, and why this hint is
    advice rather than a repair mypki performs on their behalf.

    The healthy half of the pair comes from `_server_pair`, so exactly one knob is at fault in each run and the message
    must name that one and not the other.
    """
    root = tmp_path / "data"
    _init_ec(root)
    monkeypatch.setenv(knob, value)

    if knob == "MYPKI_SSL_CERTFILE":
        _, key = _server_pair(tmp_path)
        result = _run("serve", "--data-dir", str(root), "--port", "8443", "--ssl-key", str(key))
    else:
        cert, _ = _server_pair(tmp_path)
        result = _run("serve", "--data-dir", str(root), "--port", "8443", "--ssl-cert", str(cert))

    assert result.code == cli.EXIT_USAGE
    assert knob in result.stderr
    assert "does not exist" in result.stderr
    assert "doubled separators" in result.stderr
    assert value in result.stderr
    # The healthy half is named nowhere: a message that blames both knobs sends the operator to the wrong file.
    other = "MYPKI_SSL_KEYFILE" if knob == "MYPKI_SSL_CERTFILE" else "MYPKI_SSL_CERTFILE"
    assert other not in result.stderr
    assert "cannot bind" not in result.stderr
    assert recording_server == []


def test_serve_refuses_a_tls_cert_that_is_not_a_certificate(tmp_path: Path, recording_server: list[Any]) -> None:
    """`[SSL] PEM lib`, reported as the knob that caused it (0.5.0).

    **MEASURED on this box (/tmp/ssl_probe2.py, Python 3.12.13):** a cert slot holding garbage, an empty file, or a
    private key all make `ssl.SSLContext.load_cert_chain` raise `ssl.SSLError` reading `[SSL] PEM lib`, and every one of
    them is `isinstance(exc, OSError) == True` -- so each arrived at the operator as
    `error: cannot bind 0.0.0.0:8443: [SSL] PEM lib (_ssl.c:4122)`. That sentence names no knob and no file, which is
    exactly what the operator reported after fixing their paths. Here uvicorn is never reached and the message says
    which knob holds what.
    """
    root = tmp_path / "data"
    _init_ec(root)
    # The healthy half comes from the helper, then this file's own cert is replaced with junk -- the operator's shape,
    # where only one of the two files is wrong.
    _, key = _server_pair(tmp_path)
    cert = tmp_path / "broken.crt"
    cert.write_bytes(b"not a real certificate")

    result = _run("serve", "--data-dir", str(root), "--port", "8443", "--ssl-cert", str(cert), "--ssl-key", str(key))

    assert result.code == cli.EXIT_USAGE
    assert "MYPKI_SSL_CERTFILE" in result.stderr
    assert "does not hold a PEM certificate" in result.stderr
    assert str(cert) in result.stderr
    # The sentence this check exists to replace, and the bind-shaped one before it.
    assert "cannot bind" not in result.stderr
    assert "PEM lib" not in result.stderr
    assert recording_server == []


def test_serve_refuses_a_tls_key_that_is_not_a_private_key(tmp_path: Path, recording_server: list[Any]) -> None:
    """The mirror image: a certificate sitting in the key slot says so, rather than producing `[SSL] PEM lib`."""
    root = tmp_path / "data"
    _init_ec(root)
    cert, _ = _server_pair(tmp_path)
    key = tmp_path / "server.key"
    key.write_bytes(cert.read_bytes())

    result = _run("serve", "--data-dir", str(root), "--port", "8443", "--ssl-cert", str(cert), "--ssl-key", str(key))

    assert result.code == cli.EXIT_USAGE
    assert "MYPKI_SSL_KEYFILE" in result.stderr
    assert "points at a certificate, not a private key" in result.stderr
    assert "cannot bind" not in result.stderr
    assert recording_server == []


def test_serve_refuses_a_private_key_in_the_certificate_slot(tmp_path: Path, recording_server: list[Any]) -> None:
    """The swapped-file mistake is named as the swap, not as unparsable bytes.

    Both knobs end in a filename an operator can confuse (`server.crt` / `server.key`, or two `.pem` files), and this is
    the pair that produces `[SSL] PEM lib` with both files present, readable, and full of valid PEM. Saying "a private
    key, not a certificate" is actionable; saying "could not be parsed" is not.
    """
    root = tmp_path / "data"
    _init_ec(root)
    _, key = _server_pair(tmp_path)
    swapped = tmp_path / "swapped.crt"
    swapped.write_bytes(key.read_bytes())

    result = _run("serve", "--data-dir", str(root), "--port", "8443", "--ssl-cert", str(swapped), "--ssl-key", str(key))

    assert result.code == cli.EXIT_USAGE
    assert "MYPKI_SSL_CERTFILE" in result.stderr
    assert "points at a private key, not a certificate" in result.stderr
    assert "cannot bind" not in result.stderr
    assert recording_server == []


def test_serve_refuses_a_cert_and_key_that_do_not_match(tmp_path: Path, recording_server: list[Any]) -> None:
    """`[X509: KEY_VALUES_MISMATCH]` becomes a sentence naming both knobs (0.5.0).

    **MEASURED (/tmp/ssl_probe2.py):** a valid PEM certificate next to a valid PEM private key of a *different* key pair
    raises `ssl.SSLError` reading `[X509: KEY_VALUES_MISMATCH] key values mismatch` -- again an OSError, so again
    reported as a bind failure. This is the shape of a real mistake: a leaf re-issued after a key was regenerated, with
    the old `*.key` left where the new one should be. Both files are individually fine, so only a comparison catches it,
    and `ca.key_matches_certificate` is the function that already does that comparison for the CA bundle.
    """
    root = tmp_path / "data"
    _init_ec(root)
    cert, key = _server_pair(tmp_path, mismatch=True)

    result = _run("serve", "--data-dir", str(root), "--port", "8443", "--ssl-cert", str(cert), "--ssl-key", str(key))

    assert result.code == cli.EXIT_USAGE
    assert "do not match" in result.stderr
    assert "MYPKI_SSL_CERTFILE" in result.stderr
    assert "MYPKI_SSL_KEYFILE" in result.stderr
    assert "[X509: KEY_VALUES_MISMATCH]" in result.stderr
    assert "cannot bind" not in result.stderr
    assert recording_server == []


def test_serve_refuses_an_encrypted_tls_key_instead_of_prompting_on_stdin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recording_server: list[Any]
) -> None:
    """An encrypted server key is refused up front rather than left to OpenSSL's prompt.

    **MEASURED (/tmp/ssl_probe2.py):** `load_pem_private_key(..., password=None)` on an encrypted PKCS#8 key raises
    `TypeError: Password was not given but private key is encrypted`, and handing that file to
    `ssl.SSLContext.load_cert_chain` made this probe **stop at `Enter PEM pass phrase`** -- uvicorn has no passphrase
    knob, so a `mypki serve` started by a supervisor or `&` waits forever for input nobody can give it. Refusing beats
    hanging, and the message says which file to rewrite.

    `getpass` is patched as an extra guard: if this ever reaches an interactive prompt the test fails loudly instead of
    blocking the suite.
    """
    from mypki.keys import generate_key, private_key_pem

    prompts: list[str] = []
    monkeypatch.setattr("getpass.getpass", lambda prompt="": prompts.append(prompt) or "")

    root = tmp_path / "data"
    _init_ec(root)
    cert, _ = _server_pair(tmp_path)
    key = tmp_path / "server.key"
    key.write_bytes(private_key_pem(generate_key(KeySpec.from_string("ec-p256")), passphrase=b"not-a-real-passphrase"))

    result = _run("serve", "--data-dir", str(root), "--port", "8443", "--ssl-cert", str(cert), "--ssl-key", str(key))

    assert result.code == cli.EXIT_USAGE
    assert "MYPKI_SSL_KEYFILE" in result.stderr
    assert "encrypted private key" in result.stderr
    assert "stdin" in result.stderr
    assert prompts == [], f"the CLI prompted for a passphrase: {prompts}"
    assert "cannot bind" not in result.stderr
    assert recording_server == []


def test_serve_accepts_a_certificate_chain_in_the_cert_file(tmp_path: Path, recording_server: list[Any]) -> None:
    """A leaf followed by its issuer is ordinary, and the content check must not mistake it for a broken file.

    Only the **first** certificate is parsed and matched against the key. Asserting this exists because "validate the
    cert slot" has an obvious over-strict reading (the whole file must be one certificate) that would refuse the normal
    way operators bundle a leaf with the CA that issued it.
    """
    root = tmp_path / "data"
    _init_ec(root)
    cert, key = _server_pair(tmp_path, chain=True)

    result = _run("serve", "--data-dir", str(root), "--port", "8443", "--ssl-cert", str(cert), "--ssl-key", str(key))

    assert result.code == cli.EXIT_OK
    assert "https://127.0.0.1:8443" in result.stdout
    assert len(recording_server) == 1
    assert recording_server[-1].is_ssl is True


def test_serve_maps_an_ssl_error_from_a_real_bind_to_a_tls_sentence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The last-resort mapping: an `ssl.SSLError` that reaches `cmd_serve` is not called a bind failure.

    `_tls_file_problem` catches these cases before uvicorn exists, so this arm is for the window between the pre-flight
    and the bind -- a file replaced after the check -- and for any other route into uvicorn's SSL setup. **MEASURED:**
    `ssl.SSLError` is a subclass of `OSError`, so ordering is load-bearing here: an `except OSError` written first would
    swallow it, which is how the original mislabelling happened even when the exception was already specific. The fake
    raises the real class rather than a stand-in so the ordering is what is under test.
    """
    import ssl

    import uvicorn

    class SslFailingServer:
        def __init__(self, config: object) -> None:
            self.config = config
            self.started = False

        def run(self) -> None:
            raise ssl.SSLError(1, "[SSL] PEM lib (_ssl.c:4122)")

    monkeypatch.setattr(uvicorn, "Server", SslFailingServer)
    root = tmp_path / "data"
    _init_ec(root)
    cert, key = _server_pair(tmp_path)

    result = _run("serve", "--data-dir", str(root), "--port", "8443", "--ssl-cert", str(cert), "--ssl-key", str(key))

    assert result.code == cli.EXIT_USAGE
    assert "could not be loaded" in result.stderr
    assert "PEM lib" in result.stderr
    assert "MYPKI_SSL_CERTFILE" in result.stderr
    assert "MYPKI_SSL_KEYFILE" in result.stderr
    # The sentence that used to be the only answer, and which sent the operator looking for a process holding 8443.
    assert "cannot bind" not in result.stderr
    assert "Traceback" not in result.stderr


def test_settings_keeps_the_raw_spelling_of_a_tls_path_from_every_source(tmp_path: Path) -> None:
    r"""The config layer that makes the CLI's honesty possible, asserted directly.

    `Settings._keep_raw_ssl_spellings` is a `mode="wrap"` model validator, and MEASURED (pydantic 2.14.1 /
    pydantic-settings 2.16.1, /tmp/probe5.py) it sees the merged input mapping before field coercion in all three
    construction paths mypki uses: dotenv layers, real environment variables, and `Settings(**kwargs)` from
    `cli.settings_with_cli_overrides` and `app._publish_saved_settings`. A `mode="before"` `@field_validator` also sees
    the raw value but cannot be an instance method (MEASURED: pydantic raises `PydanticUserError: The @field_validator
    decorator cannot be applied to instance methods`), so it has nowhere to put what it saw.

    A direct `Path` argument is the case that has no spelling left to record -- `raw_path_spelling` returns None and
    `cli._tls_spelling` falls back to `str(path)`, which is the pre-0.5.0 behaviour and correct on POSIX.
    """
    from mypki.config import Settings

    doubled = "C:" + BACKSLASH * 2 + "root_apps" + BACKSLASH * 2 + "www" + BACKSLASH * 2 + "server.crt"

    # kwargs, i.e. the CLI-override route.
    by_kwargs = Settings(_env_file=None, ssl_certfile=doubled)  # type: ignore[call-arg]
    assert by_kwargs.raw_path_spelling("ssl_certfile") == doubled
    # ...and the field itself is still a `Path`, i.e. recording the spelling changed nothing about the value.
    assert isinstance(by_kwargs.ssl_certfile, Path)

    env_var = "MYPKI_SSL_KEYFILE"
    os.environ[env_var] = "/tmp//doubled//dir/server.key"
    try:
        by_env = Settings(_env_file=None)  # type: ignore[call-arg]
        assert by_env.raw_path_spelling("ssl_keyfile") == "/tmp//doubled//dir/server.key"
    finally:
        del os.environ[env_var]

    dotenv = tmp_path / "mypki.env"
    dotenv.write_text(f"MYPKI_SSL_CERTFILE={doubled}\n", encoding="utf-8")
    by_dotenv = Settings(_env_file=(str(dotenv),))  # type: ignore[call-arg]
    assert by_dotenv.raw_path_spelling("ssl_certfile") == doubled

    unset = Settings(_env_file=None)  # type: ignore[call-arg]
    assert unset.ssl_certfile is None
    assert unset.raw_path_spelling("ssl_certfile") is None

    from pathlib import Path as ConcretePath

    given_as_path = Settings(_env_file=None, ssl_certfile=ConcretePath("/etc/ssl/server.crt"))  # type: ignore[call-arg]
    assert given_as_path.raw_path_spelling("ssl_certfile") is None


def test_serve_rejects_a_tls_path_that_is_a_directory(tmp_path: Path, recording_server: list[Any]) -> None:
    """`exists()` is not enough: opening a directory raises `IsADirectoryError`, an OSError like any other."""
    root = tmp_path / "data"
    _init_ec(root)
    as_dir = tmp_path / "server.crt"
    as_dir.mkdir()

    result = _run(
        "serve",
        "--data-dir",
        str(root),
        "--port",
        "8443",
        "--ssl-cert",
        str(as_dir),
        "--ssl-key",
        str(tmp_path / "server.key"),
    )

    assert result.code == cli.EXIT_USAGE
    assert "MYPKI_SSL_CERTFILE" in result.stderr
    assert "directory, not a certificate or key file" in result.stderr


@pytest.mark.skipif(not POSIX, reason="POSIX mode bits; Windows relies on NT's owner-scoped default ACLs")
def test_serve_rejects_a_tls_file_that_exists_but_is_not_readable(tmp_path: Path, recording_server: list[Any]) -> None:
    """A file the operator cannot read is a different failure from a missing one, and says so."""
    root = tmp_path / "data"
    _init_ec(root)
    cert = tmp_path / "server.crt"
    cert.write_bytes(b"not a real certificate")
    key = tmp_path / "server.key"
    key.write_bytes(b"not a real key")
    key.chmod(0o000)

    result = _run(
        "serve",
        "--data-dir",
        str(root),
        "--port",
        "8443",
        "--ssl-cert",
        str(cert),
        "--ssl-key",
        str(key),
    )

    assert result.code == cli.EXIT_USAGE
    assert "MYPKI_SSL_KEYFILE" in result.stderr
    assert "not readable" in result.stderr


def test_serve_still_serves_plain_http_when_only_half_the_tls_pair_is_named(
    tmp_path: Path, recording_server: list[Any]
) -> None:
    """The pre-flight checks the pair `tls_enabled` actually uses — a half set is not TLS and has nothing to open.

    Without this guard the natural implementation ("check every ssl_* that is set") would turn a harmless half
    configuration, which mypki already answers with the plain-HTTP warning, into a refusal.
    """
    root = tmp_path / "data"
    _init_ec(root)

    result = _run("serve", "--data-dir", str(root), "--port", "8443", "--ssl-cert", str(tmp_path / "absent.crt"))

    assert result.code == cli.EXIT_OK
    assert "WARNING: plain HTTP" in result.stdout
    assert "MYPKI_SSL_CERTFILE" not in result.stderr
    assert len(recording_server) == 1


def test_serve_warns_when_bound_off_loopback(tmp_path: Path, recording_server: list[Any]) -> None:
    """The LAN-exposure warning names the host, the port and what an attacker on that subnet can do (page-map §6)."""
    root = tmp_path / "data"
    _init_ec(root)

    result = _run("serve", "--data-dir", str(root), "--host", "10.0.0.5", "--port", "8443")

    assert result.code == cli.EXIT_OK
    assert "not loopback" in result.stdout
    assert "10.0.0.5" in result.stdout
    assert "8443" in result.stdout
    assert recording_server[0].host == "10.0.0.5"


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1", "127.0.0.42"])
def test_loopback_hosts_print_no_exposure_warning(host: str, tmp_path: Path, recording_server: list[Any]) -> None:
    """The loopback set is not a single literal: anything under 127/8 and `::1` count as local."""
    root = tmp_path / "data"
    _init_ec(root)

    result = _run("serve", "--data-dir", str(root), "--host", host, "--port", "8443")

    assert result.code == cli.EXIT_OK
    assert "not loopback" not in result.stdout


def test_serve_respects_mypki_port_from_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recording_server: list[Any]
) -> None:
    """A `.env`-style knob reaches the banner without a flag (page-map §11)."""
    monkeypatch.setenv("MYPKI_PORT", "9443")
    root = tmp_path / "data"
    _init_ec(root)

    result = _run("serve", "--data-dir", str(root))

    assert ":9443" in result.stdout


def test_serve_cli_flag_beats_the_environment_for_host_and_port(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recording_server: list[Any]
) -> None:
    """`--port` overrides `MYPKI_PORT`; the CLI is the last word (page-map §8's precedence shape)."""
    monkeypatch.setenv("MYPKI_PORT", "9443")
    root = tmp_path / "data"
    _init_ec(root)

    result = _run("serve", "--data-dir", str(root), "--port", "8231")

    assert ":8231" in result.stdout
    assert "9443" not in result.stdout


def test_serve_rejects_a_port_outside_the_valid_range(tmp_path: Path) -> None:
    """`--port 0` is a usage error.

    `Settings.port` carries `ge=1 le=65535`, and the CLI re-validates through Settings rather than copying the field.
    """
    result = _run("serve", "--data-dir", str(tmp_path / "data"), "--port", "0")

    assert result.code == cli.EXIT_USAGE
    assert "config error" in result.stderr


def test_serve_creates_the_session_secret_owner_only(tmp_path: Path, recording_server: list[Any]) -> None:
    """`<data>/instance/secret_key` appears on first `serve`, 0600, and survives a restart (page-map §8)."""
    root = tmp_path / "data"
    _init_ec(root)

    result = _run("serve", "--data-dir", str(root), "--port", "8443")

    secret = paths.secret_key_path(root)
    assert result.code == cli.EXIT_OK
    assert secret.exists()
    assert len(secret.read_text(encoding="utf-8").strip()) >= 32
    if POSIX:
        assert stat.S_IMODE(secret.stat().st_mode) == PRIVATE_FILE_MODE, oct(secret.stat().st_mode)


def test_serve_reports_a_bind_failure_as_exit_one_not_a_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The `except OSError` branch of `cmd_serve`, exercised the only way a fake can.

    **MEASURED, and it corrects an earlier claim in this file:** real uvicorn 0.54.0 does NOT let a bind failure
    reach that branch as an OSError. `uvicorn/server.py:182-192` logs the error through `uvicorn.error`, shuts the
    lifespan down and calls `sys.exit(STARTUP_FAILURE)`, i.e. `SystemExit(3)` -- which is what this suite was
    *not* testing, because `FailingServer.run()` here raises the OSError directly. So this test proves the branch
    behaves correctly if something ever does raise OSError into it (a socket error from a different layer, or a
    future uvicorn that propagates rather than swallowing), and `test_serve_reports_a_real_uvicorn_startup_failure`
    below is the one that models the failure an operator actually sees. Both are kept: deleting this one would
    leave a live branch untested, and deleting the other would leave the real bug untested.

    The banner prints *before* uvicorn binds, so a banner alone never proves a live server; that is why the exit
    code and stderr are asserted here rather than stdout.
    """
    _server_raising(monkeypatch, OSError(98, "address already in use"))
    root = tmp_path / "data"
    _init_ec(root)

    result = _run("serve", "--data-dir", str(root), "--port", "8443")

    assert result.code == cli.EXIT_USAGE
    assert "cannot bind 127.0.0.1:8443" in result.stderr
    assert "address already in use" in result.stderr
    assert "Traceback" not in result.stderr


def test_serve_reports_a_real_uvicorn_startup_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A bind failure that arrives as `SystemExit(3)` -- the shape real uvicorn produces -- becomes exit 1.

    **MEASURED on a real Windows 10 host:** `mypki serve --port 8443` against an occupied port printed
    `[Errno 10048] error while attempting to bind ... only one usage of each socket address` plus uvicorn's
    shutdown lines, and mypki added *nothing* of its own. On Linux the same command exits **3** with no
    `cannot bind` line at all -- while README documents 3 as "required state missing: no CA found", which is a
    different problem with a different fix. The operator's only clue was a uvicorn log line, and the exit code
    lied about what had happened.

    The fake reproduces uvicorn's exact mechanism rather than a convenient one: `run()` sets nothing (so
    `server.started` stays False, as it does after a failed bind) and raises `SystemExit(3)`, the
    `sys.exit(STARTUP_FAILURE)` that `uvicorn/server.py:192` actually calls.
    """
    import uvicorn

    class StartupFailureServer:
        def __init__(self, config: object) -> None:
            self.config = config
            self.started = False

        def run(self) -> None:
            raise SystemExit(3)

    monkeypatch.setattr(uvicorn, "Server", StartupFailureServer)
    root = tmp_path / "data"
    _init_ec(root)

    result = _run("serve", "--data-dir", str(root), "--port", "8443")

    # Exit 1 (usage/operational failure), not 3 -- 3 is mypki's "no CA here" code, and a wrapper that sees 3
    # would go looking for a missing certificate rather than for whatever is holding the port.
    assert result.code == cli.EXIT_USAGE
    assert "never bound" in result.stderr
    assert "8443" in result.stderr
    assert "Traceback" not in result.stderr


def test_serve_returns_130_on_ctrl_c(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Ctrl-C is 130 -- the shell's own convention, not a mypki decision (cli.py module docstring)."""
    _server_raising(monkeypatch, KeyboardInterrupt())
    root = tmp_path / "data"
    _init_ec(root)

    result = _run("serve", "--data-dir", str(root), "--port", "8443")

    assert result.code == 130


def test_serve_does_not_rewrite_the_exit_of_a_server_that_started(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`server.started` is what separates a startup failure from a clean exit -- so the guard has to bite.

    A server that bound successfully and then exited on its own terms must keep its own exit code. Without that
    distinction mypki would print "the server never bound" about a server that bound perfectly well, which is
    the mirror image of the bug this section exists to fix.
    """
    import uvicorn

    class StartedThenExitedServer:
        def __init__(self, config: object) -> None:
            self.config = config
            self.started = False

        def run(self) -> None:
            self.started = True  # bound fine, then uvicorn decided to exit
            raise SystemExit(0)

    monkeypatch.setattr(uvicorn, "Server", StartedThenExitedServer)
    root = tmp_path / "data"
    _init_ec(root)

    result = _run("serve", "--data-dir", str(root), "--port", "8443")

    assert "never bound" not in result.stderr
    assert result.code == 0


def test_serve_reuses_an_existing_session_secret(tmp_path: Path, recording_server: list[Any]) -> None:
    """Restarting does not rotate the session key: that would invalidate a pending signing step (page-map §3)."""
    root = tmp_path / "data"
    _init_ec(root)
    _run("serve", "--data-dir", str(root), "--port", "8443")
    first = paths.secret_key_path(root).read_text(encoding="utf-8")

    _run("serve", "--data-dir", str(root), "--port", "8443")

    assert paths.secret_key_path(root).read_text(encoding="utf-8") == first


# ------------------------------------------------------------------------------------------------------- info


def test_info_exits_three_when_there_is_no_ca(tmp_path: Path) -> None:
    """Exit 3 with the command that fixes it, on stderr (page-map §6)."""
    result = _run("info", "--data-dir", str(tmp_path / "missing"))

    assert result.code == cli.EXIT_MISSING_STATE
    assert "No CA found" in result.stderr
    assert "init-ca" in result.stderr


def test_info_reports_the_loaded_ca_and_the_issued_count(tmp_path: Path) -> None:
    """Every fact page-map §6 lists, on stdout, colon-grouped and UTC-formatted."""
    root = tmp_path / "data"
    _init_ec(root, common_name="Info CLI CA")

    result = _run("info", "--data-dir", str(root))

    assert result.code == cli.EXIT_OK
    assert f"mypki {__version__}" in result.stdout
    assert "Info CLI CA" in result.stdout
    assert "0 issued record(s)" in result.stdout
    assert "status             valid" in result.stdout
    assert "CA:TRUE pathLength:0" in result.stdout
    assert ":" in result.stdout.split("sha256 fingerprint")[1][:8]


def test_info_names_an_expired_ca_as_expired_and_says_what_to_do(tmp_path: Path) -> None:
    """A CA whose `notAfter` has passed must not be reported as `valid` (page-map §1's status line).

    Reaching this state honestly is the interesting part: `init-ca --days` refuses 0 and below, and cryptography's
    builder refuses a `notAfter` before its `notBefore` (MEASURED), so an expired root on disk never came from this
    CLI -- it aged in place. `_expired_ca` writes one with past dates to reproduce that. The advice the command prints
    (`init-ca --force`, then re-install everywhere) is the part an operator acts on, so it is asserted too.
    """
    root = tmp_path / "data"
    _expired_ca(root, common_name="Long Retired CLI CA")

    result = _run("info", "--data-dir", str(root))

    assert result.code == cli.EXIT_OK
    assert "status             EXPIRED" in result.stdout
    assert "has expired" in result.stdout
    assert "init-ca --force" in result.stdout


def test_info_resolves_the_data_dir_with_the_same_precedence_as_serve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`info --data-dir` and `serve --data-dir` cannot disagree about where the CA lives.

    Two commands, one precedence rule (page-map §8). A divergence here is how an operator ends up staring at a `info`
    output that describes a different CA from the one the running server loaded.
    """
    root = tmp_path / "data"
    _init_ec(root)
    monkeypatch.setenv(paths.DATA_DIR_ENV, str(tmp_path / "env-would-lose"))

    result = _run("info", "--data-dir", str(root))

    assert result.code == cli.EXIT_OK
    assert str(root) in result.stdout
    assert "env-would-lose" not in result.output


def test_info_reports_a_missing_key_as_missing(tmp_path: Path) -> None:
    """`MISSING`, not a crash and not a claim (page-map §1)."""
    root = tmp_path / "data"
    _init_ec(root)
    paths.ca_key_path(root).unlink()

    result = _run("info", "--data-dir", str(root))

    assert result.code == cli.EXIT_OK
    assert "(MISSING)" in result.stdout


# ------------------------------------------------------------------------------------------------------ main


def test_no_subcommand_is_an_argparse_usage_error_with_code_two() -> None:
    """`mypki` alone exits 2 and says which argument is missing (README exit codes)."""
    result = _run()

    assert result.code == cli.EXIT_REFUSED  # argparse's own usage exit, same code as a refusal by coincidence
    assert "the following arguments are required" in result.stderr


def test_version_flag_prints_the_package_version_and_exits_zero() -> None:
    """`--version` reads `mypki.__version__`; the number is never written into this file.

    Asserted against the imported attribute so a version bump cannot leave a stale expectation here (the same rule
    `tools/e2e_harness.py` and `tools/check_version.py` follow).
    """
    result = _run("--version")

    assert result.code == 0
    assert f"mypki {__version__}" in result.stdout


def test_unknown_subcommand_is_a_usage_error() -> None:
    """`mypki sign` does not exist and says so with exit 2 rather than a traceback (README "Naming")."""
    result = _run("sign", "--csr", "whatever")

    assert result.code == cli.EXIT_REFUSED
    assert "invalid choice" in result.stderr


def _subcommand_flags(parser: Any, name: str) -> set[str]:
    """Every option string one subparser accepts.

    Reached through argparse's `_subparsers._group_actions[0].choices` because argparse exposes no public API for
    "what flags does this subcommand have", and the assertion needs the whole set rather than a hand-written list that
    could drift alongside the parser it is checking.
    """
    choices = parser._subparsers._group_actions[0].choices  # type: ignore[union-attr]
    # argparse installs its own help action on every subparser and it carries BOTH `-h` and `--help`, so the help action
    # is skipped by identity rather than by filtering one literal out of the option strings -- that would leave `--help`
    # behind and read as though mypki advertised a flag it never added.
    return {flag for action in choices[name]._actions if action.dest != "help" for flag in action.option_strings}


def test_build_parser_exposes_the_documented_flag_surface() -> None:
    """The flags page-map §6 lists are the flags that exist -- and no others.

    Asserted as a set per subcommand rather than by running each one, because an undocumented flag is a contract
    violation in the other direction: `mypki init-ca --export-key` would be the one place this project could hand out
    what it exists to protect.
    """
    parser = cli.build_parser()
    actions = {name: _subcommand_flags(parser, name) for name in ("init-ca", "serve", "info")}

    assert actions["init-ca"] == {
        "--data-dir",
        "--common-name",
        "--organization",
        "--organizational-unit",
        "--country",
        "--key-type",
        "--key-size",
        "--curve",
        "--days",
        "--encrypt",
        "--passphrase-env",
        "--force",
        "--secure-acl",
        "--log-level",
        "--log-file",
        "--no-console-log",
    }
    assert actions["serve"] == {
        "--host",
        "--port",
        "--ssl-cert",
        "--ssl-key",
        "--data-dir",
        "--passphrase-env",
        "--log-level",
        "--log-file",
        "--no-console-log",
    }
    assert actions["info"] == {"--data-dir", "--log-level", "--log-file", "--no-console-log"}


def test_no_subcommand_ever_advertises_sign_revoke_or_export() -> None:
    """The absence is asserted, because "there is no `export-key`" is a security claim (README "Naming")."""
    parser = cli.build_parser()

    choices = parser._subparsers._group_actions[0].choices  # type: ignore[union-attr]

    assert set(choices) == {"init-ca", "serve", "info"}
    for forbidden in ("sign", "revoke", "export-key", "import-ca"):
        assert forbidden not in choices


def test_main_configures_logging_for_init_ca_and_info_but_not_twice_for_serve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recording_server: list[Any]
) -> None:
    """`main()` wires logging for the two commands that cannot do it themselves (cli.py comment).

    `serve` configures logging itself because it needs the resolved settings first; `init-ca` and `info` would
    otherwise ignore `--log-level DEBUG` entirely. Asserted through a real `configure_logging` call count rather than
    by reading log text, so the *number* of calls is what is checked -- idempotency is the property being relied on.
    """
    from mypki import cli as cli_module

    calls: list[str] = []
    real = cli_module.configure_logging

    def counting(settings: Any) -> Any:
        calls.append(str(getattr(settings, "log_level", "?")))
        return real(settings)

    monkeypatch.setattr(cli_module, "configure_logging", counting)
    root = tmp_path / "data"
    _run("init-ca", "--data-dir", str(root), "--key-type", "ec")
    _run("info", "--data-dir", str(root))
    _run("serve", "--data-dir", str(root), "--port", "8443")

    assert calls[0] == "INFO"
    assert calls[1] == "INFO"
    # `main` skips its own call for `serve`; `cmd_serve` makes the next one, and `create_app` makes another.
    assert len(calls) >= 3


def test_logging_goes_to_the_configured_file_and_not_into_the_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`--log-file` lands where the operator said, and the default never writes into the source tree.

    The relative default (`logs/mypki.log`) resolves against the working directory, which is why `configure_logging`
    prints the resolved absolute path as its first line (page-map §11). This test pins both halves: the file appears
    under `tmp_path`, and the repository's own `logs/` directory is untouched by the whole CLI test run.
    """
    log_target = tmp_path / "somewhere" / "else.log"
    root = tmp_path / "data"

    result = _run("init-ca", "--data-dir", str(root), "--key-type", "ec", "--log-file", str(log_target))

    assert result.code == cli.EXIT_OK
    assert log_target.exists()
    assert str(log_target) in log_target.read_text(encoding="utf-8")
    repo_logs = Path(__file__).resolve().parent.parent / "logs" / "mypki.log"
    marker = "mypki CLI Test CA"
    if repo_logs.exists():
        assert marker not in repo_logs.read_text(encoding="utf-8")


def test_console_logging_can_be_turned_off_from_the_cli(tmp_path: Path) -> None:
    """`--no-console-log` mirrors nothing to stderr while the file keeps receiving everything (page-map §11)."""
    root = tmp_path / "data"
    log_target = tmp_path / "quiet.log"

    result = _run(
        "init-ca",
        "--data-dir",
        str(root),
        "--key-type",
        "ec",
        "--log-file",
        str(log_target),
        "--no-console-log",
    )

    assert result.code == cli.EXIT_OK
    assert "mypki.keys" not in result.stderr
    assert "generating EC P-256 private key" in log_target.read_text(encoding="utf-8")


def test_an_empty_log_file_means_console_only(tmp_path: Path) -> None:
    """`--log-file ""` is the documented opt-out, and it must not produce a log file named after a directory."""
    root = tmp_path / "data"

    result = _run("init-ca", "--data-dir", str(root), "--key-type", "ec", "--log-file", "")

    assert result.code == cli.EXIT_OK
    assert "logging to console only" in result.stderr


def test_settings_with_cli_overrides_returns_a_fresh_object_not_the_cached_one(tmp_path: Path) -> None:
    """A CLI flag must not become process-wide state (cli.py docstring, two learned lessons).

    `get_settings()` is `lru_cache`d; mutating its result would make every later reader in the process see this
    command's flags. Asserted by identity and by re-reading the cached object afterwards, which is the only way to see
    the difference between "returned a new Settings" and "mutated the one everyone shares".
    """
    from mypki.config import get_settings

    root = tmp_path / "data"
    args = cli.build_parser().parse_args(["serve", "--data-dir", str(root), "--port", "8231"])
    base = get_settings()

    overridden = cli.settings_with_cli_overrides(args)

    assert overridden is not base
    assert overridden.port == 8231
    assert Path(str(overridden.data_dir)) == root
    assert get_settings().port != 8231, "the cached Settings still reports its own default"


def test_settings_with_cli_overrides_re_validates_instead_of_copying(tmp_path: Path) -> None:
    """`model_copy(update=…)` would skip validation; a bad flag must fail here, not mid-request."""
    args = cli.build_parser().parse_args(["serve", "--port", "70000"])

    with pytest.raises(ValueError) as excinfo:
        cli.settings_with_cli_overrides(args)

    assert "port" in str(excinfo.value).lower()


def test_main_turns_a_settings_error_into_exit_one(tmp_path: Path) -> None:
    """The `ValueError` above arrives through `main()` as a one-line config error."""
    result = _run("serve", "--data-dir", str(tmp_path / "data"), "--port", "70000")

    assert result.code == cli.EXIT_USAGE
    assert "config error" in result.stderr
    assert "Traceback" not in result.stderr
