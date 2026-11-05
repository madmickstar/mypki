"""The invariant this project's whole design leans on: **key material never leaves the host it was made on.**

Not "keys are protected" — that phrase is unfalsifiable. The assertable version is a set of negative claims about
artifacts an attacker can actually read: no response body, no response header, no `Set-Cookie` value and no log file
contains private-key armour or the CA key's bytes. Each one is checked by searching for the thing, not by expressing
confidence in the code that produces it.

Why the assertion is on the **armour** (`-----BEGIN … PRIVATE KEY-----`) and never on the phrase `PRIVATE KEY`:
`csr_generate.html` legitimately *documents* the format — it has to tell an operator what they are looking at, and
`logsetup.FORBIDDEN_MARKERS` deliberately names the same strings for a different purpose (dropping log records). A test
that banned the phrase would fail on correct prose and teach people to distrust the suite. Armour is the artifact; a
word in a sentence is not.

What this file does **not** claim: that no private key ever appears in any response. `/csr/generate`'s POST shows the
operator's freshly generated key exactly once, in the page and in a download, and stores it nowhere (page-map §2 —
`test_csr_generate.py` proves the byte-for-byte nothing-on-disk half). That is the feature. What must never appear is
**this CA's key**, on any route, under any flow, including the routes that exist to serve something else.

The log half is the mirror image of the HTTP half. A CA whose logs contain private keys has leaked even if no response
ever did, because logs get backed up, shipped to aggregators and pasted into tickets. `PrivateKeyMaterialFilter` drops
such records rather than redacting them (logsetup.py: redaction keeps the shape of a leak in the artifact), and
`dropped_record_count()` is what makes "the filter caught something" an observable fact instead of a hope.

Hermetic throughout: the data dir, the log file and every keypair belong to `tmp_path`. No test here touches an
operator's real CA (STYLE §8).
"""

from __future__ import annotations

import hashlib
import logging
import re
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat
from cryptography.x509.ocsp import OCSPRequestBuilder, OCSPResponseStatus, load_der_ocsp_response

from mypki import paths
from mypki.config import Settings
from mypki.crl import CRL_PEM_MARKER
from mypki.keys import KeySpec, private_key_pem
from mypki.logsetup import FORBIDDEN_MARKERS, dropped_record_count
from mypki.ocsp_responder import OCSP_REQUEST_MEDIA_TYPE

#: Private-key armour in any spelling cryptography produces: PKCS#8 unencrypted (`PRIVATE KEY`), traditional OpenSSL
#: (`RSA PRIVATE KEY`), PKCS#8 encrypted (`ENCRYPTED PRIVATE KEY`), SEC 1 (`EC PRIVATE KEY`). Asserted as a pattern
#: rather than as a list of literals so an unexpected spelling is caught too.
ARMOUR_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")

#: Every route an operator can reach with a GET. `/about` and `/settings` joined this list in 0.2.0, and `/settings` is
#: the
#: one of them whose entire purpose is to describe configuration — which makes it the page most likely to be "helpful"
#: about
#: where a key lives. `/version` renders `about.html`, so both spellings are checked. `/inspect` joined in 0.5.0 and it
#: is the page this file should worry about most: its whole purpose is to echo back whatever an operator pasted, and its
#: private-key branch therefore names a key without ever loading or rendering it (see `mypki.inspect`).
#:
#: `/crl` and `/crl.pem` joined in 0.7.0 for the reason every artifact does: this is now a host that signs things, and a
#: signed artifact is exactly what a careless implementation would build out of the signing bundle. Both are listed here
#: so the ordinary loop searches them like any other body — `/crl.pem` in particular is the only entry that is not HTML,
#: so its bytes are searched as text rather than through a template's rendering (the dedicated test below adds the
#: armour-free claim on the artifact itself).
PAGES = (
    "/",
    "/csr/generate",
    "/csr/sign",
    "/ca",
    "/issued",
    "/about",
    "/inspect",
    "/settings",
    "/version",
    "/crl",
    "/crl.pem",
)

#: The exact 5-byte DER refusal `/ocsp` answers for a body it cannot parse (MEASURED; the same literal `test_ocsp.py`
#: asserts and both harnesses search for). Named here because "the refusal contains nothing" is only checkable if you
#: know what the refusal is.
MALFORMED_DER = b"\x30\x03\x0a\x01\x01"

NO_CA_MARK = "Run `mypki init-ca`"


# --------------------------------------------------------------------------------- what a leak would look like


def _key_material_of(bundle) -> list[str]:
    """Every spelling of the CA's private key that a response could plausibly contain.

    DER, PKCS#8 PEM and the bare base64 body of that PEM: three forms because a leak is rarely in the form you thought
    to look for. An operator who copies a PEM into a template renders the base64 without the armour headers, and a body
    built by concatenating a download would carry exactly that. Checking only `-----BEGIN` text would miss all three.

    Returns strings rather than bytes so the same search works against a response body and a header value.
    """
    assert bundle.key is not None, "this file asserts the CA key stays private; a keyless bundle proves nothing"

    der = bundle.key.private_bytes(
        encoding=Encoding.DER, format=PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()
    )
    pem = bundle.key.private_bytes(
        encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()
    ).decode("ascii")
    body = "".join(pem.split()[1:-1])

    return [der.decode("latin-1"), pem, body]


def _headers_of(response) -> str:
    """Every response header as one searchable string.

    Headers rather than just `response.headers`: a leak can hide in a header mypki never meant to set (a proxy echo, a
    future debug header), and `raw` is the only view that shows duplicates and non-ASCII bytes faithfully.
    """
    return "\n".join(f"{name.decode('latin-1')}: {value.decode('latin-1')}" for name, value in response.headers.raw)


def _assert_no_ca_key_material(target: str, what: str, secrets_: list[str]) -> None:
    """Only the CA-key half of `_assert_clean`.

    Split out because exactly one page in this app legitimately renders private-key armour — `/csr/generate`,
    showing the
    operator their own freshly generated key (page-map §2). On that page the *armour* check would fail against correct
    behaviour while the CA-key check must still hold. Naming the two checks separately is what keeps a legitimate
    exception from turning into a general excuse.
    """
    for secret in secrets_:
        assert secret not in target, f"{what} contains CA key material ({secret[:40]}...)"


def _assert_clean(target: str, what: str, secrets_: list[str]) -> None:
    """One artifact, two checks: no armour of any kind, and none of this CA's key in any form.

    `target[:600]` in the failure message rather than the whole body: a leak report that dumps a 30 KB page into a
    traceback is how people learn to skim past these tests.
    """
    _assert_no_ca_key_material(target, what, secrets_)

    armour = ARMOUR_RE.search(target)
    if armour is not None:
        raise AssertionError(f"{what} contains private-key armour {armour.group(0)!r}: {target[:600]}")


# ---------------------------------------------------------------------------- every route an operator can reach


def test_every_page_carries_no_key_material_in_body_or_headers(session_client, ca_bundle, settings: Settings) -> None:
    """Every page in `PAGES`, each with a real CA loaded.

    The failure mode this guards against is the plausible-looking convenience: a debug block naming key paths, an error
    page that quotes what it was given, a context helper that passes `bundle` to a template instead of `describe_ca`.
    `describe_ca` has no parameter that could ask for something private (ca.py) — this test is what makes that claim
    hold at the HTTP boundary rather than in one function's signature.
    """
    secrets_ = _key_material_of(ca_bundle)

    for path in PAGES:
        response = session_client.get(path)
        assert response.status_code == 200, f"{path}: {response.text[:400]}"

        _assert_clean(response.text, f"GET {path} body", secrets_)
        _assert_clean(_headers_of(response), f"GET {path} headers", secrets_)
        assert settings.secret_key not in _headers_of(response)


def test_the_settings_page_names_knobs_without_naming_key_paths(session_client, ca_bundle, settings: Settings) -> None:
    """`/settings` is the page built to describe this host, so it is the page that has to be checked by name.

    A settings page earns its keep by listing values, and the two values that must not be listed are the session signing
    secret and any path to a private key. Asserted as *absent strings* rather than as "the template does not pass them":
    `_settings_rows` iterates `Settings.model_fields`, so a knob added tomorrow is on this page whether anyone thought
    about it or not, and the only durable guarantee is what the rendered body does not contain.
    """
    response = session_client.get("/settings")
    assert response.status_code == 200

    secrets_ = _key_material_of(ca_bundle)
    _assert_no_ca_key_material(response.text, "GET /settings body", secrets_)
    _assert_clean(_headers_of(response), "GET /settings headers", secrets_)

    assert settings.secret_key not in response.text
    # The generated-file location and the CA key's filename: neither appears in the table, and the page says so out
    # loud.
    # Asserted as the *resolved absolute* paths rather than as bare filenames: `config.py`'s Field descriptions are
    # rendered
    # verbatim in this page's description column, and two of them legitimately name `<data>/ca/ca_key.pem` and
    # `<data>/instance/secret_key` to explain what mypki does **not** touch on an operator's behalf. A resolved path
    # under a
    # real data dir is a fact about this host; a documented relative shape is prose (same reasoning as armour versus the
    # phrase "PRIVATE KEY" at the top of this file).
    assert str(paths.ca_key_path(session_client.app.state.data_root)) not in response.text
    assert str(paths.secret_key_path(session_client.app.state.data_root)) not in response.text

    # Masked, but not silently: an operator has to be able to tell "set" from "unset", or the page is a mystery instead
    # of
    # an observability tool.
    assert "set (value not displayed)" in response.text

    # 0.3.0 turned this page into a form, which adds a surface that is not about *displaying* anything: an input
    # named `MYPKI_SECRET_KEY` would move the session-signing secret out of a 0600 file and into a request body,
    # whatever proxy logged it, and the browser history holding the re-rendered value. So the unmanaged knobs are
    # asserted twice — absent as text above, and absent as a submittable control here.
    # `settingsfile.UNMANAGED_KEYS` is what keeps them out of the form; this proves it at the HTTP boundary.
    for knob in ("MYPKI_SECRET_KEY", "MYPKI_SSL_CERTFILE", "MYPKI_SSL_KEYFILE", "MYPKI_CONFIG_DIR"):
        assert f'name="{knob}"' not in response.text, f"{knob} is editable on /settings"


def test_the_settings_page_masks_a_secret_mypki_generated_itself(tmp_path: Path) -> None:
    """The unset case, built the way a real host builds it: nobody set `MYPKI_SECRET_KEY`, so mypki wrote one.

    The fixtures above cannot show this half — conftest's `settings` supplies `secret_key`, so that row always reads
    "set". Here the knob is left unset and `ca.secret_session_key` does what it does on first `serve`: create
    `<data>/instance/secret_key` (0600) and hand the value to the app. The rendered row has to say a secret exists while
    refusing both to display it and to name the file holding it — "unset" alone would be wrong, and the path alone would
    be a leak of the thing it protects.
    """
    from conftest import ScratchClient
    from mypki.app import create_app
    from mypki.ca import secret_session_key

    data_root = tmp_path / "unset-secret-data"
    unset = Settings(  # type: ignore[call-arg]
        data_dir=data_root,
        log_file=None,
        _env_file=None,
    )
    assert unset.secret_key is None, "this test is about the unset case only"

    generated = secret_session_key(data_root, None)
    assert generated  # a real value exists in this process, which is exactly what must not render
    app = create_app(unset, session_secret=generated)

    with ScratchClient(app, persist_cookies=True) as client:
        response = client.get("/settings")
        assert response.status_code == 200

        assert "unset — mypki generated one into the data dir at startup (not displayed)" in response.text
        assert generated not in response.text
        assert str(paths.secret_key_path(data_root)) not in response.text
        assert str(paths.ca_key_path(data_root)) not in response.text
        assert ARMOUR_RE.search(response.text) is None
        # The same control-shape assertion as above, against the generated-secret host: a page that says
        # "a secret exists"
        # must not also offer a box to type a new one.
        for knob in ("MYPKI_SECRET_KEY", "MYPKI_SSL_CERTFILE", "MYPKI_SSL_KEYFILE"):
            assert f'name="{knob}"' not in response.text, f"{knob} is editable on /settings"


def test_the_about_page_states_limits_without_naming_paths(session_client, ca_bundle, settings: Settings) -> None:
    """`/about` publishes version, source URL and limits — the reportable facts — and nothing private.

    Split from `PAGES` coverage because this page deliberately quotes numbers (validity ceiling, SAN cap, listening
    port) and a future edit that adds "key file: <path>" to that table would look like the same kind of helpfulness.
    """
    response = session_client.get("/about")
    assert response.status_code == 200

    _assert_no_ca_key_material(response.text, "GET /about body", _key_material_of(ca_bundle))
    assert settings.secret_key not in response.text
    assert str(paths.ca_key_path(session_client.app.state.data_root)) not in response.text
    assert str(paths.secret_key_path(session_client.app.state.data_root)) not in response.text


def test_the_ca_certificate_download_is_a_certificate_and_nothing_else(session_client, ca_bundle) -> None:
    """`/ca/certificate` is the route that serves a file about keys, so it is the route worth checking hardest.

    Asserted on three levels: no armour of any kind, none of this CA's key bytes in any form, and exactly one
    CERTIFICATE block. A body that carried the root *plus* something else would satisfy a client and leak in plain
    sight, and "the right certificate is in there" alone would not catch it.
    """
    secrets_ = _key_material_of(ca_bundle)

    response = session_client.get("/ca/certificate")

    assert response.status_code == 200
    _assert_clean(response.text, "GET /ca/certificate body", secrets_)
    _assert_clean(_headers_of(response), "GET /ca/certificate headers", secrets_)
    assert response.text.count("-----BEGIN CERTIFICATE-----") == 1
    assert response.text.count("-----BEGIN") == 1


def test_the_issued_certificate_and_chain_downloads_hold_certificates_only(
    session_client, ca_bundle, sample_csr_pem: str
) -> None:
    """Both downloads from the signing result, fetched from the links the page actually rendered.

    These are the two files an operator copies onto a server, which makes them the highest-value target: a chain that
    carried the CA key next to the leaf would be installed on every client mypki ever touches, and nothing on the page
    would say so. Asserted as *occurrences* of CERTIFICATE armour (1 and 2) alongside the absence of key armour, because
    the count is what proves the file is the artifact it claims to be.
    """
    from conftest import csrf_token

    step_a = session_client.post(
        "/csr/sign", data={"csrf_token": csrf_token(session_client, "/csr/sign"), "csr_pem": sample_csr_pem}
    )
    assert step_a.status_code == 200
    token = re.search(r'name="csrf_token" value="([^"]+)"', step_a.text)
    assert token is not None
    issued = session_client.post(
        "/csr/sign",
        data={"csrf_token": token.group(1), "confirm": "1", "cert_type": "server", "validity_days": "30"},
    )
    assert issued.status_code == 200

    secrets_ = _key_material_of(ca_bundle)
    links = re.findall(r'href="(/download/[^"]+)"', issued.text)
    assert len(links) == 2, links

    bodies = []
    for link in links:
        download = session_client.get(link)
        assert download.status_code == 200
        _assert_clean(download.text, f"GET {link} body", secrets_)
        _assert_clean(_headers_of(download), f"GET {link} headers", secrets_)
        bodies.append(download.text)

    # One certificate in the `.crt`, two in the chain: the counts are what prove each file is the artifact its name
    # promises, rather than a body that merely contains the right certificate somewhere.
    assert sorted(text.count("-----BEGIN CERTIFICATE-----") for text in bodies) == [1, 2]


def test_a_rejected_signing_request_leaks_nothing_about_the_key_it_could_not_use(client, ca_bundle) -> None:
    """Error pages are the leak vector people forget, because they render *input*.

    A garbage paste and a CA-privileged paste both reach `_render_error`, which renders `reason` straight into HTML. The
    reason strings come from `csr.py`/`errors.py` and name extensions and rules rather than echoing a whole body — that
    is a design decision (`errors.py`: the message names what to fix), and this asserts it at the boundary where an
    operator would read it.

    The two rejections are deliberately different conditions — 400 for malformed input, 403 for a request mypki refuses
    to honour — because they run through different handlers, and a leak in one handler's page is not a leak in the
    other's.
    Both need a CSRF token: without one every POST answers 400 from `require_csrf` before any CSR check runs,
    which is how
    an earlier version of this file got a 403-shaped test that never reached the CA-privilege handler at all.
    """
    garbage = client.post(
        "/csr/sign", data={"csrf_token": _token_of(client, "/csr/sign"), "csr_pem": "complete nonsense"}
    )
    privileged = _ca_privileged_body(client)

    assert garbage.status_code == 400
    assert privileged.status_code == 403
    # The refusal names the extension it rejected and says nothing about the key it could not have used.
    assert "BasicConstraints CA:TRUE" in privileged.text

    secrets_ = _key_material_of(ca_bundle)
    for response in (garbage, privileged):
        _assert_clean(response.text, f"POST rejection {response.status_code} body", secrets_)
        _assert_clean(_headers_of(response), f"POST rejection {response.status_code} headers", secrets_)


def test_a_refused_paste_that_is_echoed_back_carries_no_key_body(client, ca_bundle) -> None:
    """The new echo is the new leak vector, so it gets its own boundary check.

    `_paste_refused` puts `csr_pem` back into its textarea so a refusal can be fixed in place. That is deliberate for
    public material and dangerous for a key: an operator who pasted a private key next to their CSR must not get the key
    back into a rendered page, where it lands in a browser cache and a support screenshot.
    `inspect.redact_private_key_bodies` is what keeps that true — armour lines survive so the paste still looks like the
    paste, the base64 does not.

    Asserted against **this CA's** key material as well as the pasted one: the page is rendered with a CA loaded, and a
    context helper that passed `bundle` to the template instead of `describe_ca` would fail here rather than in review.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    pasted_key = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .private_bytes(Encoding.PEM, PrivateFormat.PKCS8, serialization.NoEncryption())
        .decode("ascii")
    )
    paste = f"{pasted_key}\nnot a csr at all\n"

    response = client.post("/csr/sign", data={"csrf_token": _token_of(client, "/csr/sign"), "csr_pem": paste})

    assert response.status_code == 400
    assert '<section class="form-errors refused">' in response.text

    secrets_ = _key_material_of(ca_bundle)
    _assert_no_ca_key_material(response.text, "refused-paste echo body", secrets_)
    _assert_no_ca_key_material(_headers_of(response), "refused-paste echo headers", secrets_)

    # The paste was echoed — the non-secret part of it verbatim.
    assert "not a csr at all" in response.text
    # The key's armour stayed (the operator can see what their paste contained) and its base64 did not.
    assert ARMOUR_RE.search(response.text) is not None
    body_lines = [line for line in pasted_key.splitlines()[1:-1] if len(line) > 40]
    assert body_lines, "the probe key has no long base64 lines to check"
    assert all(line not in response.text for line in body_lines), "a refused paste echoed a private key body back"


def test_the_generated_key_page_shows_the_operators_key_and_never_the_cas(session_client, ca_bundle) -> None:
    """The one page where private-key armour is *supposed* to appear, asserted as the exception it is.

    `/csr/generate`'s POST renders a freshly generated key once and stores nothing (page-map §2). Asserting "no armour
    anywhere ever" would fail against correct behaviour, so this test states the boundary precisely: the operator's own
    key may appear; **this CA's** key may not, on any page, in any form.

    It also pins the shape of that exception — one key block, unencrypted unless a passphrase was given, and the
    passphrase itself absent from the rendered HTML (see `test_csr_generate.py` for the full treatment).
    """
    from conftest import csrf_token

    response = session_client.post(
        "/csr/generate",
        data={
            "csrf_token": csrf_token(session_client, "/csr/generate"),
            "common_name": "leakcheck.internal",
            "sans": "leakcheck.internal",
            "key_type": "ec-p256",
        },
    )

    assert response.status_code == 200

    # The exception, stated exactly: armour is present (the operator's own key), it is exactly one block, and it is not
    # this CA's key in any of its three forms. `_assert_no_ca_key_material` rather than `_assert_clean` for that reason.
    assert ARMOUR_RE.search(response.text) is not None, "expected the operator's own generated key on this page"
    assert response.text.count("-----BEGIN PRIVATE KEY-----") == 1
    _assert_no_ca_key_material(response.text, "POST /csr/generate result", _key_material_of(ca_bundle))

    # Neither download from that page may serve the CA's key either — the operator's own key is fine, and is asserted as
    # armour-bearing in `test_csr_generate.py`.
    for link in re.findall(r'href="(/download/[^"]+)"', response.text):
        download = session_client.get(link)
        assert download.status_code == 200
        _assert_no_ca_key_material(download.text, f"GET {link}", _key_material_of(ca_bundle))


def test_no_response_on_the_keyless_host_leaks_a_path_or_a_secret(client_without_ca, settings: Settings) -> None:
    """A host with no CA still answers every page — and says nothing about where a key would have been.

    `CaNotFoundError` carries `.path` and the 503 hint renders it (app.py), which is deliberate: an operator needs
    to know
    which directory `init-ca` will write to. What must not appear is the *key* path or the session signing secret,
    because
    neither helps anyone fix the missing CA.
    """
    for path in (*PAGES, "/ca/certificate"):
        response = client_without_ca.get(path)
        assert response.status_code in (200, 503), f"{path}: {response.status_code}"

        assert ARMOUR_RE.search(response.text) is None, f"{path} carries private-key armour"
        assert settings.secret_key not in response.text
        assert settings.secret_key not in _headers_of(response)

    refused = client_without_ca.get("/ca/certificate")
    assert refused.status_code == 503
    assert NO_CA_MARK in refused.text
    assert str(paths.ca_key_path(client_without_ca.app.state.data_root)) not in refused.text


def test_an_ocsp_response_carries_no_private_bytes_and_verifies_with_the_public_key(
    session_client, ca_bundle, settings: Settings
) -> None:
    """The second signed artifact this app serves: DER out, and nothing private inside it.

    `/ocsp` is the route that signs **per request**, which makes it the most interesting body in this file: a handler
    that assembled its answer out of the signing bundle rather than from the record store could leak through a path no
    HTML page has. Checked against bytes rather than `response.text`: the body is DER, and a lossy decode of it is not
    the artifact — while `_key_material_of`'s DER form is precisely what a careless builder might embed.

    The positive half is asserted as well as the negative: the signature verifies against the CA's **public** key, and
    the responder identity is a Name plus the CA certificate. An OCSP answer is checkable by anyone while revealing
    nothing, which is the difference between publishing a revocation answer and publishing a bundle.
    """
    response = session_client.post(
        "/ocsp", content=_ocsp_request_der(ca_bundle), headers={"content-type": OCSP_REQUEST_MEDIA_TYPE}
    )
    assert response.status_code == 200

    secrets_ = _key_material_of(ca_bundle)
    # `latin-1` rather than `utf-8`: DER is not text, and this is the same lossless one-byte-per-character view used on
    # the header side (`_headers_of`), so a search for the CA key's DER form cannot miss on an encoding error.
    _assert_no_ca_key_material(response.content.decode("latin-1"), "POST /ocsp body", secrets_)
    _assert_clean(_headers_of(response), "POST /ocsp headers", secrets_)
    assert settings.secret_key not in response.content.decode("latin-1")

    parsed = load_der_ocsp_response(response.content)
    assert parsed.response_status is OCSPResponseStatus.SUCCESSFUL
    ca_bundle.cert.public_key().verify(
        parsed.signature, parsed.tbs_response_bytes, asym_padding.PKCS1v15(), hashes.SHA256()
    )
    assert parsed.responder_name == ca_bundle.cert.subject


def test_the_ocsp_refusals_carry_no_bytes_of_any_kind(session_client, ca_bundle, settings: Settings) -> None:
    """A 5-byte refusal is the smallest possible leak surface, and it is asserted as one.

    Refusals are where an error path normally adds detail — a path, a config value, a stack frame. This answer is
    byte-exact (`30 03 0a 01 01`, MEASURED), so it cannot contain anything: not the CA key in any of the three forms
    `_key_material_of` produces, and not the session signing secret either. Asserting the exact bytes is what keeps that
    claim from decaying into "the body was short".
    """
    secrets_ = _key_material_of(ca_bundle)

    response = session_client.post("/ocsp", content=b"not-an-ocsp-request")

    assert response.status_code == 200
    assert response.content == MALFORMED_DER
    _assert_no_ca_key_material(response.content.decode("latin-1"), "POST /ocsp refusal", secrets_)
    _assert_clean(_headers_of(response), "POST /ocsp refusal headers", secrets_)
    assert settings.secret_key not in response.content.decode("latin-1")


def _ocsp_request_der(bundle) -> bytes:
    """A real DER OCSP request about a serial, built the way a client builds one.

    Duplicated from `test_ocsp.py` rather than imported: this file's claim is about **what comes back**, and it should
    not lean on another test file's fixtures to ask the question. Both CertID hashes are computed from public values
    (the CA subject DER and its SubjectPublicKeyInfo DER), which is itself part of the point — asking this route a
    question needs nothing private.
    """
    subject = bundle.cert.subject.public_bytes(Encoding.DER)
    spki = bundle.cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    builder = OCSPRequestBuilder().add_certificate_by_hash(
        hashlib.sha256(subject).digest(), hashlib.sha256(spki).digest(), 0xCAFE_0001, hashes.SHA256()
    )
    return builder.build().public_bytes(Encoding.DER)


def test_the_published_crl_is_armour_free_and_carries_only_public_bytes(session_client, ca_bundle) -> None:
    """The CRL is the one body this app serves that is a signature, so it gets its own look.

    A CRL is signed *by* the CA key and must therefore contain none of it: what belongs in the artifact is the issuer
    name, the revoked serials and an Authority Key Identifier — the AKI is a hash of the **public** key, which is why
    serving a CRL is safe while serving a bundle would not be. Asserted three ways rather than one:

    * no armour of any spelling in the served bytes (the loop above already searched this body for the CA key's three
      forms; naming the armour separately here is what catches a build that embedded the PEM instead of the digest);
    * the one identifier a CRL is allowed to carry about its signer — the Authority Key Identifier — equals
      `AuthorityKeyIdentifier.from_issuer_public_key(...)`, i.e. a digest of the **public** key;
    * the signature verifies against that public key, and a second GET answers byte-identically.
    """
    response = session_client.get("/crl.pem")
    assert response.status_code == 200

    assert ARMOUR_RE.search(response.text) is None, "/crl.pem carries private-key armour"
    # The CRL's own marker is the only BEGIN line that may appear; anything else is a key or a certificate smuggled in.
    assert CRL_PEM_MARKER in response.text
    assert response.text.count("-----BEGIN") == 1

    crl = x509.load_pem_x509_crl(response.content)
    aki = crl.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    expected = x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_bundle.cert.public_key())
    assert aki.key_identifier == expected.key_identifier  # type: ignore[attr-defined]

    # Verification against the public key is the proof that rendering this artifact needed nothing private.
    assert crl.is_signature_valid(ca_bundle.cert.public_key())
    assert response.content == session_client.get("/crl.pem").content


def test_the_session_cookie_carries_ids_not_material(session_client, settings: Settings, sample_csr_pem: str) -> None:
    """The cookie is signed *with* the secret; it must never contain it.

    itsdangerous puts a base64 payload plus an HMAC digest in the value (MEASURED: the payload is JSON of session keys
    and opaque artifact ids). Asserted after driving a real two-step flow, so the session being inspected is one
    that has
    actually held a staged CSR id and an issued-cert id — the state where a naive implementation would have stuffed the
    PEM into the cookie instead of into `OneShotStore` (app.py explains why it cannot: RFC 6265 §6.1).
    """
    from conftest import csrf_token

    step_a = session_client.post(
        "/csr/sign", data={"csrf_token": csrf_token(session_client, "/csr/sign"), "csr_pem": sample_csr_pem}
    )
    assert step_a.status_code == 200
    token = re.search(r'name="csrf_token" value="([^"]+)"', step_a.text)
    session_client.post(
        "/csr/sign",
        data={"csrf_token": token.group(1), "confirm": "1", "cert_type": "server", "validity_days": "30"},
    )

    cookie_values = [f"{name}={value}" for name, value in session_client.cookies.items()]
    joined = "\n".join(cookie_values)

    assert settings.secret_key not in joined
    assert ARMOUR_RE.search(joined) is None
    assert "-----BEGIN" not in joined
    oversized = [value for value in cookie_values if len(value) >= 4096]
    assert oversized == [], "RFC 6265 §6.1: browsers may reject cookies over 4096 octets"


# ------------------------------------------------------------------------------------------------ the log file


def test_a_record_naming_key_material_is_dropped_and_counted(settings: Settings) -> None:
    """`dropped_record_count()` rises when something emits a record naming key material, and the file stays clean.

    Counting the drop is itself safe to log — it names no key material — and it is the difference between an invariant
    holding and an invariant nobody checked (`logsetup.py`). Asserted as before/after rather than as an absolute number:
    `_DROPPED` is process-global, so a test that asserted a total would fail on the ninetieth test of a full-suite run
    while passing alone.

    MEASURED, and it changes what the number means: `_DROPPED.append` runs once per **handler that would have written**
    the record, not once per record. With file logging and the console mirror both attached (the default configuration),
    one leaked line is counted twice — so `mypki info`'s "the filter dropped N records" has to be read as *dropped
    writes*,
    and the honest assertion here is that the count **rises** rather than a specific increment.

    Asserted against the log **file** rather than pytest's captured records: `caplog` installs its own unfiltered
    handler
    on the root logger, so a leak *does* appear in `caplog.records` while being correctly kept out of every
    artifact mypki
    owns. Reading the file is reading the thing an operator backs up and ships to an aggregator.
    """
    from mypki.logsetup import configure_logging

    log_file = settings.log_file
    assert log_file is not None
    configure_logging(settings)

    before = dropped_record_count()

    # Both markers from FORBIDDEN_MARKERS, because they cover different formats: `PRIVATE KEY` catches PKCS#8 and
    # traditional OpenSSL, `ENCRYPTED PRIVATE KEY` is listed explicitly so the scope is stated rather than inferred.
    logging.getLogger("mypki.probe.unencrypted").error(
        "accidental leak: %s", "-----BEGIN PRIVATE KEY-----\nTU9DSy1LRVktTk9ULVJFQUw=\n-----END PRIVATE KEY-----"
    )
    assert dropped_record_count() > before

    after_first = dropped_record_count()
    logging.getLogger("mypki.probe.encrypted").warning(
        "accidental leak: %s",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\nTU9DSy1LRVktTk9ULVJFQUw=\n-----END ENCRYPTED PRIVATE KEY-----",
    )
    assert dropped_record_count() > after_first

    contents = log_file.read_text(encoding="utf-8")
    assert ARMOUR_RE.search(contents) is None, f"log file {log_file} contains private-key armour"
    assert "accidental leak" not in contents  # the whole record went, not a masked copy of it

    # A record that names no key material still gets written, so the filter is a gate and not a mute button.
    logging.getLogger("mypki.probe.benign").info("issued serial=deadbeef type=server cn=example.internal")
    assert "serial=deadbeef" in log_file.read_text(encoding="utf-8")


def test_the_rotating_log_file_holds_no_armour_after_signing_and_generating(
    session_client, settings: Settings, ca_bundle, sample_csr_pem: str
) -> None:
    """Drive the two key-touching flows, then read the artifact an operator actually backs up.

    Generating a keypair and signing a leaf are the operations with the most key material in scope, and mypki logs both
    (page-map §0 logs the source IP and identity facts only). Asserted on the **file** rather than on captured stderr:
    logs get shipped to aggregators and attached to tickets, so the file is the artifact that matters. The startup line
    naming the resolved path is expected content — it names a log path, not a key.

    `logsetup`'s filter is installed by `configure_logging`, which `create_app` calls; asserting absence here proves the
    whole chain (handler → filter → file) rather than the filter in isolation.
    """
    from conftest import csrf_token

    session_client.post(
        "/csr/generate",
        data={
            "csrf_token": csrf_token(session_client, "/csr/sign"),
            "common_name": "logged.internal",
            "sans": "logged.internal",
            "key_type": "rsa-2048",
        },
    )

    step_a = session_client.post(
        "/csr/sign", data={"csrf_token": csrf_token(session_client, "/csr/sign"), "csr_pem": sample_csr_pem}
    )
    token = re.search(r'name="csrf_token" value="([^"]+)"', step_a.text)
    session_client.post(
        "/csr/sign",
        data={"csrf_token": token.group(1), "confirm": "1", "cert_type": "both", "validity_days": "30"},
    )

    log_file: Path = settings.log_file
    assert log_file is not None and log_file.is_file(), "expected the rotating log file this app configured"
    contents = log_file.read_text(encoding="utf-8")

    assert contents, "the log file is empty, so this test would pass vacuously"
    assert ARMOUR_RE.search(contents) is None, f"log file {log_file} contains private-key armour"
    for secret in _key_material_of(ca_bundle):
        assert secret not in contents
    assert settings.secret_key not in contents
    # The evidence that logging worked at all: mypki's own startup line naming where it writes.
    assert "logging to " in contents


def test_a_leak_from_a_third_party_logger_is_also_dropped(settings: Settings) -> None:
    """The filter guards the **root** logger, so a dependency's debug line passes through the same gate.

    `logsetup.py` states this as the reason for attaching to root rather than to `mypki`: a future dependency that
    logs a
    key is exactly as guilty as mypki would be, and a filter attached only to the `mypki.*` subtree would not see
    it. The
    probe therefore uses `uvicorn.access`, a logger mypki does not own but explicitly makes propagate (measured
    behaviour 1
    in that module's docstring).

    The cost is stated rather than hidden: dropping is not redacting, so the record — including whatever useful context
    surrounded it — is gone from every artifact. A real bug of this shape is fixed by stopping the logging, and
    `dropped_
    record_count()` is what tells an operator that something had to be dropped at all.
    """
    from mypki.logsetup import configure_logging

    log_file = settings.log_file
    assert log_file is not None
    configure_logging(settings)

    before = dropped_record_count()
    leaked = private_key_pem(_throwaway_leaf()).decode("ascii")
    logging.getLogger("uvicorn.access").error("leaked key: %s", leaked)

    assert dropped_record_count() > before
    contents = log_file.read_text(encoding="utf-8")
    assert ARMOUR_RE.search(contents) is None
    assert leaked not in contents


def test_the_forbidden_markers_cover_every_format_mypki_can_emit() -> None:
    """`FORBIDDEN_MARKERS` is a claim about formats, and formats are enumerable.

    mypki emits PKCS#8 unencrypted and PKCS#8 encrypted (`keys.private_key_pem`, `PrivateFormat.PKCS8` only — PKCS#1 is
    not encryptable at all, which is why it is absent). Traditional OpenSSL (`RSA PRIVATE KEY`) and SEC 1 (`EC PRIVATE
    KEY`) can arrive from an *imported* key rather than a generated one. Asserted as: for each armour header mypki could
    plausibly produce or ingest, some marker in the tuple is a substring of it. A marker list that grew stale would fail
    here rather than in an incident review.
    """
    spellings = (
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
    )

    for armour in spellings:
        inner = armour.strip("-").split(" ", 1)[1]  # drop the BEGIN marker, keep 'PRIVATE KEY' / 'ENCRYPTED …'
        assert any(marker in inner for marker in FORBIDDEN_MARKERS), f"{armour} is not covered by {FORBIDDEN_MARKERS}"


# ------------------------------------------------------------------------------------------------- helpers


def _token_of(client, path: str) -> str:
    """Read the CSRF token a page renders, so a rejection test reaches the handler it means to exercise.

    Without a token every POST on this app answers 400 from `require_csrf` before any CSR check runs. A test that posts
    without one and expects a specific *CSR* rejection is therefore asserting the CSRF handler, not the one it names.
    """
    from conftest import csrf_token

    return csrf_token(client, path)


def _throwaway_leaf():
    """A real keypair that belongs to no CA, for exercising the log filter."""
    from mypki.keys import generate_key

    return generate_key(KeySpec.from_string("ec-p256"))


def _ca_privileged_body(client):
    """The full 403 response of a CA-privileged paste, so assertions read the request they were produced by.

    Correctly signed and carrying a CSRF token on purpose. Without a valid token the request is answered 400 by
    `require_csrf` before any CSR is parsed, so the test would be asserting the CSRF handler while claiming to
    assert the
    CA-privilege handler — a 403 that never happened.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "evil.internal")]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("evil.internal")]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    response = client.post(
        "/csr/sign",
        data={
            "csrf_token": _token_of(client, "/csr/sign"),
            "csr_pem": csr.public_bytes(Encoding.PEM).decode("ascii"),
        },
    )

    assert response.status_code == 403, response.text[:400]
    return response
