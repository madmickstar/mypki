"""The five pages, the two-step signing flow, and every rejection's status code and page.

page-map §0 fixes four promises that only show up at the HTTP layer, so they can only be tested here:

1. **Every rejection is mypki's own page naming its own reason.** Not FastAPI's JSON `detail`, not a traceback, and —
   for oversized input — not starlette's `Field exceeded maximum size of 1024KB.` either. The size guard runs before any
   parser so the operator reads `MYPKI_MAX_CSR_CHARS`, the knob they can actually change (page-map §11).
2. **A CSRF failure says nothing was signed.** A 400 that looks like every other bad request leaves an operator
   wondering whether a certificate got out with a wrong name; here no signing code ran at all, and the page says so.
3. **Status codes carry meaning.** 400 for malformed input, 403 for a request mypki refuses to honour (CA privileges),
   413 for size, 404 for an expired one-shot download, 503 for a host with no CA — the route exists and is correct, this
   host just cannot answer it yet.
4. **Security headers on everything**, including the error pages and the standalone 413 body that never reached a
   request object.

Each negative case mutates **one** thing (STYLE §8): one field value, one added extension, one DER byte, one validity
number. Nothing hard-codes the version or the limits — bounds come from `Settings`, and the version text is read from
`mypki.__version__`.

MEASURED on this build (fastapi 0.162 / starlette 1.10), pinned here so nobody re-derives it: an oversized paste answers
**413** with mypki's page and the string `Field exceeded maximum size of 1024KB.` is **absent**; a CA-privileged CSR
answers **403** naming `BasicConstraints CA:TRUE`; `GET /` carrying a body still answers 200 because the size guard only
measures POST/PUT/PATCH; `/docs`, `/openapi.json` and `/redoc` are all 404.

Hermeticity comes from `conftest.py`'s autouse fixtures: the data dir is a `tmp_path`, so the record-store assertions
below count rows in a database that belongs to this test alone.
"""

from __future__ import annotations

import base64
import re
import time
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from mypki import __version__, paths
from mypki.app import CUSTOM_CHOICE, KNOB_PRESETS, PROJECT_URL, OneShotStore
from mypki.ca import CaBundle, describe_ca, format_fingerprint
from mypki.config import Settings
from mypki.csr import CSR_PEM_BEGIN, CSR_PEM_END
from mypki.errors import OneShotExpiredError
from mypki.settingsfile import UNMANAGED_KEYS
from mypki.store import IssuedStore

#: Every page an operator can reach with a GET. `/about` and `/settings` joined in 0.2.0, and they join *this* list as
#: well
# as `test_no_key_leakage.py`'s because the three parametrizations driven off it (200 with a CA, 200 for a cookieless
# client,
# security headers) are promises about *every* page rather than about the five 0.1.0 pages: a new route that forgot a
# CSP
# header or assumed an existing session is exactly what these cases exist to catch. `/inspect` joined in 0.5.0, and it
#: joins here for the same reason: a page that reads pasted input still has to answer 200 with a CA, without a cookie,
#: and under the same CSP as every other page.
PAGES = ("/", "/csr/generate", "/csr/sign", "/ca", "/issued", "/about", "/inspect", "/settings")

#: The starlette answer mypki's size guard exists to prevent (MEASURED, `max_part_size=1048576`). Its absence is an
#: assertion, not an observation: a framework message on the page means the operator was sent looking for a setting that
#: is not the knob they should change.
STARLETTE_SIZE_MESSAGE = "Field exceeded maximum size of 1024KB."

NO_CA_MARK = "Run `mypki init-ca`"


# --------------------------------------------------------------------------------------------- helpers


def _post(client, path: str, *, token_from: str | None = None, **fields: str):
    """POST a form with the session's own CSRF token, or with none at all.

    `token_from=None` is the negative case (submit without any token); `token_from="/csr/sign"` reads the token off that
    page first. Splitting the two into one helper keeps "no token" from accidentally becoming "the wrong token" — a
    distinction that matters because mypki answers both with 400 but only one of them is what page-map §0 tests.
    """
    payload = dict(fields)
    if token_from is not None:
        from conftest import csrf_token

        payload["csrf_token"] = csrf_token(client, token_from)
    return client.post(path, data=payload)


def _inline_reasons(response) -> str | None:
    """The `<li>` sentences in a re-rendered form's `.form-errors` block, joined — or None if there is no such block.

    app.py's heading still names *two* error surfaces while its text now counts three: a typed field re-renders
    this form at HTTP 200 with the reason here, a refused paste re-renders the sign page at 400/403, and a refusal
    with no form to put it on goes to `error.html` at 400/403/413 with `<p
    class="reason">`. Reading the block structurally rather than searching the body is the same discipline as
    `_reason()` below: "the word appears somewhere on the page" is also true of a page that mentions a field while
    refusing for another reason.
    """
    match = re.search(r'<section class="form-errors">(.*?)</section>', response.text, re.DOTALL)
    if match is None:
        return None
    items = re.findall(r"<li>(.*?)</li>", match.group(1), re.DOTALL)
    return " ".join(item.strip() for item in items)


def _reason(response) -> str:
    """The `<p class="reason">` sentence mypki rendered.

    Read structurally rather than by searching the whole body, because "the word appears somewhere on the page" is also
    true of a page that mentions the word while refusing for a different reason. Absence of the element is
    reported as an
    explicit failure so a template rename cannot turn these tests into `None in text` comparisons that pass vacuously.
    """
    match = re.search(r'<p class="reason">(.*?)</p>', response.text, re.DOTALL)
    if match is None:
        raise AssertionError(
            f'no mypki error page (class="reason") in the {response.status_code} body:\n{response.text[:400]}'
        )
    return match.group(1)


def _tampered(pem: str) -> str:
    """The same CSR with one bit flipped inside its signed region, re-armed as PEM.

    Offset -32 from the end of the DER (MEASURED on cryptography 50.0.2 for both CSRs and certificates): the
    result still
    parses as a well-formed request and reports `is_signature_valid False`. An offset that breaks the ASN.1 parse
    instead
    would test the parser rather than the signature check, and would stay green if the signature were never verified at
    all — which is the bug this helper exists to catch.
    """
    match = re.search(rf"{CSR_PEM_BEGIN}\s*(.*?)\s*{CSR_PEM_END}", pem, re.DOTALL)
    if match is None:
        raise AssertionError("_tampered needs a PEM-armoured request")

    der = bytearray(base64.b64decode("".join(match.group(1).split())))
    der[-32] ^= 0x01
    armed = "\n".join(base64.encodebytes(bytes(der)).decode("ascii").split())
    return f"{CSR_PEM_BEGIN}\n{armed}\n{CSR_PEM_END}\n"


def _ca_privileged_csr_pem() -> str:
    """A correctly signed request that asks for CA powers.

    Correctly signed on purpose: the point of the refusal is the **extension**, so a signature error would mask it
    with a
    message about tampering (page-map §3's ordering puts signature first, and `test_csr_validate.py` pins that
    ordering).
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "evil.internal")]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("evil.internal")]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(Encoding.PEM).decode("ascii")


def _confirm_and_issue(client, csr_pem: str, **overrides: str):
    """Run both steps of page-map §3 and return `(confirmation, step A)`.

    Step B re-reads the staged PEM out of the one-shot store rather than from a textarea round trip, so this
    helper has to
    keep cookies — it is a `session_client`-only helper, and that is part of what it asserts: the flow is stateful by
    design.

    The token step B submits is read out of **step A's own page** rather than fetched with another GET. That is not an
    optimisation: it is the shape of the real flow, where the confirmation form the operator clicks carries the
    token that
    the validation page rendered (see `csrf.py` on why tokens are not rotated per request).
    """
    step_a = _post(client, "/csr/sign", token_from="/csr/sign", csr_pem=csr_pem)
    assert step_a.status_code == 200, _reason(step_a)

    match = re.search(r'name="csrf_token" value="([^"]+)"', step_a.text)
    if match is None:
        raise AssertionError("step A rendered no csrf_token field")

    fields = {"confirm": "1", "cert_type": "server", "validity_days": "30"}
    fields.update(overrides)
    return _post(client, "/csr/sign", token_from=None, csrf_token=match.group(1), **fields), step_a


def _issued_pending_id(response) -> str:
    """The staged request's `?pending=` id, read out of a confirmation form's action URL.

    Read rather than invented: the id is an opaque random token (`OneShotStore.put` mints it with
    `secrets.token_urlsafe(32)`), so a test that hard-coded one would be asserting its own invention. Comparing the id
    step A handed the page against the id the **re-rendered** page hands back is what proves the staged request survived
    the round trip — which is the whole point of putting it in the action URL instead of relying on the session cookie.
    """
    match = re.search(r'action="/csr/sign\?pending=([^"]+)"', response.text)
    if match is None:
        raise AssertionError(f"no ?pending= form action in the {response.status_code} body:\n{response.text[:400]}")
    return match.group(1)


def _issued_serial(response) -> str:
    """The serial of the certificate this page just issued, read from inside the *Issued* card.

    A page-wide search for `<td class="mono">` stopped being enough in 0.2.0: `/csr/sign` (and `/`) now also render the
    CA facts strip, whose serial cell is spelled identically (csr_sign.html), so a loose regex returns the **CA's**
    serial on the very page that reports a freshly issued one — MEASURED: it captured `3432f851…` while the record was
    `21adb4d3…`. Anchoring on the card's own `<h2>Issued:` heading reads the row the test is about. Absence raises
    rather than returning None, for the same reason `_reason()` does: a renamed heading must fail loudly instead of
    degrading into `None in text`.
    """
    match = re.search(r'<h2>Issued:.*?<td class="mono">([0-9a-f]{8,})<', response.text, re.DOTALL)
    if match is None:
        raise AssertionError(f"no issued serial on the {response.status_code} body:\n{response.text[:400]}")
    return match.group(1)


# --------------------------------------------------------------------------------------- the five pages 200


@pytest.mark.parametrize("path", PAGES)
def test_every_page_answers_two_hundred_with_a_ca(session_client, path: str) -> None:
    """The advertised surface, asserted as a set rather than one at a time.

    A page that 500s on startup (a template reaching for a context key nobody passes) is the failure mode here: each of
    these five renders from `context(request)` and shares one CA object, so one broken key breaks the page silently
    rather than loudly.
    """
    response = session_client.get(path)

    assert response.status_code == 200, response.text[:400]
    assert "mypki" in response.text


@pytest.mark.parametrize("path", PAGES)
def test_every_page_answers_two_hundred_for_a_cookieless_client(client, path: str) -> None:
    """No session, no token, nothing pending — and still a page.

    `client` starts with an empty cookie jar, so each of these GETs is the first request this process has ever seen from
    "this browser". A page that assumed a session already existed (the CSRF field, the issued count) would fail here and
    pass in the stateful tests above.
    """
    assert client.get(path).status_code == 200


def test_the_version_page_renders_the_version_from_init_py(session_client) -> None:
    """`/version` is a page, not JSON, because this app advertises no API (page-map §0).

    Asserted against `mypki.__version__` rather than a literal (STYLE §1): the smoke scripts read this page, and a
    hard-coded expectation here would be a second copy of the version — exactly the drift `tools/check_version.py`
    exists
    to prevent.
    """
    response = session_client.get("/version")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert f"mypki {__version__}" in response.text


def test_no_api_surface_is_advertised(session_client) -> None:
    """`/docs`, `/openapi.json` and `/redoc` are 404 because the knobs are hard-coded off (page-map §0).

    Asserted as 404 rather than "not in the settings": `create_app` passes `docs_url=None, redoc_url=None,
    openapi_url=None` to the constructor, so no configuration value can switch an API surface back on. A 200 here would
    mean FastAPI's documentation was reachable on a host with no logins.
    """
    for path in ("/docs", "/openapi.json", "/redoc"):
        assert session_client.get(path).status_code == 404, path


def test_the_stylesheet_is_served_and_linked_by_url_for(session_client) -> None:
    """`/static/style.css` resolves through the mount registered last (page-map §1).

    The link in `base.html` comes from `url_for('static', ...)`, which is what makes mypki work under a reverse proxy's
    sub-path. Asserted on both halves — the asset answers, and the rendered page points at it — because a mount that
    shadows a page route would break the second half only.
    """
    asset = session_client.get("/static/style.css")

    assert asset.status_code == 200
    assert "text/css" in asset.headers["content-type"]
    assert "/static/style.css" in session_client.get("/").text


# -------------------------------------------------------------------------------------------- about + settings (§12)


def test_the_running_card_sits_at_the_top_of_about(session_client) -> None:
    """0.5.0 ordering: `/about` answers "what is running here" before anything else (page-map §12).

    The card was third, behind the lede and the profile hero. Its rows -- version, source URL, listening host:port,
    record counts, validity ceiling, SAN cap -- are the facts an operator needs *first*: they are what a problem report
    quotes, what tells you whether this is TLS or plain HTTP, and what `/settings` then expands on. The prose below it
    explains a product you already know you are looking at.

    Asserted as offsets rather than as presence, because every needle in this card was already present somewhere on the
    page: a test that only asked "is the version there" would have stayed green through the exact change being made.
    """
    page = session_client.get("/about")

    running = page.text.find("What this host is running")
    lede = page.text.find('<p class="lede">')
    hero = page.text.find("What the three profiles mean")

    assert running != -1 and lede != -1 and hero != -1, page.text[:300]
    assert running < lede, "the running card still sits below the lede"
    assert running < hero, "the running card still sits below the profile hero"
    # It is not merely earlier than the prose: it is the FIRST section the page renders, which is what "at the top"
    # has to mean for a reader who scrolls. Asserted against `<section` rather than the card's own markup so a change
    # of class or heading level cannot dodge the assertion by moving the needle without moving the card.
    first_section = page.text.find("<section")
    assert first_section != -1 and first_section < lede, "the running card is not the first section on /about"


def test_the_about_page_names_the_version_the_source_url_and_all_three_profiles(session_client) -> None:
    """`/about` is where a problem becomes reportable: a version, a source URL, and what each profile will not do.

    Three assertions, one per thing an operator quotes when reporting a problem (page-map §12):
      * `mypki <version>` read from `__version__` rather than a literal, so this test cannot age out (STYLE §1);
      * the source URL is a **link** (`<a href=`), because a URL in prose cannot be clicked and a URL that
        disagrees with `pyproject.toml` is exactly the drift `tools/check_version.py` polices elsewhere;
      * all three profile explanations from `signing.CERT_PROFILE_HELP`, each carrying the negative half of what that
        profile does — the sentences users asked for after 0.1.0's "Only the SANs above are copied from your request".
    """
    from mypki.signing import CERT_PROFILE_HELP

    page = session_client.get("/about")

    assert page.status_code == 200
    assert f"mypki {__version__}" in page.text
    assert f'<a href="{PROJECT_URL}">{PROJECT_URL}</a>' in page.text, PROJECT_URL

    for profile in ("server", "client", "both"):
        help_text = CERT_PROFILE_HELP[profile]
        assert help_text in page.text, profile
    # The load-bearing sentences: `server` is the web-server profile, `client` will not make a browser trust a site.
    assert "This is the web-server profile." in page.text
    assert "It will NOT make a browser trust a web site" in page.text
    # The limitation that was missing from the product entirely, rewritten for 0.7.0 (plan §8's sweep): this host now
    # signs a CRL and answers OCSP, so the honest sentence is about **clients that consult them** rather than about an
    # absent artifact. Split across lines in the template (Jinja keeps the newline verbatim), so each half is asserted
    # separately rather than as one long string that cannot match.
    assert "Revocation reaches only clients that go looking for it." in page.text
    assert "/crl" in page.text
    assert 'a revoke still means "this host says no"' in page.text
    assert 'rather than "no client will accept it"' in page.text


def test_the_settings_page_shows_a_supplied_value_as_supplied_by_the_operator(
    settings: Settings, ca_bundle: CaBundle, tmp_path: Path
) -> None:
    """`/settings` answers "what is this process actually running with", including for a value set in a `.env`.

    The `.env` is written into the directory `conftest._no_stray_env_file` already chdir'd this test into, and read
    through `Settings`'s own declared `env_file=".env"` — the real operator path, not a constructor argument. Asserted
    on one knob (`MYPKI_MAX_SANS=7`, well away from mypki's 100) at three levels: the value sitting in that knob's
    input, the status panel naming where the data directory came from, and a second knob nobody supplied still showing
    mypki's own default. A page that showed every value as operator-supplied would look informative and prove nothing.

    0.4.0: these assertions used to scrape the resolved-state table (`Knob | Value | Source | …`). The table is gone —
    it restated twenty-odd values a reader could already see in the form, and its "source" column named a layer no
    process can identify — so what is asserted now is the same honesty at the places that remain: the input's own
    `value=`, the one provenance row the status panel kept, and the 'Not editable here' card that took over the secret
    presence flag. `test_no_key_leakage.py` still checks the resolved key paths from outside.
    """
    from conftest import ScratchClient
    from mypki.app import create_app

    (Path.cwd() / ".env").write_text("MYPKI_MAX_SANS=7\n", encoding="utf-8")
    try:
        supplied = Settings(
            data_dir=settings.data_dir,
            log_file=settings.log_file,
            secret_key="test-session-secret-not-a-real-one",
        )
        assert supplied.max_sans == 7  # the fixture's default is 100; the .env moved it

        app = create_app(supplied, ca_bundle=ca_bundle, session_secret="test-session-secret-not-a-real-one")
        with ScratchClient(app, persist_cookies=True) as client:
            page = client.get("/settings")
            assert page.status_code == 200

            # The form shows the live value, not mypki's default: a box pre-filled with 100 while the process runs 7 is
            # a Save button that would write 100 back and undo the operator's own .env.
            assert _knob_value(page, "MYPKI_MAX_SANS") == "7"
            assert _knob_value(page, "MYPKI_VALIDITY_DEFAULT_DAYS") == "365"

            # The one provenance row that survived: where the data directory in force actually came from.
            assert _status_row(page, "Data directory came from") == "supplied by the operator"

            # The secret presence flag now lives in the 'Not editable here' card rather than in a table row.
            assert "set (value not displayed)" in page.text
            assert supplied.secret_key not in page.text

            # The page states its own limit rather than implying a precision the process does not have. Split across
            # lines in the template (Jinja keeps the newline verbatim), so both halves are checked separately.
            assert ".env</code> file, one from a shell variable and one from a" in page.text
            assert "indistinguishable here" in page.text
    finally:
        (Path.cwd() / ".env").unlink(missing_ok=True)


def _knob_value(page, knob: str) -> str | None:
    """The `value=` of one knob's input on `/settings`, or None when the control is absent.

    Read structurally for the same reason `_reason()` and `_inline_reasons()` are: `assert "7" in page.text` is also
    true of a page where 7 appears in an unrelated hint sentence. Anchoring on `name="MYPKI_MAX_SANS"` means the value
    belongs to the knob being asserted on. The tag is joined across lines first because settings.html breaks an input
    over five lines (type, min, max, value), exactly as tools/e2e_harness.py §12 has to handle.
    """
    joined = re.sub(r"\n\s*", " ", page.text)
    match = re.search(rf'<input[^>]*name="{knob}"[^>]*value="([^"]*)"', joined)
    if match is None:
        return None
    return match.group(1)


def _status_row(page, label: str) -> str | None:
    """The value of one 'Currently on this host' row on `/settings`, or None when the row is absent."""
    match = re.search(
        rf'<th scope="row">{re.escape(label)}</th>\s*<td class="mono[^"]*">([^<]*)</td>',
        page.text,
    )
    if match is None:
        return None
    return match.group(1)


def _choice_menu(page, name: str) -> str:
    """The inside of one Issuing-limits dropdown (`<select id="c_<name>">…</select>`), or '' when it is absent.

    Anchored on the select's own `id` so an option asserted below provably belongs to the knob being asserted on: a
    bare `assert '<option value="365"' in page.text` is equally true of a dropdown belonging to another knob. Lines
    are joined first because settings.html writes one `<option>` per line, and a tag-level assertion should not depend
    on that layout choice — the same reason `_knob_value()` joins.
    """
    joined = re.sub(r"\n\s*", " ", page.text)
    match = re.search(rf'<select id="c_{name}"[^>]*>(.*?)</select>', joined)
    if match is None:
        return ""
    return match.group(1)


def _declared_bounds(name: str) -> tuple[int | None, int | None]:
    """The `ge=`/`le=` pydantic actually enforces for one knob, read off `Settings.model_fields`.

    Deliberately re-derived here rather than imported from `app._knob_input`: the point of the assertions below is that
    the dropdown and the `<input min max>` agree with **`config.py`**, and an expectation borrowed from the code under
    test could not fail even if the page disagreed with the model. Constraint objects are matched on their `repr()`
    prefix (`Ge(…)` / `Le(…)`) because that is how pydantic stores them in `FieldInfo.metadata`.
    """
    low = high = None
    for constraint in Settings.model_fields[name].metadata:
        text = repr(constraint)
        if text.startswith("Ge("):
            low = getattr(constraint, "ge", None)
        elif text.startswith("Le("):
            high = getattr(constraint, "le", None)
    return low, high


# ------------------------------------------------------------------------------------ 0.4.0: dropdowns and cards

#: The knobs 0.4.0 renders as a preset menu over an authoritative number box: the whole 'Issuing limits' section.
#: `session_max_age` is in it despite being startup-only — see the comment on `app.KNOB_PRESETS` for why.
CHOICE_KNOBS = ("validity_default_days", "validity_max_days", "max_sans", "max_csr_chars", "session_max_age")


def test_the_issuing_limits_render_as_a_menu_over_an_authoritative_box(session_client) -> None:
    """Every Issuing limit offers the presets, and the box that actually posts still carries `config.py`'s bounds.

    Three promises, one per control, because a dropdown is only safe if all three hold:

    1. **The menu cannot post anything.** Its `<select>` has an `id` and a `data-mypki-select-for`, and **no `name`
       attribute** — so the only value that reaches the server is the number input's, which `config.py` bounds-checks
       whatever the menu says. A dropdown with a `name=` is a second way to submit a limit, and a browser with
       JavaScript off would see both controls posting.
    2. **The menu is complete.** Every value in `app.KNOB_PRESETS` for that knob renders as an `<option>`, plus the
       `Custom` option. Asserted against the table rather than a hard-coded list so a preset added for one knob cannot
       quietly fail to appear on the page. This assertion *also* proves the human-written preset table lies inside the
       machine-enforced bounds: `_preset_choices` filters out-of-bounds presets, so a preset that was not in config.py's
       range would be missing here and this test would go red — which is the failure mode it exists to catch.
    3. **The box is authoritative.** Its `min=`/`max=` are the very `Ge`/`Le` objects pydantic enforces at startup, read
       here off `Settings.model_fields`. A page advertising a range the server refuses to save is a page that always
       errors for one click.
    """
    page = session_client.get("/settings")
    assert page.status_code == 200
    joined = re.sub(r"\n\s*", " ", page.text)

    for name in CHOICE_KNOBS:
        knob = f"MYPKI_{name.upper()}"

        # (1) The menu exists, and it is not a form control.
        tag = re.search(rf'<select id="c_{name}"[^>]*>', joined)
        assert tag is not None, f"no dropdown rendered for {knob}"
        assert "name=" not in tag.group(0), f"{knob}'s dropdown can post a value: {tag.group(0)}"
        assert f'data-mypki-select-for="f_{name}"' in tag.group(0)

        # (2) Every preset, and Custom.
        menu = _choice_menu(page, name)
        presets = KNOB_PRESETS[name]
        for value in presets:
            assert f'<option value="{value}"' in menu, f"preset {value} missing from {knob}'s menu"
        assert f'<option value="{CUSTOM_CHOICE}"' in menu, f"{knob}'s menu has no Custom option"
        assert menu.count("<option") == len(presets) + 1

        # (3) The posting box, with config.py's own bounds on it.
        low, high = _declared_bounds(name)
        assert low is not None and high is not None, f"config.py declares no Ge/Le for {name}"
        box = re.search(rf'<input id="f_{name}" name="{knob}" type="number"[^>]*>', joined)
        assert box is not None, f"{knob} has no number input to post from"
        assert f'min="{low}"' in box.group(0), f"{box.group(0)} does not carry config.py's ge={low}"
        assert f'max="{high}"' in box.group(0), f"{box.group(0)} does not carry config.py's le={high}"


def test_a_live_value_outside_the_presets_selects_custom_instead_of_rounding(
    settings: Settings, ca_bundle: CaBundle
) -> None:
    """A host running `MYPKI_MAX_SANS=7` shows **7**, not the nearest preset.

    The defect this exists to prevent is the quiet kind a dropdown invites: a menu has no 7 in it, so either the page
    rounds the live value up to 10 (and a Save then writes 10 back, silently loosening an operator's own cap) or it
    shows nothing. Neither is acceptable. Asserted at four levels — the box still holds 7, the `Custom` option is the
    selected one, no preset is marked selected, and the field carries `custom-open`, which is the class that reveals
    the box in `style.css`. The value came from the constructor here; the same rendering path is what a saved file or
    a shell variable feeds, because `_knob_input` renders what **this process** resolved.
    """
    from conftest import ScratchClient
    from mypki.app import create_app

    running = Settings(  # type: ignore[call-arg]
        data_dir=settings.data_dir,
        log_file=settings.log_file,
        secret_key="test-session-secret-not-a-real-one",
        max_sans=7,
        _env_file=None,
    )
    assert running.max_sans == 7 and 7 not in KNOB_PRESETS["max_sans"]

    app = create_app(running, ca_bundle=ca_bundle, session_secret="test-session-secret-not-a-real-one")
    with ScratchClient(app, persist_cookies=True) as client:
        page = client.get("/settings")
        assert page.status_code == 200

        assert _knob_value(page, "MYPKI_MAX_SANS") == "7"

        menu = _choice_menu(page, "max_sans")
        assert f'<option value="{CUSTOM_CHOICE}" selected>' in menu
        assert " selected" not in menu.replace(f'<option value="{CUSTOM_CHOICE}" selected>', "", 1)
        assert '<option value="10" selected' not in menu  # i.e. not rounded to the nearest preset

        # `custom-open` is what makes the authoritative box visible; without it Custom would hide the only control that
        # can hold a 7. Anchored through the field's own label so the open field provably belongs to MYPKI_MAX_SANS and
        # not to some other dropdown on the page.
        assert re.search(
            r'<div class="field field-choice custom-open" data-mypki-choice>\s*<label for="c_max_sans">',
            page.text,
        ), "Custom is selected but the number box it should reveal is still hidden"
        # …and no other Issuing-limit field opened its box, which is what 'only this one value is off-preset' means.
        assert len(re.findall(r'<div class="field field-choice custom-open"', page.text)) == 1


def test_the_settings_page_no_longer_renders_the_resolved_state_table(session_client) -> None:
    """The 0.3.0 resolved-state table and its three note blocks are gone, and what they said honestly survived.

    The table restated twenty-odd values a reader could already see in the form, and its `Source` column named a layer
    no process can identify. Deleting it is only an improvement if the two things it got right survive: the precedence
    order (now a note in the Storage status panel) and "these three arrival routes are indistinguishable" (same note).
    So this test asserts absence **and** presence:

    * Absent: the table heading, its `Source` column header, and all three `<h3>` headings of the old note blocks.
      'The order values are read in' is asserted as a **heading**, because that phrase now legitimately appears again —
      as prose inside the relocated note. Asserting the whole phrase absent would fail for the wrong reason.
    * Present: `indistinguishable here` exactly once (once is the honest dose; twice would mean a copy was left behind),
      and the one provenance row the status panel kept, 'Data directory came from'.
    """
    page = session_client.get("/settings")
    assert page.status_code == 200

    assert "What this process resolved at startup" not in page.text
    assert '<th scope="col">Source</th>' not in page.text
    assert '<th scope="col">Knob</th>' not in page.text
    assert re.search(r'<h3>\s*What ["“]source["”] can and cannot tell you', page.text) is None
    assert re.search(r"<h3>\s*The order values are read in", page.text) is None
    assert "What is masked, and why" not in page.text

    # The honesty survived, exactly once.
    assert page.text.count("indistinguishable here") == 1
    assert _status_row(page, "Data directory came from") is not None


def test_the_unmanaged_card_states_presence_for_every_knob_it_refuses_to_edit(
    settings: Settings, session_client
) -> None:
    """The 'Not editable here' card states what each unmanaged knob currently **is** — presence, never value or path.

    0.4.0 moved these presence flags out of the deleted table into this card, so the card is now the only place that
    answers "is there a secret?" and "am I on plain HTTP?". Asserted for all four `UNMANAGED_KEYS` (read from the
    module, not hard-coded, so a fifth unmanaged knob cannot arrive without a decision being taken):

    * each appears as `<code>MYPKI_*</code>` in a row header and **never** as `name="MYPKI_*"` — a card that grew an
      input would stop being a refusal;
    * the session secret reports `set (value not displayed)` for this fixture, which does set one;
    * both TLS knobs report `not set — plain HTTP`, which is the sentence an operator needs before wondering why the
      session cookie is not `Secure`;
    * the `config_dir` row states the directory this page's own file lives in. That is the one value shown in full,
      and it is shown because the page already names that file out loud above the Save button.

    No key **path** is asserted on — `test_no_key_leakage.py` owns that claim. This test only checks observability.
    """
    page = session_client.get("/settings")
    assert page.status_code == 200
    joined = re.sub(r"\n\s*", " ", page.text)

    knobs = [f"MYPKI_{name.upper()}" for name in UNMANAGED_KEYS]
    assert len(knobs) == 4

    for knob in knobs:
        assert f"<code>{knob}</code>" in page.text, f"{knob} is no longer named on the card"
        assert f'name="{knob}"' not in page.text, f"{knob} grew an input on a card that refuses to edit it"

    assert "set (value not displayed)" in page.text
    assert settings.secret_key not in page.text
    assert page.text.count("not set — plain HTTP") == 2

    config_row = re.search(
        r'<th scope="row"><code>MYPKI_CONFIG_DIR</code></th>\s*<td><span class="mono">([^<]*)</span>',
        joined,
    )
    assert config_row is not None
    assert Path(config_row.group(1)).name == "mypki"


# ------------------------------------------------------------------------------------------------ CSRF


@pytest.mark.parametrize("path", ("/csr/generate", "/csr/sign"))
def test_a_post_without_a_token_is_refused_saying_nothing_was_signed(client, path: str, data_root: Path) -> None:
    """400, mypki's page, and **no record written** (page-map §0).

    The status code is the easy half. What matters operationally is the sentence "Nothing was signed" plus the store
    staying empty: a CSRF rejection that reads like any other bad request leaves an operator wondering whether a
    certificate went out with a wrong name, when in fact no signing code ran. Asserted on both POSTable pages because
    `require_csrf` is called at each handler's top rather than as a shared dependency — the point of that shape
    being that
    each handler names its own check.
    """
    before = IssuedStore(paths.db_path(data_root)).count()

    response = client.post(path, data={"common_name": "x.internal", "csr_pem": "whatever"})

    assert response.status_code == 400
    assert "Nothing was signed" in _reason(response) or "Nothing was signed" in response.text
    assert "CSRF token" in response.text
    assert IssuedStore(paths.db_path(data_root)).count() == before


def test_a_post_with_the_wrong_token_is_refused_without_quoting_either_token(session_client, data_root: Path) -> None:
    """The near-miss case: a token present but not this session's.

    Asserted that **neither** value appears in the body — the submitted one because echoing it back would confirm to an
    attacker that the field is read, and the session's own because a page containing a valid token is a second way
    to steal
    it (see `csrf.py`). `verify_csrf` uses `hmac.compare_digest` for the same reason in the other direction.
    """
    from conftest import csrf_token

    real_token = csrf_token(session_client, "/csr/sign")

    response = session_client.post("/csr/sign", data={"csrf_token": "not-this-sessions-token", "csr_pem": "x"})

    assert response.status_code == 400
    assert "CSRF token" in response.text
    assert real_token not in response.text
    assert "not-this-sessions-token" not in response.text
    assert IssuedStore(paths.db_path(data_root)).count() == 0


def test_a_two_step_flow_keeps_one_token_for_the_whole_session(session_client, sample_csr_pem: str) -> None:
    """No per-request token rotation, because the confirmation POST must carry the paste POST's token (see `csrf.py`).

    The cost is stated there out loud: a stolen token stays valid for the session's lifetime, which is why
    `session_max_age` is bounded and the cookie is `same_site="lax"`. Asserted as behaviour across the flow an operator
    actually performs — GET, paste POST, confirmation POST — with one token surviving all three.
    """
    from conftest import csrf_token

    first_token = csrf_token(session_client, "/csr/sign")
    step_a = _post(session_client, "/csr/sign", token_from="/csr/sign", csr_pem=sample_csr_pem)

    assert step_a.status_code == 200, _reason(step_a)

    issued = _post(
        session_client,
        "/csr/sign",
        token_from=None,
        csrf_token=first_token,
        confirm="1",
        cert_type="server",
        validity_days="30",
    )

    assert issued.status_code == 200, _reason(issued)
    assert "Issued:" in issued.text


# ------------------------------------------------------------------------------- rejections name their reason


def test_garbage_input_is_refused_naming_the_armour_it_expected(client) -> None:
    """`No PEM block found.` with both armour markers quoted (page-map §3).

    The message is the fix: an operator who pasted a certificate, a key or nothing at all needs to know which one they
    pasted. Asserted on the *sentence*, not on the status code alone — 400 with "invalid CSR" would pass a weaker
    version
    of this test and fail page-map §9's promise. The body is non-empty nonsense rather than an empty textarea: an empty
    paste is a different code path and is covered in `test_csr_validate.py`.
    """
    response = _post(client, "/csr/sign", token_from="/csr/sign", csr_pem="complete nonsense")

    assert response.status_code == 400
    reason = _reason(response)
    assert "No PEM block found" in reason
    assert CSR_PEM_BEGIN in reason


def test_valid_base64_that_is_not_a_request_is_refused_as_such(client) -> None:
    """Well-formed armour, decodable body, not a DER request.

    Distinguished from the previous case deliberately: "the base64 is broken" and "that decodes to something that is not
    a CSR" are different diagnoses of what looks like the same paste, and `csr.py` keeps them separate so the operator
    learns whether their paste was truncated or their file was the wrong kind.
    """
    body = "\n".join(base64.encodebytes(b"\x00" * 96).decode("ascii").split())

    response = _post(client, "/csr/sign", token_from="/csr/sign", csr_pem=f"{CSR_PEM_BEGIN}\n{body}\n{CSR_PEM_END}\n")

    assert response.status_code == 400
    assert "not a DER certificate request" in _reason(response)


def test_a_tampered_signature_is_refused_before_anything_else(client, sample_csr_pem: str) -> None:
    """One flipped bit inside the signed region (page-map §3's ordering).

    Signature before key policy, before extensions, before SANs: the first thing an operator should learn about a
    tampered request is that it was tampered with. `test_csr_validate.py` pins the same ordering at the library level;
    this pins it through the page an operator actually reads.
    """
    response = _post(client, "/csr/sign", token_from="/csr/sign", csr_pem=_tampered(sample_csr_pem))

    assert response.status_code == 400
    assert "signature does not verify" in _reason(response)


def test_a_request_for_ca_privileges_is_403_naming_the_extension_and_signs_nothing(client, data_root: Path) -> None:
    """403 rather than 400: not a malformed request, a request mypki refuses to honour (page-map §3 rule 6).

    The distinction is operational — 400 says "fix your input", 403 says "this CA will not do that at all" — and the
    extension name in the body is what makes the refusal actionable rather than mysterious. The empty store is the other
    half: refusing has to mean **no signing happened**, not "signed then hidden".
    """
    before = IssuedStore(paths.db_path(data_root)).count()

    response = _post(client, "/csr/sign", token_from="/csr/sign", csr_pem=_ca_privileged_csr_pem())

    assert response.status_code == 403
    reason = _reason(response)
    assert "BasicConstraints CA:TRUE" in reason
    assert "end-entity certificates only" in reason
    assert IssuedStore(paths.db_path(data_root)).count() == before


def test_a_refused_paste_is_named_on_the_sign_page_above_the_box_it_belongs_to(client) -> None:
    """The refusal and the paste live on one page (page-map §0/§3): no round trip to a separate error document.

    Asserted as an **order**, because "the reason appears somewhere in the body" is also true of a page that mentions it
    in a nav link while showing nothing else. `<section class="form-errors refused">` has to come before the
    `<label for="csr_pem">` it explains, and the paste has to still be in the textarea after that label — the whole
    point being that the fix is typed where the reason was read.
    """
    response = _post(client, "/csr/sign", token_from="/csr/sign", csr_pem="complete nonsense")

    assert response.status_code == 400
    body = response.text

    refusal_at = body.index('<section class="form-errors refused">')
    label_at = body.index('<label class="paste-label" for="csr_pem">Paste a CSR (PEM)</label>')
    textarea_at = body.index('name="csr_pem"')
    assert refusal_at < label_at < textarea_at, "the refusal must sit above the box it is about"

    assert "Not signed &mdash; this request was refused" in body
    assert "No PEM block found" in _reason(response)

    # The paste survived, verbatim, in its own textarea: the operator fixes it rather than retyping it.
    assert "complete nonsense" in body[textarea_at:]
    # And a refusal signed and staged nothing — no confirmation panel, no issued card.
    assert "This is what the request says" not in body
    assert "<h2>Issued:" not in body


def test_a_ca_privileged_paste_is_refused_on_the_sign_page_at_403(client, data_root: Path) -> None:
    """Moving the reason did not move the status (page-map §3 rule 6).

    The tempting simplification of "show the error on the same page" is to answer 200 like a fixable field, which would
    make a refused request indistinguishable from an accepted one to anything that is not a browser. 403 and an empty
    store are asserted alongside the on-page block, plus the hint that points at the consent box for the ignorable half
    of rule 6.
    """
    before = IssuedStore(paths.db_path(data_root)).count()

    response = _post(client, "/csr/sign", token_from="/csr/sign", csr_pem=_ca_privileged_csr_pem())

    assert response.status_code == 403
    assert '<section class="form-errors refused">' in response.text
    assert "BasicConstraints CA:TRUE" in _reason(response)
    assert "you tick the box there" in response.text
    assert IssuedStore(paths.db_path(data_root)).count() == before


def test_an_inline_refusal_is_still_the_sign_page_with_its_nav_and_headers(session_client) -> None:
    """The half-migration failure: a refusal rendered on the sign page that lost the sign page's own guarantees.

    A handler could put the sentence above the textarea and still lose `base.html` (no nav, no way back) or call
    `error.html` "inline" from inside the route. Both keep the words and drop what an operator relies on, so the nav,
    a second link and both headers are asserted on the same response as the refusal.
    """
    response = _post(session_client, "/csr/sign", token_from="/csr/sign", csr_pem="not a csr at all")

    assert response.status_code == 400
    assert '<section class="form-errors refused">' in response.text
    assert '<nav class="nav">' in response.text
    assert 'href="/csr/generate"' in response.text
    assert "Paste a CSR (PEM)" in response.text
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "unsafe-inline" not in response.headers["content-security-policy"]


def test_an_oversized_paste_gets_mypkis_own_page_and_not_starlettes(session_client, settings: Settings) -> None:
    """413 naming `MYPKI_MAX_CSR_CHARS`, with starlette's own size message **absent**.

    The guard exists because starlette answers an oversized form part with 400 and a bare JSON
    `{"detail":"Field exceeded maximum size of 1024KB."}` (MEASURED): right status family, wrong artifact. Asserting the
    absence is the point — if that string ever appears, mypki's promise has been replaced by a framework default and the
    operator is sent looking for a setting that is not the knob they should change.

    The paste is `max_csr_chars + 9000` characters: padding *under* the cap is accepted (the limit is inclusive,
    measured
    in `test_csr_validate.py`), so an oversized case has to exceed it by a margin that survives any legitimate
    knob value.
    """
    paste = f"{CSR_PEM_BEGIN}\n{'A' * 4000}\n{CSR_PEM_END}\n" + "y" * settings.max_csr_chars

    response = _post(session_client, "/csr/sign", token_from="/csr/sign", csr_pem=paste)

    assert response.status_code == 413
    assert "MYPKI_MAX_CSR_CHARS" in response.text
    assert STARLETTE_SIZE_MESSAGE not in response.text
    # mypki's own page shape, rendered without a request object (the rejection happens before routing).
    assert _reason(response)


def test_a_body_over_the_http_cap_is_refused_by_content_length_before_being_read(
    session_client, settings: Settings
) -> None:
    """The declared-length shortcut: refuse on the header rather than buffering a megabyte to measure it.

    `SizeGuardMiddleware` checks `Content-Length` first and only then reads the body (app.py). Both paths have to answer
    the same page, because an attacker who lies about the length should not get a different error — or a free
    megabyte of
    buffering — for lying.
    """
    limit = settings.max_csr_chars + 8192

    response = session_client.post(
        "/csr/sign",
        data={"csrf_token": "irrelevant-because-the-guard-runs-first"},
        headers={"content-length": str(limit * 3)},
    )

    assert response.status_code == 413
    assert "MYPKI_MAX_CSR_CHARS" in response.text
    assert STARLETTE_SIZE_MESSAGE not in response.text


def test_a_get_is_passed_through_the_size_guard_untouched(client) -> None:
    """GET has no body to measure, and buffering it would turn read-only pages into allocations.

    MEASURED: a GET carrying 200 000 bytes still answers 200. Asserted because the guard's own docstring claims it, and
    because a "defence" that buffered every request would make the app's cheapest pages its most expensive ones.
    """
    response = client.request("GET", "/", content=b"x" * 200_000)

    assert response.status_code == 200


# --------------------------------------------------------------------------------- the two-step happy path


def test_confirming_issues_a_certificate_and_adds_a_row_to_the_issued_list(
    session_client, sample_csr_pem: str, data_root: Path
) -> None:
    """The whole point of the app, end to end: paste, confirm, record.

    Asserted at three points rather than one — the confirmation page shows a serial and both download links, the store
    has exactly one new row with the names that were requested, and `GET /issued` renders that row. A bug in any single
    link of that chain (issue without recording, record without displaying) fails somewhere.
    """
    before = IssuedStore(paths.db_path(data_root)).count()

    issued, _step_a = _confirm_and_issue(session_client, sample_csr_pem)

    assert issued.status_code == 200
    assert "Issued:" in issued.text
    # `_issued_serial` rather than a page-wide regex: this same page carries the CA's serial in an identically spelled
    # cell,
    # and matching the first one on the page compares the store against the wrong certificate.
    serial = _issued_serial(issued)
    links = re.findall(r'href="(/download/[^"]+)"', issued.text)
    assert len(links) == 2, links

    store = IssuedStore(paths.db_path(data_root))
    assert store.count() == before + 1
    record = store.list_records()[0]
    assert record.serial_hex == serial
    assert record.cert_type == "server"
    assert record.common_name == "server.internal"
    assert record.sans == ("server.internal", "*.lab.internal", "10.0.0.7")

    listing = session_client.get("/issued")
    assert listing.status_code == 200
    assert "server.internal" in listing.text
    assert serial in listing.text


def test_both_downloads_after_signing_serve_the_certificate_and_the_chain(session_client, sample_csr_pem: str) -> None:
    """`.crt` holds one certificate; `-chain.pem` holds leaf then CA (page-map §3, §10).

    Fetched from the links rather than from the `<pre>` blocks, because these are the bytes an operator installs.
    Counting
    armour occurrences (not lines) is what distinguishes a chain from a single certificate — and "leaf first" is
    asserted
    by comparing each body against the page that displayed it.
    """
    issued, _step_a = _confirm_and_issue(session_client, sample_csr_pem)
    links = re.findall(r'href="(/download/[^"]+)"', issued.text)

    bodies = [session_client.get(link) for link in links]
    assert all(body.status_code == 200 for body in bodies)
    assert all(body.headers["content-type"] == "application/x-pem-file" for body in bodies)

    single = next(body for body in bodies if body.text.count("-----BEGIN CERTIFICATE-----") == 1)
    chain = next(body for body in bodies if body.text.count("-----BEGIN CERTIFICATE-----") == 2)

    assert single.text in issued.text
    assert chain.text in issued.text
    assert chain.text.startswith(single.text)
    # `_safe_stem` filters a common name into a filesystem-safe stem: `server.internal` -> `server-internal`, so the
    # download name is derived from the CN rather than interpolated from it (app.py).
    assert 'filename="server-internal.crt"' in single.headers["content-disposition"]
    assert 'filename="server-internal-chain.pem"' in chain.headers["content-disposition"]


def test_an_over_max_validity_is_refused_naming_the_limit_and_writes_no_record(
    session_client, sample_csr_pem: str, data_root: Path, settings: Settings
) -> None:
    """Step B refuses a validity above `MYPKI_VALIDITY_MAX_DAYS`, and never clamps it.

    Clamping is the tempting implementation and the wrong one: an operator who asked for 900 and silently received the
    ceiling believes they hold a certificate valid until a date nobody wrote down. From 0.7.0 this host does publish a
    CRL and answer OCSP, but validity remains the bound that needs no cooperation from the client
    (docs/REFERENCE.md gotcha 2).
    The refusal arrives *after* step A succeeded, which is the state worth testing — a staged request must not become
    a record
    just because the confirmation was invalid.

    0.2.0 moved this from `error.html` at 400 to the confirmation page at 200 (app.py `ERROR_SURFACE_RULE`): validity is
    one of the fields on that form, so the useful answer is the same page with the number named and the staged request
    still held. Four things are asserted because the move is only a benefit if all four hold: the reason names the
    limit, the staged request is still recoverable (the *same* `?pending=` id step A issued, back in the form action),
    the refused number is still in its input, and no record was written.
    """
    too_many = settings.validity_max_days + 75

    issued, step_a = _confirm_and_issue(session_client, sample_csr_pem, validity_days=str(too_many))

    assert issued.status_code == 200
    reason = _inline_reasons(issued)
    assert reason is not None, f"no inline error block in the {issued.status_code} body"
    assert "MYPKI_VALIDITY_MAX_DAYS" in reason
    assert str(settings.validity_max_days) in reason
    assert str(too_many) in reason

    # The rejected page is still the *same* confirmation: the details panel is on it, and its form carries the staged
    # id.
    assert "This is what the request says" in issued.text
    # MEASURED on this build: the id is base64url (`secrets.token_urlsafe(32)`), not hex, so it is read back and
    # compared
    # rather than pattern-matched — a `[0-9a-f]+` regex fails against a correct page.
    assert _issued_pending_id(step_a) == _issued_pending_id(issued)
    # The refused number is still in its box: the fix is a keystroke, not a retype of the whole form.
    assert f'value="{too_many}"' in issued.text

    # And nothing was signed or recorded, which is the half that has not changed.
    assert IssuedStore(paths.db_path(data_root)).count() == 0


def test_a_client_profile_may_be_issued_for_a_request_with_no_sans(session_client) -> None:
    """The profile rule, visible on the page: no SANs is refused for `server` and accepted for `client`.

    One field changed, opposite outcomes (STYLE §8). The confirmation panel warns about the empty SAN set before step B
    (csr_sign.html), and that warning is asserted too — an operator should find out from the page rather than from the
    refusal.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "deskjob")]))
        .sign(key, hashes.SHA256())
    )
    pem = csr.public_bytes(Encoding.PEM).decode("ascii")

    step_a = _post(session_client, "/csr/sign", token_from="/csr/sign", csr_pem=pem)
    assert step_a.status_code == 200
    assert "no SANs" in step_a.text

    # A profile rule this CA enforces is still a field the operator can fix on that page — they can type a SAN or pick
    # `client` — so it returns inline at 200 rather than as an error page (app._issue_from_confirmation's
    # CsrValidationError
    # branch). The sentence itself is unchanged from 0.1.0.
    refused, _ = _confirm_and_issue(session_client, pem, cert_type="server")
    assert refused.status_code == 200
    reason = _inline_reasons(refused)
    assert reason is not None, f"no inline error block in the {refused.status_code} body"
    assert "requires at least one SAN" in reason
    # The profile they chose comes back selected: a form that reset to `server` after they picked it would make the fix
    # look like it had been ignored.
    assert 'value="server" checked' in refused.text

    accepted, _ = _confirm_and_issue(session_client, pem, cert_type="client")
    assert accepted.status_code == 200
    assert "Issued: deskjob" in accepted.text


# ------------------------------------------------------------------ the editable confirm form (page-map §3)


def test_an_edited_subject_is_signed_and_named_back_on_the_issued_page(
    session_client, sample_csr_pem: str, data_root: Path
) -> None:
    """The diff is the price of the editable form: an edit must be named back on the issued page (page-map §3 step B).

    `sample_csr_pem` carries `O=mypki tests` and `C=XX`; this submits `O=Renamed Lab` and leaves every other field as
    the request said it, so exactly one entry should appear under "Changed from your request". Asserted at four points
    because a diff is a *report about* a signing and each half fails independently: the certificate was signed with the
    edit, the record stores the edited names, the page names only what differed, and an unedited signing on the same
    build renders **no** diff block at all — which is what stops "everything looks changed" from training an operator to
    ignore the warning.
    """
    store = IssuedStore(paths.db_path(data_root))

    issued, _step_a = _confirm_and_issue(
        session_client,
        sample_csr_pem,
        common_name="server.internal",
        organization="Renamed Lab",
        organizational_unit="",
        country="XX",
        state="",
        locality="",
        email="ops@example.test",
        sans="server.internal\n*.lab.internal\n10.0.0.7",
    )

    assert issued.status_code == 200
    block = re.search(r'<div class="diff">(.*?)</div>', issued.text, re.DOTALL)
    assert block is not None, issued.text[:400]
    assert "Changed from your request" in block.group(1)
    # `dt`/`dd` pairs rather than a substring search of the body: the diff must name the field and the value it became.
    entries = re.findall(r"<dt>([^<]+)</dt><dd>([^<]*)</dd>", block.group(1))
    assert entries == [("Organization", "Renamed Lab")], entries
    assert "The public key and every extension still came from mypki" in issued.text

    record = store.list_records()[0]
    assert record.common_name == "server.internal"
    # The SANs were re-typed exactly as the request carried them, so they are not reported as a change
    # (`_changed_subject_fields` compares sets, not text) while still being the names that got signed.
    assert record.sans == ("server.internal", "*.lab.internal", "10.0.0.7")

    unedited, _ = _confirm_and_issue(session_client, sample_csr_pem)
    assert unedited.status_code == 200
    assert '<div class="diff">' not in unedited.text
    assert "Changed from your request" not in unedited.text


def test_a_bad_edited_country_is_refused_inline_keeping_the_other_edits_and_the_staged_request(
    session_client, sample_csr_pem: str, data_root: Path
) -> None:
    """One bad field on the confirm page must not cost the operator the other six, or the request they pasted.

    Mutates one value (STYLE §8): `C=XXL`, three letters where `validators.validate_country` wants two. Everything else
    here is an edit worth keeping — a renamed organization and an email — so the assertions are about *recovery*: HTTP
    200, the reason names the field and the offending text, the other typed values are back in their inputs, the staged
    request's own id is back in the form action (no re-paste of a 2 KB PEM), and nothing was signed or recorded.
    """
    before = IssuedStore(paths.db_path(data_root)).count()

    rejected, step_a = _confirm_and_issue(
        session_client,
        sample_csr_pem,
        common_name="server.internal",
        organization="Renamed Lab",
        organizational_unit="",
        country="XXL",
        state="",
        locality="",
        email="ops@example.test",
        sans="server.internal\n*.lab.internal\n10.0.0.7",
    )

    assert rejected.status_code == 200
    reason = _inline_reasons(rejected)
    assert reason is not None, f"no inline error block in the {rejected.status_code} body"
    # MEASURED sentence: `country: country must be exactly two letters (got 'XXL'); e.g. DE, US, GB` — the field and the
    # typed value, which is what makes it fixable without guessing a second time.
    assert "country" in reason
    assert "exactly two letters" in reason
    assert "XXL" in reason

    # The other edits survive the rejection, including the bad field itself: an empty box reads as "the page threw my
    # input
    # away" and turns a one-character fix into a six-field retype.
    for expected in ('value="Renamed Lab"', 'value="ops@example.test"', 'value="XXL"', 'value="server.internal"'):
        assert expected in rejected.text, expected

    # Still the same confirmation, and still *this* staged request — the id step A handed out is handed back.
    assert "This is what the request says" in rejected.text
    assert _issued_pending_id(step_a) == _issued_pending_id(rejected)

    assert IssuedStore(paths.db_path(data_root)).count() == before


def test_the_confirm_page_refuses_an_over_cap_san_edit_naming_the_knob(
    session_client, sample_csr_pem: str, settings: Settings, data_root: Path
) -> None:
    """`MYPKI_MAX_SANS` is enforced on the edited SAN box as well as on the generate form (page-map §9).

    The same limit reached from the other surface: one textarea holding more names than this CA will vouch for. Asserted
    as an inline 200 naming the knob's value, because "too many SANs" is a list the operator can shorten on the page
    they are already standing on — unlike a tampered signature, which is an artifact and belongs on the error page.
    """
    too_many = "\n".join(f"host{i}.internal" for i in range(settings.max_sans + 5))

    rejected, _step_a = _confirm_and_issue(session_client, sample_csr_pem, sans=too_many)

    assert rejected.status_code == 200
    reason = _inline_reasons(rejected)
    assert reason is not None, f"no inline error block in the {rejected.status_code} body"
    assert "subject alternative names" in reason
    assert str(settings.max_sans) in reason
    assert IssuedStore(paths.db_path(data_root)).count() == 0


# ------------------------------------------------------------------------------- revocation controls (§5)


def test_a_record_can_be_revoked_from_the_issued_page_and_says_what_that_does_not_do(
    session_client, sample_csr_pem: str, data_root: Path
) -> None:
    """The whole revoke round trip, including the sentence that stops it being over-read (page-map §5).

    Asserted in order, because every state has to be reachable through the page alone: a fresh record renders `pill
    active` **and** a tickable control carrying its serial; submitting that control returns 200 with the confirmation
    block naming serial and common name and **stamps nothing**; the confirmed submit returns `pill revoked`, the UTC
    stamp, the reason, and no control for a row that already carries a stamp; and the page states both halves of what a
    stamp now does — it re-signs the published CRL, **and** a client only acts on that if it consults one, so a
    certificate issued before 0.7.0 stays trusted until it expires. That last pair is the part that matters most:
    without it, a page that says "revoked" implies an effect every client honours, and 0.7.0 does not have it.

    0.3.0 changed the markup deliberately and these assertions moved with it: rows carry `type="checkbox"` inside one
    bulk form rather than a hidden input inside a per-row form, so `/issued` always contains exactly one
    `action="/issued/revoke"`. What is asserted instead of that form's absence is what the old assertion was really
    checking — that a stamped row offers no control, because there is nothing this page can do to it.
    """
    issued, _step_a = _confirm_and_issue(session_client, sample_csr_pem)
    serial = _issued_serial(issued)

    listing = session_client.get("/issued")
    assert listing.status_code == 200
    assert '<span class="pill active">active</span>' in listing.text
    # The control carries the serial rather than a row position, so a revoke always names a certificate.
    assert f'<input type="checkbox" name="serial_hex" value="{serial}"' in listing.text

    unconfirmed = _post(
        session_client,
        "/issued/revoke",
        token_from="/issued",
        serial_hex=serial,
        reason="key compromised during a lab exercise",
    )
    assert unconfirmed.status_code == 200
    # The confirmation step is a block on the page, read structurally for the same reason `_reason()` is.
    assert '<section class="confirm-revoke">' in unconfirmed.text
    assert "Revoke 1 certificate?" in unconfirmed.text
    assert serial in unconfirmed.text
    assert "server.internal" in unconfirmed.text
    assert '<span class="status-ok">active now</span>' in unconfirmed.text
    # The whole point of the step: a submit that only *asked* changed nothing.
    assert IssuedStore(paths.db_path(data_root)).count_revoked() == 0
    assert 'class="pill revoked"' not in unconfirmed.text

    revoked = _post(
        session_client,
        "/issued/revoke",
        token_from="/issued",
        serial_hex=serial,
        confirm="1",
        reason="key compromised during a lab exercise",
    )

    assert revoked.status_code == 200
    assert "<h2>Revocation batch</h2>" in revoked.text
    assert "1 stamped now," in revoked.text
    assert '<span class="pill revoked">revoked</span>' in revoked.text
    assert "is marked revoked as of" in revoked.text
    assert serial in revoked.text
    assert "key compromised during a lab exercise" in revoked.text
    # Both halves of 0.7.0's revocation story, on the same page as the button that performed it: what this host now does
    # (publish) and what it still cannot promise (that every client consults what it published).
    assert "stays trusted by clients until it expires" in revoked.text
    assert "Published a new CRL listing 1 entry (CRL Number 1)" in revoked.text
    assert "/crl" in revoked.text
    # A stamped row offers no control (issued.html): there is no un-revoke and no delete, so a checkbox here would
    # promise one of the two. The bulk form itself stays on the page, which is why the old `action=` absence stopped
    # being the thing worth asserting.
    assert f'<input type="checkbox" name="serial_hex" value="{serial}"' not in revoked.text

    store = IssuedStore(paths.db_path(data_root))
    record = store.list_records()[0]
    assert record.status == "revoked"
    assert record.revocation_reason == "key compromised during a lab exercise"
    assert record.revoked_at_utc is not None
    assert store.count_revoked() == 1

    # And the state survives a plain GET, which is what an operator actually does next: refresh, bookmark, another
    # browser.
    again = session_client.get("/issued")
    assert again.status_code == 200
    assert '<span class="pill revoked">revoked</span>' in again.text
    assert 'class="pill active"' not in again.text
    # The date of the decision is the last column (`Revoked (UTC)`), not a second fact in the Status cell.
    assert re.search(r'<td class="revoked-at">\d{4}-\d{2}-\d{2}', again.text)
    assert not re.search(r'<span class="hint">\d{4}-\d{2}-\d{2}', again.text)


def test_a_revoke_for_an_unknown_serial_is_404_naming_the_serial_and_the_database(
    session_client, sample_csr_pem: str, data_root: Path
) -> None:
    """A serial this host never signed is missing state, not a server fault (page-map §5).

    **MEASURED defect found by driving the app:** with only `MypkiError` registered as the net, this exact request
    answered **500** and logged at `error` — mypki describing its own behaviour as broken for "that record is not in
    this database". It now has its own handler answering 404, matching every other missing-thing answer here
    (`/download/{id}`, `/docs`). Asserted with both the serial and the db path present, because an operator who pasted a
    serial from another machine's CA needs to know *which* store this server is reading.

    A real record is issued first for two reasons: `/issued` renders its CSRF field inside each row's revoke form, so
    with no records there is no token on the page to read (the session has one; the template shows none), and "nothing
    was revoked" is only a meaningful assertion when there was something that could have been.
    """
    issued, _step_a = _confirm_and_issue(session_client, sample_csr_pem)
    real_serial = _issued_serial(issued)

    response = _post(session_client, "/issued/revoke", token_from="/issued", serial_hex="deadbeefcafebabf")

    assert response.status_code == 404, response.text[:400]
    reason = _reason(response)
    assert "deadbeefcafebabf" in reason
    assert str(paths.db_path(data_root)) in reason
    assert "only revoke certificates this host signed" in reason

    store = IssuedStore(paths.db_path(data_root))
    assert store.count_revoked() == 0
    assert store.list_records()[0].serial_hex == real_serial
    assert store.list_records()[0].status == "active"


def test_a_revoke_without_a_serial_is_400_and_without_a_valid_token_changes_nothing(
    session_client, sample_csr_pem: str, data_root: Path
) -> None:
    """The two malformed revoke requests, answered differently (page-map §0).

    A POST with a blank serial is a form that arrived without its subject → 400 naming `serial_hex`. A POST carrying the
    wrong CSRF token is this page's only state change attempted from somebody else's site → 400 and nothing stamped,
    which is what `require_csrf` as the handler's first act exists for (app.issued_revoke). Both run against a real
    record, so "nothing changed" means nothing was stamped on the certificate that was actually there.
    """
    issued, _step_a = _confirm_and_issue(session_client, sample_csr_pem)
    serial = _issued_serial(issued)
    store = IssuedStore(paths.db_path(data_root))

    no_serial = _post(session_client, "/issued/revoke", token_from="/issued", serial_hex="   ")
    assert no_serial.status_code == 400
    assert "serial_hex is required" in _reason(no_serial)

    wrong_token = _post(
        session_client,
        "/issued/revoke",
        token_from=None,
        csrf_token="not-this-sessions-token",
        serial_hex=serial,
    )
    assert wrong_token.status_code == 400
    assert "CSRF" in wrong_token.text
    assert store.count_revoked() == 0
    assert store.list_records()[0].status == "active"


# --------------------------------------------------------------------------------- CA certificate download


def test_the_ca_download_is_an_attachment_with_no_store_and_nosniff(session_client) -> None:
    """`application/x-pem-file`, `filename="mypki-root-ca.crt"`, `Cache-Control: no-store`, `nosniff` (page-map §0, §4).

    Every header is a decision rather than a default. `no-store` because a key/CSR/certificate body cached by a proxy or
    a browser profile is a copy mypki promised never to keep; `.crt` because Windows' double-click installer and
    Debian's
    `update-ca-certificates` both key off the extension (page-map §4); `nosniff` because a PEM served to a browser
    without it can be rendered as HTML by something that guesses.
    """
    response = session_client.get("/ca/certificate")

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/x-pem-file"
    assert response.headers["content-disposition"] == 'attachment; filename="mypki-root-ca.crt"'
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"


def test_the_ca_download_body_is_exactly_one_copy_of_the_public_certificate(session_client, ca_bundle) -> None:
    """Byte-equal to `bundle.cert`'s PEM, with exactly one CERTIFICATE block.

    The body equality is the assertion that matters for installation (an operator installs *this* root); the block count
    is the assertion that it is a certificate and not a chain or a key. Both are needed: a file containing the right
    certificate plus something else would satisfy a client and confuse a human.
    """
    expected = ca_bundle.cert.public_bytes(Encoding.PEM).decode("ascii")

    response = session_client.get("/ca/certificate")

    assert response.text == expected
    assert response.text.count("-----BEGIN CERTIFICATE-----") == 1
    assert response.text.count("-----END CERTIFICATE-----") == 1
    assert "-----BEGIN" not in response.text.replace("-----BEGIN CERTIFICATE-----", "")


def test_the_ca_page_offers_the_certificate_by_url_and_not_as_a_second_copy(session_client, ca_bundle) -> None:
    """0.7.1 (operator brief): `/ca` offers download + copy at the top and renders **no** certificate bytes on the page.

    0.5.0 put the PEM in a `<pre>` on this page so an operator with no file transfer had something to paste. The
    brief moved "download root-CA cert" and "copy to clipboard" to the top of the page, which left three
    renderings of one certificate on one host -- the attachment, the block, and the table describing it.
    Deleting the middle one is the reasoning that deleted the home-page CA card in 0.3.0 (page-map §1): a fact
    in two places is two facts that can drift, and this time the two
    places were the same page.

    So the assertions invert, and both halves are asserted because each catches a different mistake:
      * the copy control exists and points at `/ca/certificate` -- by attribute, not label, because `app.js` resolves it
        through `data-mypki-copy-url` (`wireCopyUrl`) and a rename of the visible text must not silently unwire it;
      * no `<pre>`, no armour, and no `pem-ca` id anywhere on the page -- an orphaned id would be a button wired to an
        element that no longer exists, which is the failure mode `wireCopyUrl` was written to avoid.

    Parity between "what the page says" and "what the download serves" now has to be asserted some other way,
    and it is: the serial and colon-grouped fingerprint this page prints are compared against the DER of the
    bytes `/ca/certificate` serves. That is a stronger claim than comparing two copies of the same text, because
    it asks the parser rather than the string.
    """
    page = session_client.get("/ca")

    assert 'data-mypki-copy-url="/ca/certificate"' in page.text
    assert 'class="copy-pem"' in page.text
    assert "download root-CA cert" in page.text

    # The block is gone, and so is everything that used to point at it. `pre.pem` rather than a bare `<pre`: the
    # install card legitimately carries `pre.cmd` command blocks (`certutil`, `keytool`), and this assertion is
    # about certificate bytes rather than about every monospace box on the page.
    assert 'id="pem-ca"' not in page.text
    assert 'data-mypki-copy="pem-ca"' not in page.text
    assert '<pre class="pem"' not in page.text
    assert "-----BEGIN" not in page.text

    download = session_client.get("/ca/certificate")
    served = x509.load_pem_x509_certificate(download.content)
    facts = describe_ca(served)

    assert facts["serial_hex"] in page.text, "the table no longer matches the certificate this route serves"
    assert format_fingerprint(facts["fingerprint_sha256"]) in page.text
    assert facts["subject"] in page.text


def test_the_ca_page_is_a_settings_styled_card_titled_with_the_roots_own_name(session_client, ca_bundle) -> None:
    """0.7.1 (operator brief): the facts card is `/settings`-styled and its heading is the root's Common Name, in blue.

    The brief was a styling request, so what a box with no browser can assert is the **markup contract** the
    stylesheet keys
    off, not the rendering: `style.css` colours `.section-heading` with `--blue` and paints its background on
    `.card.settings-section`, and both classes already exist for `/settings`. Reusing them here is the point --
    a page that
    invented a second look-alike heading could drift from `/settings` while looking identical today.

    Two things are counted because both were part of the request: the heading sits **outside** the card (an
    `<h2>` before the `<section>`, not inside it, which is how this page titled its card before) and it carries
    the root's own Common Name rather
    than a sentence written by me. The order assertion is what proves "outside": heading index < card index.
    """
    page = session_client.get("/ca")
    cn = describe_ca(ca_bundle.cert)["common_name"]

    headings = page.text.count('class="section-heading"')
    assert headings >= 2, "the facts card and the install card both need a blue heading"
    assert f'<h2 class="section-heading">{cn}</h2>' in page.text, page.text[:600]
    assert '<section class="card settings-section">' in page.text

    heading = page.text.index(f'<h2 class="section-heading">{cn}</h2>')
    card = page.text.index('<section class="card settings-section">')
    assert heading < card, "the title is inside the card rather than above it"
    # The old in-card title is gone rather than joined with the new one: two titles on one card is the drift
    # removed here.
    assert "This host's root CA &mdash; verify it out of band first" not in page.text


def test_the_ca_certificate_download_holds_one_certificate_and_no_armour(session_client, ca_bundle) -> None:
    """The certificate is not private-key armour, and since 0.7.1 it is the only place `/ca`'s path prints one.

    This assertion used to live next to the page's `<pre>` because that block was the feature being proven. The
    page no longer renders certificate bytes, so the same claim moved onto the route that does serve them --
    which is the narrower, stronger version of it: exactly one CERTIFICATE block, no other BEGIN marker of any
    kind, and the public key inside it is this CA's
    (the thing served is the certificate, not a key that happens to sit in the same file).

    `/ca` itself stays in `test_no_key_leakage.py`'s armour sweep as it has since 0.1.0; what changed is that
    its now-trivial
    "no armour" result is no longer the interesting half of this pair.
    """
    download = session_client.get("/ca/certificate")

    assert download.text.count("-----BEGIN CERTIFICATE-----") == 1
    assert download.text.count("-----END CERTIFICATE-----") == 1
    others = [
        line for line in download.text.splitlines() if line.startswith("-----BEGIN") and "CERTIFICATE-----" not in line
    ]
    assert others == [], f"unexpected PEM armour on /ca/certificate: {others}"

    shown = ca_bundle.cert.public_bytes(Encoding.PEM).decode("ascii").strip()
    assert x509.load_pem_x509_certificate(shown.encode("ascii")).public_key().public_numbers() == (
        ca_bundle.cert.public_key().public_numbers()
    )


def test_the_ca_page_offers_no_pem_block_when_there_is_no_ca(client_without_ca) -> None:
    """The no-CA host renders the notice and no `<pre>`, rather than an empty block or a 500.

    `ca_of()` returns None here, so every CA half of this page is behind `{% if ca_facts %}` and none of it renders. The
    reason this case still needs its own test after 0.7.1 deleted the in-page PEM block: a template edit that moved the
    controls or the facts card **outside** that guard would make a keyless host render an anchor to
    `/ca/certificate`, which answers 503 on such a host, or print "None" where a value is missing -- both
    first-run impressions of a fresh install.
    """
    page = client_without_ca.get("/ca")

    assert page.status_code == 200
    assert 'id="pem-ca"' not in page.text
    assert "data-mypki-copy" not in page.text
    # The whole card is inside `{% if ca_facts %}`: a keyless host renders no PEM block and no copy control at all.
    assert '<pre class="pem"' not in page.text
    assert 'href="/ca/certificate"' not in page.text
    assert NO_CA_MARK in page.text


def test_the_ca_page_shows_the_fingerprint_the_download_matches(session_client, ca_bundle) -> None:
    """The page an operator reads before installing, and the file they install, describe one certificate.

    `ca_download.html` warns to compare the fingerprint out of band; that advice is only usable if the displayed
    value is
    derived from the same certificate the download serves. Asserted through `describe_ca` so the derivation (SHA-256,
    colon-grouped) is checked rather than assumed.
    """
    facts = describe_ca(ca_bundle.cert)

    page = session_client.get("/ca")
    body = session_client.get("/ca/certificate").text

    assert format_fingerprint(facts["fingerprint_sha256"]) in page.text
    assert (
        x509.load_pem_x509_certificate(body.encode("ascii")).fingerprint(hashes.SHA256()).hex()
        == facts["fingerprint_sha256"]
    )


# ------------------------------------------------------------------------------------------- the no-CA state


@pytest.mark.parametrize("path", PAGES)
def test_every_page_still_answers_without_a_ca(client_without_ca, path: str) -> None:
    """A host with no CA is a state every page has to handle (page-map §1), not an error page.

    `client_without_ca` builds the app through `create_app`'s discovery path with nothing on disk — the same path
    `mypki serve` takes when `init-ca` has not been run. The pages must render, because the notice *is* the useful
    answer
    and a 500 would hide it.
    """
    response = client_without_ca.get(path)

    assert response.status_code == 200, response.text[:400]


@pytest.mark.parametrize("path", ("/", "/csr/sign", "/ca"))
def test_the_init_ca_notice_appears_where_an_operator_would_look_for_it(client_without_ca, path: str) -> None:
    """The same sentence on the home page, the sign page and the CA page (page-map §1).

    Asserted as the literal phrase including the command, because "no CA" alone is not an instruction. The GUI cannot
    create a CA by design (page-map §6), so the only correct message is the terminal command that fixes it — and
    it has to
    appear on all three pages rather than only on the home page an operator may never visit again.
    """
    response = client_without_ca.get(path)

    assert response.status_code == 200
    assert NO_CA_MARK in response.text
    assert "the web UI cannot create one" in response.text


def test_the_ca_page_shows_the_colon_grouped_fingerprint_when_a_ca_exists(session_client, ca_bundle) -> None:
    """The fingerprint a human compares against a client's UI, two characters at a time.

    Colon grouping is a Jinja filter shared by several pages precisely because duplicating the expression is how
    one page ends up displaying a fingerprint differently from another (app.py). Asserted here as the rendered
    grouping **and** as the absence of the ungrouped hex, so a template that dropped the filter fails rather than
    rendering both spellings.

    Re-pointed from `/` to `/ca` in 0.3.0: the CA facts card above the signing form was deleted (page-map §1)
    because a fact shown in two places is two facts that can disagree, and `/ca` already owned them. The assertion
    did not weaken — it moved to the single page that now has to carry it, which is also the page the download
    sits next to.
    """
    facts = describe_ca(ca_bundle.cert)
    grouped = format_fingerprint(facts["fingerprint_sha256"])

    page = session_client.get("/ca")

    assert grouped in page.text
    assert facts["fingerprint_sha256"] not in page.text
    assert re.search(r"[0-9A-F]{2}:[0-9A-F]{2}:", page.text)


def test_the_ca_page_reports_key_presence_as_a_boolean_only(session_client, ca_bundle) -> None:
    """`present — this host can sign` / `absent — this host cannot sign`, and nothing about the key itself.

    `describe_ca` has no parameter that could ask for something private (ca.py), and `ca_key_present` is a bool. The
    failure this test guards against is the plausible-looking addition of "and here is where the key file is" to a
    page an
    operator screenshots into a support ticket. Asserted on `/ca`, the one page that reports key presence as of 0.3.0.
    """
    page = session_client.get("/ca")

    assert "CA private key on this host" in page.text
    # The em dash is an HTML entity in the template (`&mdash;`), so it is asserted as the entity rather than as the
    # character: `|safe` renders what is written and does not translate it.
    assert "present &mdash; this host can sign" in page.text
    assert str(ca_bundle.key_path) not in page.text


def test_the_home_page_is_the_sign_form_and_offers_the_paste_box(session_client) -> None:
    """What `/` still owes an operator after 0.3.0 removed the CA card above it (page-map §1).

    The front page is the signing action: it renders the sign heading and, when nothing has been staged yet,
    the paste box that starts step A. Asserted here rather than left to this file's generic 200 sweep, because "the
    home page is the sign form" is a design decision with a specific failure mode — a template refactor that turned
    `/` back into prose would still return 200 and still render.

    The heading reads `Sign a certificate` in this build (Unreleased; it was "Sign a certificate signing request"): the
    page takes a CSR as its input but its output is a certificate, and the sidebar already calls it *Sign CSR*. Asserted
    as the exact `<h1>` so a rename that changes the visible title without changing this assertion — or the reverse —
    fails loudly.
    """
    page = session_client.get("/")

    assert page.status_code == 200
    assert "<h1>Sign a certificate</h1>" in page.text
    assert "CSR requesting CA powers will be refused." in page.text
    assert 'name="csr_pem"' in page.text
    assert "Validate and show details" in page.text
    # And what it no longer says: the root CA's identity belongs to `/ca`, one fact in one place.
    assert "BasicConstraints" not in page.text


def test_the_signed_page_says_so_when_the_key_is_not_loaded(settings: Settings, ca_bundle) -> None:
    """A CA certificate without its private key is a real host state, and the sign page names it.

    `CaBundle.key is None` is modelled rather than crashed on (ca.py): `/` and `/ca/certificate` can still answer. What
    the sign page must do is say plainly that nothing can be signed here, instead of letting step B fail with an error
    about private keys. Produced the way an operator produces it — a restore that brought the certificate but not
    the key.
    """
    from conftest import ScratchClient
    from mypki.app import create_app

    # `replace` on the frozen bundle: the certificate and both paths stay exactly as they are, only the loaded key
    # disappears — which is precisely the state a partial restore produces.
    keyless = replace(ca_bundle, key=None)
    assert keyless.key_present is False
    assert keyless.cert_path == ca_bundle.cert_path
    assert keyless.key_path == ca_bundle.key_path

    app = create_app(settings, ca_bundle=keyless, session_secret="test-session-secret-not-a-real-one")
    with ScratchClient(app, persist_cookies=True) as keyless_client:
        page = keyless_client.get("/csr/sign")

        assert page.status_code == 200
        assert "private key is not loaded" in page.text
        # The public pages still work; only signing is refused.
        assert keyless_client.get("/ca/certificate").status_code == 200
        assert NO_CA_MARK not in page.text


def test_a_ca_page_without_a_certificate_is_503_naming_the_command(client_without_ca, data_root: Path) -> None:
    """`/ca/certificate` is the one no-CA route that cannot render a notice, so it answers 503 (page-map §1).

    503 rather than 404: the route exists and is correct, this host just cannot answer it yet — and the hint names the
    terminal command. Asserted alongside the pages above so the split "render a notice" versus "refuse to serve a file"
    stays visible in the test record.
    """
    response = client_without_ca.get("/ca/certificate")

    assert response.status_code == 503
    assert NO_CA_MARK in response.text
    assert str(paths.ca_cert_path(data_root)) in response.text


# ---------------------------------------------------------------------------------------- one-shot downloads


def test_an_expired_one_shot_artifact_is_a_named_404(session_client) -> None:
    """A stale link 404s rather than re-running the generation (page-map §10).

    Re-running would mint a **different key** behind what looks like the same bookmark, which is worse than saying the
    one-shot output is gone. The expiry here is produced by ageing the artifact's own timestamp rather than by sleeping
    for `ONE_SHOT_TTL_SECONDS`: the TTL logic is asserted in milliseconds instead of a quarter of an hour, and the test
    stays honest about which clock it moved.
    """

    response = _post(
        session_client,
        "/csr/generate",
        token_from="/csr/generate",
        common_name="expiry.internal",
        sans="expiry.internal",
        key_type="ec-p256",
    )
    assert response.status_code == 200
    link = re.findall(r'href="(/download/[^"]+)"', response.text)[0]
    artifact_id = link.removeprefix("/download/")

    store = session_client.app.state.oneshot
    aged = replace(store._items[artifact_id], created_at=time.monotonic() - (store.ttl_seconds + 1))
    store._items[artifact_id] = aged

    expired = session_client.get(link)

    assert expired.status_code == 404
    assert "no longer available" in _reason(expired)
    assert "Generate again" in expired.text


def test_one_shot_expiry_and_capacity_are_unit_assertions_not_sleeps() -> None:
    """TTL expiry and oldest-first eviction, asserted directly on `OneShotStore`.

    Two behaviours the routes depend on but cannot demonstrate cheaply: a 900-second TTL is not worth waiting through,
    and `ONE_SHOT_MAX_ITEMS` bounds how much secret material can be resident in one process (app.py). Eviction drops the
    **oldest** rather than refusing the newest, because refusing would fail an operator's current action to punish an
    abandoned earlier one.

    Ageing is done by rewriting `created_at` (`dataclasses.replace` on a frozen dataclass) so the assertions run against
    the real `_evict()` with no clock manipulation.

    MEASURED, and worth stating exactly: `put` runs `_evict()` **before** inserting, so one over-capacity artifact
    can be
    resident until the next operation. Asserting `len(store) == max_items` straight after an over-capacity put would
    therefore be wrong; what is true — and what this asserts — is that the oldest entry is the one that goes and
    that the
    newest survives.
    """
    store = OneShotStore(ttl_seconds=10, max_items=3)

    first = store.put(filename="a.pem", media_type="application/x-pem-file", body="A")
    second = store.put(filename="b.pem", media_type="application/x-pem-file", body="B")
    third = store.put(filename="c.pem", media_type="application/x-pem-file", body="C")

    # Capacity: the fourth put is accepted, and the eviction that follows drops the oldest.
    fourth = store.put(filename="d.pem", media_type="application/x-pem-file", body="D")
    with pytest.raises(OneShotExpiredError):
        store.take(first.id)
    assert len(store) == 3
    assert store.take(second.id).body == "B"
    assert store.take(third.id).body == "C"
    assert store.take(fourth.id).body == "D"

    # TTL: the same eviction path, driven by an aged timestamp rather than by waiting.
    store._items[second.id] = replace(second, created_at=time.monotonic() - 11)
    with pytest.raises(OneShotExpiredError):
        store.take(second.id)
    assert len(store) == 2

    # An unknown or absent id is the same named failure, not a KeyError and not a redirect.
    with pytest.raises(OneShotExpiredError):
        store.take("nobody-ever-issued-this-id")
    with pytest.raises(OneShotExpiredError):
        store.take(None)


def test_a_download_id_from_another_process_is_a_404_not_a_guess(client) -> None:
    """Artifact ids are random, and an unguessable one is simply absent (page-map §10).

    `secrets.token_urlsafe(32)` rather than a counter or a hash of the filename: a predictable id would let one session
    guess another session's download link. Asserted as 404 plus mypki's own page, because "not found" for an id that was
    never issued is the same answer as "expired" and must not be confused with a server error.
    """
    response = client.get("/download/zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")

    assert response.status_code == 404
    assert "no longer available" in _reason(response)


def test_the_staged_csr_is_consumed_by_signing(session_client, sample_csr_pem: str, data_root: Path) -> None:
    """A signed request cannot be re-signed by a reload (page-map §3 step B).

    `request.session.pop(SESSION_CSR_ID)` is the whole mechanism; without it, refreshing the confirmation page
    would mint
    a second certificate for the same names from an action that looks like viewing. Asserted through what an
    operator can
    observe — the replay 404s and the store still holds exactly one row — rather than by reading the server-side session
    dict, which is not something a browser can check either.
    """
    issued, _step_a = _confirm_and_issue(session_client, sample_csr_pem)
    assert issued.status_code == 200

    store = IssuedStore(paths.db_path(data_root))
    assert store.count() == 1

    # Same session, same token, same `confirm=1` — and nothing staged any more.
    replay = _post(session_client, "/csr/sign", token_from="/csr/sign", confirm="1", cert_type="server")

    assert replay.status_code == 404
    assert "no longer available" in _reason(replay)
    assert store.count() == 1


# ------------------------------------------------------------------------------------------ security headers


@pytest.mark.parametrize("path", PAGES)
def test_security_headers_are_on_every_page(client, path: str) -> None:
    """nosniff, DENY, same-origin, and a CSP with **no** `unsafe-inline` (page-map §0).

    The CSP is only credible because the UI ships one stylesheet from `/static` and no JavaScript at all, so inline
    scripts are not merely disallowed but absent — which is what turns a template-escaping mistake into a rendering bug
    rather than an XSS. Asserted as absence of `unsafe-inline` rather than presence of `default-src 'self'`, because the
    dangerous half is the exception someone adds back later.
    """
    response = client.get(path)

    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "same-origin"
    csp = response.headers["content-security-policy"]
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "unsafe-inline" not in csp
    assert "unsafe-eval" not in csp


def test_security_headers_are_on_error_pages_and_on_the_size_guard_page(client, settings: Settings) -> None:
    """Rejections carry the same headers as successes.

    Two different code paths produce error pages: the exception handlers (which build a `TemplateResponse`) and
    `SizeGuardMiddleware._reject` (which sends headers by hand, because there is no request object yet).
    Duplicated header
    lists are exactly the kind that drift, so both are asserted against the same expectations.
    """
    validation = client.post("/csr/sign", data={"csr_pem": "nope"})
    oversized = client.post(
        "/csr/sign",
        data={"csrf_token": "x"},
        headers={"content-length": str(settings.max_csr_chars + 8192 + 10_000)},
    )

    for response in (validation, oversized):
        assert response.status_code in (400, 413)
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"
        assert "unsafe-inline" not in response.headers["content-security-policy"]


def test_the_session_cookie_is_signed_http_only_and_namespaced(session_client, settings: Settings) -> None:
    """`mypki_session`, `HttpOnly`, `SameSite=lax`, and no secret material in the value.

    The cookie carries an opaque one-shot id and the CSRF token, signed by itsdangerous — never a key or a PEM
    body, which
    is why `OneShotStore` exists at all (a 3072-bit key PEM is far past RFC 6265 §6.1's 4096-octet guidance).
    `https_only`
    follows `tls_enabled`, so the cookie cannot claim a security property the transport does not provide: for this app
    TLS is off, and `Secure` must therefore be **absent** rather than aspirationally present.

    Read from the first response that actually creates the session (the CSRF token is issued on that GET), because
    Starlette only re-sends a session cookie when the session changed.
    """
    response = session_client.get("/csr/generate")
    cookies = response.headers.get_list("set-cookie")
    session_cookie = next(
        (value for value in cookies if value.startswith("mypki_session=")),
        None,
    )

    assert session_cookie is not None, cookies
    # Starlette serialises the attributes lower-case (`httponly; samesite=lax`), so every flag check here runs against a
    # lowered copy. Asserting the canonical `"HttpOnly"` spelling would fail on a cookie that genuinely *is* HttpOnly,
    # which is the kind of test that teaches people to distrust their own suite.
    attributes = session_cookie.lower()
    assert "httponly" in attributes
    assert "samesite=lax" in attributes
    assert "secure" not in attributes  # settings.tls_enabled is False for this app
    assert "max-age=3600" in attributes  # settings.session_max_age, from Settings.session_max_age
    assert settings.secret_key not in session_cookie
    assert "-----BEGIN" not in session_cookie
    assert len(session_cookie) < 4096, "RFC 6265 §6.1: browsers may reject cookies over 4096 octets"


def test_the_issued_page_truncates_long_sans_without_hiding_them(session_client) -> None:
    """72 characters in the cell, the full value in `title=` (page-map §5, issued.html).

    A long name list has to be readable *and* complete: truncation that hides information is how an operator ends up
    trusting a name they never actually saw. Issued through the real flow so the row is a genuine record rather than a
    fixture.

    The name is built from 60-character labels because `validators.py` refuses any label over 63 (RFC 1123) — a
    90-character label would be rejected by the sign page and this test would be asserting a rejection instead of a
    rendering rule.
    """
    from mypki.csr import CsrFields, build_csr

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    long_name = f"{'a' * 60}.{'b' * 60}.internal"
    fields = CsrFields(common_name="long.internal", sans=_san_set((long_name,)))
    pem = build_csr(fields, key)

    issued, _ = _confirm_and_issue(session_client, pem)
    assert issued.status_code == 200

    page = session_client.get("/issued")

    assert page.status_code == 200
    assert long_name in page.text  # reachable via title=
    cell = re.search(r"<td[^>]*title=\"" + re.escape(long_name) + r"\">([^<]*)</td>", page.text)
    assert cell is not None, "expected a title= carrying the full SAN value"
    assert len(cell.group(1)) <= 72


# ------------------------------------------------------------------------------------------------ helpers


def _san_set(dns: tuple[str, ...]):
    from mypki.validators import SanSet

    return SanSet(dns=dns)
