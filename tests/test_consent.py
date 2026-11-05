"""Consent for dropped extensions: page-map §3 rule 6 end to end.

`test_csr_validate.py` pins the **library** split — which extensions are refused outright and which are disclosed. This
file pins what an operator actually meets, because the library answer is half the design (PLAN.md §6.3): a list step A
shows and step B ignores is still a silent omission, and a box step B trusts from the form rather than from the staged
request is a consent nobody was asked for.

Five things are asserted here and nowhere else:

  * **The panel can now show an extension.** Before this change it never could: rule 6 refused every non-SAN extension
    at step 6, so page-map §3's "disallowed extensions found (if any)" described a page state that could not exist. A
    `CA:FALSE` request reaching the confirmation panel *is* the feature.
  * **Consent is default OFF at the HTTP layer.** An unticked checkbox submits nothing at all, so step B answers 200
    with the box still on the page and signs nothing — an unchanged issued store is asserted wherever a refusal is.
  * **Both call sites agree.** `parse_and_validate_csr` runs twice (step A's paste, step B's re-parse of the staged
    artifact) and the dropped list is derived from the request both times. Nothing here is read out of a form field, so
    a POST cannot consent to an extension the page never showed, nor claim a list other than the one it was shown.
  * **Consent does not reach a privilege claim.** Ticking the box buys the dropping of `CA:FALSE`, never the issuing of
    `CA:TRUE`. The 403 and its empty store are asserted with the field present in the POST.
  * **The request is never rewritten.** "Ignored" means not copied: the staged PEM still carries every extension the
    paste did, and the issued certificate carries mypki's own profile even when consent was granted.

Autoescape is pinned on in `app.py`, so rendering CSR-derived text into the panel is safe **provided no `|safe` filter
is added** — which `test_the_consent_markup_adds_no_safe_filter` checks against the template rather than assuming,
because that promise is one template edit away from being false and no page assertion can see it.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from mypki import paths
from mypki.app import CONSENT_FIELD
from mypki.csr import CSR_PEM_BEGIN, CSR_PEM_END
from mypki.store import IssuedStore

BUILD_ROOT = Path(__file__).resolve().parent.parent
SIGN_TEMPLATE = BUILD_ROOT / "src" / "mypki" / "templates" / "csr_sign.html"

MAX_CHARS = 32000


# --------------------------------------------------------------------------------------------- fixtures


@pytest.fixture(scope="module")
def consent_key() -> rsa.RSAPrivateKey:
    """One RSA-2048 key for every CSR this file builds.

    Module-scoped because these tests are about the *flow*, not about key generation, and a dozen 2048-bit keypairs
    would make this the slowest file in the suite without asserting anything extra. Throwaway, never written to disk.
    """
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _csr_pem(
    key: rsa.RSAPrivateKey,
    *,
    common_name: str = "consent.internal",
    sans: tuple[str, ...] = ("consent.internal",),
    extensions: tuple[tuple[x509.ExtensionType, bool], ...] = (),
) -> str:
    """A PEM CSR built the way an outside tool builds one — SAN first, then whatever is being tested.

    `extensions` is the whole point of this helper: every case here differs from every other only in that tuple
    (STYLE §8), so a failure names the extension rather than the fixture.
    """
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(value) for value in sans]), critical=False
        )
    for extension, critical in extensions:
        builder = builder.add_extension(extension, critical=critical)
    return builder.sign(key, hashes.SHA256()).public_bytes(Encoding.PEM).decode("ascii")


def _benign_pem(key: rsa.RSAPrivateKey) -> str:
    """The request the operator report was actually about: OpenSSL's own default `[v3_req]` extensions.

    `openssl req` with a distro `openssl.cnf` writes `basicConstraints = CA:FALSE` and
    `keyUsage = digitalSignature, keyEncipherment` into every request it makes. Until this build, mypki refused that
    request at step 6 — correct policy under rule 6's first form, and a sign page that could not sign a normal CSR.
    """
    return _csr_pem(
        key,
        extensions=[
            (x509.BasicConstraints(ca=False, path_length=None), True),
            (_benign_usage(), False),
        ],
    )


def _benign_usage() -> x509.KeyUsage:
    """OpenSSL's own `keyUsage = digitalSignature, keyEncipherment`, as one object.

    Extracted because three tests here need exactly this pair and one of them needs it *next to* a privilege claim: the
    mixed case is where "refused" and "disclosed" first meet in a single request.
    """
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=True,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )


def _privileged_pem(key: rsa.RSAPrivateKey) -> str:
    """`CA:TRUE` + `keyCertSign` + `crlSign`: the privilege half, unchanged by this build."""
    return _csr_pem(
        key,
        common_name="privileged.internal",
        extensions=[
            (x509.BasicConstraints(ca=True, path_length=0), True),
            (
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                True,
            ),
        ],
    )


# ------------------------------------------------------------------------------------------ page plumbing


def _post(client, path: str, *, token_from: str | None = None, **fields: str):
    payload = dict(fields)
    if token_from is not None:
        from conftest import csrf_token

        payload["csrf_token"] = csrf_token(client, token_from)
    return client.post(path, data=payload)


def _inline_reasons(response) -> str | None:
    """The `<li>` sentences of a re-rendered form's `.form-errors` block, or None when there is no such block."""
    match = re.search(r'<section class="form-errors">(.*?)</section>', response.text, re.DOTALL)
    if match is None:
        return None
    return " ".join(item.strip() for item in re.findall(r"<li>(.*?)</li>", match.group(1), re.DOTALL))


def _reason(response) -> str:
    """The `<p class="reason">` sentence on mypki's error page (403/400/413 surface)."""
    match = re.search(r'<p class="reason">(.*?)</p>', response.text, re.DOTALL)
    if match is None:
        raise AssertionError(f'no mypki error page (class="reason") in the {response.status_code} body')
    return match.group(1)


def _consent_boxes(page: str) -> list[str]:
    """Every consent control on the page, as its raw `<input …>` tag.

    A list rather than a count so "present once" and "rendered ticked" are two assertions on the same read rather than
    one assertion that can satisfy both by accident: a box that appears twice would also appear checked-or-not once.
    """
    return re.findall(r'<input type="checkbox"[^>]*name="' + CONSENT_FIELD + r'"[^>]*>', page)


def _dropped_names(page: str) -> list[str]:
    """The extension names the confirmation panel listed, read out of its `<code>` elements.

    Scoped to the dropped-extensions block rather than searched page-wide: the provenance list beside it legitimately
    names `BasicConstraints` and `KeyUsage` as things mypki sets, and a page-wide search would pass on a build that
    disclosed nothing at all.
    """
    match = re.search(r'<div class="provenance dropped-extensions">(.*?)</div>', page, re.DOTALL)
    if match is None:
        return []
    return list(re.findall(r"<code>([^<]+)</code>", match.group(1)))


def _pending_id(response) -> str:
    match = re.search(r'action="/csr/sign\?pending=([^"]+)"', response.text)
    if match is None:
        raise AssertionError(f"no ?pending= form action in the {response.status_code} body")
    return match.group(1)


def _issued_certificate(response) -> x509.Certificate:
    """The certificate the issued card rendered, parsed out of its own `<pre>`.

    Parsed rather than substring-searched because every assertion this file makes about *what was signed* has to be
    about the artifact, and `class="pem" id="pem-cert"` is the element that holds it (as opposed to the chain block
    beside it, which contains two certificates).
    """
    # `\s*` before `</pre>`: the PEM body ends with its own newline (signing.py returns armour and the template puts it
    # in the element verbatim), so a regex demanding the END line sit flush against the closing tag matches nothing on a
    # correct page.
    match = re.search(
        r'<pre class="pem" id="pem-cert">(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)\s*</pre>',
        response.text,
        re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"no issued certificate block in the {response.status_code} body")
    return x509.load_pem_x509_certificate(match.group(1).encode("ascii"))


def _diff_entries(response) -> list[tuple[str, str]]:
    """The `dt`/`dd` pairs of the issued page's 'Changed from your request' block."""
    match = re.search(r'<div class="diff">(.*?)</div>', response.text, re.DOTALL)
    if match is None:
        return []
    return [(label, value) for label, value in re.findall(r"<dt>([^<]+)</dt><dd>([^<]*)</dd>", match.group(1))]


# ------------------------------------------------------------------ step A: the panel can now show extensions


def test_a_ca_false_request_reaches_the_panel_and_names_what_will_be_dropped(
    session_client, consent_key: rsa.RSAPrivateKey
) -> None:
    """The feature, in one assertion pair: 200 rather than 403, and the extension named on the page.

    Under rule 6's first form this paste answered 403 at step 6 and no panel existed to describe it. Now the request is
    accepted, the panel lists `BasicConstraints CA:FALSE` and both KeyUsage bits by name, and the names are the same
    strings `CsrDetails.ignored_extensions` carries — which is what makes the issued page's diff traceable back to a
    line of the operator's own openssl config.
    """
    response = _post(session_client, "/csr/sign", token_from="/csr/sign", csr_pem=_benign_pem(consent_key))

    assert response.status_code == 200, _reason(response)
    assert "This is what the request says" in response.text
    assert _dropped_names(response.text) == [
        "BasicConstraints CA:FALSE",
        "KeyUsage (digitalSignature, keyEncipherment)",
    ]


def test_the_consent_box_is_rendered_once_and_unchecked(session_client, consent_key: rsa.RSAPrivateKey) -> None:
    """Default OFF, asserted as markup rather than as an intention.

    `checked` absent is the whole promise: a box that arrives ticked would mean the operator's first submission of a
    request carrying extensions already consents, which is the exact outcome PLAN.md §6.3 rules out. The `state-off`
    span is asserted alongside it because 0.4.0 established that the word beside a checkbox carries the state in colour,
    and a server-rendered `on` next to an unticked box would be a page that contradicts its own control.
    """
    response = _post(session_client, "/csr/sign", token_from="/csr/sign", csr_pem=_benign_pem(consent_key))

    boxes = _consent_boxes(response.text)
    assert len(boxes) == 1, boxes
    assert "checked" not in boxes[0]
    assert 'class="checkbox-state state-off">off<' in response.text


def test_a_request_mypki_generated_itself_renders_no_consent_box(session_client, sample_csr_pem: str) -> None:
    """`build_csr` adds SAN and nothing else, so a mypki CSR shows no list and no box.

    Asserted because the absence of a consent box is otherwise ambiguous: "this request carried nothing to drop" and
    "the box was removed from the template" render identically, and only one of them is correct behaviour. This is also
    the case that keeps 0.1.0-style flows (generate here, sign here) free of a decision they never need.
    """
    response = _post(session_client, "/csr/sign", token_from="/csr/sign", csr_pem=sample_csr_pem)

    assert response.status_code == 200, _reason(response)
    assert _consent_boxes(response.text) == []
    assert _dropped_names(response.text) == []


def test_a_crl_distribution_point_now_reaches_the_panel_rather_than_a_403(
    session_client, consent_key: rsa.RSAPrivateKey
) -> None:
    """CRLDistributionPoints moved from the refused half to the disclosed half (PLAN.md §6.3).

    Asserted through the app and not only through `csr.py` because this is the case where the two categories look
    closest: a distribution point *looks* like a CA feature (it points at a CRL), and it is the one name a future edit
    would plausibly move back to the refused list. It stays disclosed because **disclosing and obeying are different
    things**: since 0.7.0 this CA publishes its own CRL and bakes its own pointer into every new leaf
    (`<crl_base_url>/crl.pem`, page-map §14), and a request's distribution point is still dropped rather than honoured
    (`test_a_consent_grant_never_copies_an_extension_into_the_certificate` proves that half on the parsed certificate).
    Refusing it instead would make a request from a template that carried one unsignable, for no protection at all.
    """
    pem = _csr_pem(
        consent_key,
        extensions=[
            (
                x509.CRLDistributionPoints(
                    [
                        x509.DistributionPoint(
                            full_name=[x509.UniformResourceIdentifier("http://crl.internal/crl.der")],
                            relative_name=None,
                            reasons=None,
                            crl_issuer=None,
                        )
                    ]
                ),
                False,
            )
        ],
    )

    response = _post(session_client, "/csr/sign", token_from="/csr/sign", csr_pem=pem)

    assert response.status_code == 200, _reason(response)
    assert _dropped_names(response.text) == ["CRLDistributionPoints"]


# ------------------------------------------------------------- step B without consent: refuse at 200, sign nothing


def test_confirming_without_the_box_signs_nothing_and_names_every_dropped_extension(
    session_client, consent_key: rsa.RSAPrivateKey, data_root: Path
) -> None:
    """An unticked box is an input to fix, not a refused request (page-map §3, app.py `ERROR_SURFACE_RULE`).

    Three things have to be true at once and each fails independently: **200**, because nothing was refused and the
    staged request is still here; **every extension named** in the inline block, because a refusal that says "some
    extensions" cannot be acted on; and **an unchanged issued store**, because "nothing was signed" is the promise the
    status code alone cannot make.

    The alternative — a 403 here — would put an operator who simply forgot to tick a box on the same page as one who
    asked for a CA, and (measured before this change) it would drop the staged request too: `error.html` carries no
    `?pending=` action, so the fix means re-pasting a 2 KB PEM.
    """
    before = IssuedStore(paths.db_path(data_root)).count()

    step_a = _post(session_client, "/csr/sign", token_from="/csr/sign", csr_pem=_benign_pem(consent_key))
    assert step_a.status_code == 200, _reason(step_a)
    token = re.search(r'name="csrf_token" value="([^"]+)"', step_a.text)
    assert token is not None

    refused = _post(
        session_client,
        "/csr/sign",
        confirm="1",
        cert_type="server",
        validity_days="30",
        csrf_token=token.group(1),
    )

    assert refused.status_code == 200
    reason = _inline_reasons(refused)
    assert reason is not None, refused.text[:400]
    assert "consent to dropped extensions" in reason
    assert "BasicConstraints CA:FALSE" in reason
    assert "KeyUsage (digitalSignature, keyEncipherment)" in reason
    assert "Nothing was signed." in reason
    assert IssuedStore(paths.db_path(data_root)).count() == before


def test_the_unticked_refusal_keeps_the_box_and_the_staged_request(
    session_client, consent_key: rsa.RSAPrivateKey
) -> None:
    """The refused confirm page is still a confirmation page: box present, request still staged.

    The `?pending=` id is compared against step A's rather than merely asserted non-empty — a re-render that minted a
    new id would point at a second copy of the PEM and leave the first resident in the one-shot store, which is how an
    "expired" download link and a signed-but-invisible request both start.
    """
    step_a = _post(session_client, "/csr/sign", token_from="/csr/sign", csr_pem=_benign_pem(consent_key))
    pending = _pending_id(step_a)
    token = re.search(r'name="csrf_token" value="([^"]+)"', step_a.text)
    assert token is not None

    refused = _post(
        session_client,
        f"/csr/sign?pending={pending}",
        confirm="1",
        cert_type="server",
        validity_days="30",
        csrf_token=token.group(1),
    )

    assert refused.status_code == 200
    assert _pending_id(refused) == pending
    assert len(_consent_boxes(refused.text)) == 1
    assert "checked" not in _consent_boxes(refused.text)[0]
    # The panel above the error block still shows what the request said, because "you did not consent to these" is only
    # actionable next to the list of what they are.
    assert _dropped_names(refused.text) == [
        "BasicConstraints CA:FALSE",
        "KeyUsage (digitalSignature, keyEncipherment)",
    ]


def test_an_empty_or_nonsense_consent_value_is_not_consent(
    session_client, consent_key: rsa.RSAPrivateKey, data_root: Path
) -> None:
    """The field's presence is not enough; its value has to be one a ticked box can produce.

    `?ignore_extensions=` (empty), `=0`, and `=maybe` all name the field. Under a truthiness test they would consent —
    which means a bookmark, a proxy that rewrites query strings, or a hand-built POST could consent on an operator's
    behalf without ever having seen the list. The accepted spellings are the ones this app's own forms produce
    (`settings.html` posts `value="true"` for its checkboxes), and everything else means no.
    """
    before = IssuedStore(paths.db_path(data_root)).count()

    step_a = _post(session_client, "/csr/sign", token_from="/csr/sign", csr_pem=_benign_pem(consent_key))
    token = re.search(r'name="csrf_token" value="([^"]+)"', step_a.text)
    assert token is not None

    for value in ("", "0", "maybe", "off"):
        refused = _post(
            session_client,
            "/csr/sign",
            confirm="1",
            cert_type="server",
            validity_days="30",
            csrf_token=token.group(1),
            **{CONSENT_FIELD: value},
        )
        assert refused.status_code == 200, f"value {value!r} was accepted as consent"
        assert "consent to dropped extensions" in (_inline_reasons(refused) or "")

    assert IssuedStore(paths.db_path(data_root)).count() == before


# ------------------------------------------------------------------ step B with consent: issue and disclose


def test_confirming_with_the_box_issues_and_names_everything_it_dropped(
    session_client, consent_key: rsa.RSAPrivateKey, data_root: Path
) -> None:
    """Consent granted → signed, and every dropped extension named on the issued page.

    The diff block is asserted as `dt`/`dd` pairs rather than as a substring search, for the same reason
    `test_views.py` asserts the name-edit diff that way: the block has to *name* each thing and say what replaced it. A
    build that printed one vague sentence about extensions would satisfy a substring assertion and fail this one — and a
    vague sentence is exactly what an operator cannot carry into a certificate viewer six months from now.

    The store gaining exactly one row is the other half: consent has to actually produce the certificate, or the box is
    decoration.
    """
    before = IssuedStore(paths.db_path(data_root)).count()

    step_a = _post(session_client, "/csr/sign", token_from="/csr/sign", csr_pem=_benign_pem(consent_key))
    assert step_a.status_code == 200, _reason(step_a)
    token = re.search(r'name="csrf_token" value="([^"]+)"', step_a.text)
    assert token is not None

    issued = _post(
        session_client,
        "/csr/sign",
        confirm="1",
        cert_type="server",
        validity_days="30",
        csrf_token=token.group(1),
        **{CONSENT_FIELD: "true"},
    )

    assert issued.status_code == 200, issued.text[:400]
    assert "Issued: consent.internal" in issued.text

    entries = _diff_entries(issued)
    assert entries == [
        ("Extension not copied: BasicConstraints CA:FALSE", "set by mypki instead"),
        ("Extension not copied: KeyUsage (digitalSignature, keyEncipherment)", "set by mypki instead"),
    ], entries

    # The closing sentence the name-edit diff already carries is asserted here too: with an extension dropped it is more
    # true than it was before, and it is asserted verbatim in test_views.py, so a rewrite would break two files.
    assert "The public key and every extension still came from mypki" in issued.text

    store = IssuedStore(paths.db_path(data_root))
    assert store.count() == before + 1
    assert store.list_records()[0].common_name == "consent.internal"


def test_a_consent_grant_never_copies_an_extension_into_the_certificate(
    session_client, consent_key: rsa.RSAPrivateKey
) -> None:
    """The certificate is parsed and compared against mypki's profile, not searched for strings.

    This is the assertion that separates "ignore" from "accept": a build that threaded `details` into
    `signing.leaf_extensions()` would keep every page assertion above green — the diff still names the extensions, the
    panel still lists them — while quietly shipping the request's own KeyUsage on the leaf. So the check is made on the
    parsed certificate. Since 0.7.0 the CRLDistributionPoints half has to be written as **two** claims, because there is
    now a pointer on the leaf and a bare "no CDP appears" assertion is simply false: the request's own
    `http://crl.internal/crl.der` is not copied, and mypki's own `<crl_base_url>/crl.pem` is present instead. Consent
    changes nothing about which of the two a leaf carries — that is decided by `signing.leaf_extensions()` alone.

    ExtendedKeyUsage stays the profile's (`serverAuth` only, not the request's clientAuth) and `keyEncipherment` follows
    mypki's rule rather than the request's.

    Asserted on a `server` profile with consent granted, because that is the state where copying would be visible.
    """
    pem = _csr_pem(
        consent_key,
        common_name="profile.internal",
        sans=("profile.internal",),
        extensions=[
            (
                x509.ExtendedKeyUsage([x509.ObjectIdentifier("1.3.6.1.5.5.7.3.2")]),
                False,
            ),  # clientAuth: not what server issues get
            (
                x509.CRLDistributionPoints(
                    [
                        x509.DistributionPoint(
                            full_name=[x509.UniformResourceIdentifier("http://crl.internal/crl.der")],
                            relative_name=None,
                            reasons=None,
                            crl_issuer=None,
                        )
                    ]
                ),
                False,
            ),
        ],
    )

    step_a = _post(session_client, "/csr/sign", token_from="/csr/sign", csr_pem=pem)
    assert step_a.status_code == 200, _reason(step_a)
    assert _dropped_names(step_a.text) == ["ExtendedKeyUsage (clientAuth)", "CRLDistributionPoints"]

    token = re.search(r'name="csrf_token" value="([^"]+)"', step_a.text)
    assert token is not None
    issued = _post(
        session_client,
        "/csr/sign",
        confirm="1",
        cert_type="server",
        validity_days="30",
        csrf_token=token.group(1),
        **{CONSENT_FIELD: "true"},
    )

    certificate = _issued_certificate(issued)
    # 0.7.0: the leaf DOES carry a CDP — this CA's own. What must be absent is the *request's* URL, and what must be
    # present is the configured one, so consent cannot redirect a client to someone else's CRL.
    points = [
        extension.value
        for extension in certificate.extensions
        if isinstance(extension.value, x509.CRLDistributionPoints)
    ]
    assert len(points) == 1, "exactly one CDP on a leaf: mypki's own, never the request's"
    # `CRLDistributionPoints` iterates `DistributionPoint` objects; each carries `.full_name` as GeneralNames, whose
    # payload attribute is `.value` (MEASURED: `UniformResourceIdentifier` has no `.uri`).
    urls = [name.value for point in points[0] for name in (point.full_name or [])]
    assert urls == ["http://mypki.my.lab/crl.pem"], "the request's http://crl.internal/crl.der must not be copied"
    # The configured base comes from the fixture Settings, so a change to the knob changes this assertion loudly.
    assert all(url.startswith("http://mypki.my.lab/") for url in urls)
    eku = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert [oid.dotted_string for oid in eku] == ["1.3.6.1.5.5.7.3.1"]  # serverAuth only
    usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    assert usage.key_cert_sign is False and usage.crl_sign is False


def test_the_staged_request_is_untouched_after_a_consent_grant_signing(
    session_client, consent_key: rsa.RSAPrivateKey
) -> None:
    """The byte-identity invariant, asserted where a refactor would actually break it.

    The staged body is read out of the app's own one-shot store rather than inferred from the issued certificate,
    because "nothing was stripped" has two failure modes and only one shows up in the artifact: `app.py` could re-armour
    the PEM from a rebuilt request (different bytes, valid signature over the *new* bytes, step B signs a document step
    A never validated), or it could pass the original through unchanged. Both issue a certificate that looks identical.

    The comparison is on DER rather than PEM text: two armours of one DER differ in line width while describing the same
    signed document, and a rebuilt request parses identically. Only the bytes the signature covers settle it — and the
    staged body still carrying `BasicConstraints` and `KeyUsage` is what proves "ignored" meant not copied.
    """
    pem = _benign_pem(consent_key)
    requested_der = _der_of(pem)

    step_a = _post(session_client, "/csr/sign", token_from="/csr/sign", csr_pem=pem)
    pending = _pending_id(step_a)
    staged = session_client.app.state.oneshot.take(pending)

    staged_csr = x509.load_pem_x509_csr(staged.body.encode("ascii"))
    # `.value` rather than the `Extension` wrapper: `type(extension).__name__` is `Extension` for every extension there
    # ever was, which would make this assertion pass on a request carrying anything at all.
    assert [type(item.value).__name__ for item in staged_csr.extensions] == [
        "SubjectAlternativeName",
        "BasicConstraints",
        "KeyUsage",
    ]
    assert staged_csr.is_signature_valid
    assert _der_of(staged.body) == requested_der

    token = re.search(r'name="csrf_token" value="([^"]+)"', step_a.text)
    assert token is not None
    issued = _post(
        session_client,
        f"/csr/sign?pending={pending}",
        confirm="1",
        cert_type="server",
        validity_days="30",
        csrf_token=token.group(1),
        **{CONSENT_FIELD: "true"},
    )
    assert issued.status_code == 200, issued.text[:400]

    # Signing drops the session's pointer to the staged request (app.py pops `SESSION_CSR_ID`), which is what makes a
    # re-submit of the *issued* page answer 404 rather than issue the same names a second time. Asserted through the
    # app's own page rather than store internals, because "what happens when I press submit again" is the question an
    # operator has, and a consent feature a reload could re-run would drop extensions twice.
    # The issued card renders no form, so there is no new token to read off it — the same session token step A's page
    # carried is reused, which is what `csrf.py` promises by not rotating per request.
    stale = _post(
        session_client,
        "/csr/sign",
        confirm="1",
        cert_type="server",
        validity_days="30",
        csrf_token=token.group(1),
        **{CONSENT_FIELD: "true"},
    )

    assert stale.status_code == 404
    assert "no longer available" in _reason(stale)


def test_a_consent_grant_does_not_extend_to_a_privilege_claim(
    client, consent_key: rsa.RSAPrivateKey, data_root: Path
) -> None:
    """The box buys the dropping of `CA:FALSE`. It does not buy the issuing of `CA:TRUE`.

    The field is present in this POST on purpose: the tempting implementation of "consent" is one boolean that unlocks
    the whole extension gate, and the way to find out whether a build did that is to send the consent value alongside a
    request that asks for a CA. 403 and an empty store are the answer this asserts.

    The 403 page also has to keep pointing at the *right* fix. Its hint now names both halves — this extension was
    refused, and extensions that ask for nothing are listed on the panel behind a box — because an operator reading only
    the hint should be able to tell which of their two extensions caused the refusal.
    """
    before = IssuedStore(paths.db_path(data_root)).count()

    response = _post(
        client,
        "/csr/sign",
        token_from="/csr/sign",
        csr_pem=_privileged_pem(consent_key),
        **{CONSENT_FIELD: "true"},
    )

    assert response.status_code == 403
    reason = _reason(response)
    assert "BasicConstraints CA:TRUE" in reason
    assert "keyCertSign" in reason
    assert "crlSign" in reason
    # The hint is a separate element from the reason (`_render_error` renders both), so it is read off the body rather
    # than out of `_reason()` — and it has to name both halves now that one extension class is refused and another is
    # listed for consent.
    assert "Rejected extension: BasicConstraints CA:TRUE" in response.text
    # MEASURED wording, with the needle corrected rather than the page rewritten: app.py's hint closes "… and dropped
    # only when you tick the box there." This assertion read "only if you tick the box", a phrase no build prints, and
    # it failed against a correct 403 page — the assertion was the defect. Both harnesses carry the same correction.
    assert "you tick the box there" in response.text
    assert IssuedStore(paths.db_path(data_root)).count() == before


def test_a_privilege_claim_and_an_ignorable_extension_in_one_request_refuses_naming_only_the_claim(
    client, consent_key: rsa.RSAPrivateKey
) -> None:
    """Consent cannot be traded for a privilege, and a refusal does not list what it would have dropped.

    The request carries `CA:TRUE` *and* a benign KeyUsage. Only `CA:TRUE` is named: nothing was signed, so a message
    reading "we would have dropped your KeyUsage" describes a decision this request never got. The operator fixing it
    gets one accurate list rather than a half-accepted one.
    """
    # One `BasicConstraints` per request, because cryptography refuses to build a request with the same extension twice
    # (MEASURED: `ValueError: This extension has already been set.`). The mixed case is therefore benign-KeyUsage +
    # `CA:TRUE`, which is also the shape an openssl template actually produces.
    pem = _csr_pem(
        consent_key,
        common_name="mixed.internal",
        extensions=[
            (_benign_usage(), False),
            (x509.BasicConstraints(ca=True, path_length=None), True),
        ],
    )

    response = _post(client, "/csr/sign", token_from="/csr/sign", csr_pem=pem)

    assert response.status_code == 403
    reason = _reason(response)
    assert "BasicConstraints CA:TRUE" in reason
    # The ignorable half is not listed on a refusal: nothing was signed, so naming the KeyUsage would read as though it
    # had been accepted. Asserted on the whole body rather than only the reason, because a hint that leaked the list
    # would be just as misleading as a reason that did.
    assert "digitalSignature" not in response.text


# --------------------------------------------------------------------- the list cannot be supplied by the client


def test_the_dropped_list_is_derived_from_the_request_not_from_anything_the_form_posted(
    session_client, consent_key: rsa.RSAPrivateKey
) -> None:
    """No client-supplied extension list exists, so none can be forged.

    This POST carries three plausible injections: a field naming an extension the request does not carry, a field
    claiming nothing was dropped, and a field with the same name step A's context uses. None changes what is signed or
    what is reported, because `CsrDetails.ignored_extensions` is rebuilt from the staged bytes at step B
    (`_issue_from_confirmation`) exactly as it was built from the paste at step A (`csr_sign_submit`).

    The issued page naming exactly the two real names — and not the injected one — is what proves the two call sites
    agree. If either trusted a form value, this is the assertion that would fail.
    """
    step_a = _post(session_client, "/csr/sign", token_from="/csr/sign", csr_pem=_benign_pem(consent_key))
    token = re.search(r'name="csrf_token" value="([^"]+)"', step_a.text)
    assert token is not None

    issued = _post(
        session_client,
        "/csr/sign",
        confirm="1",
        cert_type="server",
        validity_days="30",
        csrf_token=token.group(1),
        **{CONSENT_FIELD: "true"},
        ignored_extensions="AuthorityKeyIdentifier",
        dropped_extensions="none",
    )

    assert issued.status_code == 200, issued.text[:400]
    names = [label.removeprefix("Extension not copied: ") for label, _ in _diff_entries(issued)]
    assert names == ["BasicConstraints CA:FALSE", "KeyUsage (digitalSignature, keyEncipherment)"]
    assert "AuthorityKeyIdentifier" not in str(names)


def test_the_consent_markup_adds_no_safe_filter() -> None:
    """Autoescape is the only thing standing between a CSR-derived string and markup (PLAN.md §6.3).

    `app.py` pins Jinja autoescape on, which makes rendering these names safe — *provided nothing in this block opts out
    per expression*. A `|safe` here would be invisible to every page assertion in this file: the tests read text that is
    correctly escaped today and identically-present-but-live markup tomorrow. So the promise is checked where it can
    actually be broken, against the template source, the way `test_packaging.py` checks asset presence.

    The block is located by its own markers rather than by scanning the whole file for `|safe`: `csrf_field(request) |
    safe` is legitimate and load-bearing elsewhere in this template, and a file-wide ban would fail against correct code
    and teach the next reader to distrust the assertion.
    """
    text = SIGN_TEMPLATE.read_text(encoding="utf-8")

    dropped = re.search(r"{# page-map §3 rule 6.*?Not copied from your request.*?</div>", text, re.DOTALL)
    consent = re.search(r"<fieldset class=\"consent\">.*?</fieldset>", text, re.DOTALL)
    assert dropped is not None and consent is not None, "the disclosure or consent block is missing from csr_sign.html"

    for block_name, block in (("dropped-extension", dropped.group(0)), ("consent", consent.group(0))):
        assert "|safe" not in block, f"{block_name} block renders with a |safe filter"

    # The consent field's name comes from app.py rather than being spelled again in the template: two spellings of one
    # field name is how a box stops being readable by the handler that checks it.
    assert "{{ consent_field }}" in consent.group(0)


def test_consent_field_name_is_one_constant_in_app_and_template() -> None:
    """`CONSENT_FIELD` is imported rather than duplicated, and this file uses it too.

    The third copy matters: a test that hard-coded `name="ignore_extensions"` would stay green after someone renamed the
    field in `app.py` and the template together, while every client built against the old name stopped consenting. This
    file's own assertions read the constant, so a rename is only consistent if the *behaviour* moved with it.
    """
    text = SIGN_TEMPLATE.read_text(encoding="utf-8")

    assert CONSENT_FIELD == "ignore_extensions"
    assert text.count("{{ consent_field }}") == 1
    assert CONSENT_FIELD not in text, "the template spells the field name instead of reading it from context"


def _der_of(pem: str) -> bytes:
    """The DER inside a PEM armour — what a CSR signature actually covers."""
    match = re.search(rf"{CSR_PEM_BEGIN}\s*(.*?)\s*{CSR_PEM_END}", pem, re.DOTALL)
    if match is None:
        raise AssertionError("_der_of needs a PEM-armoured request")
    return __import__("base64").b64decode("".join(match.group(1).split()))
