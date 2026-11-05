"""`/csr/generate` produces a key and a request **and stores neither**.

page-map §2 is unusually explicit about this: "Nothing is written to disk or the DB. The key exists only in request
memory and the response body." That promise is what makes the page safe to expose on a host with no logins, and it
is the
kind of promise a refactor breaks by accident -- adding `store.save(csr_pem)` so the download link works after a restart
looks like a small improvement and turns the data directory into a pile of private keys.

So the central assertion here is a **tree hash**: every file under `<data>` (path, size, SHA-256) before the POST,
and the
same map after. A single appended row in `issued.db` changes that database's hash; a stray `.pem` or `.key` appears as a
new key in the map; even an emptied new directory shows up. "Nothing changed" is stated as something measurable rather
than as confidence.

Each negative case mutates exactly one form field (STYLE §8), and nothing here hard-codes the version -- the footer text
is read from `mypki.__version__`.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_private_key

from conftest import ScratchClient, csrf_token, pem_block_count, snapshot_tree
from mypki import __version__
from mypki.csr import PASSPHRASE_MIN_LENGTH, PASSPHRASE_RECOMMENDED_LENGTH

FORM_BASE = {
    "common_name": "server.internal",
    "sans": "server.internal\n*.lab.internal\n10.0.0.7",
    "key_type": "rsa-2048",
    "organization": "mypki tests",
    "country": "XX",
}


def _post(client: ScratchClient, **overrides: str):
    """Submit the generate form with one field changed and nothing else."""
    fields = dict(FORM_BASE)
    fields.update(overrides)
    fields["csrf_token"] = csrf_token(client, "/csr/generate")
    return client.post("/csr/generate", data=fields)


def _form_error(response) -> str | None:
    """The `<li>` sentences inside the re-rendered form's `.form-errors` block, joined.

    Read structurally rather than by searching the whole body, for the same reason `test_views._reason()` exists: "the
    word appears somewhere on the page" is also true of a page that mentions a field while refusing for a different
    reason. On a 200 response there is no `<p class="reason">` to read — the inline block *is* the error surface
    (`app.py`'s `ERROR_SURFACE_RULE`) — so absence of it is reported as an explicit failure rather than as
    `None in text`.
    """
    match = re.search(r'<section class="form-errors">(.*?)</section>', response.text, re.DOTALL)
    if match is None:
        return None
    items = re.findall(r"<li>(.*?)</li>", match.group(1), re.DOTALL)
    return " ".join(item.strip() for item in items)


# ----------------------------------------------------------------------------------- the byte-for-byte assertion


def test_the_data_dir_is_byte_for_byte_unchanged_by_a_generation(
    session_client: ScratchClient, data_root: Path
) -> None:
    """The headline claim of page-map §2, measured as a tree hash rather than asserted as an intention.

    Taken after `GET /csr/generate` so the snapshot already includes what startup legitimately creates (`ca/`,
    `issued.db`): the assertion is then precisely "the generation itself wrote nothing", with no baseline noise to
    explain away.
    """
    csrf_token(session_client, "/csr/generate")
    before = snapshot_tree(data_root)
    assert before, "expected startup to have created the data tree"

    response = _post(session_client)
    assert response.status_code == 200

    after = snapshot_tree(data_root)
    assert after == before, {
        path: (before.get(path), after.get(path))
        for path in set(before) | set(after)
        if before.get(path) != after.get(path)
    }


def test_no_new_pem_or_key_file_appears_under_the_data_dir(session_client: ScratchClient, data_root: Path) -> None:
    """One mutation relative to the previous test: the assertion is on *names*, not hashes.

    The CA fixture legitimately owns `ca/ca_key.pem` and `ca/ca_cert.pem`, so this is deliberately a comparison against
    what already existed rather than "no such file anywhere": what must not appear is a **generated** key or
    request file.
    Naming the extensions catches an artifact stashed under a filename the hash test would have to get lucky to notice,
    and it states the rule as a class of thing rather than as one unlucky path.
    """
    suffixes = {".pem", ".key", ".crt", ".csr", ".p12"}
    before = {path for path in data_root.rglob("*") if path.suffix.lower() in suffixes}

    _post(session_client)

    new_files = [path for path in data_root.rglob("*") if path.suffix.lower() in suffixes and path not in before]
    assert new_files == [], new_files


def test_a_second_generation_changes_nothing_either(session_client: ScratchClient, data_root: Path) -> None:
    """The invariant is not "the first POST happens to be clean".

    Two generations, two different key types. Anything that accumulated per generation -- a queue flushed to disk, an
    artifact cache spilled to a temp file, a log written inside the data dir -- shows up on the second pass and not the
    first.
    """
    csrf_token(session_client, "/csr/generate")
    before = snapshot_tree(data_root)

    assert _post(session_client).status_code == 200
    assert _post(session_client, common_name="other.internal", key_type="ec-p256").status_code == 200

    assert snapshot_tree(data_root) == before


def test_the_issued_table_is_untouched_by_a_generation(session_client: ScratchClient, data_root: Path) -> None:
    """The DB half of the promise, read through the store rather than inferred from a file hash.

    `/csr/generate` must not create an "issued" row for something that was only generated: page-map §5's list is what
    this CA *signed*, and a generated-but-unsigned request appearing there would make the list lie.
    """
    _post(session_client)

    from mypki import paths
    from mypki.store import IssuedStore

    store = IssuedStore(paths.db_path(data_root))
    assert store.count() == 0
    assert store.list_records() == []


# -------------------------------------------------------------------------------------- what the page shows once


def test_exactly_one_csr_block_and_one_key_block_are_rendered(session_client: ScratchClient) -> None:
    """Counts, not presence (STYLE §9).

    `if "BEGIN CERTIFICATE REQUEST" in body` is true for a page that rendered the CSR twice, or that rendered a private
    key and called it a request. Counting armour markers is what answers the real question: one of each, once.
    """
    response = _post(session_client)

    assert pem_block_count(response.text, "-----BEGIN CERTIFICATE REQUEST-----") == 1
    assert pem_block_count(response.text, "-----BEGIN PRIVATE KEY-----") == 1
    assert pem_block_count(response.text, "-----END CERTIFICATE REQUEST-----") == 1
    assert pem_block_count(response.text, "-----END PRIVATE KEY-----") == 1


def test_the_generated_csr_is_a_valid_request_for_the_key_it_ships_with(session_client: ScratchClient) -> None:
    """The two blocks on the page belong to each other.

    A page that showed a CSR signed by key A and printed key B would pass every "is this PEM" check and fail the moment
    someone used it. Loading both and asking cryptography whether the request's public key equals the private key's is
    the only way to assert the pairing rather than the shapes.
    """
    response = _post(session_client)
    csr_pem = _block(response.text, "CERTIFICATE REQUEST")
    key_pem = _block(response.text, "PRIVATE KEY")

    request = x509.load_pem_x509_csr(csr_pem.encode("ascii"))
    private_key = load_pem_private_key(key_pem.encode("ascii"), password=None)

    assert request.is_signature_valid is True
    left = request.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    right = private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    assert left == right


def test_the_san_set_reaches_the_request_verbatim(session_client: ScratchClient) -> None:
    """DNS names and the bare address become DNS + IP general names, in the order typed.

    `10.0.0.7` is typed as a bare address (page-map §9) and must arrive as an `IPAddress`, not as a `DNSName` a client
    will never match against a socket. The wildcard keeps its leftmost position.
    """
    response = _post(session_client)
    request = x509.load_pem_x509_csr(_block(response.text, "CERTIFICATE REQUEST").encode("ascii"))

    names = list(request.extensions.get_extension_for_class(x509.SubjectAlternativeName).value)
    dns = [name.value for name in names if isinstance(name, x509.DNSName)]
    ips = [str(name.value) for name in names if isinstance(name, x509.IPAddress)]

    assert dns == ["server.internal", "*.lab.internal"]
    assert ips == ["10.0.0.7"]


def test_an_encrypted_key_is_returned_as_pkcs8_armour(session_client: ScratchClient) -> None:
    """With a passphrase the armour changes, and the passphrase is not echoed back.

    Three assertions in one mutation (a passphrase pair added to the form): the header says `ENCRYPTED PRIVATE KEY`
    (page-map §2 -- the format an operator can actually hand to a service), the plaintext header is gone, and neither
    `passphrase` nor its value appears anywhere in the rendered HTML.
    """
    passphrase = "a-passphrase-not-a-real-one"
    response = _post(session_client, passphrase=passphrase, confirm=passphrase)

    assert pem_block_count(response.text, "-----BEGIN ENCRYPTED PRIVATE KEY-----") == 1
    assert pem_block_count(response.text, "-----BEGIN PRIVATE KEY-----") == 0
    assert "encrypted (PKCS#8)" in response.text
    assert passphrase not in response.text
    assert 'name="passphrase" value=' not in response.text


def test_mismatched_passphrases_are_refused_naming_the_field_not_the_value(session_client: ScratchClient) -> None:
    """One mutation: `confirm` differs. The refusal must name `confirm`, never either string.

    This message is rendered straight into HTML, and a passphrase echoed into an error page is a passphrase in a browser
    history, a proxy log and a screenshot someone posts.

    0.2.0 changed *where* that sentence appears, not what it says: a mistyped pair is a field the operator can fix, so
    the form comes back at HTTP 200 with the reason in the `.form-errors` block and the eight non-secret values still
    filled in (app.py `ERROR_SURFACE_RULE`). Asserting 400 here would be asserting that the app throws away what was
    typed.
    """
    response = _post(session_client, passphrase="a-passphrase-not-a-real-one", confirm="another-value-not-a-one")

    assert response.status_code == 200
    assert _form_error(response) is not None
    assert "confirm" in _form_error(response)
    for secret in ("a-passphrase-not-a-real-one", "another-value-not-a-one"):
        assert secret not in response.text
    # The pair is re-rendered empty, and the rest of the form survives the rejection.
    assert 'name="passphrase" value=' not in response.text
    assert 'name="confirm" value=' not in response.text
    assert 'value="server.internal"' in response.text
    # Nothing was generated, which is the other half of a rejected form (page-map §2's ordering).
    assert "-----BEGIN" not in response.text


def test_a_short_passphrase_is_refused_naming_the_floor_and_the_better_value(session_client: ScratchClient) -> None:
    """One mutation: the passphrase is 5 characters, under the floor of `PASSPHRASE_MIN_LENGTH`.

    The floor exists because PKCS#8 encryption is only as strong as the passphrase, and the refusal has to say both
    numbers — the minimum it enforces and the value it recommends. "Too short" alone reads like a form-validation quirk;
    "at least 8 … 12 or more is better" is the security rule an operator can act on.

    The value 5 is chosen deliberately rather than 11: 11 is now *accepted* (with an advisory), and a test that used it
    as the refusing case would silently become a test of the wrong branch.
    """
    response = _post(session_client, passphrase="short", confirm="short")

    assert response.status_code == 200
    reason = _form_error(response)
    assert reason is not None
    assert str(PASSPHRASE_MIN_LENGTH) in reason
    assert "12 or more is better" in reason
    # Refused means refused: no keypair, no PEM on the page.
    assert "-----BEGIN" not in response.text


def test_a_passphrase_at_the_floor_is_accepted_and_advised(session_client: ScratchClient) -> None:
    """8 characters generates a key **and** draws the 12-or-more advisory (csr.passphrase_advisory).

    Two facts have to hold at once and they pull in opposite directions, which is why they are one test: the floor is
    what mypki *enforces*, and the recommendation is what it *says* — a page that refused 8 would be enforcing two
    rules, and a page that accepted 8 silently would be enforcing a rule it advertises as advisory.

    The exact length appears in the advisory because the operator typed it into a form they are looking at; the value
    itself never does (asserted separately, because that is the half that keeps an advisory from becoming a leak).
    """
    passphrase = "12345678"  # exactly PASSPHRASE_MIN_LENGTH characters, not "about eight"
    assert len(passphrase) == PASSPHRASE_MIN_LENGTH

    response = _post(session_client, passphrase=passphrase, confirm=passphrase)

    assert response.status_code == 200
    assert pem_block_count(response.text, "-----BEGIN ENCRYPTED PRIVATE KEY-----") == 1
    assert f"{PASSPHRASE_MIN_LENGTH}-character passphrase is accepted" in response.text
    assert str(PASSPHRASE_RECOMMENDED_LENGTH) in response.text
    assert passphrase not in response.text


def test_a_passphrase_at_the_recommended_length_is_accepted_without_an_advisory(session_client: ScratchClient) -> None:
    """12 characters generates a key and says nothing about length.

    The advisory's absence is the assertion: an always-on warning trains an operator to ignore warnings, and
    `passphrase_advisory` returns None at or above the recommended length rather than hedging.
    """
    passphrase = "twelve-char-passphrase"
    assert len(passphrase) >= PASSPHRASE_RECOMMENDED_LENGTH

    response = _post(session_client, passphrase=passphrase, confirm=passphrase)

    assert response.status_code == 200
    assert pem_block_count(response.text, "-----BEGIN ENCRYPTED PRIVATE KEY-----") == 1
    assert "is accepted, but" not in response.text
    assert passphrase not in response.text


# -------------------------------------------------------------------------------------- rejected forms


@pytest.mark.parametrize(
    ("field", "value", "marker"),
    [
        ("common_name", "", "common_name is required"),
        ("common_name", "server..internal", "empty label"),
        ("common_name", "api.inte\nrnal", "control characters"),
        ("sans", "bad-.internal", "begins or ends with a hyphen"),
        ("sans", "*.10.0.0.1", "cannot wildcard an IP address"),
        ("key_type", "rsa-1024", "not a known key type"),
        ("country", "DEU", "exactly two letters"),
        ("email", "no-at-sign.internal", "exactly one @"),
    ],
)
def test_a_rejected_form_shows_its_specific_reason(
    session_client: ScratchClient, field: str, value: str, marker: str
) -> None:
    """Eight single-field mutations, eight specific reasons (page-map §0).

    Never "invalid CSR": each one names the field and what is wrong with it. The parametrised shape is deliberate -- the
    same code path with one input changed proves the check on that input, and a shared assertion proves none of them
    collapsed into a generic message.

    0.2.0 moved these eight from `error.html` at HTTP 400 to the form itself at HTTP 200 (app.py `ERROR_SURFACE_RULE`).
    Three things are asserted per case, because the move is only a benefit if all three hold:
      * the reason still names the specific problem (`marker`);
      * the value the operator typed is back in its own field — except where re-rendering it would be wrong;
      * nothing was generated: no armour on the page.
    """
    response = _post(session_client, **{field: value})

    assert response.status_code == 200
    reason = _form_error(response)
    assert reason is not None, f"no .form-errors block in the {response.status_code} body"
    assert marker in reason, f"{marker!r} missing from the inline reason {reason!r}"

    # The typed value survives, so an operator fixes one field instead of re-typing six. `key_type` is a <select>, whose
    # rejected value cannot be "preserved" as text; its own assertion is that the *other* fields came back. An empty
    # value
    # has nothing to preserve (and `"" in text` is vacuously true), so that case asserts only the reason.
    #
    # MEASURED, Jinja 3.1.6 with autoescape on: escaping covers `& < > ' "` and leaves a line break verbatim, which is
    # why
    # the control-character case round-trips as literal text rather than as `&#10;`. Asserting the entity spelling would
    # fail against correct rendering.
    if field != "key_type" and value:
        assert value in response.text, f"the submitted {field} was not re-rendered"
    assert 'value="mypki tests"' in response.text, "an unrelated field was dropped from the re-rendered form"

    # A passphrase is never re-rendered, on any path (page-map §0).
    assert 'name="passphrase" value=' not in response.text
    assert "-----BEGIN" not in response.text


def test_a_rejected_form_generates_nothing(session_client: ScratchClient, data_root: Path) -> None:
    """A refused form renders no PEM and spends no keypair (page-map §2's ordering).

    `validate_generate_fields` runs before `generate_key`, so a malformed submission cannot be used to make this host
    burn CPU generating keys nobody asked for -- which on an unauthenticated page is a cheap way to keep one busy. The
    observable half is asserted here: no armour on the page, nothing on disk.
    """
    csrf_token(session_client, "/csr/generate")
    before = snapshot_tree(data_root)

    response = _post(session_client, common_name="")

    # 200 rather than 400 in 0.2.0: the reason is on the form, and the form is still fixable. The *nothing generated*
    # half is unchanged, and that is what this test has always been about.
    assert response.status_code == 200
    assert "-----BEGIN" not in response.text
    assert snapshot_tree(data_root) == before


def test_the_form_is_repopulated_without_the_passphrase(session_client: ScratchClient) -> None:
    """On a successful submit the typed fields come back; the secret does not.

    `values=_without_secrets(form)` is the whole mechanism (app.py): losing eight fields because one was wrong is how
    people stop using a tool, while a passphrase re-rendered into a form ends up in a browser's autofill store and in
    whatever cached the page. Asserted on an **accepted** submission here;
    `test_a_rejected_form_shows_its_specific_reason` above asserts the same helper on the rejected path, which since
    0.2.0 is the same template rather than `error.html`.
    """
    passphrase = "a-passphrase-not-a-real-one"
    response = _post(session_client, organization="Acme Widgets", passphrase=passphrase, confirm=passphrase)

    assert response.status_code == 200
    assert 'value="Acme Widgets"' in response.text
    assert 'value="server.internal"' in response.text
    assert passphrase not in response.text
    assert 'name="passphrase" value=' not in response.text


def test_downloads_are_links_into_process_memory_not_files(session_client: ScratchClient) -> None:
    """The two download hrefs are `/download/<opaque id>` (page-map §10).

    Asserted as a shape rather than as ids, because the id is random by design -- a predictable one would let one
    session
    guess another's download link. What must hold is that the link is not a file path and not a static asset.
    """
    response = _post(session_client)

    links = re.findall(r'href="(/download/[^"]+)"', response.text)
    assert len(links) == 2, links
    assert all(link.count("/") == 2 for link in links), links
    assert not any(link.endswith((".pem", ".key")) for link in links), links


def test_both_downloads_serve_the_body_that_was_shown(session_client: ScratchClient) -> None:
    """The `<pre>` and the attachment are the same bytes.

    Two artifacts, one generation: if the download rendered a re-generated CSR (rather than the one on screen) the
    operator would install a key that does not match the request they copied, and nothing on the page would say so.
    """
    response = _post(session_client)
    shown_csr = _block(response.text, "CERTIFICATE REQUEST")
    shown_key = _block(response.text, "PRIVATE KEY")

    links = re.findall(r'href="(/download/[^"]+)"', response.text)
    bodies = [session_client.get(link) for link in links]
    assert all(body.status_code == 200 for body in bodies)

    csr_body = next(body.text for body in bodies if "CERTIFICATE REQUEST" in body.text)
    key_body = next(body.text for body in bodies if "PRIVATE KEY" in body.text)
    assert _block(csr_body, "CERTIFICATE REQUEST") == shown_csr
    assert _block(key_body, "PRIVATE KEY") == shown_key


def test_two_generations_behind_similar_links_are_different_keys(session_client: ScratchClient) -> None:
    """The page's warning -- "a reload generates a different key" -- is true, and the links prove it.

    Two submissions of the same form. Both links still resolve (expiry is a TTL and a capacity, not a session swap), so
    what has to hold is that they do **not** serve the same bytes: if the second generation re-served the first key, an
    operator who copied the CSR from one page and downloaded the key from another would install a mismatched pair.
    """

    def csr_of(link: str) -> str:
        body = session_client.get(link)
        assert body.status_code == 200
        return _block(body.text, "CERTIFICATE REQUEST")

    first = _post(session_client)
    second = _post(session_client)
    first_link = re.findall(r'href="(/download/[^"]+)"', first.text)[0]
    second_link = re.findall(r'href="(/download/[^"]+)"', second.text)[0]

    assert first_link != second_link
    assert csr_of(first_link) != csr_of(second_link)


def test_an_unknown_download_id_is_a_named_404(session_client: ScratchClient) -> None:
    """A link from an expired artifact or a restarted server says so (page-map §10).

    404 with mypki's own page rather than a redirect back to the form: re-running generation behind a stale bookmark
    would mint a different key and look like success. `OneShotStore`'s TTL and capacity behaviour is pinned in
    `test_views.py`; this is the route-level half.
    """
    response = session_client.get("/download/not-an-artifact-id-anyone-issued")

    assert response.status_code == 404
    assert "no longer available" in response.text


def test_the_page_carries_the_version_from_init_py_without_hard_coding_it(session_client: ScratchClient) -> None:
    """The footer prints `mypki <version>` straight from `__init__.py`, the single source hatchling also reads.

    Asserted as the whole rendered string rather than as a bare number, so a template that hard-coded an old release --
    or printed nothing -- fails here. Nothing in this file states what the version *is* (STYLE §1).
    """
    response = session_client.get("/csr/generate")

    assert f"mypki {__version__}" in response.text


# ------------------------------------------------------------------------------------------------- helpers


def _block(text: str, kind: str) -> str:
    """Extract one PEM armour block from a rendered page.

    Reads the *rendered* body rather than re-generating anything: the point of these tests is what the operator
    sees, and
    HTML escaping is exactly the kind of thing that silently corrupts a PEM an operator copies out of a browser.
    """
    pattern = rf"-----BEGIN {kind}-----(.*?)-----END {kind}-----"
    match = re.search(pattern, text, re.DOTALL)
    if match is None:
        raise AssertionError(f"no -----BEGIN {kind}----- block in the rendered page")
    return f"-----BEGIN {kind}-----{match.group(1)}-----END {kind}-----"
