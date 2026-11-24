"""Bulk revoke on `/issued`: the confirmation step, the three-way batch report, and where a 404 still belongs.

0.3.0 turned "revoke this one row" into "tick N rows and press Revoke Selected". Three things had to be true at the same
time, and each is a separate test below:

1. **The confirmation step changes nothing.** A POST without `confirm=1` comes back naming every certificate about to be
   stamped — serial *and* common name — and stamps none of them. "Are you sure?" that already did it is not a
   confirmation.
2. **A batch reports its three outcomes separately.** `store.revoke()` answers None for a serial this host never signed
   and returns the untouched record for one already stamped, so a batch can legitimately mix all three. Reporting
   one number would hide the case an operator most needs told about: a stale tab selecting a certificate somebody else
   already revoked.
3. **A miss does not 404 the batch, but a single unknown serial still does.** `app.issued_revoke` keeps 0.2.0's measured
   contract (a hand-pasted serial from another machine's CA is one certificate, and answering it with a 200 batch card
   would say "nothing was changed" in the same shape as "the submit worked") while letting a batch of two or more carry
   on to the report, because 404-ing N-1 decisions the operator did mean to make is the larger error.

Records are seeded straight into `IssuedStore` rather than issued through the two-step signing flow. That is deliberate:
every assertion here is about serials, rows and counts, and signing a real certificate for each one would add an
keypair per test (~0.15 s) while asserting nothing about this feature. The issuing path has its own tests
(`test_views.py`, `test_csr_sign.py`), and the revoke round trip through real records is asserted there too.

MEASURED on this build (fastapi 0.162 / starlette 1.10): a repeated form key reaches `_form_fields_multi` as several
values via `FormData.getlist`, which is why `/issued/revoke` takes a bulk-shaped dependency at all —
`FormData.items()` yields only the *last* value of a repeated key, so three ticked boxes would silently collapse to one.
"""

from __future__ import annotations

import datetime as dt
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from conftest import ScratchClient, csrf_token
from mypki import paths
from mypki.app import create_app
from mypki.config import Settings
from mypki.store import IssuedStore

#: Three serials this host signed, plus one it never did. Fixed rather than random so every assertion can name the
#: certificate it means: a revoke is addressed by its serial number, and a test that generated them would have to read
#: them back out of the page before it could ask a question about one.
SERIAL_ONE = "a1b2c3d4e5f60708"
SERIAL_TWO = "0f0f0f0f0f0f1e2d"
SERIAL_THREE = "11aa11aa11aa11bb"
UNKNOWN_SERIAL = "deadbeefcafebabf"

NAMES = {SERIAL_ONE: "one.internal", SERIAL_TWO: "two.internal", SERIAL_THREE: "three.internal"}


def _seed(store: IssuedStore, serial_hex: str, *, reason: str | None = None) -> None:
    """One issued record, optionally already stamped.

    `revoked_at_utc` is set through `store.revoke()` rather than by writing the column directly: the stamp has to arrive
    the way a previous submit would have made it, including the reason-capping and the no-op behaviour the tests below
    depend on.
    """
    now = dt.datetime.now(dt.timezone.utc)
    store.add_record(
        serial_hex=serial_hex,
        cert_type="server",
        common_name=NAMES[serial_hex],
        sans=(NAMES[serial_hex],),
        not_before_utc=now,
        not_after_utc=now + dt.timedelta(days=30),
        fingerprint_sha256="aa" * 32,
    )
    if reason is not None:
        store.revoke(serial_hex=serial_hex, reason=reason)


@pytest.fixture
def bulk_store(data_root: Path) -> IssuedStore:
    """A ledger holding all three records, none of them revoked.

    Written before the app is built (and therefore before `create_app` runs `init_schema`) so the fixture and the app
    looking at the same database file rather than two stores that happen to share a path.
    """
    store = IssuedStore(paths.db_path(data_root))
    for serial in (SERIAL_ONE, SERIAL_TWO, SERIAL_THREE):
        _seed(store, serial)
    return store


@pytest.fixture
def bulk_client(settings: Settings, bulk_store: IssuedStore) -> TestClient:
    """A cookie-persisting client over the seeded ledger.

    No CA: `/issued` renders its no-CA notice and every row still renders, and nothing in a revoke reads key material
    (`store.revoke` addresses a row by its serial). A cookie-persisting client is required rather than optional — the
    token read off `/issued` has to be in the same session as the POST that submits it, or every test here would be
    asserting "no token in this session" instead of the batch.
    """
    app = create_app(settings, session_secret="test-session-secret-not-a-real-one")
    with ScratchClient(app, persist_cookies=True) as client:
        yield client


def _revoke(client: TestClient, serials: list[str], *, confirm: bool = False, reason: str | None = None):
    """POST `/issued/revoke` carrying `serial_hex` once per ticked row, with `/issued`'s own token."""
    data: dict[str, object] = {"csrf_token": csrf_token(client, "/issued"), "serial_hex": serials}
    if confirm:
        data["confirm"] = "1"
    if reason is not None:
        data["reason"] = reason
    return client.post("/issued/revoke", data=data)  # type: ignore[arg-type]


def _count_line(response) -> tuple[int, int, int]:
    """`(stamped now, already revoked before, no record)` as the batch card states them.

    Read structurally rather than by searching for a bare number: "1 stamped now," and "1 with no record" are three
    sentences on one line, and a test that looked for `text.count("1")` would pass on a card that reported the same
    serial twice. Absence raises, because a batch that rendered no card is the bug rather than a detail of it.
    """
    match = re.search(
        r"(\d+) stamped now,\s*(\d+) already revoked before this submit,\s*(\d+) with no record on this host",
        response.text,
    )
    if match is None:
        raise AssertionError(f"no batch card in the {response.status_code} body:\n{response.text[:600]}")
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


# --------------------------------------------------------------------------------- the confirmation step stamps nothing


def test_the_issued_page_carries_a_checkbox_per_unrevoked_row_and_one_bulk_form(bulk_client: TestClient) -> None:
    """What "multi-select" means in markup, asserted before anything is submitted.

    Every unrevoked row carries a `serial_hex` checkbox whose value is the serial rather than a row position (so a
    always names a certificate), there is one form to submit, and the Select column has the All box. The token has to be
    inside that form: with the old per-row forms it was rendered once per row, and a page whose only control is one bulk
    bar would otherwise carry no readable token at all.
    """
    listing = bulk_client.get("/issued")

    assert listing.status_code == 200
    for serial in (SERIAL_ONE, SERIAL_TWO, SERIAL_THREE):
        assert f'<input type="checkbox" name="serial_hex" value="{serial}"' in listing.text
    assert '<form method="post" action="/issued/revoke" class="bulk-revoke">' in listing.text
    assert "data-mypki-select-all" in listing.text
    assert "Revoke Selected" in listing.text
    assert 'name="csrf_token" value="' in listing.text


def test_an_unconfirmed_bulk_submit_names_every_certificate_and_stamps_none(
    bulk_client: TestClient, bulk_store: IssuedStore, data_root: Path
) -> None:
    """The whole point of the confirmation step: a submit that only *asked* changed nothing.

    Asserted on both halves — the page says what is about to happen to each certificate, and the database says nothing
    happened. A confirmation block that stamped first would still pass the first half.
    """
    response = _revoke(bulk_client, [SERIAL_ONE, SERIAL_TWO, SERIAL_THREE], reason="lab exercise")

    assert response.status_code == 200
    assert '<section class="confirm-revoke">' in response.text
    assert "Revoke 3 certificates?" in response.text
    # Serial *and* name: a confirmation that lists only hex strings asks the operator to compare two things they cannot
    # read against each other.
    for serial in (SERIAL_ONE, SERIAL_TWO, SERIAL_THREE):
        assert serial in response.text
        assert NAMES[serial] in response.text
        assert '<span class="status-ok">active now</span>' in response.text
    assert "Revoking a record cannot be undone from this page" in response.text
    assert "Nothing has been changed yet." in response.text

    assert bulk_store.count_revoked() == 0
    assert 'class="pill revoked"' not in response.text

    # A plain GET afterwards, because that is what an operator does next: refresh. Counted on `name="serial_hex"` rather
    # than on `type="checkbox"`, since the Select column's All box is a checkbox too and counting it would make this
    # assertion about the table's rows impossible to read.
    after = bulk_client.get("/issued")
    for serial in (SERIAL_ONE, SERIAL_TWO, SERIAL_THREE):
        assert f'<input type="checkbox" name="serial_hex" value="{serial}"' in after.text
    assert after.text.count('name="serial_hex"') == 3


def test_the_confirmation_page_carries_every_serial_forward_as_hidden_fields(bulk_client: TestClient) -> None:
    """The confirm POST has to carry the same N serials, or "confirm" would mean a different batch than the one shown.

    Asserted by counting hidden inputs and checking each value, because a template that carried only the first would
    render a confirmation naming three certificates and then revoke one.
    """
    response = _revoke(bulk_client, [SERIAL_ONE, SERIAL_TWO])

    for serial in (SERIAL_ONE, SERIAL_TWO):
        assert f'<input type="hidden" name="serial_hex" value="{serial}">' in response.text
    assert '<input type="hidden" name="confirm" value="1">' in response.text


# ------------------------------------------------------------------------------------------------ a confirmed batch


def test_a_confirmed_bulk_submit_stamps_every_selected_record(bulk_client: TestClient, bulk_store: IssuedStore) -> None:
    """`confirm=1` is the moment the decision is made; N ticked rows become N stamped records.

    Asserted in the page *and* in the store, because the page is what an operator reads and the store is what a future
    CRL will be built from.
    """
    response = _revoke(bulk_client, [SERIAL_ONE, SERIAL_TWO], confirm=True, reason="retired host")

    assert response.status_code == 200
    assert "<h2>Revocation batch</h2>" in response.text
    assert _count_line(response) == (2, 0, 0)
    for serial in (SERIAL_ONE, SERIAL_TWO):
        assert f"{NAMES[serial]} is marked revoked as of" in response.text
        assert "reason: retired host" in response.text

    assert bulk_store.count_revoked() == 2
    for serial in (SERIAL_ONE, SERIAL_TWO):
        record = bulk_store.find(serial)
        assert record is not None
        assert record.status == "revoked"
        assert record.revocation_reason == "retired host"
        assert record.revoked_at_utc is not None
    # A certificate nobody ticked is untouched.
    untouched = bulk_store.find(SERIAL_THREE)
    assert untouched is not None and untouched.status == "active"


def test_a_stamped_row_offers_no_checkbox_and_the_reason_shows_in_its_status_cell(
    bulk_client: TestClient, bulk_store: IssuedStore
) -> None:
    """There is no un-revoke and no delete, so a checkbox on a stamped row would promise one of the two.

    The reason is asserted where an operator reads it — under the Status pill and again in the Revoked column —
    decision recorded without its stated reason is not evidence of anything.
    """
    _revoke(bulk_client, [SERIAL_ONE], confirm=True, reason="wrong SANs")

    listing = bulk_client.get("/issued")

    assert f'<input type="checkbox" name="serial_hex" value="{SERIAL_ONE}"' not in listing.text
    assert f'<input type="checkbox" name="serial_hex" value="{SERIAL_TWO}"' in listing.text
    assert '<span class="pill revoked">revoked</span>' in listing.text
    assert "wrong SANs" in listing.text
    # The stamp date is NOT in the Status cell any more: it has its own last column; an unrevoked row shows a dash.
    assert not re.search(r'<span class="hint">\d{4}-\d{2}-\d{2}', listing.text)
    headers = re.findall(r'<th scope="col">(.*?)</th>', listing.text, re.DOTALL)
    assert headers[-1] == "Revoked (UTC)", headers
    revoked_cells = re.findall(r'<td class="revoked-at">(.*?)</td>', listing.text, re.DOTALL)
    stamped = [c for c in revoked_cells if re.fullmatch(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", c)]
    assert len(stamped) == 1, revoked_cells
    assert revoked_cells.count("&mdash;") == len(revoked_cells) - 1, revoked_cells


# --------------------------------------------------------------------------- a batch that mixes all three outcomes


def test_a_mixed_batch_reports_stamped_already_revoked_and_missing_separately(
    bulk_client: TestClient, bulk_store: IssuedStore
) -> None:
    """One submit, three answers, each naming its own serial.

    `SERIAL_ONE` is stamped by this submit, `SERIAL_TWO` was already revoked (its stamp and reason must not move), and
    `UNKNOWN_SERIAL` is not a record on this host at all. Reported as "3 revoked" the batch would read like three
    successes, which is precisely the lie the stale browser tab tells.
    """
    bulk_store.revoke(serial_hex=SERIAL_TWO, reason="revoked by another tab")

    response = _revoke(bulk_client, [SERIAL_ONE, SERIAL_TWO, UNKNOWN_SERIAL], confirm=True, reason="lab exercise")

    assert response.status_code == 200
    assert _count_line(response) == (1, 1, 1)

    # Stamped now.
    assert f"{NAMES[SERIAL_ONE]} is marked revoked as of" in response.text
    assert '<span class="status-ok">stamped now</span>' in response.text
    # Already revoked: named, with its original stamp and reason left alone.
    assert NAMES[SERIAL_TWO] in response.text
    assert "already revoked &mdash; its stamp and reason were left alone" in response.text
    assert "revoked by another tab" in response.text
    # No record: named as a serial, with what did *not* happen stated.
    assert UNKNOWN_SERIAL in response.text
    assert "no record with that serial in this host's database &mdash; nothing was changed" in response.text

    assert bulk_store.count_revoked() == 2
    already = bulk_store.find(SERIAL_TWO)
    assert already is not None and already.revocation_reason == "revoked by another tab"


def test_an_already_stamped_record_keeps_its_original_stamp_and_reason(
    bulk_client: TestClient, bulk_store: IssuedStore
) -> None:
    """`revoked_at_utc` is a fact about when the decision was made, so a double-click must not move it to "now".

    Asserted by comparing the two stamps rather than by asserting "it is still revoked": the failure this catches is the
    subtle one, where re-revoking silently rewrites history and an audit of *when* a certificate was revoked becomes
    unanswerable.
    """
    before = bulk_store.find(SERIAL_ONE)
    assert before is not None and before.revoked_at_utc is None

    bulk_store.revoke(serial_hex=SERIAL_ONE, reason="first decision")
    first = bulk_store.find(SERIAL_ONE)
    assert first is not None and first.revoked_at_utc is not None

    _revoke(bulk_client, [SERIAL_ONE], confirm=True, reason="second attempt")

    after = bulk_store.find(SERIAL_ONE)
    assert after is not None
    assert after.revoked_at_utc == first.revoked_at_utc
    assert after.revocation_reason == "first decision"


def test_the_confirmation_page_says_what_it_knows_about_each_serial(
    bulk_client: TestClient, bulk_store: IssuedStore
) -> None:
    """A serial with no record is named as such *before* the stamp rather than reported after it.

    This is where an operator finds out that a ticked row belongs to another tab or another CA. Dropping unknown serials
    from the confirmation list would make the confirm POST silently different from the selection the operator made.
    """
    bulk_store.revoke(serial_hex=SERIAL_TWO, reason="already gone")

    response = _revoke(bulk_client, [SERIAL_ONE, SERIAL_TWO, UNKNOWN_SERIAL])

    assert "Revoke 3 certificates?" in response.text
    assert "not a record on this host &mdash; it will be reported, not revoked" in response.text
    assert "already revoked &mdash; its stamp and reason will not change" in response.text
    assert UNKNOWN_SERIAL in response.text


# ------------------------------------------------------------------------------------- 404 for one, report for a batch


def test_a_single_unknown_serial_still_answers_404_naming_the_database(
    bulk_client: TestClient, bulk_store: IssuedStore, data_root: Path
) -> None:
    """0.2.0's measured contract, kept deliberately (app.issued_revoke).

    A hand-pasted serial from another machine's CA is one certificate rather than a batch, and answering it with a 200
    batch card reading "0 stamped now, 0 already revoked, 1 with no record" is the same shape as a successful submit.
    The 404 also names the database file, because an operator who pasted a serial needs to know *which* store this
    is reading.
    """
    response = _revoke(bulk_client, [UNKNOWN_SERIAL])

    assert response.status_code == 404
    assert UNKNOWN_SERIAL in response.text
    assert str(paths.db_path(data_root)) in response.text
    assert "only revoke certificates this host signed" in response.text

    # And the real records are untouched by a request about something that is not one of them.
    assert bulk_store.count_revoked() == 0


def test_one_miss_in_a_multi_serial_batch_does_not_404_the_batch(
    bulk_client: TestClient, bulk_store: IssuedStore
) -> None:
    """The other half of the same rule: 404-ing N-1 decisions the operator did mean to make is the larger error.

    Asserted as a pair with the test above rather than as two unrelated status codes, because the interesting thing
    this handler is *where it draws the line* — one unknown serial is missing state, an unknown serial inside a batch of
    three is one row of a report.
    """
    response = _revoke(bulk_client, [SERIAL_ONE, UNKNOWN_SERIAL], confirm=True)

    assert response.status_code == 200
    assert _count_line(response) == (1, 0, 1)
    assert bulk_store.count_revoked() == 1
    assert bulk_store.find(SERIAL_ONE) is not None and bulk_store.find(SERIAL_ONE).status == "revoked"


def test_a_multi_serial_batch_of_only_unknown_serials_reports_rather_than_404s(
    bulk_client: TestClient, bulk_store: IssuedStore
) -> None:
    """The boundary case the rule has to survive: a batch where *nothing* was found is still a batch.

    Stated because it is the version an operator hits after a restore onto an older database — every serial on the page
    predates it. A 404 would name one of them and leave the operator to guess about the rest.
    """
    response = _revoke(bulk_client, [UNKNOWN_SERIAL, "ffffffffffffffff"], confirm=True)

    assert response.status_code == 200
    assert _count_line(response) == (0, 0, 2)
    assert bulk_store.count_revoked() == 0


# ------------------------------------------------------------------------------------------- malformed selections


def test_a_blank_selection_is_400_naming_the_field(bulk_client: TestClient, bulk_store: IssuedStore) -> None:
    """Pressing Revoke Selected with nothing ticked is a form that arrived without its subjects.

    Answered 400 rather than by re-rendering `/issued` with a note, because "nothing was ticked" and "this host cannot
    find the list" must not look alike (page-map §0).
    """
    response = _revoke(bulk_client, [])

    assert response.status_code == 400
    assert "serial_hex is required" in response.text
    assert bulk_store.count_revoked() == 0


def test_a_selection_of_only_whitespace_is_400(bulk_client: TestClient, bulk_store: IssuedStore) -> None:
    """The same answer for the version that arrives as a value rather than as an absent field."""
    response = _revoke(bulk_client, ["   ", ""])

    assert response.status_code == 400
    assert "serial_hex is required" in response.text
    assert bulk_store.count_revoked() == 0


def test_duplicate_checkboxes_collapse_to_one_revocation(bulk_client: TestClient, bulk_store: IssuedStore) -> None:
    """Select-all plus a hand-ticked row must not count as two revocations of one certificate.

    Also the case where a *batch* silently becomes a single serial: with duplicates collapsed, two checkboxes for one
    row are one serial, and app.py's single-unknown rule then applies to it. Asserted here so that interaction is on
    the record rather than discovered by someone changing either rule.
    """
    response = _revoke(bulk_client, [SERIAL_ONE, SERIAL_ONE], confirm=True)

    assert response.status_code == 200
    assert _count_line(response) == (1, 0, 0)
    assert bulk_store.count_revoked() == 1


def test_serials_are_stripped_and_lowercased_before_being_matched(
    bulk_client: TestClient, bulk_store: IssuedStore
) -> None:
    """`store.revoke` addresses rows by the lowercase hex it wrote, so a pasted uppercase serial is still one row.

    Asserted with an uppercase value because the failure mode is silent in the other direction: an unmatched serial that
    *looks* right would be reported as "no record on this host", sending the operator to check a certificate that is
    plainly on the page.
    """
    response = _revoke(bulk_client, [f"  {SERIAL_ONE.upper()}  "], confirm=True)

    assert response.status_code == 200
    assert _count_line(response) == (1, 0, 0)
    assert bulk_store.count_revoked() == 1


def test_the_batch_keeps_the_order_the_operator_selected_in(bulk_client: TestClient, bulk_store: IssuedStore) -> None:
    """Order preserved so the report names certificates in the order they were read.

    Asserted by position rather than presence: "names each serial" is satisfiable by any permutation, and the reason to
    preserve order is exactly that an operator reads a list top to bottom.
    """
    response = _revoke(bulk_client, [SERIAL_THREE, SERIAL_ONE], confirm=True)

    assert _count_line(response) == (2, 0, 0)
    assert response.text.index(SERIAL_THREE) < response.text.index(SERIAL_ONE)


# -------------------------------------------------------------------------------------- the honesty sentence, again


@pytest.mark.parametrize("path", ["unconfirmed", "confirmed"])
def test_every_batch_answer_says_what_a_stamp_does_not_accomplish(
    bulk_client: TestClient, bulk_store: IssuedStore, path: str
) -> None:
    """Both halves of the flow state what a stamp does *not* accomplish.

    The confirmation step and the batch card are different responses with the same risk: each shows the word "revoked"
    next to a certificate that some client may still accept. Without this sentence on both, mypki's own UI is what
    overstates the feature (page-map §5).

    0.7.0 rewrote this test rather than deleting it, and its fixture makes the honest half sharper than `test_views.py`
    can: **this host has no CA**, so it cannot sign a CRL at all. The batch card must therefore say so instead of
    implying that a stamp now reaches every client — which is exactly the sentence this test exists to force.
    """
    if path == "unconfirmed":
        response = _revoke(bulk_client, [SERIAL_ONE])
    else:
        response = _revoke(bulk_client, [SERIAL_ONE], confirm=True)

    assert "stays trusted by clients until it expires" in response.text
    if path == "confirmed":
        assert "no CA private key loaded" in response.text
        assert "nothing is published" in response.text


def test_a_revoke_with_the_wrong_token_stamps_nothing(bulk_client: TestClient, bulk_store: IssuedStore) -> None:
    """CSRF runs before any serial is read, on the one route that changes ledger state.

    Kept here rather than only in `test_views.py` because the promise is about the batch: a forged POST naming three
    serials must leave all three active.
    """
    response = bulk_client.post(
        "/issued/revoke",
        data={"csrf_token": "not-this-sessions-token", "serial_hex": [SERIAL_ONE, SERIAL_TWO]},
    )

    assert response.status_code == 400
    assert "CSRF" in response.text
    assert bulk_store.count_revoked() == 0
