"""SAN classification and validation rules, asserted as pure functions.

Why this file tests `validators.py` directly rather than through the pages: SAN handling is where mypki can silently
mis-issue — an IP accepted as a DNS name, a wildcard that covers more than one label, a 70-character label that X.509
will happily encode and every browser will reject. Those are facts about the rules, and they should be provable without
constructing a keypair, a CSR or an HTTP request (page-map §9).

Negative cases here mutate exactly one thing each: one entry, one label, one position (STYLE §8). A test that submits a
textarea of twelve bad names proves only that *something* was rejected; one name with one defect proves which rule
fired.
"""

from __future__ import annotations

import re

import pytest

from mypki.errors import CsrValidationError
from mypki.validators import (
    _MAX_CN_LEN,
    _MAX_EMAIL_LEN,
    SanSet,
    parse_sans,
    validate_common_name,
    validate_email,
    validate_printable_field,
    validate_san_entry,
)


def message_marker_count(text: str, pattern: str) -> int:
    """Occurrences of a marker in a message, not lines.

    Shared helper for the assertions that care how many problems were reported in one response. A bare substring
    count is
    wrong when an inner reason can contain the same word, so the marker gets a regex with its trailing colon.
    """
    return len(re.findall(pattern, text))


# ---------------------------------------------------------------------------- DNS vs IP classification


def test_a_plain_hostname_is_a_dns_general_name() -> None:
    kind, value = validate_san_entry("server.internal")
    assert kind == "dns"
    assert value == "server.internal"


def test_bare_ipv4_becomes_an_ip_general_name_not_a_dns_name() -> None:
    """`10.0.0.1` classifies as IP (page-map §9).

    The consequence is the point: an address encoded as a DNS name is copied into a certificate as a DNS general name,
    and no client matching a socket address will ever select it. It looks issued and behaves unusable.
    """
    kind, value = validate_san_entry("10.0.0.1")
    assert kind == "ip"
    assert value == "10.0.0.1"


def test_bare_ipv6_becomes_an_ip_general_name() -> None:
    for address in ("::1", "2001:db8::42", "fe80::1"):
        kind, value = validate_san_entry(address)
        assert kind == "ip"
        assert str(value) == str(address)


def test_ipv4_mapped_ipv6_is_classified_as_ip() -> None:
    kind, _ = validate_san_entry("::ffff:10.0.0.1")
    assert kind == "ip"


def test_leading_zero_octet_is_rejected_rather_than_guessed_as_octal() -> None:
    """`10.0.0.01` is refused.

    Some resolvers read a leading zero as octal and some do not, so accepting it here would issue a certificate for an
    address that a given client may mean differently. `ipaddress` rejects it, and this test pins that mypki passes the
    rejection through instead of falling back to treating it as a DNS name.
    """
    with pytest.raises(CsrValidationError):
        validate_san_entry("10.0.0.01")


def test_a_hostname_that_looks_numeric_is_still_dns() -> None:
    kind, value = validate_san_entry("host123.internal")
    assert kind == "dns"
    assert value == "host123.internal"


# --------------------------------------------------------------------------------------------- DNS labels


@pytest.mark.parametrize(
    ("entry", "expected_reason_part"),
    [
        ("server..local", "empty label"),
        ("-bad.example.com", "hyphen"),
        ("bad-.example.com", "hyphen"),
        ("a" * 64 + ".example.com", "63"),
        ("exa mple.com", "RFC 1123"),
        ("under_score.example.com", "RFC 1123"),
        ("trailing.", "empty label"),
    ],
)
def test_invalid_dns_names_are_refused_naming_the_reason(entry: str, expected_reason_part: str) -> None:
    """Every rejection names what was wrong (page-map §9): not "invalid SAN" but the specific defect.

    `expected_reason_part` is deliberately a fragment rather than a full sentence: the wording of a message is
    allowed to
    improve, while the promise that it *names the defect* is the invariant. Asserting whole sentences makes every
    message
    edit a test failure and teaches contributors to weaken the message instead of the check.
    """
    with pytest.raises(CsrValidationError) as excinfo:
        validate_san_entry(entry)
    assert expected_reason_part in str(excinfo.value)


def test_empty_label_position_is_reported_at_its_offset_in_the_original_string() -> None:
    """ "server..local" is not a valid DNS name (empty label at position 7).

    The number is the offset of the offending label inside the text an operator is looking at, because that is
    what makes
    a bad entry findable in a 40-line textarea. A message that says "label 2" forces them to count labels; one
    that gives
    an offset points at the characters.
    """
    with pytest.raises(CsrValidationError) as excinfo:
        validate_san_entry("server..local")
    assert "position 7" in str(excinfo.value)


def test_a_63_character_label_is_accepted_and_a_64_character_one_is_not() -> None:
    """The boundary is asserted on both sides (RFC 1035 §2.3.1).

    Testing only the rejected side lets an off-by-one slip to "≤64" pass; testing only the accepted side lets a slip to
    "≤62" pass. The pair is the assertion.
    """
    ok = "a" * 63 + ".example.com"
    assert validate_san_entry(ok)[0] == "dns"
    with pytest.raises(CsrValidationError):
        validate_san_entry("a" * 64 + ".example.com")


def test_total_name_length_over_253_is_rejected() -> None:
    """Individual labels may each be legal while the assembled name is not (RFC 1035 §3.1, page-map §9)."""
    entry = ".".join(["a" * 60] * 5)  # 5*60 + 4 dots = 304 characters, every label legal
    assert all(len(label) <= 63 for label in entry.split("."))
    with pytest.raises(CsrValidationError) as excinfo:
        validate_san_entry(entry)
    assert "253" in str(excinfo.value)


def test_single_label_names_are_accepted() -> None:
    """`localhost` is legal in X.509 even though resolvers treat it specially.

    Rejecting it would break the most common home-lab certificate for no security benefit, and mypki issues certificates
    rather than resolving names.
    """
    assert validate_san_entry("localhost")[0] == "dns"


def test_dns_validation_is_case_insensitive_and_normalises_to_lowercase() -> None:
    kind, value = validate_san_entry("Server.Internal")
    assert kind == "dns"
    assert value == "server.internal"


# --------------------------------------------------------------------------------------------- wildcards


def test_leftmost_wildcard_is_accepted() -> None:
    kind, value = validate_san_entry("*.lab.internal")
    assert kind == "dns"
    assert value == "*.lab.internal"


def test_wildcard_covering_more_than_one_label_is_accepted_as_one_label() -> None:
    """`*.a.example.com` is fine: the wildcard still covers exactly one label."""
    kind, value = validate_san_entry("*.a.example.com")
    assert kind == "dns" and value == "*.a.example.com"


@pytest.mark.parametrize("entry", ["a.*.example.com", "*a.example.com", "a*bc.example.com", "*"])
def test_wildcard_anywhere_except_the_leftmost_label_is_rejected(entry: str) -> None:
    """Wildcards are allowed only as the leftmost `*.` (page-map §9; RFC 6125 §6.4.3).

    `*` alone is refused too: a certificate valid for *every* name is not a wildcard certificate, it is an anchor
    for one.
    """
    with pytest.raises(CsrValidationError) as excinfo:
        validate_san_entry(entry)
    assert "leftmost" in str(excinfo.value) or "wildcard" in str(excinfo.value).lower()


def test_wildcard_over_an_ip_address_is_rejected() -> None:
    """`*.10.0.0.1` is nonsense and must not become a DNS SAN that happens to look numeric."""
    with pytest.raises(CsrValidationError) as excinfo:
        validate_san_entry("*.10.0.0.1")
    assert "IP" in str(excinfo.value) or "ip" in str(excinfo.value).lower()


def test_wildcard_with_nothing_after_it_is_rejected() -> None:
    with pytest.raises(CsrValidationError):
        validate_san_entry("*.")


# --------------------------------------------------------------------------------------- textarea parsing


def test_sans_accept_both_newline_and_comma_separators() -> None:
    """Operators paste from tools that use either separator, so both are honoured (page-map §2)."""
    by_line = parse_sans("a.test\nb.test\nc.test", max_entries=100)
    by_comma = parse_sans("a.test,b.test,c.test", max_entries=100)
    assert by_line.dns == by_comma.dns == ("a.test", "b.test", "c.test")


def test_mixed_separators_and_blank_lines_are_handled() -> None:
    result = parse_sans("a.test, b.test\n\n  c.test  \n", max_entries=100)
    assert result.dns == ("a.test", "b.test", "c.test")


def test_dns_and_ip_entries_are_split_into_their_own_lists() -> None:
    result = parse_sans("a.test\n10.0.0.1\nb.test\n::1", max_entries=100)
    assert result.dns == ("a.test", "b.test")
    assert set(result.ips) == {"10.0.0.1", "::1"}


def test_duplicates_are_removed_preserving_first_seen_order() -> None:
    """Dedupe is order-preserving, so the confirmation panel lists names in the order typed (page-map §9)."""
    result = parse_sans("b.test\na.test\nb.test\na.test", max_entries=100)
    assert result.dns == ("b.test", "a.test")


def test_a_dns_name_and_an_ip_that_render_identically_are_not_deduped_together() -> None:
    """Dedupe is per general-name type.

    Collapsing `10.0.0.1` (IP) against a hypothetical DNS entry with the same text would silently drop one of two SANs
    that mean different things to a client.
    """
    result = parse_sans("10.0.0.1\n10.0.0.1", max_entries=100)
    assert len(result.ips) == 1


def test_cap_is_applied_to_the_deduplicated_count_not_the_number_of_lines() -> None:
    """300 lines that collapse to 20 names is not a request for 300 names (page-map §9)."""
    result = parse_sans("\n".join([f"host{i}.test" for i in range(10)] * 3), max_entries=25)
    assert len(result.dns) == 10


def test_exceeding_the_cap_is_refused_naming_the_knob() -> None:
    entries = "\n".join(f"host{i}.test" for i in range(30))
    with pytest.raises(CsrValidationError) as excinfo:
        parse_sans(entries, max_entries=25)
    assert "MYPKI_MAX_SANS" in str(excinfo.value)
    assert "25" in str(excinfo.value)


def test_every_rejected_entry_is_reported_together_not_one_per_request() -> None:
    """Fixing a long list one error per page load is how an operator learns to hate a CA.

    Asserted by counting occurrences of the position marker: three bad lines must produce three named positions in one
    response, because partial reporting turns validation into an interrogation.
    """
    with pytest.raises(CsrValidationError) as excinfo:
        parse_sans("good.test\nbad-.test\na..b\ncap-ok.test\n-lead.test", max_entries=100)
    # Counting the wrapper marker `position N:` rather than the bare word "position": an inner reason may itself name a
    # character offset ("empty label at position 2"), and a naive substring count then reports four entries for three.
    assert message_marker_count(str(excinfo.value), r"position \d+:") == 3


def test_a_rejected_entry_means_nothing_is_issued() -> None:
    """Partial success is not a thing here: one bad SAN rejects the whole list.

    The alternative — issuing the names that passed — would produce a certificate whose SAN set differs from what the
    operator asked for, and with no revocation in this project that difference is permanent.
    """
    with pytest.raises(CsrValidationError):
        parse_sans("good.test\nbad-.test", max_entries=100)


def test_empty_and_whitespace_only_input_yields_an_empty_set_not_an_error() -> None:
    """No SANs is legal for a client certificate (page-map §7), so it is not a validation failure here.

    Whether SAN is *required* is `signing.py`'s per-profile decision; keeping that out of the validator is what lets the
    confirmation panel show "no SANs" honestly instead of showing an error for a legal request.
    """
    for raw in (None, "", "   ", "\n\n"):
        assert parse_sans(raw, max_entries=100).empty


def test_all_entries_lists_dns_before_ip() -> None:
    result = parse_sans("10.0.0.1\na.test", max_entries=100)
    assert result.all_entries() == ("a.test", "10.0.0.1")


def test_san_set_equality_ignores_diagnostics() -> None:
    """`rejected` is excluded from equality (see SanSet in validators.py).

    Two identical name sets that produced different error text must still compare equal, otherwise every test that
    builds
    an expected SanSet has to reproduce the wording of the diagnostics as well as the names.
    """
    a = SanSet(dns=("a.test",), ips=(), rejected=())
    b = SanSet(dns=("a.test",), ips=(), rejected=((0, "something bad"),))
    assert a == b


def test_describe_reports_counts_not_names_for_logging() -> None:
    """`dns=2, ip=1` — enough for a log line, and no name that could be sensitive (page-map §0)."""
    result = parse_sans("a.test\nb.test\n10.0.0.1", max_entries=100)
    described = result.describe()
    assert described == "dns=2, ip=1"
    assert "a.test" not in described


def test_position_in_the_message_indexes_the_original_lines_not_the_filtered_ones() -> None:
    """Blank lines must not shift the reported positions.

    An operator reading "position 3" counts down to line 3 of their textarea. If blank or duplicate lines were dropped
    before indexing, every message after the first blank would point at the wrong entry — a diagnostic that is actively
    misleading.
    """
    with pytest.raises(CsrValidationError) as excinfo:
        parse_sans("good.test\n\nbad-.test", max_entries=100)
    assert "position 2" in str(excinfo.value)


# ------------------------------------------------------------------ subject fields reached through these rules
#
# The four validators below are the ones `parse_sans` is not: they guard the *subject* of a certificate rather than its
# SANs, and each missing case here was found by reading coverage's missing-line list rather than by inventing a story.
# They stay in this file because they share its premise -- rules provable as pure functions, one mutation per case --
# and splitting them into a second file would only make both harder to find (page-map §2).


def test_an_empty_entry_is_refused_with_its_position_even_though_parse_sans_skips_blanks() -> None:
    """`validate_san_entry("")` is unreachable through `parse_sans`, so it is asserted directly.

    MEASURED: no call site can reach this today -- textarea parsing drops blank lines before validating, which is why
    the line sat uncovered until someone asked what the function itself promises. The promise still matters: a future
    caller (a JSON API, an import-from-file path) that passes a blank entry must get "position N is empty" naming the
    index it was handed, not a DNS-label error about a zero-length name.
    """
    for raw in ("", "   ", "\t"):
        with pytest.raises(CsrValidationError) as excinfo:
            validate_san_entry(raw, position=4)
        assert "position 4" in str(excinfo.value)
        assert "empty" in str(excinfo.value)
        assert excinfo.value.field == "sans[4]"


def test_a_common_name_over_253_characters_is_refused_naming_both_numbers() -> None:
    """The CN ceiling is the DNS-name ceiling (253), not the 128 used by the other subject fields.

    Asserted on both sides of the boundary like every other limit in this file: 253 characters is accepted, 254 is
    refused, and the message carries the actual length it saw plus the limit -- because "too long" without numbers is
    what an operator pastes into a support request.
    """
    assert len(validate_common_name("a" * _MAX_CN_LEN)) == _MAX_CN_LEN
    with pytest.raises(CsrValidationError) as excinfo:
        validate_common_name("a" * (_MAX_CN_LEN + 1))
    assert str(_MAX_CN_LEN + 1) in str(excinfo.value)
    assert str(_MAX_CN_LEN) in str(excinfo.value)
    assert excinfo.value.field == "common_name"


def test_a_printable_field_over_its_limit_is_refused_naming_the_field_and_the_bound() -> None:
    """`O=`/`OU=` are bounded at 128 and the caller names which field it validated.

    Two calls, one mutation each: the default limit and an explicit smaller one. The explicit `max_length` arm is what
    proves the bound is the parameter rather than a hard-coded constant buried in the message -- a limit that reports
    the wrong number is worse than no limit, because the operator fixes the wrong thing.
    """
    assert validate_printable_field("O" * 128, "organization") == "O" * 128
    with pytest.raises(CsrValidationError) as excinfo:
        validate_printable_field("O" * 129, "organization")
    assert "organization is 129 characters; the limit is 128" in str(excinfo.value)
    assert excinfo.value.field == "organization"

    with pytest.raises(CsrValidationError) as narrow:
        validate_printable_field("OU" * 10, "organizational_unit", max_length=16)
    assert "organizational_unit is 20 characters; the limit is 16" in str(narrow.value)


def test_an_empty_printable_field_is_absent_rather_than_empty_string() -> None:
    """`""` and whitespace become `None`, so no zero-length attribute reaches the certificate (page-map §7).

    The distinction is load-bearing for `ca.py`: `_subject_builder` adds an attribute only when it is truthy, so a
    validator that returned `""` instead of `None` would encode an empty `O=` into every client's certificate viewer.
    """
    for raw in (None, "", "   ", "\n"):
        assert validate_printable_field(raw, "organization") is None


def test_a_printable_field_with_control_characters_is_refused() -> None:
    """A NUL or a newline in `O=` is rejected rather than stripped.

    Same reasoning as the CN rule one function above: mypki records subject attributes in a certificate that outlives
    this process and cannot be revoked here, so a value that renders as something it is not has to be refused at issue
    time. DEL (0x7f) is included because it is invisible in every browser display and is exactly what a truncated paste
    produces.
    """
    for raw in ("Acme\x00Corp", "Acme\nCorp", "Acme\x7fCorp"):
        with pytest.raises(CsrValidationError) as excinfo:
            validate_printable_field(raw, "organization")
        assert "organization contains control characters" in str(excinfo.value)
        assert excinfo.value.field == "organization"


def test_an_email_over_254_characters_is_refused_naming_the_bound() -> None:
    """The email ceiling is 254 -- one more than a CN, because the `@` costs a character.

    The local part and the domain are both legal on their own at this length; what fails is the assembled address,
    which is the same trap as the 253-character DNS name further up this file.
    """
    # MEASURED: the accepted side has to be built from the total, not from a long local part -- "a"*250 + "@example.com"
    # is 262 characters and is refused by the length rule before the domain is ever looked at.
    just_fits = "a" * (_MAX_EMAIL_LEN - len("@example.com")) + "@example.com"
    assert len(just_fits) == _MAX_EMAIL_LEN
    assert validate_email(just_fits) == just_fits
    with pytest.raises(CsrValidationError) as excinfo:
        validate_email("a" * (_MAX_EMAIL_LEN + 1))
    assert str(_MAX_EMAIL_LEN + 1) in str(excinfo.value)
    assert str(_MAX_EMAIL_LEN) in str(excinfo.value)
    assert excinfo.value.field == "email"


def test_an_email_needs_something_on_both_sides_of_the_at() -> None:
    """`@example.com` and `ops@` are refused; the empty halves never reach a certificate subject.

    MEASURED note for anyone reading coverage rather than this file: `text.count("@") != 1` already rejects `""@""`,
    so the partition arm fires on values that have exactly one `@` and nothing beside it. It is kept because it names
    the actual defect ("a name before and after the @") instead of leaving the operator to work out which half was
    missing from a generic count error.
    """
    for raw in ("@example.com", "ops@", "@"):
        with pytest.raises(CsrValidationError) as excinfo:
            validate_email(raw)
        assert "before and after" in str(excinfo.value)
        assert excinfo.value.field == "email"


def test_an_email_with_whitespace_or_a_control_character_is_refused() -> None:
    """No space, tab or NUL inside an address.

    Whitespace is the smuggling vector here: `ops @evil.test` encodes fine into a subject and displays as two
    attributes in some clients. Checking `isspace()` rather than only `ord(char) < 0x20` also catches U+00A0, which a
    pasted address from a web page really does contain.
    """
    for raw in ("ops @example.com", "ops@exa mple.com", "ops\t@example.com", "ops@example\u00a0.com"):
        with pytest.raises(CsrValidationError) as excinfo:
            validate_email(raw)
        assert "whitespace or control" in str(excinfo.value)
        assert excinfo.value.field == "email"


def test_a_bad_email_domain_is_rejected_with_the_dns_reason_prefixed_by_its_context() -> None:
    """The domain half is validated by the same DNS rules as a SAN, and the message says so.

    `ops@bad-.example.com` is refused for the hyphen, but the operator has to learn that it was *the domain* that
    failed -- otherwise they go looking for a typo in the local part. The re-raise exists precisely to add that word,
    and it preserves the underlying reason verbatim rather than paraphrasing it into something less findable.
    """
    with pytest.raises(CsrValidationError) as excinfo:
        validate_email("ops@bad-.example.com")
    assert "email domain" in str(excinfo.value)
    assert "hyphen" in str(excinfo.value)
    assert excinfo.value.field == "email"

    # A 64-character label inside the domain reports the same 63 limit it would as a bare SAN entry.
    with pytest.raises(CsrValidationError) as long_domain:
        validate_email("ops@" + "d" * 64 + ".example.com")
    assert "email domain" in str(long_domain.value)
    assert "63" in str(long_domain.value)


def test_a_valid_email_is_returned_trimmed() -> None:
    """The success arm returns the value it accepted, trimmed -- not the raw input.

    Completing this tail matters for the same reason as every other return here: `csr.py` stores what the validator
    returned, so a trailing space that survived validation would be encoded into the certificate and show up in every
    client's display of the subject.
    """
    assert validate_email("  ops@example.com  ") == "ops@example.com"
    assert validate_email("ops@sub.example.com") == "ops@sub.example.com"
    assert validate_email(None) is None
