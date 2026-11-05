"""The sidebar nav: seven links, exactly one of them lit, on every page (page-map §12).

No test in this suite looked at the nav before 0.5.0 added a seventh link. That gap is worth naming rather than
glossing: `base.html` decides which item is `.active` by comparing `request.url.path` against a literal written in the
template, so a new route can be registered and rendered perfectly while its nav item is missing, duplicated, or lit on
the wrong page — and every existing test would stay green, because they assert on content. These tests are the only
thing between "the route exists" and "an operator can find it".

Why the assertions are written as counts over the rendered page rather than as a check of `base.html`: a grep of the
template passes against a page that never renders the markup (the same lesson `scripts/smoke_test.sh` §9 records for the
CA facts, which used to be asserted against a file rather than a response).

MEASURED on this build: `/` and `/csr/sign` share one item (`Sign CSR`) because `home()` renders the sign page, so the
active count on both is 1; `/version` renders `about.html`, whose template sets no `path`, so **no** item is lit there —
asserted below as 0 rather than left untested, because "the version page lights nothing" is a fact a reader would
otherwise assume was a bug. `base.html` currently places About before Inspect PEM and Settings; this test locks that
measured sidebar order so later edits make layout drift visible.
"""

from __future__ import annotations

import re

import pytest

# Every nav-bearing page, spelled out rather than imported from test_views.PAGES: this file is about the nav, and a list
# shared with another file is a list someone else can quietly shorten. `/version` is included because it renders through
# base.html too.
NAV_PAGES = ("/", "/csr/generate", "/csr/sign", "/ca", "/issued", "/inspect", "/settings", "/about", "/version")

#: The seven links `base.html` must render, in the order they appear in the sidebar. A nav that gains a link without
#: this list gaining it is caught by the count assertion below; the order matters because the sidebar is a physical
#: layout, not a set.
EXPECTED_LINKS = {
    "/": "Sign CSR",
    "/csr/generate": "Generate CSR",
    "/ca": "CA certificate",
    "/issued": "Issued",
    "/about": "About",
    "/inspect": "Inspect PEM",
    "/settings": "Settings",
}

#: Which page template lights which nav href. `/version` is absent on purpose: `about.html` renders it with no `path`
#: variable set, so the version page deliberately lights nothing (MEASURED, asserted below).
ACTIVE_BY_PATH = {
    "/": "/",
    "/csr/generate": "/csr/generate",
    "/csr/sign": "/",
    "/ca": "/ca",
    "/issued": "/issued",
    "/inspect": "/inspect",
    "/settings": "/settings",
    "/about": "/about",
}


def _nav_block(page: str) -> str:
    """The `<nav class="nav">…</nav>` element, or an explicit failure.

    Fails loudly rather than returning `""`: every assertion in this file would then compare against an empty string and
    "no nav links" would read as a test that passes. Same discipline as `test_views._reason()`.
    """
    match = re.search(r'<nav class="nav">(.*?)</nav>', page, re.DOTALL)
    if match is None:
        raise AssertionError(f'no <nav class="nav"> in the page:\n{page[:400]}')
    return match.group(1)


def _nav_links(page: str) -> list[tuple[str, bool]]:
    """`(href, is_active)` for every nav item on the page, in document order."""
    nav = _nav_block(page)
    links: list[tuple[str, bool]] = []
    for tag in re.findall(r'<a class="nav-item[^"]*"[^>]*>', nav):
        href = re.search(r'href="([^"]+)"', tag)
        if href is None:  # pragma: no cover - defensive: a nav item with no href is not a link at all
            raise AssertionError(f"nav item without href: {tag}")
        classes = re.search(r'class="nav-item([^"]*)"', tag)
        links.append((href.group(1), "active" in (classes.group(1) if classes else "")))
    return links


# --------------------------------------------------------------------------------- the seven links, everywhere


@pytest.mark.parametrize("path", NAV_PAGES)
def test_the_sidebar_carries_exactly_seven_links(session_client, path: str) -> None:
    """Seven links on every page that shows a sidebar (page-map §12).

    Asserted as a count *and* as the set of hrefs, because the two catch different mistakes: a count alone passes when a
    link is duplicated and another is missing, and a set alone passes when one appears twice.
    """
    links = _nav_links(session_client.get(path).text)
    assert len(links) == 7, f"{path} renders {len(links)} nav links: {links}"
    assert [href for href, _ in links] == list(EXPECTED_LINKS), f"{path}'s nav hrefs drifted: {links}"


@pytest.mark.parametrize("path", NAV_PAGES)
def test_the_inspect_link_is_in_the_nav(session_client, path: str) -> None:
    """0.5.0's seventh link is present on every page, not only on `/inspect` itself.

    A nav item that exists only on its own page is a page nobody finds. The label is asserted too, because the href
    alone would still pass if the sidebar rendered an empty `<span>`.
    """
    nav = _nav_block(session_client.get(path).text)
    assert 'href="/inspect"' in nav, f"no Inspect PEM link on {path}: {nav}"
    assert "Inspect PEM" in nav, f"the Inspect link on {path} renders no label"


# ----------------------------------------------------------------------------------- exactly one item lit


@pytest.mark.parametrize("path", sorted(ACTIVE_BY_PATH))
def test_exactly_one_nav_item_is_lit_on_each_page(session_client, path: str) -> None:
    """One `.active` per page — and it is the item this page is.

    Two halves on purpose. "Exactly one" catches a template that lit nothing (an operator cannot tell where they are) or
    lit everything (which makes the highlight meaningless). "Which one" catches the subtler bug: `/inspect` lighting
    `/settings`, which renders fine and reads as if the nav were working.

    `/csr/sign` lights `Sign CSR` (`/`) because `home()` and the sign page are one implementation — asserted here so
    that fact is a tested contract rather than an emergent one.
    """
    links = _nav_links(session_client.get(path).text)
    active = [href for href, isActive in links if isActive]
    assert len(active) == 1, f"{path} lights {len(active)} nav item(s): {active} (links: {links})"
    assert active[0] == ACTIVE_BY_PATH[path], f"{path} lights {active[0]!r}, expected {ACTIVE_BY_PATH[path]!r}"


def test_the_inspect_page_lights_itself_and_nothing_else(session_client) -> None:
    """`/inspect` is its own nav position, not a variant of Sign CSR.

    Written out separately from the parametrized case above because it is 0.5.0's actual new behaviour and this is the
    one assertion that names it in words a reader searching for "inspect" will find.
    """
    links = _nav_links(session_client.get("/inspect").text)
    active = [href for href, isActive in links if isActive]
    assert active == ["/inspect"], f"/inspect should light only itself: {active} / all links {links}"


def test_the_version_page_lights_no_nav_item(session_client) -> None:
    """`/version` renders `about.html` without setting `path`, so nothing is lit — asserted, not assumed.

    Left untested, a future reader sees an unlit sidebar and "fixes" it by adding a `/version` case to the nav, which
    would put a link in the sidebar that `EXPECTED_LINKS` does not know about. Recording the current behaviour as an
    assertion is what makes the change a decision rather than an accident.
    """
    links = _nav_links(session_client.get("/version").text)
    assert [href for href, isActive in links if isActive] == [], f"/version should light nothing: {links}"


def test_the_nav_highlight_survives_a_query_string(session_client) -> None:
    """`/issued?pending=…` still lights Issued.

    `base.html` compares `request.url.path`, which excludes the query, so a confirm-step URL keeps its highlight.
    Asserted because the alternative (comparing `request.url`) would silently un-highlight every page reached through a
    query parameter, and `/csr/sign?pending=` is exactly such a URL in this app.
    """
    links = _nav_links(session_client.get("/issued?pending=not-a-real-id").text)
    assert [href for href, isActive in links if isActive] == ["/issued"], links


def test_the_no_ca_state_still_renders_the_whole_nav(client_without_ca) -> None:
    """A host with no CA shows the same seven links.

    The sidebar is not conditional on having a CA (only `standalone` error pages drop the nav entirely), so an
    uninitialised host still exposes Inspect PEM — which matters because `/inspect` needs no CA and is the page an
    operator reaches for *before* they have one.
    """
    links = _nav_links(client_without_ca.get("/inspect").text)
    assert len(links) == 7, f"no-CA host renders {len(links)} nav links: {links}"
    assert [href for href, _ in links] == list(EXPECTED_LINKS), links
