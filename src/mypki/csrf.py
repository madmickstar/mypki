"""CSRF protection for a five-page app, without a framework dependency.

Why this module exists separately: Flask-WTF-style CSRF is a dependency whose main job is wiring tokens into forms and
sessions for an app that has exactly four forms. The mechanism mypki actually needs is three lines long — put a random
token in the signed session, render it in every form, compare it with `hmac.compare_digest` on every POST — and a
dependency that does that hides the one decision worth making visible: **what happens on failure**. Here it is a
400 page
and no signing performed (page-map §0), which is testable as stated rather than inherited from a library default.

Why `hmac.compare_digest` and not `==`: a plain comparison stops at the first mismatching byte, so the time it takes
leaks how much of the token an attacker guessed correctly. That is a weak attack against a 256-bit random token over a
localhost-bound service, and it is also free to avoid — there is no version of this code where constant-time comparison
costs anything.

Why the token lives in the **session** rather than in a separate cookie: mypki already has a signed session
(`SessionMiddleware`) for carrying the two-step signing state (page-map §3). A double-submit-cookie design would need a
second cookie, and the equality check then proves only that two cookies agree with each other — which an attacker
who can
set one cookie can arrange. Tying the token to the signed session means forging it requires forging the session
signature.

Why there is no per-form or per-request token rotation: rotating on every GET would break the two-step flow, where the
confirmation POST must carry the token that the paste POST's page rendered. One token per session is the design that
matches the flow; its cost is that a stolen token stays valid for the session's lifetime, which is why `session_max_age`
is bounded and the cookie is `same_site="lax"` (page-map §11).
"""

from __future__ import annotations

import hmac
import logging
import secrets

from starlette.requests import Request

log = logging.getLogger("mypki.csrf")

#: Session key holding this session's CSRF token. Namespaced so it cannot collide with the signing-state keys another
#: part of `app.py` stores in the same session dict.
SESSION_KEY = "mypki_csrf_token"

#: Name of the hidden form field. One name for every form, so a route cannot accidentally accept a token under a
#: different key and skip the check.
FIELD_NAME = "csrf_token"

_TOKEN_BYTES = 32  # 256 bits of entropy from the OS CSPRNG, matching what `secrets.token_urlsafe` is documented for.

__all__ = ["FIELD_NAME", "SESSION_KEY", "csrf_field_html", "issue_csrf_token", "verify_csrf"]


def issue_csrf_token(request: Request) -> str:
    """Return this session's CSRF token, creating it on first use.

    Stored in the signed session rather than returned fresh each call: a token that changes on every GET invalidates the
    token embedded in the form the operator is about to submit (see module docstring). Mutating `request.session` marks
    the cookie for re-send automatically in Starlette, so nothing here has to manage expiry.
    """
    existing = request.session.get(SESSION_KEY)
    if isinstance(existing, str) and existing:
        return existing
    token = secrets.token_urlsafe(_TOKEN_BYTES)
    request.session[SESSION_KEY] = token
    return token


def csrf_field_html(request: Request) -> str:
    """Ready-to-render hidden input for a template.

    Returns HTML rather than the bare token because every form in this app must carry the field, and a helper that only
    hands back a string is a helper every template can forget to wrap in `<input type="hidden" name="csrf_token">`. The
    value is escaped here (the token is URL-safe base64 by construction, so escaping is a no-op today) so that the one
    place tokens enter HTML cannot become an XSS sink if the generator ever changes.

    Templates mark this `| safe` — justified because the only content is a fixed attribute name plus an escaped
    token from `secrets`, never operator input.
    """
    token = issue_csrf_token(request)
    return f'<input type="hidden" name="{FIELD_NAME}" value="{token}">'


def verify_csrf(request: Request, submitted: str | None) -> bool:
    """True when `submitted` matches this session's token.

    Absent session token and absent submission both answer False: a POST that arrives before any GET has never been
    issued a token, and accepting it would mean "no CSRF protection for the first request", which is exactly the
    window a
    cross-site attacker works in.

    The comparison is length-safe by construction — `compare_digest` on two unequal-length byte strings returns False in
    constant time relative to the contents rather than leaking a prefix.
    """
    expected = request.session.get(SESSION_KEY)
    if not isinstance(expected, str) or not expected:
        log.info("csrf check failed: no token issued for this session yet")
        return False
    if submitted is None:
        log.info("csrf check failed: form submitted without a token")
        return False
    ok = hmac.compare_digest(expected.encode("utf-8"), submitted.encode("utf-8"))
    if not ok:
        # Names the failure, never either token value: a log line containing a valid token is a second way to steal it.
        log.info("csrf check failed: submitted token does not match the session token")
    return ok
