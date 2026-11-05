"""The FastAPI application factory: middleware, error handlers and every route in one place.

Why a factory and not a module-level `app`: uvicorn needs an importable app object, but mypki's CLI must be able to hand
the running process its already-loaded CA, its resolved data dir and its session secret (page-map §6). A module-level
`app = FastAPI()` would have to discover those from the environment at request time — which means reading and decrypting
the CA key per request, exactly what `ca.py` exists to prevent. `create_app(settings, ca_bundle=…, session_secret=…)`
takes them as arguments, so the app is a configured object rather than a global that reaches into the world.

Why FastAPI at all, when this project explicitly has no REST API: FastAPI is the house framework, and what it buys a
server-rendered HTML app is `Form(...)` parsing, per-exception-type handlers and Jinja2 integration. The out-of-scope
promise is honoured structurally rather than by convention — `docs_url=None, redoc_url=None, openapi_url=None` are
hard-coded in the constructor and not read from settings, so "no API surface advertised" cannot be switched on by a
config value (page-map §0).

Why handlers are registered per exception type instead of one catch-all: each mypki error carries the fact its page
needs (`CaPrivilegeRequestedError.extension`, `RequestTooLargeError.limit`, `CsrValidationError.field`), and a shared
handler would flatten three different answers into "error". The pure modules raise (see `errors.py`) and this file
chooses status codes — the split that keeps `csr.py` and `validators.py` importable without FastAPI.

Why request handlers are plain `def` rather than `async def`: they do CPU-bound crypto and blocking SQLite work, which
belongs on a threadpool; declaring them async would run key generation and signing **on the event loop** and stall every
other request for the duration. It also means no async test machinery is needed (STYLE §11). The consequence is that a
handler cannot call `await request.form()` itself, so form parsing lives in one `async` dependency (`_form_fields`)
injected as an `Annotated` parameter — Annotated rather than `Depends()` in an argument default, which is why this
project needs no `B008` ignore in `pyproject.toml` (STYLE §11).

Why the body-size guard is middleware that buffers the body: starlette's own multipart limit answers **400** with a bare
JSON `{"detail":"Field exceeded maximum size of 1024KB."}` (starlette's own part limit). Right status, wrong
artifact — mypki promises its own error page naming its own knob (`MYPKI_MAX_CSR_CHARS`), so the raw body is measured
before any parser sees it.

Why generated keys/CSRs and issued certs are handed out from an in-process one-shot store: downloads must work without
writing anything to disk or the DB (page-map §2), and a signed session cookie cannot carry them — RFC 6265 §6.1 lets
browsers reject cookies over 4096 octets, and a 3072-bit key PEM plus a max-size CSR is far past that. The cookie
carries an opaque id; the bytes live in memory until they expire or the process exits. See `OneShotStore` for the
trade-offs accepted out loud.

"Two error surfaces instead of one" — the name is kept, the count is not: there are three now -- page-map §0
has always promised mypki's own page for every rejection, and for anything *CSR-shaped* it still delivers exactly that.
What first broke here was a refusal of something the operator typed into a form field: mistyping `AUSTRALIA` into the
country box used to throw away eight other fields and land them on a page with no form on it.

  * **A typed field was rejected** (common name, a SAN entry, country, email, key type, the passphrase pair, validity
    days) → the same form re-renders, the problem named in a block at the top of it, every other value still filled in.
    Status 200: nothing was refused, one input needs fixing. Consent for extensions mypki will not copy is answered on
    this surface too (`page-map §3` rule 6): an unticked box re-renders the confirmation page at 200 naming every
    extension at stake, because "tick the box or remove them from your request" is a choice this form can present.
    A privilege claim (`CA:TRUE`, `keyCertSign`, `crlSign`, NameConstraints) is not that kind of input and stays below.
  * **A pasted request was refused** (no PEM block, a signature that does not verify, a weak key, a CSR asking for CA
    powers) → **the sign page re-renders**, the reason named in red directly above "Paste a CSR (PEM)" with the paste
    still in the textarea (`_paste_refused`). The status is unchanged — 400 for malformed input, 403 for a privilege
    claim — because the status answers "what was wrong" for a script while the block answers "what do I fix" for the
    person standing at the form. Moving the reason did not move the answer.
  * **There was no form to put it on** (an oversized body, refused by `SizeGuardMiddleware` before any route runs; a
    missing CSRF token; `/inspect`, which describes rather than signs) → mypki's error page at 400/403/413.

The split is decided by *where the exception is caught* (`_generate_form`, `csr_sign_submit` and
`_issue_from_confirmation` validate their own inputs and render their own page) rather than by inspecting messages at
render time. A rule built on message text is one refactor away from sending an operator to the wrong surface.
"""

from __future__ import annotations

import secrets
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.ocsp import OCSPResponseStatus
from cryptography.x509.oid import NameOID, ObjectIdentifier
from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from . import __version__, paths
from .ca import CaBundle, describe_ca, format_fingerprint, load_ca, secret_session_key
from .config import Settings, get_settings
from .crl import CRL_PEM_MARKER, CrlFacts, read_crl_pem, rebuild_crl, summarise_crl
from .csr import (
    PASSPHRASE_MIN_LENGTH,
    PASSPHRASE_RECOMMENDED_LENGTH,
    CsrFields,
    build_csr,
    parse_and_validate_csr,
    passphrase_advisory,
    subject_from_fields,
    validate_generate_fields,
)
from .csrf import FIELD_NAME, csrf_field_html, issue_csrf_token, verify_csrf
from .errors import (
    CaNotFoundError,
    CaPassphraseError,
    CaPrivilegeRequestedError,
    CsrfValidationError,
    CsrValidationError,
    KeyPolicyError,
    MypkiError,
    OneShotExpiredError,
    RequestTooLargeError,
    RevocationRecordNotFoundError,
)
from .inspect import KEY_BODY_REDACTED, MAX_BLOCKS_TO_TRY, PemReport, describe_pem, redact_private_key_bodies
from .keys import ALLOWED_KEY_SPECS, generate_key, private_key_pem
from .logsetup import configure_logging, get_logger, resolved_log_file
from .ocsp_responder import (
    OCSP_MAX_REQUEST_BYTES,
    OCSP_RESPONSE_MEDIA_TYPE,
    answer_for,
    malformed_response_der,
    parse_ocsp_request,
    render_ocsp_response,
    serial_hex_of,
)
from .settingsfile import (
    UNMANAGED_KEYS,
    SettingsFileError,
    config_file_path,
    editable_field_names,
    env_file_layers,
    preserve_unmanaged,
    read_saved_values,
    render_file,
    unmanaged_reason,
    validate_candidate,
    write_settings_file,
)
from .signing import CERT_PROFILE_HELP, CERT_TYPES, IssuedCert, issue_certificate
from .store import MAX_REVOCATION_REASON_LENGTH, IssuedStore
from .validators import (
    SanSet,
    parse_sans,
    validate_common_name,
    validate_country,
    validate_email,
    validate_printable_field,
    validity_days,
)

#: The project's source. Rendered on `/about` (page-map §12) because "where do I report this?" is asked at the moment
#: something went wrong, and it is what makes a version number citable by somebody else.
PROJECT_URL = "https://github.com/madmickstar/mypki"

log = get_logger("mypki.app")

PACKAGE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = PACKAGE_DIR / "templates"
STATIC_DIR = PACKAGE_DIR / "static"

#: Lifetime of a one-shot download artifact (page-map §10). 15 minutes is long enough to finish a copy-and-paste or a
#: re-click on a slow machine, short enough that an unclaimed key does not sit in memory for a working day.
ONE_SHOT_TTL_SECONDS = 900

#: How many artifacts one process holds at once. Each holds a key or a certificate body, so this also bounds
#: how much secret material can be resident; 32 is generous against a single operator's pace and small enough
#: that an abandoned browser tab cannot grow the process.
ONE_SHOT_MAX_ITEMS = 32

#: Session keys for pending one-shot artifacts. Namespaced with the `mypki_` prefix so they cannot collide with another
#: component's session data, exactly as the CSRF key is namespaced in `csrf.py`.
SESSION_CSR_ID = "mypki_pending_csr_id"
SESSION_GENERATION_CSR_ID = "mypki_pending_generation_csr_id"
SESSION_GENERATION_KEY_ID = "mypki_pending_generation_key_id"
SESSION_ISSUED_CERT_ID = "mypki_pending_issued_cert_id"
SESSION_ISSUED_CHAIN_ID = "mypki_pending_issued_chain_id"

#: The confirm form's affirmative consent box for extensions mypki will not copy (page-map §3 rule 6, PLAN.md §6.3).
#:
#: A checkbox rather than a text field, because the only value that consents is the one a browser sends when the box is
#: ticked: an unticked box submits **nothing**, so `form.get(...)` is None and the request is not signed. That is what
#: makes "default OFF" true at the HTTP layer rather than in a comment — there is no value an old client, a script or a
#: hand-built curl call can send that means "consent" without the box having been rendered with the extensions named on
#: it. The field name is deliberately not `confirm`-like: `_subject_edit_submitted` and the confirm branch both key off
#: other names, and a consent flag that collided with one of them would silently inherit that field's meaning.
CONSENT_FIELD = "ignore_extensions"

_PEM_MEDIA_TYPE = "application/x-pem-file"

#: Media type for the CRL artifact (RFC 5280 §7.1, IANA `application/pkix-crl`). Deliberately **not**
#:`_PEM_MEDIA_TYPE`: this body is a CRL, and the client that fetched `<crl_base_url>/crl.pem` out of a certificate's
#: `CRLDistributionPoints` deserves to be told what it received rather than left to guess from a `.pem` suffix.
_CRL_MEDIA_TYPE = "application/pkix-crl"

#: The literal `Content-Disposition` filename for the artifact. Never `_safe_stem()` — there is no operator input here,
#: and reaching for a filtering helper would imply that there is. It is also the name `paths.crl_path()` writes on disk,
#: so the download name and the file name are one spelling (plan §4).
CRL_FILENAME = "mypki.crl.pem"

#: This file's *name* for where a refusal is rendered, as distinct from the status code it carries — the rule spelled
#: out in the module docstring above. Living code cites `ERROR_SURFACE_RULE` instead of quoting that sentence, so
#: rewording it touches this file alone rather than the tests, three templates and two documents at once.
#: The quoted phrase itself stays in the docstring heading as the thing being named. `tests/test_packaging.py` pins both
#: ends — exactly one heading here, and no quotation of it anywhere else in living code.
ERROR_SURFACE_RULE = "Two error surfaces instead of one"

__all__ = ["OneShotArtifact", "OneShotStore", "SecurityHeadersMiddleware", "SizeGuardMiddleware", "create_app"]


# --------------------------------------------------------------------------------------------- one-shot store


@dataclass(frozen=True)
class OneShotArtifact:
    """A body handed to the browser once, held in process memory (page-map §10)."""

    id: str
    filename: str
    media_type: str
    body: str
    created_at: float = field(default_factory=time.monotonic)


class OneShotStore:
    """Session-scoped, expiring store for the artifacts downloads read from.

    Why not a signed session cookie, as an earlier draft of this plan suggested: a 3072-bit RSA key PEM is ~3.2 KB and a
    max-size CSR is 32 000 characters; RFC 6265 §6.1 makes browsers free to reject cookies over 4096 octets, so
    the cookie
    would silently drop the very bytes it was carrying — which shows up as "the download link does nothing" rather
    than as an
    error. The cookie therefore carries only an opaque id and this store holds the body.

    Accepted consequences, stated rather than discovered:
      * a restart loses pending downloads (the operator regenerates; mypki keeps nothing by design);
      * `--workers > 1` would make an artifact visible to only one worker — mypki runs one process per log file
      for the same
        reason (`logsetup.py`) and `serve` deliberately exposes no workers flag;
      * TTL expiry means a stale bookmark 404s rather than re-running the generation, because re-running would mint a
        different key behind what looks like the same link.

    Concurrency: uvicorn runs one event loop per process and these handlers are sync `def`s on that worker's threadpool.
    `put`/`take` are short enough that interleaving is not a correctness question, and dict operations here stay
    within what
    the GIL makes atomic — so no lock is taken, and none is needed for a single-worker app.
    """

    def __init__(self, ttl_seconds: int = ONE_SHOT_TTL_SECONDS, max_items: int = ONE_SHOT_MAX_ITEMS) -> None:
        self._items: dict[str, OneShotArtifact] = {}
        self.ttl_seconds = ttl_seconds
        self.max_items = max_items

    def put(self, *, filename: str, media_type: str, body: str) -> OneShotArtifact:
        self._evict()
        # Random rather than sequential ids: a predictable artifact id would let one session guess another
        # session's download
        # link, which is the whole reason the id is opaque.
        artifact = OneShotArtifact(id=secrets.token_urlsafe(32), filename=filename, media_type=media_type, body=body)
        self._items[artifact.id] = artifact
        return artifact

    def take(self, artifact_id: str | None) -> OneShotArtifact:
        """Look an artifact up by id, raising `OneShotExpiredError` for anything missing or stale."""
        self._evict()
        if not artifact_id:
            raise OneShotExpiredError("That download is no longer available: nothing is pending for this session.")
        artifact = self._items.get(artifact_id)
        if artifact is None:
            raise OneShotExpiredError("That download is no longer available — it expired, or the server restarted.")
        return artifact

    def _evict(self) -> None:
        now = time.monotonic()
        for key in [key for key, item in self._items.items() if now - item.created_at > self.ttl_seconds]:
            del self._items[key]
        # Over capacity: drop the oldest rather than refusing the new one. Refusing would fail an operator's
        # current action
        # to punish an abandoned earlier one.
        while len(self._items) > self.max_items:
            oldest = min(self._items.values(), key=lambda item: item.created_at)
            del self._items[oldest.id]

    def __len__(self) -> int:
        return len(self._items)


# ------------------------------------------------------------------------------------------- middlewares


class SecurityHeadersMiddleware:
    """Add mypki's response headers to every response, including downloads and error pages.

    Pure ASGI rather than a `BaseHTTPMiddleware` subclass on purpose: the base middleware buffers every response
    through an
    internal stream, which is cost without benefit when all this does is append headers, and it has a history in
    Starlette of
    interfering with streaming responses and background tasks.

    CSP `default-src 'self'` with no `unsafe-inline`: the UI ships one stylesheet from `/static` and **no
    JavaScript at all**
    (page-map §0), so inline scripts are not merely disallowed but absent — which is what turns a
    template-escaping mistake
    into a rendering bug rather than an XSS. The cost of that choice is stated plainly: no CDN, no JS widgets, and
    any future
    interactivity must ship as a same-origin file.

    Headers are added only if the response did not already set them, so a route that deliberately overrides (a
    download's
    `Cache-Control`) wins over this default rather than being overwritten by it.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":  # lifespan passes straight through
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers") or [])
                already = {name.decode("latin-1").lower() for name, _ in headers}
                for name, value in (
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"same-origin"),
                    # No unsafe-inline and no CDN: server-rendered HTML plus one same-origin stylesheet (page-map §0).
                    (b"content-security-policy", b"default-src 'self'; base-uri 'self'; frame-ancestors 'none'"),
                ):
                    if name.decode("latin-1") not in already:
                        headers.append((name, value))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_headers)


class SizeGuardMiddleware:
    """Measure the request body against mypki's own limit **before** any parser can answer.

    The alternative is accepting starlette's answer, which is 400 plus `{"detail":"Field exceeded maximum size of
    1024KB."}`
    (the framework's own limit). That is a correct status and a wrong artifact: page-map §0 promises mypki's own page
    its own
    limit, and an operator reading `1024KB` would go looking for a framework setting that is not the knob they
    should change.

    The body is buffered and then replayed to the application, which is what makes "measured before parsing"
    possible at all.
    Cost, stated: every POST body is held in memory twice (buffer + parsed form) for the duration of one request.
    mypki's cap
    makes that tens of kilobytes; an app that accepted megabyte uploads would need a streaming guard instead, and
    this one
    refuses megabyte uploads.

    GET/HEAD requests are passed through untouched: they have no body to measure, and buffering them would turn
    the app's
    read-only pages into allocations.
    """

    def __init__(self, app: ASGIApp, limit_provider: Any, render_error: Any) -> None:
        self.app = app
        self.limit_provider = limit_provider
        self.render_error = render_error

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method", "GET").upper() not in ("POST", "PUT", "PATCH"):
            await self.app(scope, receive, send)
            return

        limit = int(self.limit_provider())
        declared = _header_value(scope, b"content-length")
        if declared and declared.isdigit() and int(declared) > limit:
            await self._reject(scope, send, int(declared), limit)
            return

        chunks: list[bytes] = []
        total = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body = message.get("body", b"")
            total += len(body)
            if total > limit:
                await self._reject(scope, send, total, limit)
                return
            chunks.append(body)
            if not message.get("more_body", False):
                break

        index = 0

        async def replay() -> Message:
            nonlocal index
            if index < len(chunks) - 1:
                chunk = chunks[index]
                index += 1
                return {"type": "http.request", "body": chunk, "more_body": True}
            if index < len(chunks):
                chunk = chunks[index]
                index += 1
                return {"type": "http.request", "body": chunk, "more_body": False}
            # Starlette may ask again after the final chunk; answering with an empty body keeps it satisfied rather than
            # hanging on a receive that will never produce data.
            return {"type": "http.request", "body": b"", "more_body": False}

        await self.app(scope, replay, send)

    async def _reject(self, scope: Scope, send: Send, actual: int, limit: int) -> None:
        log.info("oversized request body at %s (%d bytes; limit %d)", scope.get("path", "?"), actual, limit)
        exc = RequestTooLargeError(actual, limit, "MYPKI_MAX_CSR_CHARS")
        body = self.render_error(413, str(exc)).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"text/html; charset=utf-8"),
                    (b"content-length", str(len(body)).encode()),
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"same-origin"),
                    (b"content-security-policy", b"default-src 'self'; base-uri 'self'; frame-ancestors 'none'"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


def _header_value(scope: Scope, name: bytes) -> str | None:
    for key, value in scope.get("headers") or []:
        if key.lower() == name:
            return value.decode("latin-1")
    return None


# ------------------------------------------------------------------------------------------------ app factory


def create_app(
    settings: Settings | None = None,
    *,
    ca_bundle: CaBundle | None = None,
    session_secret: str | None = None,
    cli_overrides: Mapping[str, object] | None = None,
) -> FastAPI:
    """Build the application. `ca_bundle=None` means "discover it from the data dir", which tests and embedders want.

    Called by `mypki serve` with a CA already loaded (page-map §6: the key is read once at startup), and by
    `tests/conftest.py` with a throwaway CA in a temporary directory — never an operator's real one.
    """
    settings = settings or get_settings()
    configure_logging(settings)

    data_root = paths.resolve_data_dir(env_override=str(settings.data_dir) if settings.data_dir else None)

    # debug=False and the three URL knobs are hard-coded rather than read from settings: an operator who can set a
    # config
    # value can turn "no API surface" back into an API surface (page-map §0).
    app = FastAPI(
        title="mypki",
        version=__version__,
        debug=False,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    app.state.settings = settings
    # Hot-reload needs to know which values arrived from `mypki serve` flags, because a *fresh* `Settings` built
    # from the dotenv layers after a Save would otherwise let the saved file outrank the flags that started
    # this process.
    # `cli.settings_with_cli_overrides` therefore passes its own merged overrides through here rather than leaving them
    # implicit inside `settings`. Empty/absent for tests and embedders, where there is no flag layer to preserve.
    app.state.cli_overrides = dict(cli_overrides or {})
    app.state.data_root = data_root
    app.state.store = IssuedStore(paths.db_path(data_root))
    app.state.store.init_schema()
    app.state.oneshot = OneShotStore()

    if ca_bundle is None:
        # Discovery path for embedders and tests. `serve` passes a bundle in, so the CLI's exit-code handling
        # (page-map §6)
        # stays in the CLI where an operator sees it rather than surfacing as a 500 from inside a request handler.
        try:
            ca_bundle = load_ca(data_root)
        except MypkiError as exc:
            log.warning("no usable CA at startup: %s", exc)
            ca_bundle = None
    app.state.ca = ca_bundle

    # Startup build (plan §4): a host with a CA **and a key** publishes a CRL before anyone revokes anything, so
    # `GET /crl.pem` answers a valid zero-entry artifact instead of 404-ing until the first revoke. A keyless host is
    # skipped rather than warned about on every start — `/ca` already says "absent — this host cannot sign", and
    # `crl.build_crl` refuses the same condition with a message that reaches an operator who actually asks for one.
    # A failure here never prevents serving: a CRL this host could not write is a degraded feature, not a broken app,
    # and refusing to start would turn "the data dir is read-only" into "this CA is unavailable".
    if ca_bundle is not None and ca_bundle.key is not None:
        try:
            facts = rebuild_crl(bundle=ca_bundle, store=app.state.store, path=paths.crl_path(data_root))
            log.info(
                "published CRL at startup (entries=%d, crl_number=%d, next_update=%s)",
                facts.entry_count,
                facts.crl_number,
                facts.next_update_utc.isoformat(),
            )
        except (MypkiError, OSError) as exc:
            log.error("startup CRL build failed (%s); /crl will report no published artifact", exc)

    secret = session_secret or secret_session_key(data_root, settings.secret_key)
    app.add_middleware(
        SessionMiddleware,
        # `itsdangerous` arrives via SessionMiddleware rather than with it. https_only follows tls_enabled so
        # the cookie
        # cannot claim a security property the transport does not provide (page-map §0).
        secret_key=secret,
        session_cookie="mypki_session",
        max_age=settings.session_max_age,
        same_site="lax",
        https_only=settings.tls_enabled,
    )

    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    templates.env.autoescape = True  # default, pinned: every value rendered below is operator input
    templates.env.globals["mypki_version"] = __version__
    templates.env.globals["csrf_field"] = csrf_field_html
    # A filter rather than formatting in each template: colon-grouping a fingerprint is one rule, and three pages
    # display
    # it. Duplicating the grouping expression is how one page ends up showing a fingerprint differently from another.
    templates.env.filters["fingerprint"] = format_fingerprint
    app.state.templates = templates

    # Registered outermost-to-innermost as listed, but Starlette applies middleware in reverse order of addition:
    # the size
    # guard is added last so it runs **first**, which is the entire point of it (see SizeGuardMiddleware).
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(
        SizeGuardMiddleware, limit_provider=lambda: _body_limit(app), render_error=_standalone_error_page
    )

    _register_error_handlers(app)
    _register_routes(app)

    log.info(
        "app ready (data_dir=%s, ca=%s, tls=%s)",
        data_root,
        "loaded" if (ca_bundle and ca_bundle.key_present) else "absent",
        settings.tls_enabled,
    )
    return app


# ------------------------------------------------------------------------------------------- error rendering


def _render_error(request: Request, status: int, reason: str, *, hint: str | None = None) -> HTMLResponse:
    """mypki's own error page (page-map §0). Never a bare JSON `detail`, never an HTML traceback.

    `debug=False` in the factory already prevents FastAPI's traceback page; this function is what makes *expected*
    failures
    readable — reason first, because "invalid CSR" is not an answer an operator can act on (see `errors.py`).
    """
    templates: Jinja2Templates = request.app.state.templates
    return templates.TemplateResponse(
        request,
        "error.html",
        {"status": status, "reason": reason, "hint": hint, "version": __version__},
        status_code=status,
    )


def _standalone_error_page(status: int, reason: str, hint: str | None = None) -> str:
    """Error HTML for a rejection that happens before any request object exists (the size guard).

    Rendered from the same template file rather than a second inline copy: two error page implementations is two
    chances for
    one of them to say something different about why it refused. `None` as the request argument is safe because
    `error.html`
    deliberately links with literal paths instead of `url_for` — it has to work when nothing resolved.
    """
    from jinja2 import Environment, FileSystemLoader, select_autoescape

    environment = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    return environment.get_template("error.html").render(
        status=status, reason=reason, hint=hint, version=__version__, standalone=True
    )


def _register_error_handlers(app: FastAPI) -> None:
    """One handler per condition, because each condition needs a different page and a different status.

    Registration order is irrelevant to dispatch (Starlette matches by exception class), but the grouping here follows
    `errors.py`: input rejections first, refusals second, missing state third. `MypkiError` — the base type — is
    registered
    last so it acts as the net rather than shadowing the specific handlers.
    """

    @app.exception_handler(CsrfValidationError)
    def on_csrf_failure(request: Request, exc: CsrfValidationError) -> HTMLResponse:
        # csrf.py already logged the failure without naming either token value. 400 and no signing performed
        # (page-map §0).
        return _render_error(
            request,
            400,
            str(exc),
            hint="Nothing was signed. Reload the page and submit again — the token is issued when the page loads.",
        )

    @app.exception_handler(CsrValidationError)
    def on_csr_validation(request: Request, exc: CsrValidationError) -> HTMLResponse:
        # The net, not the primary surface for a sign-page paste: `csr_sign_submit` catches its own step-A rejections
        # (`_paste_refused`) so the reason can sit above the box it describes, and `_generate_form` /
        # `_issue_from_confirmation` render their own forms. What reaches this handler is a validation failure raised on
        # a route with no form of its own to re-render — same status, same sentence.
        log.info("rejected input at %s: %s", request.url.path, exc.reason)
        return _render_error(request, 400, exc.reason, hint="Nothing was signed. Fix the named field and submit again.")

    @app.exception_handler(CaPrivilegeRequestedError)
    def on_ca_privilege(request: Request, exc: CaPrivilegeRequestedError) -> HTMLResponse:
        # 403 rather than 400: not a malformed request, a request mypki refuses to honour (page-map §3). As of this
        # build this handler answers **privilege claims only** — `BasicConstraints CA:TRUE`, `keyCertSign`, `crlSign`,
        # NameConstraints and any extension csr.py does not recognise. The other non-SAN extensions reach the
        # confirmation panel instead and are refused at 200 by `_consent_problems` when the box is left unticked, so a
        # dropped extension no longer looks like a refused request.
        #
        # A `/csr/sign` paste no longer reaches this handler: `csr_sign_submit` catches it and re-renders the sign page
        # with the same 403, the same reason and the same hint (`_paste_refused`). This registration is what answers a
        # privilege claim raised anywhere else.
        log.info("refused CA privilege at %s: %s", request.url.path, exc.extension)
        return _render_error(
            request,
            403,
            str(exc),
            hint=(
                f"Rejected extension: {exc.extension}. mypki sets leaf extensions itself; only SAN is read from a CSR. "
                "Extensions that ask for nothing are listed on the confirmation page, and dropped only when you tick "
                "the box there."
            ),
        )

    @app.exception_handler(KeyPolicyError)
    def on_key_policy(request: Request, exc: KeyPolicyError) -> HTMLResponse:
        log.info("rejected key policy at %s: %s", request.url.path, exc.spec)
        return _render_error(request, 400, str(exc))

    @app.exception_handler(RequestTooLargeError)
    def on_too_large(request: Request, exc: RequestTooLargeError) -> HTMLResponse:
        log.info("oversized input at %s (%d characters)", request.url.path, exc.actual)
        return _render_error(request, 413, str(exc), hint="mypki's own limit is applied before the framework's.")

    @app.exception_handler(CaNotFoundError)
    def on_ca_missing(request: Request, exc: CaNotFoundError) -> HTMLResponse:
        # 503 rather than 404: the route exists and is correct, this host just cannot answer it yet (page-map §1).
        return _render_error(
            request, 503, str(exc), hint="The web UI cannot create a CA; run `mypki init-ca` in a terminal."
        )

    @app.exception_handler(CaPassphraseError)
    def on_ca_passphrase(request: Request, exc: CaPassphraseError) -> HTMLResponse:
        return _render_error(request, 503, str(exc))

    @app.exception_handler(RevocationRecordNotFoundError)
    def on_revocation_record_missing(request: Request, exc: RevocationRecordNotFoundError) -> HTMLResponse:
        """A revoke named a serial this host has no record of: 404, not 500.

        Defect found by driving the app: with only the `MypkiError` net registered, this arrived as **500** and
        an `log.error`, i.e. mypki reported its own broken behaviour for what is really "that certificate is not in this
        database". 404 matches every other missing-thing answer here (`/download/{id}`, `/docs`), and the reason already
        names both the serial and the database file, so the operator can tell which data dir this server reads.
        Registered before the base-type net so it cannot be swallowed by it.
        """
        log.info("revoke refused at %s: no record with serial %s", request.url.path, exc.serial_hex)
        return _render_error(
            request,
            404,
            str(exc),
            hint="Nothing was changed. Use the Revoke control on the row you mean, from the Issued list.",
        )

    @app.exception_handler(OneShotExpiredError)
    def on_one_shot_expired(request: Request, exc: OneShotExpiredError) -> HTMLResponse:
        # 404 rather than a redirect back to the form: re-running generation would mint a different key behind
        # what looks
        # like the same bookmark (page-map §10).
        return _render_error(request, 404, str(exc), hint="Generate again; nothing is stored between requests.")

    @app.exception_handler(RequestValidationError)
    def on_request_validation(request: Request, exc: RequestValidationError) -> HTMLResponse:
        # FastAPI's own validation failures would answer JSON. page-map §0 promises a page for every rejection, so
        # the first
        # problem is named and rendered instead of the whole error list dumped into a body.
        errors = exc.errors()
        first = errors[0] if errors else {}
        location = ".".join(str(part) for part in first.get("loc", ()) if part != "body") or "input"
        reason = f"{location}: {first.get('msg', 'invalid value')}"
        log.info("form validation failed at %s: %s", request.url.path, reason)
        return _render_error(request, 400, reason)

    @app.exception_handler(MypkiError)
    def on_mypki_error(request: Request, exc: MypkiError) -> HTMLResponse:
        log.error("mypki error at %s: %s", request.url.path, exc)
        return _render_error(request, 500, str(exc))


# --------------------------------------------------------------------------------------------- pem responses


def _pem_response(body: str, filename: str, media_type: str = _PEM_MEDIA_TYPE) -> Response:
    """A PEM download with the headers page-map §0 requires.

    `Cache-Control: no-store` on every key/CSR/certificate body: a generated private key cached by a shared proxy,
    a browser
    profile or a disk cache is a copy of the key that mypki promised never to keep. The `.crt` name used for the
    CA download
    is deliberate — Windows' double-click installer keys off the extension (page-map §4).

    `filename` reaches this point only through `_safe_stem()` or a literal, never raw operator input: an
    unfiltered common
    name in `Content-Disposition` would be both a path-traversal hint and a header-injection vector.
    """
    return Response(
        content=body.encode("utf-8"),
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


def _ocsp_response(body: bytes) -> Response:
    """A DER OCSP response with the headers a protocol client needs, always at HTTP 200.

    `no-store` here carries the same weight as on `/crl.pem` and more: an OCSP answer is a statement about whether a
    certificate is revoked **now**, and a proxy that replays a cached GOOD for four hours keeps a revoked certificate
    trusted for the length of that cache. The singleResponse's own `nextUpdate` (+4 h, `ocsp_responder.OCSP_LIFETIME`)
    tells a client how long the answer may be reused; this header is what stops an intermediary from deciding on its
    own.

    No `Content-Disposition`: an OCSP response is consumed by a library, not saved as a file, and attaching a filename
    invites an operator to download bytes they have no way to open.
    """
    return Response(
        content=body,
        media_type=OCSP_RESPONSE_MEDIA_TYPE,
        headers={
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


def _published_crl(data_root: Path) -> CrlFacts | None:
    """Read the published CRL and report its facts, or answer None when this host has not written one.

    Read from disk rather than from what the last build remembered, because `/crl` and `/crl.pem` must describe the
    **same** artifact: a page rendering what a variable said while the file said something else would be two answers to
    "what did this CA publish?" (page-map §1). The cost is one PEM parse per request, against an artifact written only
    at startup, after a stamping batch, and on an explicit Rebuild.

    Three answers, deliberately different:
      * no file → None: "nothing published yet", which `/crl` renders as a notice carrying the Rebuild control rather
        than as an error (plan §4's startup build means this only happens when that build was skipped or failed).
      * a file that will not parse → `MypkiError` naming the path. The atomic write exists precisely to prevent this, so
        if it is seen it is this host's filesystem talking and must be said rather than rendered as "no CRL".
      * a file that parses → its facts read back from the object (`crl.summarise_crl`), `CRLNumber` included — which is
        how `/crl` shows a number it never had to hold in memory between requests.
    """
    path = paths.crl_path(data_root)
    if not path.is_file():
        return None
    try:
        return summarise_crl(read_crl_pem(path))
    except (MypkiError, ValueError) as exc:
        log.error("published CRL at %s could not be read: %s", path, exc)
        raise MypkiError(
            f"The published CRL at {path} could not be read ({exc}). Use Rebuild on /crl to sign a fresh one."
        ) from None


def _safe_stem(name: str) -> str:
    """Filesystem-safe filename stem derived from a common name.

    A CN is operator input and may contain `/`, `\\`, `..` or a character Windows reserves, so it is filtered to a known
    alphabet rather than interpolated into a header. Names that filter down to nothing fall back to "mypki": an
    empty stem
    produces a filename like `.crt`, which some browsers refuse to save at all.
    """
    allowed = [char if char.isalnum() or char in "-_" else "-" for char in (name or "").strip()]
    stem = "".join(allowed).strip("-_")[:64]
    return stem or "mypki"


async def _form_fields_multi(request: Request) -> dict[str, list[str]]:
    """A POST body where a field may legitimately appear more than once, kept as `name -> [values]`.

    Bulk revoke needs this because `/issued` posts N checkboxes all named `serial_hex`, and on
    starlette 1.10: `FormData.items()` (which `_form_fields` uses) yields **only the last** value for a repeated key
    — three boxes named `serial_hex` collapse to one. `getlist` is the accessor that does not lose them.

    A separate dependency rather than a change to `_form_fields`: every other handler in this app has exactly one
    value per field, and flattening those to lists would spread `[0]` subscripts through handlers for no reason. The
    two shapes are named differently so a reader can see which kind of form a handler takes.
    """
    form = await request.form()
    return {key: [str(value) for value in form.getlist(key)] for key in form}


def _one_of(values: Iterable[str]) -> str:
    """The single value of a field that a bulk form may also carry several times.

    Used for `csrf_token` and `reason` on `/issued/revoke`, where a browser can only send one but a hand-built POST
    could send more. Taking the first rather than the last is deliberate: for a CSRF token the pair (session, token)
    has to match, and "the first token in the body" is what a form rendered by this app actually contains.
    """
    for value in values:
        return value
    return ""


async def _form_fields(request: Request) -> dict[str, str]:
    """Parse a multipart/urlencoded body into plain strings, once, for sync handlers to read.

    A dependency rather than inline parsing because the handler functions are `def` (module docstring): a sync
    handler cannot
    await `request.form()`, and duplicating parse-and-flatten code in each POST handler is how one of them ends up
    forgetting
    a field. Injected via `Annotated[..., Depends(...)]` rather than `Depends()` in an argument default so the
    project needs no
    `B008` ruff ignore (STYLE §11).

    Values are flattened to `str` and non-string parts (an uploaded file part, should one ever appear) are
    stringified rather
    than rejected: mypki has no upload field, and a str() is the cheapest way to keep a stray part from becoming a
    TypeError
    deep inside a validator. The size guard already ran before this point (SizeGuardMiddleware), so nothing large
    reaches here.
    """
    form = await request.form()
    return {key: str(value) for key, value in form.items()}


def _without_secrets(form: dict[str, str]) -> dict[str, str]:
    """The submitted form minus the passphrase fields, for re-populating a page after output.

    Re-populating is deliberate — losing what an operator typed in eight fields because one of them was wrong is
    how people
    stop using a tool. Dropping `passphrase` and `confirm` is equally deliberate: echoing a passphrase back into a
    rendered
    form is how it lands in a browser's autofill store and in whatever cached the page.
    """
    return {key: value for key, value in form.items() if key not in ("passphrase", "confirm")}


async def _raw_body(request: Request) -> bytes:
    """The request body as bytes, for a handler that is not a form.

    A dependency for the same reason `_form_fields` is one: mypki's handlers are `def` (module docstring), so a handler
    cannot `await request.body()` itself. `/ocsp` is the only route that needs this — every other POST in the app is a
    form, and a DER body must **not** be run through `request.form()`, which would treat an OCSP request as multipart
    text and corrupt it before any parser saw it.

    `SizeGuardMiddleware` has already measured and buffered the body by this point (it is added last so it runs first),
    so this reads a replay rather than a live socket, and whatever arrives here is at most `max_csr_chars + 8192` bytes.
    """
    return await request.body()


def _client_ip(request: Request) -> str:
    """Source address for log lines. page-map §0 logs the source IP and no other client data."""
    if request.client is None:
        return "unknown"
    return request.client.host


def _body_limit(app: FastAPI) -> int:
    """Body cap for a POST, derived from `max_csr_chars` rather than invented as a second constant.

    The largest thing any mypki form can legitimately carry is a max-size CSR plus the small fields that accompany
    it (cert
    type, validity days, the CSRF token). Adding headroom to one documented knob beats a second knob nobody reads: two
    constants would be two answers to "how big may a request be?", and the drift between them is invisible until a
    legitimate
    request starts being refused.
    """
    return app.state.settings.max_csr_chars + 8192


# ---------------------------------------------------------------------------------- inline form-error plumbing


def _form_values(form: Mapping[str, object] | None) -> dict[str, str]:
    """The submitted fields as strings, ready for a template to put back into its inputs.

    `str(...)` rather than a type check because `_form_fields` already flattens everything and a re-rendered form must
    never print `None` into a value attribute: an input showing the four characters `None` is what an operator reads as
    "the page forgot my value", when the page in fact faithfully reproduced an absent field.
    """
    if form is None:
        return {}
    return {key: "" if value is None else str(value) for key, value in form.items()}


def _sans_text(sans: SanSet | None) -> str:
    """A SAN set back into the textarea spelling one entry per line.

    Prefilling a form from a parsed object needs the inverse of `parse_sans`, and it has to be the *inverse* rather than
    a plausible rendering: DNS first then IP is the order `all_entries()` displays on every page, so what comes back out
    of an edited form reads the same way it was shown.
    """
    if sans is None:
        return ""
    return "\n".join(sans.all_entries())


def _subject_defaults(settings: Settings) -> dict[str, str]:
    """The Generate-CSR form's pre-filled values, for a form nobody has submitted yet (page-map §2).

    `values=` is deliberately shaped like a submitted form rather than like settings: the template has exactly one way
    to fill an input (`values.get('organization', '')`), and giving it a second mechanism for the first visit is how one
    of the two paths ends up ignoring a knob. Empty defaults render as empty inputs, which is what "no default" is
    supposed to look like.
    """
    return {
        "organization": settings.default_organization or "",
        "organizational_unit": settings.default_organizational_unit or "",
        "country": settings.default_country or "",
        "state": settings.default_state or "",
        "locality": settings.default_locality or "",
        "email": settings.default_email or "",
        "key_type": "rsa-3072",
    }


def _edited_subject_fields(
    form: Mapping[str, object],
    *,
    max_sans: int,
) -> tuple[x509.Name | None, SanSet | None, list[str]]:
    """Validate the confirmation page's editable fields into a subject and a SAN set.

    Returns `(subject, sans, problems)`; `problems` is empty when both built cleanly, and nothing is signed in that
    case. Every rule here is a rule from `validators.py` — the same `parse_sans`, `validate_common_name`,
    `validate_country`, `validate_email` and `validate_printable_field` the Generate-CSR form runs — because an edited
    field is operator input again, and a second implementation of "what is a valid country" is how one page starts
    accepting what the other refuses (page-map §9).

    Problems are **collected** rather than raised on the first: the confirmation page shows every field the operator can
    still fix in one reload, and a form that reports one mistake per submission turns a six-field edit into six reloads.

    This function sees only the submitted fields. Which staged request those fields belong to is decided by
    `_staged_pem_id` at the call site — a helper that validates a text field has no business resolving a `?pending=` id,
    and taking a `Request` here would invite it to start doing so.
    """
    problems: list[str] = []

    def check(label: str, value: str | None, validate: Any) -> str | None:
        try:
            return validate(value)
        except CsrValidationError as exc:
            problems.append(f"{label}: {exc.reason}")
            return None

    common_name = check("common name", _text_of(form, "common_name"), validate_common_name)
    organization = check(
        "organization",
        _text_of(form, "organization"),
        lambda value: validate_printable_field(value, "organization"),
    )
    organizational_unit = check(
        "organizational unit",
        _text_of(form, "organizational_unit"),
        lambda value: validate_printable_field(value, "organizational_unit"),
    )
    country = check("country", _text_of(form, "country"), validate_country)
    state = check("state", _text_of(form, "state"), lambda value: validate_printable_field(value, "state"))
    locality = check("locality", _text_of(form, "locality"), lambda value: validate_printable_field(value, "locality"))
    email = check("email", _text_of(form, "email"), validate_email)

    sans: SanSet | None = None
    try:
        # The same cap the sign page states next to its validity input (`MYPKI_MAX_SANS`), so a 200-line edit is refused
        # by the limit an operator can raise in `.env` rather than by a second number invented here.
        sans = parse_sans(_text_of(form, "sans"), max_sans)
    except CsrValidationError as exc:
        problems.append(f"subject alternative names: {exc.reason}")

    if problems:
        return None, None, problems

    assert common_name is not None  # validate_common_name returns None only by rejecting an empty value
    fields = CsrFields(
        common_name=common_name,
        sans=sans if sans is not None else SanSet(),
        organization=organization,
        organizational_unit=organizational_unit,
        country=country,
        state=state,
        locality=locality,
        email=email,
    )
    return subject_from_fields(fields), fields.sans, []


def _staged_pem_id(request: Request) -> str | None:
    """Which staged request this POST means: the `?pending=` id it was given, or the session's (page-map §3).

    The confirm form carries no copy of the CSR — what gets signed must be byte-identical to what was validated, so the
    bytes stay in this process and only an opaque id travels. A browser submits the action URL's query string with the
    POST, so a `?pending=` form action survives a round trip that a session cookie might not (a rejected edit re-renders
    this page, and losing the staged request there would throw away the paste the operator is trying to fix).

    The id is looked up in the one-shot store rather than used as a path or a name, so a `?pending=` value cannot reach
    anything except this process's own expiring artifacts — and an unknown one raises `OneShotExpiredError`, which has
    its own 404 page.
    """
    pending = request.query_params.get("pending")
    if pending:
        return pending
    return request.session.get(SESSION_CSR_ID)


def _text_of(form: Mapping[str, object], key: str) -> str | None:
    value = form.get(key)
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _consent_given(form: Mapping[str, object]) -> bool:
    """Did this confirm POST tick the box that consents to dropping extensions (page-map §3 rule 6)?

    `CONSENT_FIELD in form` and nothing else. A browser submits a ticked checkbox and submits **nothing** for an
    unticked one, so absence is the default-OFF state at the HTTP layer: no value means "consent" other than the one a
    box rendered next to the extensions it names produces.

    Deliberately not truthiness on the value. `?ignore_extensions=` with an empty value, or a hand-built POST naming the
    field with garbage, would then read as consent from a page that never asked — and the whole point of the box is that
    somebody saw the list first. A checkbox whose value has to be one of a known set is the same shape `settings.html`
    uses for its own on/off controls (`value="true"`), which is why the accepted spellings here are the ones a form this
    app built can actually produce.
    """
    if CONSENT_FIELD not in form:
        return False
    value = str(form.get(CONSENT_FIELD) or "").strip().lower()
    return value in ("1", "true", "on", "yes")


def _consent_problem(dropped: Sequence[str]) -> str:
    """The sentence a confirmation page shows when the box was left unticked.

    Names every extension at stake, because the operator has to be able to see what they are deciding about — a refusal
    that says "some extensions were not accepted" cannot be acted on. The wording is deliberately *not* the 403 wording:
    nothing here is refused, one box needs ticking (page-map §3, `ERROR_SURFACE_RULE`).
    """
    return (
        f"consent to dropped extensions: this request carries {', '.join(dropped)} and mypki does not copy any "
        "extension from a CSR. Tick the box below to issue anyway with those extensions dropped, or remove them from "
        "your request. Nothing was signed."
    )


def _dropped_extension_fields(dropped: Sequence[str]) -> list[tuple[str, str]]:
    """`(label, value)` rows for the extensions this CA did not copy, shaped like the name-edit diff.

    Same block on the issued page because they are the same kind of fact: something in your request is not in the
    certificate you are about to install (page-map §3). Walking a silent difference back needs a client that consults
    this CA's CRL or OCSP, and a leaf carrying no pointer gives the operator nothing to consult,
    so "I asked for `BasicConstraints CA:FALSE` and got mypki's own profile" has to be as visible as "you renamed the
    organization". One row per extension rather than one joined row, because a `<dl>` entry is what makes each dropped
    item findable when somebody later diffs this certificate against their openssl config.
    """
    return [(f"Extension not copied: {name}", "set by mypki instead") for name in dropped]


def _subject_edit_submitted(form: Mapping[str, object]) -> bool:
    """Did this confirm POST actually submit the editable fields?

    `in form` rather than a truthiness test, because an empty string is an edit: clearing `O=` is how you remove an
    attribute from a certificate, and treating "" as "the field was not submitted" would silently re-issue the request's
    own value instead of the removal the operator asked for.
    """
    return any(key in form for key in _SUBJECT_KEYS) or "sans" in form


def _confirmation_prefill(details: Any) -> dict[str, str]:
    """The confirm form's initial values: the request's own subject and SANs, as editable text (page-map §3 step B).

    Prefilling from `details` rather than leaving the fields blank is what makes an edit *deliberate*: the operator sees
    `O=Lab` in a box and can decide to change it, instead of submitting an empty field that silently drops an attribute
    the request carried. Blank boxes here would be indistinguishable from "this request had no organization", which is
    exactly the confusion `_changed_subject_fields` exists to prevent.

    `sans` uses `_sans_text`, the inverse of `parse_sans`, so what appears in the textarea is the same spelling the
    panel above it displays and the same spelling a re-rendered error page will send back.
    """
    values = {key: details.subject.get(key) or "" for key in _SUBJECT_KEYS}
    values["sans"] = _sans_text(details.sans)
    return values


#: The subject fields the confirm form exposes, in the order `csr._subject_dict` produces them. One list rather than six
#: literals repeated in the prefill, the diff and the revoke-free path: a field added here is prefilled, compared and
#: reported by the same edit.
_SUBJECT_KEYS = ("common_name", "organization", "organizational_unit", "country", "state", "locality", "email")

#: The ignorable-extension names `csr.py` puts on `CsrDetails.ignored_extensions`, restated here as the shape this app's
#: own CSR never produces: `build_csr` adds SAN and nothing else, so a request mypki generated carries an empty list and
#: renders no consent box at all. Written down because "the box is missing" is otherwise indistinguishable from "the box
#: was removed".
#: (The names themselves live in `csr._csr_extension_problems`, which is the only place that decides them.)

#: `secret_key` is the one knob `/settings` renders as a presence flag instead of a value.
#:
#: It signs the session cookie, so printing it would hand a way to forge sessions to anything that can read this page —
#: including a browser history, a proxy log or a screenshot posted in a support ticket. On a host with no logins
#: (page-map
#: §0), "the settings page shows the signing secret" is the single sentence that turns an observability feature into a
#: compromise of every other control on this app: the CSRF token lives inside a session this key authenticates.
SECRET_KNOB = "secret_key"


def _unmanaged_card(settings: Settings) -> list[dict[str, Any]]:
    """The 'Not editable here' card: one row per `UNMANAGED_KEYS` knob, its presence, and why it is not a text box.

    This card is more than "a reason list beside the form": it is also "the place stating what each knob currently
    is", because the resolved-state table it replaces used to carry those presence flags and removing the table
    without relocating them would have made `MYPKI_SECRET_KEY` *less* observable, which is the opposite of why the
    card exists. An operator has to be able to tell "a secret exists" from "no secret was set", or the page is a
    mystery rather than an observability tool (`test_no_key_leakage.py` asserts both strings from outside).

    Presence, never value: `secret_key` renders as a flag and both `ssl_*` render as "set (path not displayed)" —
    naming a TLS private key's path on a page with no logins is how a path ends up in a screenshot. No CA or
    instance file path is consulted here at all: `paths.ca_key_path` and `paths.secret_key_path` do not appear in
    this function, which is what `test_no_key_leakage.py` proves by fetching `/settings`.
    """
    rows: list[dict[str, Any]] = []
    for name in UNMANAGED_KEYS:
        value = getattr(settings, name, None)
        if name == SECRET_KNOB:
            presence = _SECRET_KEY_PRESENT if value else _SECRET_KEY_ABSENT
        elif name in ("ssl_certfile", "ssl_keyfile"):
            presence = "set (path not displayed)" if value else "not set — plain HTTP"
        else:  # config_dir: the directory this page's own file lives in, which the page already names out loud.
            presence = str(config_file_path(settings).parent)
        rows.append({"knob": f"MYPKI_{name.upper()}", "presence": presence, "reason": unmanaged_reason(name)})
    return rows


_SECRET_KEY_PRESENT = "set (value not displayed)"
_SECRET_KEY_ABSENT = "unset — mypki generated one into the data dir at startup (not displayed)"


# --------------------------------------------------------------------- the editable form's metadata

#: The sections `/settings` renders, in page order. Names must be `Settings` fields; `_settings_sections` refuses a
#: name it does not know and refuses to leave one out, so a knob added to `config.py` cannot become invisible on the
#: page — which is the same reason `_settings_rows` iterates the model rather than copying it.
SETTINGS_SECTIONS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Serving", ("host", "port", "public_base_url", "crl_base_url")),
    ("Storage", ("data_dir",)),
    ("Root CA defaults", ("ca_cn", "ca_default_days")),
    (
        "Issuing limits",
        ("validity_default_days", "validity_max_days", "max_sans", "max_csr_chars", "session_max_age"),
    ),
    (
        "CSR subject defaults",
        (
            "default_organization",
            "default_organizational_unit",
            "default_country",
            "default_state",
            "default_locality",
            "default_email",
        ),
    ),
    ("Logging", ("log_level", "log_file", "log_max_bytes", "log_backup_count", "log_to_console")),
)

#: Knobs this page cannot make live, because the object that consumed them was built before the form existed.
#:
#: `host`/`port` are uvicorn's bind; `session_max_age` (with `secret_key` and `https_only`) is baked into the
#: SessionMiddleware instance `create_app` adds once; `data_dir` decided where the SQLite handle, the CA lookup and the
#: instance secret were opened. Everything else — every issuing limit, every CSR subject default, the CA defaults and
#: all five logging knobs — is read from `app.state.settings` per request, or re-applied by `configure_logging`, so as
#: of this build a successful save publishes a fresh `Settings`, and those values apply from the next request onward.
#:
#: The logging knobs belong here only while there is no way to re-run `logsetup.configure_logging`; that is why this
#: set used to be nine deep and is four. Keeping a knob in this list when it *is* live would tell an operator to reboot
#: a working service, which is worse than the ambiguity it was written to remove.
STARTUP_ONLY_KNOBS: frozenset[str] = frozenset({"host", "port", "session_max_age", "data_dir"})

#: Preset values offered as a dropdown for the Issuing limits, in page order. A **menu, not a policy**:
#: `config.py`'s own `Field(ge=…, le=…)` is still the rule — `_knob_input` filters these against the very `Ge`/`Le`
#: objects pydantic enforces, and the box that Custom reveals carries them as `min`/`max`. A preset outside a knob's
#: bounds is therefore not just dropped here, it could not be constructed at startup either.
#:
#: The lists are the values an operator plausibly means (a quarter-, half- and one-year leaf; the SAN caps that fit a
#: host with a few names up to a busy internal service; CSR sizes around the ~2.5 KB a 4096-bit RSA request costs).
#: The last entry of every dropdown is `Custom`, which reveals a free number box — without it a dropdown would be a
#: smaller version of the same text box, and a knob whose only honest answer is 7 would have nowhere to put it.
KNOB_PRESETS: dict[str, tuple[int, ...]] = {
    "validity_default_days": (30, 90, 180, 365, 730, 1095, 1461),
    "validity_max_days": (30, 90, 180, 365, 730, 1095, 1461),
    "max_sans": (1, 5, 10, 25, 50, 100, 250, 500, 1000),
    "max_csr_chars": (4096, 16384, 32000, 65536, 131072, 262144),
    # Included although it is startup-only: `session_max_age` sits in the Issuing-limits section and an operator who
    # reaches for it is reaching for "how long may a half-finished signing survive a closed browser", which is the same
    # question the other four answer. The red marker beside it is what says a change here needs a reboot.
    "session_max_age": (300, 900, 1800, 3600, 14400, 43200, 86400),
}

#: The option every dropdown ends with. It carries no value of its own: choosing it is what reveals the number box.
CUSTOM_CHOICE = "custom"


def _first_sentences(text: str, limit: int = 190) -> str:
    """The opening sentences of a `Field(description=…)`, cut at a sentence boundary.

    The hint line under an input has to come from config.py rather than be written again here, for the reason the whole
    settings layer keeps repeating: a second copy of a description is a document that rots. Taking the first sentences —
    never mid-word — means the page can be narrow without lying about what the knob does; the full text stays in the
    resolved-state table below the form.
    """
    cleaned = " ".join((text or "").split())
    if not cleaned:
        return ""
    parts = cleaned.split(". ")
    out = parts[0]
    for part in parts[1:]:
        if len(out) + len(part) + 2 > limit:
            break
        out = f"{out}. {part}"
    if not out.endswith("."):
        out = f"{out}."
    return out


def _preset_choices(name: str, minimum: int | None, maximum: int | None) -> tuple[int, ...]:
    """The dropdown values for one knob, filtered against `config.py`'s own bounds.

    Filtering rather than trusting the table: `KNOB_PRESETS` is written by a human and `Field(ge=…, le=…)` is what
    pydantic enforces, so the pair is checked here instead of being assumed consistent. A preset that fell outside the
    bounds would render an option the server refuses to save, which is a page that always errors for one click.
    """
    return tuple(
        value
        for value in KNOB_PRESETS.get(name, ())
        if (minimum is None or value >= minimum) and (maximum is None or value <= maximum)
    )


def _knob_input(
    name: str,
    settings: Settings,
    overrides: Mapping[str, str] | None = None,
    saved_values: Mapping[str, str] | None = None,
    live_display: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """One editable field: what kind of input it is, its bounds, its current value and the line under it.

    Bounds come from `Settings.model_fields[name].metadata` — the very `Ge`/`Le` objects pydantic enforces at
    startup — so an `<input min max>` cannot promise a range `config.py` does not implement. That matters most for
    the two knobs whose bounds are load-bearing security posture (`MYPKI_VALIDITY_MAX_DAYS`, `MYPKI_MAX_CSR_CHARS`):
    a page that let an operator type 3650 into a box capped at 1461 would be a page that always errors.

    Which value goes in the box, and why that rule changed:

      * `overrides` (a rejected save, or a save this process could not adopt) wins over everything -- the operator must
        see what they typed, not what the server kept;
      * for a knob in `STARTUP_ONLY_KNOBS`, the box now shows **what was just saved** (`saved_values`, read out of
        `<config>/mypki.env` by `settingsfile.read_saved_values`) whenever that differs from what this process is
        running, and the field carries `pending_saved` with it so the template can say so in rose. Earlier these
        four boxes showed the live value, which was defensible -- the box then matched the bind -- but it made a Save
        look like it had done nothing, and the operator's own report was "I typed 8444, the box still says 8443". The
        input now states the file's truth and the sentence beside it states the process's truth; both are on screen at
        once instead of one being inferred from the absence of the other.
      * for every other knob the box shows what this process resolved, exactly as before: a shell variable that beat
        the saved file must not be silently written back over by a Save, and for a live knob those two values are the
        same value anyway.

    `live_display` covers the knobs whose live value is not simply `getattr(settings, name)`: `data_dir` is None on a
    host running mypki's OS default, so "this process is still running nothing" would be a sentence about a field
    rather than about the server. `render_settings` passes the resolved data directory here for exactly that reason.
    """
    model_field = Settings.model_fields[name]
    annotation = str(model_field.annotation)
    live = getattr(settings, name)
    kind = "text"
    if "bool" in annotation:
        kind = "checkbox"
    elif "int" in annotation:
        kind = "number"

    minimum = maximum = None
    for constraint in model_field.metadata:
        text = repr(constraint)
        if text.startswith("Ge("):
            minimum = getattr(constraint, "ge", None)
        elif text.startswith("Le("):
            maximum = getattr(constraint, "le", None)

    hint = _first_sentences(model_field.description or "")
    if minimum is not None and maximum is not None:
        hint = f"{hint} Allowed range: {minimum} to {maximum}."
    elif minimum is not None:
        hint = f"{hint} Minimum: {minimum}."
    elif maximum is not None:
        hint = f"{hint} Maximum: {maximum}."
    if name in STARTUP_ONLY_KNOBS:
        hint = f"{hint} Read once at startup — saved for the next start, not applied to this one."

    # `overrides` is the only reason an input ever shows something other than the live value: a rejected save puts
    # back what was typed, and a successful one shows the file that was just written. Both are spelled in the
    # form's own vocabulary (`true`/`false`, empty for unset) so a re-render never turns "console only" into the
    # word `None`.
    knob_name = f"MYPKI_{name.upper()}"
    override = None if overrides is None else overrides.get(knob_name)
    saved = None if saved_values is None else saved_values.get(knob_name)

    # The startup-only knobs show the file's value when the file and the process disagree, because that disagreement IS
    # the state an operator is trying to understand. `pending` is what the template renders in rose; it stays False
    # when the saved line agrees with what is running (there is nothing to announce) and when a shell variable or a CLI
    # flag outranks the file -- in that case the box showing the live value is the honest answer, and `overrides` is not
    # involved because this is a plain GET. See `_pending_saved_value` for the whole rule and its exceptions.
    pending = _pending_saved_value(name, knob_name, saved, live, override, settings)
    if pending is not None:
        text_value = pending
    elif kind == "checkbox":
        checked = bool(live)
        text_value = "true" if checked else "false"
    elif override is not None:
        text_value = override
    elif live is None:
        text_value = ""
    else:
        text_value = str(live)

    if kind == "checkbox":
        checked = text_value.strip().lower() in ("true", "1", "yes", "on")

    # A checkbox needs a real boolean (the template tests it for `checked`); every other input needs the text.
    value: object = checked if kind == "checkbox" else text_value

    # Dropdowns, Issuing limits only. The choice list is filtered against this knob's own `ge`/`le`, and the
    # number box stays rendered whatever the menu says — see `_preset_choices` for why a menu is convenience and not
    # policy. A value that is live but not in the preset list selects `Custom` on its own, so a host running 7 SANs
    # still shows 7 rather than being silently rounded to the nearest preset.
    choices = _preset_choices(name, minimum, maximum) if kind == "number" else ()
    is_custom = bool(choices) and text_value not in {str(choice) for choice in choices}

    # What the process is *actually* running, spelled for a sentence rather than for an input. `live_display` first
    # because `data_dir`'s field value and its resolved value are different facts; `str(live)` next; an empty string
    # means "this process has no value for this knob", which the template words as "unset here".
    live_text = None
    if live_display is not None:
        live_text = live_display.get(name)
    if live_text is None:
        live_text = "" if live is None else str(live)

    return {
        "name": name,
        "knob": f"MYPKI_{name.upper()}",
        "kind": kind,
        "value": value,
        "text_value": text_value,
        "min": minimum,
        "max": maximum,
        "hint": hint,
        "startup_only": name in STARTUP_ONLY_KNOBS,
        "choices": choices,
        "custom": is_custom,
        # The pair the restart-only boxes show together -- the saved value sitting in the input, and the
        # value this process is still honouring. Both are rendered whenever `pending_saved` is true; both are None
        # otherwise, so a template that renders them unconditionally would print empty strings on ordinary fields.
        "pending_saved": pending is not None,
        "saved_value": pending,
        "live_value": live_text if pending is not None else None,
    }


def _pending_saved_value(
    name: str,
    knob_name: str,
    saved: str | None,
    live: object,
    override: str | None,
    settings: Settings,
) -> str | None:
    """The value to put in a restart-only knob's box, or None when the box should show the live value.

    Four rules, in the order they are applied, each one closing a way this could mislead:

      1. `name not in STARTUP_ONLY_KNOBS` -> None. Every other knob is re-read per request, so "saved but not applied"
         cannot happen for it and a marker there would be a lie about a knob that did apply.
      2. `override is not None` -> None. A rejected save, or a save this process could not adopt, already shows what was
         typed; the pending line would then describe a value that never reached the file at all.
      3. `saved is None` -> None. A host that has never saved anything (or whose file has no line for this knob) has
         nothing pending, and rendering an empty box would look like the operator cleared it.
      4. `saved == live_text` -> None. When the file agrees with the running process there is no disagreement to
         explain, and a rose marker on every startup-only knob would train an operator to ignore it.

    The comparison is textual on purpose: these values arrive as text from the file and as typed text from the form, and
    `8543` against `8543` is the question. A numeric comparison would need per-knob parsing -- for a knob this module
    deliberately does not parse, since `validate_candidate` in `settingsfile.py` is where bounds live.

    `settings` is not read here; it is carried so this function's signature matches the call site's data and so a future
    rule that needs another resolved value (a default, a bound) has the object to ask. Keeping it now costs one unused
    parameter and avoids the version of this call site that reaches for `Settings()` again mid-render.
    """
    if name not in STARTUP_ONLY_KNOBS:
        return None
    if override is not None or saved is None:
        return None
    live_text = "" if live is None else str(live)
    if saved == live_text:
        return None
    return saved


#: Field names whose annotation is `bool`. A checkbox that is unticked submits **nothing** — that is how HTML forms
#: work — and a dotenv file with the key absent means "mypki's default", not "false". So the save layer has to turn
#: "the box was not ticked" into an explicit `false`, or unticking "log to console" would silently revert to the
#: default instead of turning the feature off.
_BOOL_FIELDS: frozenset[str] = frozenset(
    name for name in editable_field_names() if "bool" in str(Settings.model_fields[name].annotation)
)


def _submitted_settings_fields(form: Mapping[str, list[str]]) -> dict[str, str]:
    """The posted `MYPKI_*` field names back into `Settings` field names, with checkboxes made explicit.

    The form speaks the spelling an operator types in a shell (`MYPKI_PORT`) because that is the spelling every
    mypki document uses and the one `<config>/mypki.env` carries; `validate_candidate` speaks field names because
    that is what pydantic's model, its `Field` bounds and its error messages are keyed by. This function is the only
    place that knows both.

    Unknown `MYPKI_*` names in the body are ignored rather than refused: a browser extension or a hand-built POST
    adding a knob this page never rendered should not be able to write it into the file, and `model_config`'s
    `extra="ignore"` is the same posture at startup.
    """
    fields: dict[str, str] = {}
    for name in editable_field_names():
        knob = f"MYPKI_{name.upper()}"
        values = form.get(knob)
        if values is None:
            # A checkbox submits nothing when unticked; every other control submits at least an empty string.
            fields[name] = "false" if name in _BOOL_FIELDS else ""
            continue
        raw = _one_of(values)
        fields[name] = raw
    return fields


def _settings_sections(
    settings: Settings,
    overrides: Mapping[str, str] | None = None,
    saved_values: Mapping[str, str] | None = None,
    live_display: Mapping[str, str] | None = None,
) -> list[dict[str, Any]]:
    """The form's sections. Two refusals make this safe to keep as a table rather than a checklist.

    A name in `SETTINGS_SECTIONS` that is not a `Settings` field raises (a typo would render an input that saves
    nothing), and an editable field that appears in no section raises too — the failure being a knob that quietly
    stops being editable. Both are louder than a missing box on a page nobody scrolls to the bottom of.
    """
    listed = [name for _, fields in SETTINGS_SECTIONS for name in fields]
    unknown = [name for name in listed if name not in Settings.model_fields]
    if unknown:
        raise RuntimeError(f"SETTINGS_SECTIONS names non-knob(s): {', '.join(unknown)}")
    missing = sorted(set(editable_field_names()) - set(listed))
    if missing:
        raise RuntimeError(f"SETTINGS_SECTIONS omits editable knob(s): {', '.join(missing)}")
    return [
        {
            "title": title,
            "fields": [_knob_input(name, settings, overrides, saved_values, live_display) for name in fields],
        }
        for title, fields in SETTINGS_SECTIONS
    ]


def _settings_status(
    settings: Settings, data_root: Path, log_file: Path | None, cli_overrides: Mapping[str, object]
) -> list[dict[str, Any]]:
    """The read-only panel inside the Storage section: label left, value right, colour from the state itself.

    Five rows. Four answer the four questions a settings page is asked out loud — what directory is in use, where logs
    actually go, whether this is HTTP or HTTPS, and which file Save writes to — and the fifth answers "where did that
    directory come from", which is the one provenance an operator acts on.

    The fifth row is why `_settings_source` survived the resolved-state table it used to fill. That table stated
    a source for all twenty-odd knobs, most of them a fact nobody could act on; this row states the one whose answer
    changes what you do next (a shell variable beating your saved file), and the note under the panel then says plainly
    what no label can say.

    `cli_overrides` is what `mypki serve` was handed as flags. Naming it here is what lets the panel admit that a value
    in force may have arrived from the command line rather than from the file this page writes — the old panel hinted
    at that, because the flags were folded into `Settings` and then forgotten.
    """
    rows = [
        {
            "label": "Data directory (resolved)",
            "value": str(data_root),
            "state": "ok",
        },
        {
            "label": "Log file (resolved)",
            "value": str(log_file) if log_file else "console only — MYPKI_LOG_FILE is empty",
            "state": "ok" if log_file else "warn",
        },
        {
            "label": "Serving",
            "value": "TLS" if settings.tls_enabled else "plain HTTP",
            "state": "ok" if settings.tls_enabled else "warn",
        },
        {
            "label": "Settings file (written by Save)",
            "value": str(config_file_path(settings)),
            "state": "ok",
        },
    ]
    origin = _settings_source(settings, "data_dir")
    if cli_overrides.get("data_dir"):
        origin = "set by a `mypki serve` flag"
    rows.append({"label": "Data directory came from", "value": origin, "state": "ok"})
    return rows


def _cli_overrides(app: FastAPI) -> Mapping[str, object]:
    """`create_app`'s `cli_overrides`, read defensively so an embedder that never set it still renders."""
    value = getattr(app.state, "cli_overrides", None)
    return value if isinstance(value, Mapping) else {}


def _publish_saved_settings(app: FastAPI, previous: Settings) -> Settings:
    """Rebuild `Settings` from the layers on disk and make this process use them (hot-reload).

    Why a rebuild rather than patching the live object: `validate_candidate` has already constructed and validated a
    `Settings` from exactly these values, so re-reading the file is not a new risk — it is the same construction the
    next `mypki serve` would perform, performed now. Patching fields in place would skip the model validators that keep
    `validity_default_days <= validity_max_days` true, and a live object violating its own model is worse than a save
    that needs a reboot.

    Precedence is preserved rather than approximated: the dotenv layers are named through
    `settingsfile.env_file_layers` (`./.env` then `<config>/mypki.env`, later wins) exactly as `get_settings` names
    them, and whatever `mypki serve` was given as flags is re-applied on top, so a save cannot silently outrank the
    command line that started this process. That is why `create_app` keeps `app.state.cli_overrides`.

    Raises whatever pydantic raises. The caller decides how to say it: a file that became unreadable between the Save
    and now is a real state change, and "saved, but this process did not adopt it" is the honest sentence.

    `STARTUP_ONLY_KNOBS` are re-pinned from the settings this process started with, and this is the load-bearing line.
    Without it a rebuild would put `port=8543` into `app.state.settings` on a server still listening on 8443, and every
    page that quotes "what this host is running" — the status panel, `/about`, the log lines — would then be describing
    a bind that never happened. The file records what the operator asked for; the live object keeps only what this
    process can actually honour, which is exactly what the red marker on those four knobs is telling the reader.
    """
    overrides = dict(getattr(app.state, "cli_overrides", {}) or {})
    pinned = {name: getattr(previous, name) for name in STARTUP_ONLY_KNOBS}
    fresh = Settings(_env_file=env_file_layers(previous), **{**overrides, **pinned})  # type: ignore[call-arg]
    app.state.settings = fresh
    # The logging knobs are live because `configure_logging` is idempotent and drops the handlers it installed before
    # re-installing them (`logsetup._MANAGED_ATTR` / `_drop_managed_handlers`). It also carries its own degradation:
    # a log path that has become unwritable warns once and falls back to console rather than raising here, which is
    # why a successful Save never turns into a red block because of a disk problem.
    configure_logging(fresh)
    return fresh


def _changed_subject_fields(
    request: Mapping[str, object],
    details: Any,
    sans: SanSet | None,
) -> list[tuple[str, str]]:
    """`(label, new_value)` for every subject field the operator edited away from what the request said.

    The comparison is against the **parsed CSR** (`details.subject` / `details.sans`) and not against what the form was
    prefilled with, because those can already differ: a prefill comes from the request, an edit changes it, and the
    thing worth reporting is "the certificate now says something your request did not". Blank means "no such attribute",
    which makes removing `O=` visible instead of looking like a field that was never there.

    This list is what page-map §3 owes the operator for the freedom `signing.py` grants: an edit nobody noticed is a
    mis-issuance, and walking it back needs a client that consults the published CRL or OCSP.
    """
    fields = (
        ("Common name", "common_name", _text_of(request, "common_name"), details.subject.get("common_name")),
        ("Organization", "organization", _text_of(request, "organization"), details.subject.get("organization")),
        (
            "Organizational unit",
            "organizational_unit",
            _text_of(request, "organizational_unit"),
            details.subject.get("organizational_unit"),
        ),
        ("Country", "country", _upper_or_none(_text_of(request, "country")), details.subject.get("country")),
        ("State", "state", _text_of(request, "state"), details.subject.get("state")),
        ("Locality", "locality", _text_of(request, "locality"), details.subject.get("locality")),
        ("Email", "email", _text_of(request, "email"), details.subject.get("email")),
    )

    changed: list[tuple[str, str]] = []
    for label, _, submitted, requested in fields:
        if submitted != requested:
            changed.append((label, submitted or "(removed)"))

    # SANs compare as sets rather than as text: `parse_sans` lowercases DNS entries and dedupes, so re-typing the same
    # names in a different order or case is not a change to what this CA vouched for, and reporting it as one would
    # train
    # an operator to ignore the warning.
    issued = sans if sans is not None else details.sans
    if set(issued.all_entries()) != set(details.sans.all_entries()):
        changed.append(("Subject alternative names", ", ".join(issued.all_entries()) or "(none)"))
    return changed


def _upper_or_none(value: str | None) -> str | None:
    """`validate_country` uppercases, so a prefill of `au` against an edit of `AU` is not a change."""
    return value.upper() if value else None


def _revoke_reason(value: object) -> str | None:
    """The optional revoke note, capped at `MAX_REVOCATION_REASON_LENGTH` (page-map §5).

    Capped rather than refused: the reason is operator prose attached to a record that already exists, and refusing a
    121-character note would mean no revocation gets recorded at all — which loses the fact while protecting nothing.
    The cap is the one this table's column declares, so what is stored is what the column can hold.
    """
    text = str(value or "").strip()
    if not text:
        return None
    return text[:MAX_REVOCATION_REASON_LENGTH]


# --------------------------------------------------------------------- bulk-revoke plumbing (page-map §5)


def _selected_serials(values: Iterable[str]) -> list[str]:
    """The checkboxes a submit carried, as clean lowercase serials, in the order they arrived, de-duplicated.

    Three rules that all exist to stop a checkbox list becoming a way to stamp the same row twice:
      * values are lowercased and stripped, because `store.revoke` addresses rows by the lowercase hex it wrote;
      * duplicates collapse — a select-all plus a hand-ticked row must not count as two revocations of one certificate;
      * order is preserved so the confirmation page names certificates in the order the operator read them.
    """
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        serial_hex = (value or "").strip().lower()
        if not serial_hex or serial_hex in seen:
            continue
        seen.add(serial_hex)
        ordered.append(serial_hex)
    return ordered


def _pending_revoke(serial_hex: str, store: IssuedStore) -> dict[str, Any]:
    """One row of the confirmation list: what this host can say about the serial being selected.

    `common_name` is the whole point of the block — a confirmation that lists only hex strings asks the operator to
    compare two things they cannot read against each other. A serial with no record here is named as such rather
    than dropped: if an operator ticked a row that another tab already revoked, or pasted a serial from a different
    CA, the confirmation page has to show that it knows this one is not a certificate on this host.
    """
    record = store.find(serial_hex)
    return {
        "serial_hex": serial_hex,
        "common_name": record.common_name if record else None,
        "cert_type": record.cert_type if record else None,
        "already_revoked": bool(record and record.revoked_at_utc is not None),
        "known": record is not None,
    }


def _stamp_revocations(
    store: IssuedStore, serial_hexes: list[str], reason: str | None
) -> tuple[list[Any], list[Any], list[str]]:
    """Stamp a batch, sorted into `(stamped now, already stamped before this submit, no such record)`.

    The pre-read is not an optimisation and not a race to be clever about: `store.revoke()` returns a stamped record
    both when it just wrote the stamp and when the row already carried one (its re-revoke no-op preserves
    `revoked_at_utc` on purpose — a page refresh must not move the moment a decision was made). Without reading
    first, `/issued` could only report "N revoked", which is the number that hides the case an operator most needs
    told about.

    No transaction wraps the batch. Stated as a cost rather than glossed: mypki's store is one short-lived SQLite
    connection per operation (see `IssuedStore._connect`), so a 500-serial batch is 500 stamps that could, in
    principle, be interrupted halfway by a crash. The consequence of an interruption is a partially revoked ledger,
    not an inconsistent one — every stamp written is complete and correct on its own — and the alternative (a write
    lock over a whole batch) trades a real busy-database failure for a hypothetical one.
    """
    stamped: list[Any] = []
    already: list[Any] = []
    missing: list[str] = []

    for serial_hex in serial_hexes:
        before = store.find(serial_hex)
        if before is None:
            missing.append(serial_hex)
            continue
        record = store.revoke(serial_hex=serial_hex, reason=reason)
        if record is None:
            # pragma: no cover - the row existed one statement ago. Defensive only: `IssuedStore` has no
            # DELETE (page-map §5), so nothing in this app can remove the row between the read above and
            # this write.
            missing.append(serial_hex)
            continue
        (already if before.revoked_at_utc is not None else stamped).append(record)
    return stamped, already, missing


def _publish_after_revoke(app: FastAPI, stamped: Sequence[Any]) -> str | None:
    """Re-sign the published CRL after a batch that stamped something; return the sentence for `/issued`.

    Returns text rather than rendering it here because `/issued`'s template owns its own result card, and a helper that
    built HTML would be a second place revocation results get formatted (page-map §1). None means "nothing to say": no
    row was stamped, so nothing moved and no new artifact is needed — a re-sign would mint a fresh signature to report
    that nothing happened, which is how a CRL Number becomes noise.

    The failure branch is why this function has its own name: `store.revoke()` has already committed by the time it is
    called. Raising there would report a revoke that **worked** as a failure, and an operator who re-submitted
    now reporting "already revoked" with no published CRL anywhere — worse than "stamped, but not published, and here is
    what to do". The wording never quotes a private path beyond the published artifact's own.
    """
    if not stamped:
        return None

    bundle = app.state.ca
    if bundle is None or bundle.key is None:
        return (
            "This host has no CA private key loaded, so it cannot sign a CRL: the stamps above are recorded but "
            "nothing is published. Run `mypki init-ca`, or supply the passphrase if the existing key is encrypted."
        )
    try:
        facts = rebuild_crl(bundle=bundle, store=app.state.store, path=paths.crl_path(app.state.data_root))
    except (MypkiError, OSError) as exc:
        log.error("CRL rebuild after a revoke batch failed: %s", exc)
        return (
            f"The certificates above are stamped revoked, but this host could not publish a CRL ({exc}). "
            "Use Rebuild on /crl once the problem is fixed; until then no client can read these revocations."
        )
    entry_word = "entry" if facts.entry_count == 1 else "entries"
    return (
        f"Published a new CRL listing {facts.entry_count} {entry_word} (CRL Number {facts.crl_number}), valid until "
        f"{facts.next_update_utc.strftime('%Y-%m-%d %H:%M:%S')}Z. See /crl for the artifact and its limits."
    )


def _settings_source(settings: Settings, name: str) -> str:
    """One of three honest labels: mypki's default, supplied by the operator, or a default passed through explicitly.

    This build keeps this function while dropping the resolved-state table it used to fill, because it is now what the
    Storage status panel answers one question with: *where did the directory this host is using come from?* That is the
    one provenance an operator acts on ("my shell variable is beating my saved file"), and it is answered for one row
    rather than restated for every knob on the page.

    Two signals are combined because neither alone answers the question. `model_fields_set` is pydantic's record of
    which fields were *supplied*, and `model_fields[name].default` is what mypki would have used if nobody had said
    anything; comparing the live value against that default is what catches a wildcard bind from a flag, whose Settings
    is built by merging every field back in (`cli.settings_with_cli_overrides`) and therefore reports *every* knob as
    supplied.

    What this function deliberately does **not** claim: the ability to tell `.env` from a shell variable from a CLI
    flag. pydantic-settings resolves that precedence internally and exposes no record of which layer won, so all three
    share one label and `/settings` states the limit instead of inventing a more precise answer than the process can
    give.
    """
    declared = Settings.model_fields[name].default
    supplied = name in settings.model_fields_set
    effective = getattr(settings, name)
    if not supplied:
        return "mypki default"
    if effective == declared:
        # Reached through a CLI merge or an explicit constructor: the value is mypki's own, whatever the route was.
        return "mypki default (passed through explicitly)"
    return "supplied by the operator"


# --------------------------------------------------------------------------------------------------- routes


def _register_routes(app: FastAPI) -> None:
    """Register every page plus the download route (page-map §1-§5, §12, §13, §10).

    One function rather than a router module per page: these pages share one context builder, one CA object and one
    error contract, so they are not separable concerns, and splitting them would spread `app.state` access across files
    while adding nothing testable. Handlers are plain `def` (see module docstring) so crypto and SQLite run on the
    threadpool.
    """
    templates: Jinja2Templates = app.state.templates

    def settings_of() -> Settings:
        return app.state.settings

    def cli_overrides_of() -> Mapping[str, object]:
        """What `mypki serve` was given as flags, for the status panel and for every hot-reload."""
        return _cli_overrides(app)

    def ca_of() -> CaBundle | None:
        return app.state.ca

    def context(request: Request, **extra: Any) -> dict[str, Any]:
        """Common template context: version, CA facts, the no-CA notice, issued-record count.

        `ca_facts` comes from the **public certificate only** — `describe_ca` has no parameter that could ask for
        something private — and `ca_key_present` is a boolean (page-map §1): the home page reports whether this host can
        sign without exposing anything about the key beyond that fact.

        `revoked_count` joins `issued_count` so a footer can state both halves of `/issued`'s Status column at once.
        Read per request rather than cached: it is one `COUNT(*)` against a table this app caps at 500 rendered rows,
        and a counter that lags on the page whose whole purpose is "what did I sign" is worse than one extra query.
        """
        bundle = ca_of()
        base: dict[str, Any] = {
            "request": request,
            "version": __version__,
            # Profile help sits in the common context rather than in the sign route's extras because `about.html`
            # renders it
            # too (and `/version` renders `about.html`): a template that explains a profile must not depend on which
            # route
            # happened to pass the mapping in. It is a module constant from `signing.py`, so carrying it costs nothing.
            "cert_profile_help": CERT_PROFILE_HELP,
            "ca_facts": describe_ca(bundle.cert) if bundle else None,
            "ca_key_present": bool(bundle and bundle.key_present),
            "no_ca_notice": (
                None
                if bundle
                else "No CA on this host yet. Run `mypki init-ca` in a terminal — the web UI cannot create one."
            ),
            "issued_count": app.state.store.count(),
            "revoked_count": app.state.store.count_revoked(),
        }
        base.update(extra)
        return base

    def require_csrf(request: Request, token: str | None) -> None:
        """Abort before any signing work happens (page-map §0).

        Called as the first statement of every POST handler rather than as a dependency, so the ordering is
        visible at each
        call site: there is no way to add a route and forget the check, because the handler's own body names it.
        """
        if not verify_csrf(request, token):
            raise CsrfValidationError(
                "The CSRF token was missing or did not match this session.",
                field=FIELD_NAME,
            )

    def one_shot() -> OneShotStore:
        return app.state.oneshot

    # --------------------------------------------------------------------------------------------- home (§1)

    @app.get("/", response_class=HTMLResponse)
    def home(request: Request) -> HTMLResponse:
        """The front page **is** the Sign CSR form, and nothing else (page-map §1).

        It has been led three ways: prose first, then the form with a CA facts card above it, then a pass that
        removed the card. The facts are not gone — they sit on `/ca`, next to the root's own download, which is where
        a reader who wants to verify this host's root before signing anything against it will look. Rendering them on
        three pages was rendering them three times, and a fact in two places is two facts that can disagree (§4).

        `/csr/sign` renders this same template through these same helpers, so "the front page is the sign page" is one
        implementation rather than two that drift. The harness reads the CA facts on `/ca` (§9) and the sign form on `/`
        (§1), which is what keeps this split honest rather than merely intended.
        """
        return sign_page(request)

    # ----------------------------------------------------------------------------------- generate CSR (§2)

    def generate_context(request: Request, **extra: Any) -> dict[str, Any]:
        """Generate-page context in one place, for a first visit and for a re-render after a rejection.

        `values` is the same shape both ways — a first visit gets `_subject_defaults()` (page-map §2: this host's own
        `MYPKI_DEFAULT_*` knobs prefilled), a rejected submit gets what the operator typed. One shape means the template
        has one way to fill an input, which is why no field can be prefilled on one path and forgotten on the other.
        """
        base: dict[str, Any] = {
            "key_types": ALLOWED_KEY_SPECS,
            "result": None,
            "values": _subject_defaults(settings_of()),
            "errors": [],
            "advisory": None,
            "passphrase_min": PASSPHRASE_MIN_LENGTH,
            "passphrase_recommended": PASSPHRASE_RECOMMENDED_LENGTH,
            "max_sans": settings_of().max_sans,
        }
        base.update(extra)
        return context(request, **base)

    @app.get("/csr/generate", response_class=HTMLResponse)
    def csr_generate_form(request: Request) -> HTMLResponse:
        issue_csrf_token(request)
        return templates.TemplateResponse(request, "csr_generate.html", generate_context(request))

    @app.post("/csr/generate", response_class=HTMLResponse)
    def csr_generate_submit(request: Request, form: Annotated[dict[str, str], Depends(_form_fields)]) -> HTMLResponse:
        issue_csrf_token(request)
        require_csrf(request, form.get(FIELD_NAME))

        try:
            fields, spec, passphrase = validate_generate_fields(
                common_name=form.get("common_name"),
                sans_raw=form.get("sans"),
                organization=form.get("organization"),
                organizational_unit=form.get("organizational_unit"),
                country=form.get("country"),
                state=form.get("state"),
                locality=form.get("locality"),
                email=form.get("email"),
                key_type=form.get("key_type"),
                passphrase=form.get("passphrase"),
                confirm=form.get("confirm"),
                max_sans=settings_of().max_sans,
            )
        except (CsrValidationError, KeyPolicyError) as exc:
            # A typed field was rejected (module docstring): the same form comes back at 200 with the reason named at
            # the
            # top and every non-secret value still filled in. `KeyPolicyError` belongs here rather than with the
            # artifact
            # handlers because `key_type` is a field this form owns, not something that arrived inside a pasted request.
            #
            # The passphrase pair is re-rendered **empty** by `_without_secrets`: an error page that echoed what was
            # typed
            # would put it in the browser history and any cache of this response (page-map §0).
            reason = exc.reason if isinstance(exc, CsrValidationError) else str(exc)
            log.info("rejected generate form at %s: %s", request.url.path, reason)
            return templates.TemplateResponse(
                request,
                "csr_generate.html",
                generate_context(request, values=_without_secrets(form), errors=[reason]),
                status_code=200,
            )

        # Key generation happens only after every field validated: a rejected form spends no CPU on a keypair (csr.py).
        key = generate_key(spec)
        csr_pem = build_csr(fields, key)
        key_pem = private_key_pem(key, passphrase).decode("ascii")

        # Both artifacts exist only in this process and in the response body. Nothing here touches disk or the DB:
        # test_csr_generate.py asserts the data dir is byte-for-byte unchanged across a generation (page-map §2).
        store = one_shot()
        stem = _safe_stem(fields.common_name)
        csr_artifact = store.put(filename=f"{stem}-csr.pem", media_type=_PEM_MEDIA_TYPE, body=csr_pem)
        key_artifact = store.put(
            filename=f"{stem}-key{'-encrypted' if passphrase else ''}.key",
            media_type=_PEM_MEDIA_TYPE,
            body=key_pem,
        )
        request.session[SESSION_GENERATION_CSR_ID] = csr_artifact.id
        request.session[SESSION_GENERATION_KEY_ID] = key_artifact.id

        log.info("generated CSR for %s (%s) from %s", fields.common_name, spec.label, _client_ip(request))
        result = {
            "csr_pem": csr_pem,
            "key_pem": key_pem,
            "csr_download": f"/download/{csr_artifact.id}",
            "key_download": f"/download/{key_artifact.id}",
            "encrypted": passphrase is not None,
            "key_label": spec.label,
            "sans": fields.sans.all_entries(),
            "common_name": fields.common_name,
        }
        return templates.TemplateResponse(
            request,
            "csr_generate.html",
            # `values` re-populates the form so a successful submit does not wipe what the operator typed; the
            # passphrase
            # fields are deliberately dropped -- echoing a passphrase back into a rendered form is how it ends up in a
            # browser's form-autofill and a page cache. `advisory` is the 8-to-11-character warning, shown on a page
            # that
            # succeeded because the choice was the operator's to make.
            generate_context(
                request,
                result=result,
                values=_without_secrets(form),
                advisory=passphrase_advisory(form.get("passphrase")),
            ),
        )

    # ------------------------------------------------------------------------------------- sign CSR (§3)

    def sign_context(request: Request, **extra: Any) -> dict[str, Any]:
        """Sign-page context for every path that renders it: `/`, `/csr/sign`, step A's panel and a rejected confirm.

        `cert_profile_help` arrives via `context` rather than from here (see the note there): it belongs next to
        `cert_types` because the mapping lives in `signing.py` beside the profiles it describes (page-map §7) — a
        profile added there without help text would render a radio button with no explanation. It is rendered
        server-side because this app ships **no JavaScript** — a description toggled by a click is not available here
        (page-map §0).

        `pending_id` puts step A's staged request into the confirm form's action URL. The session cookie alone is not
        enough once the page becomes editable: an operator who fixes six fields and gets the page back with errors must
        not have to paste the CSR again.
        """
        settings = settings_of()
        base: dict[str, Any] = {
            "cert_types": CERT_TYPES,
            "max_csr_chars": settings.max_csr_chars,
            "max_sans": settings.max_sans,
            "default_validity": settings.validity_default_days,
            "max_validity": settings.validity_max_days,
            "details": None,
            "issued": None,
            "errors": [],
            "request_values": {},
            "selected_profile": CERT_TYPES[0],
            "pending_id": request.session.get(SESSION_CSR_ID),
            # The consent box's field name and its state, both supplied from here rather than invented in the template:
            # `CONSENT_FIELD` is what step B reads, so a template that spelled the name differently would render a box
            # whose submission this handler cannot see (page-map §3 rule 6).
            "consent_field": CONSENT_FIELD,
            "consent_checked": False,
            # The refusal block and the paste echo are inert here and filled by `_paste_refused`: a step-A paste this
            # CA will not sign is named **on this page**, in red, directly above the box that produced it, with the
            # paste itself still in the textarea. The status code does not change (400/403) — see the module docstring
            # for why the status and the surface are separate decisions.
            "refused_reason": None,
            "refused_hint": None,
            "paste_value": "",
            "paste_redacted": 0,
        }
        base.update(extra)
        return context(request, **base)

    def sign_page(request: Request) -> HTMLResponse:
        issue_csrf_token(request)  # the token must exist in the session before any form is rendered
        return templates.TemplateResponse(request, "csr_sign.html", sign_context(request))

    @app.get("/csr/sign", response_class=HTMLResponse)
    def csr_sign_form(request: Request) -> HTMLResponse:
        """`/csr/sign` stays as the address page-map §3 and every existing link names (page-map §1).

        It renders `home`'s page rather than redirecting to it: a redirect is a round trip that tells nobody anything,
        and a second copy of this template is exactly the drift the two handlers above exist to prevent.
        """
        return sign_page(request)

    @app.post("/csr/sign", response_class=HTMLResponse)
    def csr_sign_submit(request: Request, form: Annotated[dict[str, str], Depends(_form_fields)]) -> HTMLResponse:
        issue_csrf_token(request)
        require_csrf(request, form.get(FIELD_NAME))
        settings = settings_of()

        if form.get("confirm"):
            return _issue_from_confirmation(request, form)

        # Step A: a pasted request this CA will not sign is answered **on this page** — the reason in red directly
        # above the paste box, the paste itself still in the textarea — while the status stays 400 for malformed input
        # and 403 for a privilege claim (`ERROR_SURFACE_RULE`). The status is what a script reads; the
        # block is what an operator reads. Only an oversized body still lands on `error.html`, because that refusal is
        # made by `SizeGuardMiddleware` before this handler, or indeed any route, exists.
        #
        # As of this build 403 answers **privilege claims** only; a request carrying ignorable extensions
        # (`BasicConstraints CA:FALSE`, a benign KeyUsage) reaches the panel below, which names them and asks for
        # consent before anything is signed.
        #
        # This is the first of the two `parse_and_validate_csr` call sites. The list of ignorable extensions it produces
        # travels on `details`, and step B rebuilds the same list from the staged bytes — never from a form field — so
        # the two paths cannot disagree about what was dropped (page-map §3 rule 6).
        try:
            details = parse_and_validate_csr(form.get("csr_pem", ""), settings.max_csr_chars)
        except (CsrValidationError, KeyPolicyError, CaPrivilegeRequestedError) as exc:
            return _paste_refused(request, exc, form)
        # The validated PEM is staged in the one-shot store; the session carries only its opaque id (page-map §10
        # explains
        # why the bytes themselves cannot ride in the cookie).
        artifact = one_shot().put(filename="pending-request.pem", media_type=_PEM_MEDIA_TYPE, body=details.pem)
        request.session[SESSION_CSR_ID] = artifact.id
        log.info("csr staged for confirmation: %s from %s", details.summary, _client_ip(request))
        # The editable fields start as exactly what the request said, so an edit is a deliberate act against values the
        # operator can see rather than a blank form they have to reconstruct from memory.
        return templates.TemplateResponse(
            request,
            "csr_sign.html",
            sign_context(
                request,
                details=details,
                pending_id=artifact.id,
                request_values=_confirmation_prefill(details),
            ),
        )

    def _paste_refused(request: Request, exc: MypkiError, form: dict[str, str]) -> HTMLResponse:
        """Step A's refusal, rendered on the sign page itself rather than on a second page.

        Two decisions that look like one and are not:

        * **The surface moves, the status does not.** `CsrValidationError` → 400, `KeyPolicyError` → 400,
          `CaPrivilegeRequestedError` → 403, exactly as `_register_error_handlers` chose them (page-map §0). A curl or
          PowerShell script still sees "bad input" and "refused" as different answers; only the HTML an operator reads
          changed location. Status is decided by *what was wrong*, the surface by *where the fix can be typed*.
        * **The paste survives.** `csr_pem` comes back into its own textarea, so a refusal names the reason next to the
          thing it is about instead of discarding a 2 KB PEM and asking for it again. Private-key bodies inside the
          echo are filtered by `inspect.redact_private_key_bodies` — armour lines kept, base64 replaced — and the count
          rendered, because filtering what somebody pasted with nothing on screen saying so is the quiet edit this
          project refuses elsewhere (see `settingsfile.preserve_unmanaged`).

        The reason keeps the class `<p class="reason">` it had on `error.html`, so "read mypki's stated reason"
        remains one selector for a test or a scraper whichever surface rendered it. `log.info` lines are unchanged:
        they are what the harness and an operator's own log reader already depend on.
        """
        if isinstance(exc, CsrValidationError):
            status, reason, hint = 400, exc.reason, "Nothing was signed. Fix the paste above and submit again."
            log.info("rejected input at %s: %s", request.url.path, exc.reason)
        elif isinstance(exc, CaPrivilegeRequestedError):
            # 403 rather than 400: not a malformed request, a request mypki refuses to honour (page-map §3 rule 6).
            # Privilege claims only — the ignorable half of rule 6 reaches the confirmation panel and is refused at 200
            # by `_consent_problems` when the box is left unticked.
            status = 403
            reason = str(exc)
            hint = (
                f"Rejected extension: {exc.extension}. mypki sets leaf extensions itself; only SAN is read from a CSR. "
                "Extensions that ask for nothing are listed on the confirmation page, and dropped only when you tick "
                "the box there."
            )
            log.info("refused CA privilege at %s: %s", request.url.path, exc.extension)
        else:
            status, reason, hint = 400, str(exc), None
            log.info("rejected key policy at %s: %s", request.url.path, getattr(exc, "spec", "?"))

        paste, redacted = redact_private_key_bodies(form.get("csr_pem", ""))
        return templates.TemplateResponse(
            request,
            "csr_sign.html",
            sign_context(
                request,
                refused_reason=reason,
                refused_hint=hint,
                paste_value=paste,
                paste_redacted=redacted,
            ),
            status_code=status,
        )

    def _confirm_rejected(
        request: Request,
        details: Any,
        form: dict[str, str],
        problems: list[str],
        pending_id: str,
    ) -> HTMLResponse:
        """Re-render the confirmation page with every problem named and every typed value still in its field.

        Status 200 (module docstring): nothing was refused, one input needs fixing, and the staged request is still here
        — `pending_id` goes back into the form's action URL so the operator who fixes a country code is not also
        required to paste a 2 KB PEM again.

        The panel that shows *what the request said* stays on the page alongside the editable fields, because "your edit
        was rejected" is only actionable next to what the edit was supposed to replace.
        """
        log.info("rejected confirm form at %s: %s", request.url.path, "; ".join(problems))
        return templates.TemplateResponse(
            request,
            "csr_sign.html",
            sign_context(
                request,
                details=details,
                pending_id=pending_id,
                errors=problems,
                request_values=_form_values(form),
                selected_profile=form.get("cert_type") or CERT_TYPES[0],
                # The box comes back as the operator left it. Consent is what this page exists to ask for, so a
                # re-render that silently reset it would read as "the page forgot my tick" — and one that kept a tick
                # the form did not send would consent on the operator's behalf.
                consent_checked=_consent_given(form),
            ),
            status_code=200,
        )

    def _issue_from_confirmation(request: Request, form: dict[str, str]) -> HTMLResponse:
        """Step B: re-read the staged CSR, apply any edits the operator made, and sign it (page-map §3 step B).

        The PEM comes back out of the one-shot store rather than from a textarea round-trip, so what gets signed is
        byte-identical to what was validated — a confirmation page cannot alter the request it displayed. It is
        **re-parsed** rather than trusted from memory: the staged entry is only as trustworthy as any other input, and
        re-running the same validation costs milliseconds against a signing operation that costs none.

        The subject and SANs, by contrast, come from the form when the form supplied them. That is the
        deliberate loosening documented in `signing.py`: the public key still comes only from the request, extensions
        still never come from anywhere but mypki's own profiles, and an edited name has to satisfy the same validators
        the generate form runs before a single byte is signed. `_changed_subject_fields` then records what differed,
        because an edit nobody noticed is a mis-issuance this CA cannot walk back.

        Consent for dropped extensions is asked here too, from the **re-parsed** request rather than from the form
        (page-map §3 rule 6): `details.ignored_extensions` is recomputed from the staged bytes, so step A's disclosure
        and step B's decision are about one artifact. Unticked means no signing, answered at 200 with the box still on
        the page — this is an input to fix, not a request mypki refuses to honour.
        """
        settings = settings_of()
        bundle = ca_of()
        if bundle is None:
            raise CaNotFoundError(paths.ca_cert_path(app.state.data_root))

        # `_staged_pem` prefers the form's `?pending=` id and falls back to the session, which is what makes an
        # edited-and-rejected confirmation page recoverable: the browser resubmits the action URL it was given, so the
        # staged request survives a round trip even if the cookie does not.
        artifact = one_shot().take(_staged_pem_id(request))
        pending_id = artifact.id
        details = parse_and_validate_csr(artifact.body, settings.max_csr_chars)

        subject: x509.Name | None = None
        sans: SanSet | None = None
        problems: list[str] = []
        edited = _subject_edit_submitted(form)

        try:
            days = validity_days(
                form.get("validity_days"), settings.validity_default_days, 1, settings.validity_max_days
            )
        except CsrValidationError as exc:
            days = -1
            problems.append(f"validity in days: {exc.reason}")

        if edited:
            # The confirm form submits its editable fields, so the certificate's subject comes from the form
            # rather
            # than from the request. A POST that names none of them — an older client, or a test posting only
            # `confirm`/`cert_type`/`validity_days` — unedited behaviour: sign exactly what the request says,
            # which is
            # also why `edited` gates the diff below: "no edit submitted" must never render as "every field was
            # removed".
            subject, sans, subject_problems = _edited_subject_fields(form, max_sans=settings.max_sans)
            problems.extend(subject_problems)

        cert_type = form.get("cert_type") or CERT_TYPES[0]
        if cert_type not in CERT_TYPES:
            problems.append(f"certificate profile: must be one of {', '.join(CERT_TYPES)} (got {cert_type!r})")

        # Consent for the ignorable half of rule 6, asked **after** the re-parse rather than before it, and answered
        # from `details` rather than from anything the form claimed (page-map §3 rule 6). This is the second call site
        # of `parse_and_validate_csr`, and reading the list here — not a list posted by the browser — is what makes step
        # A's disclosure and step B's consent describe the same bytes: a POST cannot consent to an extension the page
        # never showed, nor withhold consent from one it did by omitting it from a form field.
        dropped = list(details.ignored_extensions)
        if dropped and not _consent_given(form):
            problems.append(_consent_problem(dropped))

        if problems:
            return _confirm_rejected(request, details, form, problems, pending_id)

        try:
            issued = issue_certificate(
                bundle,
                details,
                cert_type=cert_type,
                validity_days=days,
                max_sans=settings.max_sans,
                subject=subject,
                sans=sans,
                # The pointer baked into this leaf. Read per request rather than captured at startup, so a save
                # on /settings takes effect for the very next certificate — and stated here rather than defaulted inside
                # `signing.py`, because a default URL in the signing module would be a second answer to "which base does
                # this CA advertise" and the one that a typo on /settings could not reach.
                crl_base_url=settings.crl_base_url,
            )
        except CsrValidationError as exc:
            # A *profile* rule this CA enforces (a `server` leaf with no SANs, an over-cap SAN set after editing) is
            # still a
            # field the operator can fix on this page, so it returns to the form rather than to the error page.
            return _confirm_rejected(request, details, form, [exc.reason], pending_id)

        app.state.store.add_record(
            serial_hex=issued.serial_hex,
            cert_type=issued.cert_type,
            common_name=issued.common_name,
            sans=issued.sans,
            not_before_utc=issued.not_before_utc,
            not_after_utc=issued.not_after_utc,
            fingerprint_sha256=issued.fingerprint_sha256,
        )

        store = one_shot()
        stem = _safe_stem(issued.common_name)
        cert_artifact = store.put(filename=f"{stem}.crt", media_type=_PEM_MEDIA_TYPE, body=issued.pem)
        chain_artifact = store.put(filename=f"{stem}-chain.pem", media_type=_PEM_MEDIA_TYPE, body=issued.chain_pem)
        request.session[SESSION_ISSUED_CERT_ID] = cert_artifact.id
        request.session[SESSION_ISSUED_CHAIN_ID] = chain_artifact.id
        # The staged CSR is consumed by signing: leaving it staged would let a reload issue the same names again.
        request.session.pop(SESSION_CSR_ID, None)

        log.info("signed %s from %s", issued.summary, _client_ip(request))
        return templates.TemplateResponse(
            request,
            "csr_sign.html",
            sign_context(
                request,
                details=details,
                issued=_issued_view(issued, cert_artifact.id, chain_artifact.id),
                pending_id=None,
                # The diff between what the request said and what this CA signed. Empty for every unedited signing,
                # which is
                # still the common case; non-empty means the operator edited something and is being told so in plain
                # words.
                # Both halves of "what differed from your request" land in the same block (page-map §3): a name the
                # operator edited, and an extension mypki did not copy because the operator agreed it would not. The
                # second half is derived from `details` — the re-parsed staged request — so it cannot be talked out of
                # the page by a form field.
                changed_from_request=(_changed_subject_fields(form, details, sans) if edited else [])
                + _dropped_extension_fields(dropped),
            ),
        )

    # -------------------------------------------------------------------------------- CA cert + page (§4)

    @app.get("/ca", response_class=HTMLResponse)
    def ca_page(request: Request) -> HTMLResponse:
        """The CA page, showing the certificate itself next to the facts about it.

        `ca_pem` is passed as an extra rather than added to `context()` because it is a several-hundred-character block
        that only this page renders: putting it in the common context would put it on `/`, `/issued`, `/settings` and
        `/about` too, where nothing displays it but every one of them becomes a page a future refactor could leak.
        It is also the same bytes `GET /ca/certificate` already serves as an attachment, so showing it adds no fact that
        was not already public on this host — a certificate is public by design, and `describe_ca` has been publishing
        its subject, serial and fingerprint here already.
        """
        issue_csrf_token(request)
        bundle = ca_of()
        pem = None
        if bundle is not None:
            pem = bundle.cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
        return templates.TemplateResponse(request, "ca_download.html", context(request, ca_pem=pem))

    @app.get("/ca/certificate")
    def ca_certificate(request: Request) -> Response:
        """Public CA certificate only, as a `.crt` attachment (page-map §4)."""
        bundle = ca_of()
        if bundle is None:
            raise CaNotFoundError(paths.ca_cert_path(app.state.data_root))
        pem = bundle.cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
        log.info("served CA certificate to %s", _client_ip(request))
        return _pem_response(pem, "mypki-root-ca.crt")

    # ------------------------------------------------------------------------------- CRL page + artifact (§14)

    def rebuild_and_report() -> CrlFacts:
        """Sign a fresh CRL from the store and write it, or refuse naming what is missing.

        The one path all three triggers take (startup, the revoke hook below, the Rebuild button), which is why
        `crl.rebuild_crl` exists: three call sites each assembling their own builder would be three chances to disagree
        about the entry rule or the CRL Number. A keyless host raises `CaNotFoundError` — the same 503 the CA download
        already answers — because "this host cannot sign a CRL" and "this host has no CA" are the same answer to the
        person holding a URL.
        """
        bundle = ca_of()
        if bundle is None or bundle.key is None:
            raise CaNotFoundError(paths.ca_cert_path(app.state.data_root))
        return rebuild_crl(bundle=bundle, store=app.state.store, path=paths.crl_path(app.state.data_root))

    @app.get("/crl", response_class=HTMLResponse)
    def crl_page(request: Request) -> HTMLResponse:
        """The CRL page (page-map §14): what this host published, in words and in PEM.

        A page rather than only an artifact because the honest limits of a home-lab CRL need somewhere to be written: no
        IssuingDistributionPoint (and the measured `error 44 … different CRL scope` reason), pre-0.7 certificates with
        no pointer at all, openssl never fetching a CDP, and revoked-and-expired answering UNKNOWN. Those four sentences
        are the difference between an operator who believes revocation works everywhere and one who knows where it does.

        The facts are read back **from the artifact on disk**, not from what the last build was told — so this page
        cannot describe a CRL that is not the one `GET /crl.pem` serves. A host with no published file renders "nothing
        published yet" rather than a 500: the route exists and is correct, this host just has not written the file
        (page-map §6's posture for missing state).
        """
        issue_csrf_token(request)  # the page carries the Rebuild form
        bundle = ca_of()
        facts = _published_crl(app.state.data_root)
        return templates.TemplateResponse(
            request,
            "crl.html",
            context(
                request,
                crl_facts=facts,
                crl_pem_marker=CRL_PEM_MARKER,
                crl_base_url=settings_of().crl_base_url,
                can_rebuild=bool(bundle is not None and bundle.key_present),
                rebuilt=bool(request.query_params.get("rebuilt")),
            ),
        )

    @app.get("/crl.pem")
    def crl_artifact(request: Request) -> Response:
        """The published CRL itself, as PEM (page-map §14).

        The URL every certificate this host now issues carries in its `CRLDistributionPoints`
        (`<crl_base_url>/crl.pem`), so this is the handler a client reaches without being told about it — hence the
        media type, which says what the body is instead of leaving a parser to infer it from a filename.

        No CSRF (it is a GET and publishes nothing new: every byte here is already on `/crl`), and no `Cache-Control`
        other than `no-store`: a CRL whose stated freshness is 24 hours must not be served from a proxy cache that
        refreshes daily, or a revoked certificate stays "valid" for the length of that cache.
        """
        facts = _published_crl(app.state.data_root)
        if facts is None:
            # No file at all. On a host with no CA this is the same missing state `/ca/certificate` answers 503 for;
            # where the startup build failed, `mypki init-ca` is not the fix, so name the artifact instead.
            if ca_of() is None:
                raise CaNotFoundError(paths.ca_cert_path(app.state.data_root))
            raise MypkiError(
                f"No published CRL exists at {paths.crl_path(app.state.data_root)}. Use Rebuild on /crl to sign one."
            )
        log.info(
            "served CRL to %s (entries=%d, crl_number=%d)",
            _client_ip(request),
            facts.entry_count,
            facts.crl_number,
        )
        return _pem_response(facts.pem, CRL_FILENAME, media_type=_CRL_MEDIA_TYPE)

    @app.post("/crl/rebuild", response_class=HTMLResponse)
    def crl_rebuild(request: Request, form: Annotated[dict[str, str], Depends(_form_fields)]) -> HTMLResponse:
        """Re-sign the CRL from the current store and report what the new one says (page-map §14).

        CSRF first, as on every POST in this app — and this one matters more than most: it is a signing operation, so a
        cross-site submit would be asking this CA to produce fresh signatures on demand for free. `require_csrf` is the
        handler's first statement rather than a dependency so the ordering is visible at the call site (page-map §0).

        **A re-sign of the same data, not a new decision.** Nothing here revokes anything: the entry set comes from the
        rows `store.revoke()` already stamped. The page says that in the same breath as the button, because "Rebuild"
        on a revocation page reads to a nervous operator like "make my revocations take effect".

        Answers 200 with the facts rendered on `/crl` rather than a 303 back to it. This app has no flash-message store,
        and the numbers an operator wants after a rebuild (entry count, CRL Number, thisUpdate/nextUpdate) are already
        what `/crl` reads off disk — so a redirect would either re-sign (a second signature for nothing) or render the
        same card without saying it had just moved. Staying on the POST response names action and result at once.
        """
        require_csrf(request, form.get(FIELD_NAME))

        facts = rebuild_and_report()
        log.info(
            "CRL rebuilt by %s (entries=%d, crl_number=%d, this_update=%s, next_update=%s)",
            _client_ip(request),
            facts.entry_count,
            facts.crl_number,
            facts.this_update_utc.isoformat(),
            facts.next_update_utc.isoformat(),
        )
        return templates.TemplateResponse(
            request,
            "crl.html",
            context(
                request,
                crl_facts=facts,
                crl_pem_marker=CRL_PEM_MARKER,
                crl_base_url=settings_of().crl_base_url,
                can_rebuild=True,
                rebuilt=True,
            ),
            status_code=200,
        )

    # ------------------------------------------------------------------------------ OCSP responder (§15)

    def ocsp_der(body: bytes, request: Request) -> Response:
        """One DER in, one DER out, HTTP 200 whatever the answer is (page-map §15).

        The shape of an OCSP failure is *inside* the body, not the status line: RFC 6960 §4.2 puts
        `OCSPResponseStatus` in the response, and a client library reads that. mypki's house rule — every rejection gets
        mypki's own HTML page with a status that says what happened — is deliberately suspended on this route, because
        HTML where a client expects DER is indistinguishable from a broken responder. The one exception is measured and
        documented (plan §2/P-OCSP-3): a body above `SizeGuardMiddleware`'s limit is answered by the middleware's HTML
        413 before this function runs, which is why the cap below sits far under it.

        Four answers, in order:
          * body over `OCSP_MAX_REQUEST_BYTES` -> MALFORMED_REQUEST. A real request is tens of bytes, so this
            is about malformed abuse; the middleware's own limit stays where it is and `/ocsp` is not exempted from it.
          * unparseable body → MALFORMED_REQUEST (`ocsp_responder.parse_ocsp_request` folds every parse failure into
            None rather than raising, which is what keeps this branch one line).
          * no CA, or a CA with no key → INTERNAL_ERROR. Not 503 like `/crl.pem`: the same reasoning as above, a client
            that cannot read HTML learns nothing, and `internalError` is the protocol's word for "this responder cannot
            answer". The log line names the fix (`mypki init-ca`).
          * a parsed request → GOOD / REVOKED / UNKNOWN from the record store.
        """
        if len(body) > OCSP_MAX_REQUEST_BYTES:
            log.info(
                "oversized OCSP request from %s (%d bytes; handler cap %d)",
                _client_ip(request),
                len(body),
                OCSP_MAX_REQUEST_BYTES,
            )
            return _ocsp_response(malformed_response_der())

        parsed = parse_ocsp_request(body)
        if parsed is None:
            return _ocsp_response(malformed_response_der())

        bundle = ca_of()
        if bundle is None or bundle.key is None:
            log.error(
                "OCSP request from %s refused: this host has no CA private key to sign an answer with",
                _client_ip(request),
            )
            return _ocsp_response(malformed_response_der(OCSPResponseStatus.INTERNAL_ERROR))

        try:
            # `find()` keys on the store's spelling of a serial; the request carries an integer, and `serial_hex_of`
            # is the one conversion (it refuses a negative serial rather than letting it become a lookup key).
            record = app.state.store.find(serial_hex_of(parsed))
            answer = answer_for(parsed, record)
            der = render_ocsp_response(parsed, answer, bundle)
        except (ValueError, TypeError) as exc:
            # A request that parsed but cannot be answered: an unsupported CertID hash algorithm, a serial the builder
            # refuses. MALFORMED_REQUEST would blame the client for something this responder could not do, so the
            # protocol's own word for that is used, and the reason reaches the log rather than the wire.
            log.error("OCSP answer failed for %s: %s", _client_ip(request), exc)
            return _ocsp_response(malformed_response_der(OCSPResponseStatus.INTERNAL_ERROR))

        log.info(
            "OCSP answered %s for serial=%s to %s",
            answer.status_name,
            answer.serial_hex,
            _client_ip(request),
        )
        return _ocsp_response(der)

    @app.post("/ocsp")
    def ocsp_respond(request: Request, body: Annotated[bytes, Depends(_raw_body)]) -> Response:
        """The OCSP endpoint (page-map §15): `POST /ocsp`, DER in, DER out.

        **No CSRF check, and that is the documented exception to page-map §0's rule.** A CSRF defence protects a
        session by requiring a token only a page this host rendered could carry; an OCSP request is a
        machine-to-machine protocol body sent by a TLS/HTTP client library that has never seen mypki's HTML and holds
        no cookie. Demanding a token here would break every real client while protecting nothing: there is no session
        state for a cross-site submit to abuse, and the handler signs *what its own store says about a serial*, which
        is the same answer a GET of `/crl.pem` publishes.

        It is also why this route is named in §12's standing-risk list rather than waved through: it is a signing oracle
        reachable over HTTP, one signature per request. What bounds it is that every signature states a fact drawn from
        this host's own record store — the responder cannot be made to sign an answer this CA does not hold — plus the
        8 KiB body cap above.

        The URL is what `signing.py` bakes into new leaves as the AIA OCSP access location
        (`<crl_base_url>/ocsp`), so like `/crl.pem` it is a route a client reaches without being told about it.
        """
        return ocsp_der(body, request)

    # ------------------------------------------------------------------------------------- issued (§5)

    def render_issued(
        request: Request,
        *,
        records: list[Any],
        stamped: Sequence[Any] = (),
        already: Sequence[Any] = (),
        missing: Sequence[str] = (),
        pending: Sequence[dict[str, Any]] = (),
        reason: str = "",
        crl_note: str | None = None,
    ) -> HTMLResponse:
        """`/issued` in one render path, for a GET, the confirmation step and the result of a bulk revoke.

        `pending` is the server-side confirmation step: what the operator selected, named as serial **and** common
        name, before anything is stamped. It exists because this app cannot rely on a JavaScript modal — with JS
        off (or a harness that runs no JS at all) the only way to ask "are you sure about these three?" is to
        answer the POST with a page that lists them and a second button that carries `confirm=1`.
        """
        issue_csrf_token(request)
        return templates.TemplateResponse(
            request,
            "issued.html",
            context(
                request,
                records=records,
                stamped=list(stamped),
                already=list(already),
                missing=list(missing),
                pending=pending,
                pending_reason=reason,
                crl_note=crl_note,
            ),
        )

    @app.get("/issued", response_class=HTMLResponse)
    def issued_page(request: Request) -> HTMLResponse:
        return render_issued(request, records=app.state.store.list_records())

    @app.post("/issued/revoke", response_class=HTMLResponse)
    def issued_revoke(
        request: Request, form: Annotated[dict[str, list[str]], Depends(_form_fields_multi)]
    ) -> HTMLResponse:
        """Record revocations for the serials this host signed (page-map §5), one or many.

        CSRF-checked first, like every other POST here. The `require_csrf` call matters more on this route than on most:
        without it, a link on somebody else's page could flip a certificate to revoked with a single GET-shaped request,
        and "revoked" is the one state change `/issued` can cause.

        Two steps, both server-side
        -------------------------------------
        A POST without `confirm=1` stamps **nothing**. It re-renders `/issued` with an amber block at the top
        naming every certificate about to be stamped — serial and common name, because a wall of hex is not a
        confirmation an operator can actually read — and a second control that carries the same selection plus
        `confirm=1`. The browser's own modal (`static/app.js`, styled like the reference design) short-circuits
        this by submitting `confirm=1` directly; both paths land in this handler, so "the confirmation" is one
        rule rather than two.

        Why a server step at all when there is a modal: the modal is a client that may be disabled, and page-map
        §0 promises every flow works without JavaScript. A revoke that could only be confirmed by a script is a
        revoke that breaks when the operator's browser settings say no.

        Three outcomes, reported separately
        ------------------------------------
        `store.revoke()` answers None for a serial this host never signed and returns the untouched record for
        one already stamped. A bulk submit can therefore mix all three, and reporting them as one number would
        hide the interesting case: a stale tab selecting a certificate somebody else already revoked. So the
        result block names each serial under `stamped`, `already stamped` or `no record`, and a miss does not
        404 the whole batch — one stale checkbox should not discard N-1 decisions the operator meant to make.

        One exception, kept deliberately: a submit naming **exactly one** serial with no record here still raises
        `RevocationRecordNotFoundError` and answers 404. That is the contract here (a single unknown serial was
        once a 500, and the fix was a 404 naming both the serial and the database file), and a hand-pasted serial from
        another machine's CA is one certificate rather than a batch. Reporting it as a 200 batch card would say
        "nothing was changed" in the same shape as "the submit worked".

        What this does and does not do, stated on the page rather than only in `store.py`: it stamps rows and (when a CA
        key is loaded) re-signs the published CRL, which also answers OCSP — but a certificate already installed
        somewhere keeps working until its own client consults one of those, and an older leaf may carry no
        pointer to either (page-map §14/§15). Saying that next to the button is the difference between an operator who
        records a decision and an operator who believes they revoked something a client will honour.
        """
        issue_csrf_token(request)
        require_csrf(request, _one_of(form.get(FIELD_NAME, [])))

        serial_hexes = _selected_serials(form.get("serial_hex", []))
        reason = _revoke_reason(_one_of(form.get("reason", [])))
        if not serial_hexes:
            # Rendered as a 400 rather than re-rendering `/issued` with a note: an empty selection is a
            # form that arrived without its subjects, not a list this host cannot find, and the two
            # answers must not look alike.
            return _render_error(
                request,
                400,
                "serial_hex is required: revoke addresses certificates by their serial numbers.",
                hint="Tick the rows you mean on the Issued list, then use Revoke Selected.",
            )

        # The single-unknown-serial case keeps its own answer (see the docstring); a batch carries on to the three-way
        # report instead, because 404-ing N-1 decisions the operator did mean to make is the larger error.
        if len(serial_hexes) == 1 and app.state.store.find(serial_hexes[0]) is None:
            raise RevocationRecordNotFoundError(serial_hexes[0], paths.db_path(app.state.data_root))

        if not form.get("confirm"):
            pending = [_pending_revoke(serial_hex, app.state.store) for serial_hex in serial_hexes]
            log.info(
                "revoke awaiting confirmation: %d serial(s) selected by %s",
                len(pending),
                _client_ip(request),
            )
            return render_issued(
                request,
                records=app.state.store.list_records(),
                pending=pending,
                reason=reason or "",
            )

        # `store.revoke()` cannot answer "did I just stamp this?" — a fresh stamp and an untouched
        # already-stamped row both come back as a record with `revoked_at_utc` set. So the three outcomes are
        # decided by reading each serial **before** stamping it (see `_stamp_revocations`), which is the only
        # way the page can honestly separate "stamped now" from "was already revoked, and mypki will not move
        # that stamp".
        stamped, already, missing = _stamp_revocations(app.state.store, serial_hexes, reason)

        log.info(
            "revocation batch by %s: %d stamped, %d already stamped, %d with no record",
            _client_ip(request),
            len(stamped),
            len(already),
            len(missing),
        )

        # The publish half of a revoke: a stamp that never reaches a CRL is a decision no client can
        # read, so a batch that actually stamped something re-signs the artifact immediately. Two deliberate limits:
        #   * only when `stamped` is non-empty — an "already revoked" batch changed no data, and re-signing would mint a
        #     fresh signature and a later thisUpdate to say nothing had happened;
        #   * never fatal — a revoke the store accepted but this host could not publish is reported on the page rather
        #     than turned into a 500 after the write. "Nothing was revoked" and "it is revoked but not published" are
        #     different answers, and only the second is fixable by the operator standing in front of it.
        crl_note = _publish_after_revoke(app, stamped)

        return render_issued(
            request,
            records=app.state.store.list_records(),
            stamped=stamped,
            already=already,
            missing=missing,
            reason=reason or "",
            crl_note=crl_note,
        )

    # ------------------------------------------------------------------------------- about + settings (§12)

    @app.get("/about", response_class=HTMLResponse)
    def about_page(request: Request) -> HTMLResponse:
        """What this host is, what version it is, and where the source lives (page-map §12).

        The prose that used to open the home page lives here, because `/` is now the signing form and a lede above it
        buys an operator nothing they can act on. Two facts are worth putting on their own page rather than in a footer:
        what this CA's revocation story does and does not reach (a published CRL and OCSP that only consulting clients
        act on, page-map §14/§15; no accounts) and which build this is — a version number
        someone else can quote against `PROJECT_URL` is what turns "my CA behaves oddly" into a reportable problem.
        """
        issue_csrf_token(request)
        settings = settings_of()
        return templates.TemplateResponse(
            request,
            "about.html",
            context(
                request,
                project_url=PROJECT_URL,
                host=settings.host,
                port=settings.port,
                tls_enabled=settings.tls_enabled,
                max_validity=settings.validity_max_days,
                validity_default=settings.validity_default_days,
                max_sans=settings.max_sans,
            ),
        )

    def render_settings(
        request: Request,
        *,
        problems: Sequence[str] = (),
        overrides: Mapping[str, str] | None = None,
        changed: tuple[str, ...] = (),
        just_saved: bool = False,
    ) -> HTMLResponse:
        """`/settings` in one place, for the GET, a rejected save and a successful one.

        `overrides` is what the inputs show: submitted text after a rejection (so nobody retypes eight boxes),
        or the file's own contents after a save. That is also what this process runs with, because a
        successful save publishes a fresh `Settings` — the two questions "what is running now" and "what the next start
        will read" collapsed into one for everything except `STARTUP_ONLY_KNOBS`, which is exactly why those four are
        marked in red on the page instead of being described in a paragraph.
        """
        issue_csrf_token(request)
        settings = app.state.settings
        config_file = config_file_path(settings)
        # `changed` arrives in MYPKI_* spelling and STARTUP_ONLY_KNOBS is written in field names; the page has to show
        # the spelling an operator would type into a shell, so the intersection is taken on the field name and reported
        # in knob form. `live_changed` is its complement, and naming both is what makes "it took effect" checkable.
        restart_needed = sorted(knob for knob in changed if knob.removeprefix("MYPKI_").lower() in STARTUP_ONLY_KNOBS)
        return templates.TemplateResponse(
            request,
            "settings.html",
            context(
                request,
                # Read once per render, and read defensively: `read_saved_values` returns {} for a file that does
                # not exist, so a host that has never saved anything renders with nothing filled in. This is the
                # same parser `/settings` writes through and `mypki serve` reads through dotenv at startup, and
                # `test_settings_save.py::test_the_own_parser_and_dotenv_agree_on_every_managed_knob` is what proves
                # the two readings cannot disagree about a line this page wrote.
                sections=_settings_sections(
                    settings,
                    overrides,
                    saved_values=read_saved_values(config_file),
                    # `data_dir`'s field value and the directory this process actually opened are different facts;
                    # the pending sentence has to name the one the operator is standing in.
                    live_display={"data_dir": str(app.state.data_root)},
                ),
                status_rows=_settings_status(
                    settings, app.state.data_root, resolved_log_file(settings), _cli_overrides(app)
                ),
                data_root=str(app.state.data_root),
                log_file=resolved_log_file(settings),
                tls_enabled=settings.tls_enabled,
                config_file=str(config_file),
                # `just_saved` rather than "the file has contents in it": a plain GET after a save last week must not
                # render a green confirmation for an action nobody just took. Conflating them meant that visiting
                # `/settings` on a host that had ever been saved said "Saved" at you.
                just_saved=just_saved,
                problems=list(problems),
                changed=list(changed),
                restart_needed=restart_needed,
                live_changed=[knob for knob in changed if knob not in restart_needed],
                unmanaged=_unmanaged_card(settings),
                # The dropdown's last option, spelled once here rather than in the template, so `CUSTOM_CHOICE` is the
                # single name for it in both languages (app.py and settings.html) — same reason
                # `_PEM_MEDIA_TYPE` exists.
                custom_choice=CUSTOM_CHOICE,
            ),
        )

    @app.get("/settings", response_class=HTMLResponse)
    def settings_page(request: Request) -> HTMLResponse:
        """Every knob this process is running with, its value, where it came from and what changing it costs.

        This page was read-only at first, on the reasoning that a page able to edit a limit would need the
        logins this project deliberately does not have. The reasoning holds; the conclusion changed: the login
        question was never really what made editing dangerous — **writing a value nobody validated** was. So `/settings`
        is editable now, under three rules that carry the old intent forward:

          * every value is validated against `config.py`'s own `Field` bounds and model validators **before** the
            file is touched (see `settingsfile.validate_candidate`), because a bad save would otherwise surface as a CA
            that refuses to start an hour later;
          * `secret_key` and both `ssl_*` paths stay masked and non-editable (`settingsfile.UNMANAGED_KEYS`), so nothing
            this page can write is a credential or a path to one;
          * the save goes to `<config-dir>/mypki.env`, which startup reads **below** real environment variables and CLI
            flags, and the page says plainly that host/port/session/log knobs are read once at startup — saved for the
            next start.

        The masked half of the contract is unchanged: `secret_key` renders as a presence flag, no CA or instance
        key path is rendered anywhere on this page, and `test_no_key_leakage.py` still fetches it from outside
        to prove that.
        """
        # No `changed`/`just_saved` here on purpose: a GET is not proof of a save. An earlier release passed the
        # file's contents in and let the template read "the file exists" as "a save just happened", so a host that had
        # been saved once showed a green confirmation to every later visitor.
        return render_settings(request)

    @app.post("/settings", response_class=HTMLResponse)
    def settings_save(
        request: Request, form: Annotated[dict[str, list[str]], Depends(_form_fields_multi)]
    ) -> HTMLResponse:
        """Write `<config-dir>/mypki.env`, or refuse and say which knob and why (page-map §12).

        Order matters here as much as on every other POST in this app: CSRF first, because this is the one route
        that writes a file the next startup trusts. Then validation against `config.py`'s own rules, then the
        write — never the reverse. A save that wrote first and failed at the next `mypki serve` would look like
        a broken server rather than a bad form submission, and page-map §0's promise is that the mistake is
        named where it was made.

        On refusal nothing is written and every submitted value comes back filled in. On success the response
        re-renders the page from the file's contents plus a green block naming what changed, because "saved"
        without a list of what moved is indistinguishable from "nothing needed to move".

        Two refusals, two shapes: a `SettingsFileError` is the operator's typo and lands in the amber block naming the
        knob and the bound it failed; an `OSError` out of the write is this host's filesystem (a config dir that exists
        as a file, a read-only mount, a full disk) and names the path instead. Only the second can happen *after*
        validation has already succeeded, which is why its handler sits on the write rather than on the validation.
        """
        issue_csrf_token(request)
        require_csrf(request, _one_of(form.get(FIELD_NAME, [])))

        settings = app.state.settings
        # Knob spellings (`MYPKI_PORT`) to field names (`port`), with unticked checkboxes made explicit as `false`.
        submitted = _submitted_settings_fields(form)
        # Rejected saves and successful ones both re-render the inputs from knob-spelled text, so the
        # overrides dict keeps the spelling the template posts.
        posted = {f"MYPKI_{name.upper()}": value for name, value in submitted.items()}
        config_file = config_file_path(settings)

        try:
            written = validate_candidate(settings, submitted)
        except SettingsFileError as exc:
            log.info("settings save refused at %s: %s", _client_ip(request), exc.reason)
            return render_settings(
                request,
                problems=[exc.reason],
                overrides=posted,
            )

        before = read_saved_values(config_file)
        body = render_file(written, preserve_unmanaged(config_file))
        try:
            write_settings_file(config_file, body)
        except OSError as exc:
            # The write is what touches this host's filesystem, so the write is what needs the handler. The defect
            # found by test_settings_save.py: this `except OSError` used to hang off the `validate_candidate` try, which
            # performs no I/O at all — so the promise made a few lines above ("named plainly, with the path, rather than
            # rendered as a 500") was unenforceable, and a config dir that exists as a *file* answered **500** with a
            # traceback. `validate_candidate` stays outside this try on purpose: a SettingsFileError is the operator's
            # typo and belongs in the amber block, an OSError here is the host's state and belongs with the path.
            log.warning("settings save could not write %s: %s", config_file, exc)
            return render_settings(
                request,
                problems=[f"Could not write {config_file}: {exc}. Fix the directory and save again."],
                overrides=posted,
            )
        changed = tuple(name for name in sorted(written) if before.get(name) != written[name])
        log.info(
            "settings saved to %s by %s: %d of %d knobs changed",
            config_file,
            _client_ip(request),
            len(changed),
            len(written),
        )

        # A save that only reaches the next start is half a feature, so this process adopts what it just wrote.
        # `adopted` is False only when the file on disk no longer agrees with this process — a hand-edit between the
        # Save and now, or a knob whose value became unreadable — and in that case the honest answer is "written to the
        # file, not applied here", which is the honest fallback for every knob.
        adopted = True
        adoption_problem: str | None = None
        try:
            _publish_saved_settings(app, settings)
        except Exception as exc:  # pydantic ValidationError and OSError are both "this host changed under us"
            adopted = False
            adoption_problem = (
                f"Saved to {config_file}, but this process could not adopt it ({exc}). "
                "The values take effect at the next start."
            )
            log.warning("settings saved to %s but not adopted by this process: %s", config_file, exc)

        if adopted and changed:
            # `changed` is spelled the way a shell spells it (`MYPKI_PORT`) and STARTUP_ONLY_KNOBS the way pydantic
            # spells it (`port`), so the comparison has to happen on one spelling. Comparing them directly was this
            # function's first bug: every knob reported itself as live, including the four that are not.
            def needs_reboot(knob_spelling: str) -> bool:
                return knob_spelling.removeprefix("MYPKI_").lower() in STARTUP_ONLY_KNOBS

            live = [knob for knob in changed if not needs_reboot(knob)]
            reboot = [knob for knob in changed if needs_reboot(knob)]
            log.info(
                "settings applied without a restart: %d live (%s); %d need one (%s)",
                len(live),
                ", ".join(live) or "none",
                len(reboot),
                ", ".join(reboot) or "none",
            )

        # Which text the boxes show afterwards. On success, no overrides at all: for a live knob `_knob_input` renders
        # what this process resolved, which after an adopted save IS the file's value. For the four startup-only knobs
        # The answer is a pair: the box shows what was just saved (8543) and the rose sentence beside it names
        # what is genuinely still running (8443), because showing only the live value made a port save look like it had
        # done nothing. `_publish_saved_settings` still pins those four, so the page reports a saved request rather than
        # a bind that has not happened. On a failed adoption the boxes show what was typed instead, because this process
        # is demonstrably not running those values and the amber block above has to be readable against them.
        return render_settings(
            request,
            overrides=None if adopted else posted,
            changed=changed,
            just_saved=True,
            problems=[adoption_problem] if adoption_problem else (),
        )

    # ------------------------------------------------------------------------------------ inspect PEM (§13)

    def render_inspect(
        request: Request,
        *,
        paste: str = "",
        reports: Sequence[PemReport] = (),
        redacted_keys: int = 0,
    ) -> HTMLResponse:
        """`/inspect` in one render path, for an empty form and for a paste that was read.

        `paste` comes back so the text an operator just described is still on screen under the description; without it
        the page answers a question and throws away the thing that was asked about. Same reasoning as `/settings`
        re-filling every box after a refusal, with one difference worth naming: this page has nothing to refuse, so the
        echo is not a recovery from a mistake — it is what lets a reader line up a finding against the bytes it
        describes.

        `max_csr_chars` is passed rather than hard-coded in the template because the hint has to state the limit this
        process will actually apply (the knob may be 4096 or 262144), and `MAX_BLOCKS_TO_TRY` likewise: a page that
        promises "up to N blocks" must promise the N the code enforces.
        """
        issue_csrf_token(request)
        return templates.TemplateResponse(
            request,
            "inspect.html",
            context(
                request,
                paste=paste,
                reports=list(reports),
                redacted_keys=redacted_keys,
                # The exact marker text the template has to quote: passing it from `inspect.py` means the sentence on
                # the page and the string the code wrote cannot drift apart.
                redaction_marker=KEY_BODY_REDACTED,
                max_csr_chars=settings_of().max_csr_chars,
                max_blocks=MAX_BLOCKS_TO_TRY,
            ),
        )

    @app.get("/inspect", response_class=HTMLResponse)
    def inspect_page(request: Request) -> HTMLResponse:
        """An empty Inspect form (page-map §13).

        A GET is not evidence that anybody pasted anything, so no report is fabricated here — the same rule
        `settings_page` follows by refusing to pass `just_saved` on a GET. Nothing is read from disk and nothing about
        this host is shown: what `/inspect` describes is the text an operator supplies, not this server's state.
        """
        return render_inspect(request)

    @app.post("/inspect", response_class=HTMLResponse)
    def inspect_submit(request: Request, form: Annotated[dict[str, str], Depends(_form_fields)]) -> HTMLResponse:
        """Describe a pasted PEM and report what it says, refusing nothing but an oversized body (page-map §13).

        CSRF first, as on every POST in this app — even though this handler writes nothing, signs nothing and stores
        nothing, because a POST that skips the check is one missing `require_csrf` line away from being the template
        for a POST that does write. Then one call: `describe_pem` applies mypki's own cap before any parser sees the
        body (so an oversized paste answers 413 naming `MYPKI_MAX_CSR_CHARS` rather than starlette's `Field exceeded
        maximum size of 1024KB.`) and turns every content failure into a report instead of an exception —
        which is why there is no `try` here.

        The absence of a try is the feature. On `/csr/sign` a bad PEM raises and is answered by `_paste_refused` — 400
        or 403 with the reason named above the paste box — because there is a signing decision hanging on it. Here an
        expired, SHA-1-signed, RSA-1024, self-signed certificate is exactly what the operator came to look at, and it
        gets the same full table a healthy one gets.
        """
        require_csrf(request, form.get(FIELD_NAME))
        paste = form.get("pem_paste", "")
        reports = describe_pem(paste, settings_of().max_csr_chars)
        # What the textarea shows back is the paste with any private-key **body** replaced. A certificate is public
        # material and is echoed whole so a finding can be read against the bytes it describes; a key is not public, and
        # `describe_pem` already refused to open it — echoing its base64 back one line later would undo that (§13).
        echo, redacted = redact_private_key_bodies(paste)
        log.info(
            "inspected %d character(s) of PEM from %s: %s%s",
            len(paste),
            _client_ip(request),
            ", ".join(report.kind for report in reports),
            f" ({redacted} key body/bodies redacted in the echo)" if redacted else "",
        )
        return render_inspect(request, paste=echo, reports=reports, redacted_keys=redacted)

    # --------------------------------------------------------------------------------- downloads (§10)

    @app.get("/download/{artifact_id}")
    def download(request: Request, artifact_id: str) -> Response:
        artifact = one_shot().take(artifact_id)
        log.info("served one-shot download %s to %s", artifact.filename, _client_ip(request))
        return _pem_response(artifact.body, artifact.filename, artifact.media_type)

    # ------------------------------------------------------------------------------------- version line

    @app.get("/version", response_class=HTMLResponse)
    def version_page(request: Request) -> HTMLResponse:
        """A page rather than JSON, because this app advertises no API (page-map §0). The smoke scripts read it.

        `/version` renders `about.html` with the version line as a banner, not a dedicated home template:
        The home prose (what mypki is, which pages exist, what it does not do) moved verbatim to `/about`, and a
        second page carrying the same sentences is two documents that drift. The contract the harness depends on — a 200
        HTML body containing `mypki <version>` — is unchanged; only which file supplies it is.
        """
        return templates.TemplateResponse(
            request, "about.html", context(request, version_banner=f"mypki {__version__}")
        )

    # Mounted last so it cannot shadow a page route: StaticFiles answers anything under /static, and a mount registered
    # earlier would sit in front of a future /static/... page. base.html reaches this via url_for('static'), which
    # is what
    # makes the stylesheet link follow `root_path` when nginx/Caddy serves mypki under a sub-path (the recommended
    # deployment in README "Serving and exposure").
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


def _subject_display(name: x509.Name) -> dict[str, str | None]:
    """The subject a certificate was actually signed with, as label → value for the issued panel.

    Read off the finished certificate rather than from the form or the request, because those are the two things that
    may have differed. The panel has to describe the artifact an operator is about to install, and "what we meant to
    sign" is a different claim from "what this file says".
    """
    out: dict[str, str | None] = {}
    for key, oid in _SUBJECT_OIDS:
        attributes = name.get_attributes_for_oid(oid)
        if not attributes:
            out[key] = None
            continue
        value = attributes[0].value
        # `NameAttribute.value` is typed `str | bytes` because the ASN.1 string type behind an attribute varies by OID;
        # a
        # `bytes` value rendered into a template prints as `b'...'` to an operator (see ca._one for the same trap).
        out[key] = value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)
    return out


#: `(context key, NameOID)` pairs mirroring `_SUBJECT_KEYS`, so the panel and the diff speak about the same seven
#: fields. Typed as `ObjectIdentifier` (which is exactly what every `NameOID` member is) so `_subject_display` can pass
#: one to `Name.get_attributes_for_oid` without a cast.
_SUBJECT_OIDS: tuple[tuple[str, ObjectIdentifier], ...] = (
    ("common_name", NameOID.COMMON_NAME),
    ("organization", NameOID.ORGANIZATION_NAME),
    ("organizational_unit", NameOID.ORGANIZATIONAL_UNIT_NAME),
    ("country", NameOID.COUNTRY_NAME),
    ("state", NameOID.STATE_OR_PROVINCE_NAME),
    ("locality", NameOID.LOCALITY_NAME),
    ("email", NameOID.EMAIL_ADDRESS),
)


def _issued_view(issued: IssuedCert, cert_id: str, chain_id: str) -> dict[str, Any]:
    """Template view of an issued certificate.

    Built explicitly rather than by dumping `issued.__dict__`: the dataclass carries a `cryptography` certificate
    object that
    a template has no business touching, and passing it along "because it is already there" is how a template ends
    up calling
    library methods with arguments nobody reviewed.
    """
    subject = _subject_display(issued.cert.subject)
    return {
        "pem": issued.pem,
        "chain_pem": issued.chain_pem,
        "serial_hex": issued.serial_hex,
        "cert_type": issued.cert_type,
        "common_name": issued.common_name,
        "sans": issued.sans.all_entries(),
        "not_before_utc": issued.not_before_utc,
        "not_after_utc": issued.not_after_utc,
        "fingerprint_display": format_fingerprint(issued.fingerprint_sha256),
        "cert_download": f"/download/{cert_id}",
        "chain_download": f"/download/{chain_id}",
        # The subject as the certificate actually carries it (not as the request stated it, not as the form submitted
        # it),
        # so an edited `O=` shows up here rather than only in a warning line. The joined spelling is computed here
        # rather
        # than assembled by the template: a Jinja filter chain over a dict of Optionals is unreadable at 2am, and "which
        # attributes landed in this certificate" is a fact worth deriving once in Python where it can be asserted.
        "subject": subject,
        "subject_display": " / ".join(value for value in subject.values() if value) or issued.common_name,
    }
