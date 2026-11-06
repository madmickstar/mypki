# mypki

A small, self-hosted **certificate authority with a browser front end**. One command creates a single root CA on
your own machine; seven server-rendered pages then let you sign a CSR (or generate a key and one), edit the names at
the confirm step, download the CA certificate with per-OS install instructions, list what has been issued and mark a
record revoked, and read back every limit this process is running with. It runs on Linux and Windows from one
code path, needs no OpenSSL binary, no Apache, no HSM, and no account system — and it is deliberately *not* a REST
API: FastAPI here serves HTML only, with `docs_url=None, redoc_url=None, openapi_url=None` hard-coded so there is
no API surface to advertise.

If you want ACME, SCEP, intermediate CAs or certificate profiles per team, this is the wrong tool. Revocation is a
partial story: from 0.7.0 mypki **signs and serves a CRL and answers OCSP** (`/crl`, `/crl.pem`, `POST /ocsp`), and bakes
both pointers into every certificate it issues from now on — but a client only acts on that if it knows to ask, openssl
never fetches a CDP, and certificates issued before 0.7.0 carry no pointer at all. See
[Known gaps](#known-gaps-what-this-project-deliberately-does-not-do) and gotcha 2 for the four measured caveats.

Badges below are marked **live now** versus **after the first release**, because a badge that 404s is worse than no
badge: `pypi/pyversions/mypki` and coverage only mean something once a tag is published on PyPI.

[![CI](https://github.com/madmickstar/mypki/actions/workflows/ci.yml/badge.svg)](https://github.com/madmickstar/mypki/actions/workflows/ci.yml)
![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

*(Live from day one: CI, Ruff, license. After the first release is cut: PyPI Python-version badge and coverage —
`--cov-fail-under=85` in CI enforces the number either way, so if Codecov is not enabled the coverage badge is left
out rather than shipped broken.)*

---

## Quick start

```bash
python3 -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"                             # or: pip install mypki   (after the first release)

mypki init-ca                                       # creates the root CA; the GUI cannot do this
mypki serve                                         # http://127.0.0.1:8443
mypki info                                          # what CA is loaded, and where the data lives
```

Then open <http://127.0.0.1:8443>, generate or paste a CSR, sign it as `server`, download
`mypki-root-ca.crt` from `/ca`, and install that on the machine that has to trust the result (instructions are on
the page). Before serving anything real, put TLS in front — see [Serving](#serving-and-exposure).

---

## What it does

| Surface | What you get |
| --- | --- |
| `mypki init-ca` | RSA-3072 / SHA-256 self-signed root, `CA:TRUE pathLength:0`, written to `<data>/ca/` (mode 0600). Refuses to overwrite without `--force`; with it, archives the old pair instead of deleting it. Optional passphrase encryption. |
| `GET /` | The **sign form**, headed *Sign a certificate*: paste a CSR, and mypki shows what it actually asks for before you confirm. No CA facts here — `/ca` is the one page that states them (0.3.0 removed that card rather than duplicate it); what this page does say about the CA is whether a root exists and whether its key is loaded on this host. A request that asks for CA powers is refused **on this page**, in red above the paste box, with your paste left in place (`/csr/sign` renders the same page). |
| `GET/POST /csr/generate` | A private key + matching CSR, shown **once**, optionally encrypted. Nothing written to disk or the database. Prefilled from your own `MYPKI_DEFAULT_*` knobs, in fields labelled with the X.501 abbreviations a certificate viewer shows (`Common Name (CN)`, `Subject Alternative Names (SAN)`, `Organisation (O)`, …). On a successful submit three capsule controls sit at the **top** of the page — `Download CSR and Private Key` (one file, request block first then key), `Copy CSR to clipboard`, `Copy Private Key to clipboard` — with the separate `.pem` / `.key` links still under their blocks below. |
| `GET/POST /csr/sign` | Two steps: validate and show what the CSR actually asks for, then issue with mypki's own extension profile for `server`, `client` or `both`. The name fields are editable at the confirm step, and anything you changed is named back to you on the issued page. A refusal needs no round trip: garbage PEM, a bad signature, a weak key and a CA-privileged request all re-render this page with the reason above the box it belongs to and the paste still in the textarea, at **400** or **403** as before. |
| `GET /ca` + `/ca/certificate` | The CA certificate as a `.crt` download, with Windows / macOS / Linux install steps and the fingerprint to verify it out of band. Two controls sit at the **top** of the page — `download root-CA cert` and `copy to clipboard`, which fetches `/ca/certificate` rather than copying text off the page — above a facts card titled with this root's own Common Name. Since 0.7.1 the page renders **no certificate bytes at all**: the copyable PEM block 0.5.0 added was deleted, because with the controls at the top one page was offering the same root three times, so `/ca/certificate` is again the only route on this path that emits them. |
| `GET /crl` + `GET /crl.pem` + `POST /crl/rebuild` | **The CRL** (0.7.0): `/crl` is the human page — issuer, `thisUpdate`/`nextUpdate`, CRL Number, entry count, the advertised URL, the copyable PEM and the four measured caveats — and `/crl.pem` serves the same bytes as `application/pkix-crl`, `no-store`. `<data>/crl/mypki.crl.pem` is re-signed at startup, after any revoke batch that actually stamped something, and by the Rebuild button (which re-signs; it revokes nothing). No `IssuingDistributionPoint`: see gotcha 4. |
| `POST /ocsp` | **The OCSP responder** (0.7.0): DER in, DER out, HTTP 200 whatever the answer is — GOOD / REVOKED / UNKNOWN from this host's own record store, and `MALFORMED_REQUEST` or `INTERNAL_ERROR` inside a five-byte body rather than as an HTTP error. Signed by the root itself. It carries no CSRF token (the one stated exception in page-map §0) and appears on no page as a link: a client learns the URL from a certificate's `AuthorityInfoAccess`. |
| `GET/POST /inspect` | **Inspect PEM** (0.5.0): paste any PEM and read what it says — subject, issuer, SANs, key and size, validity, serial, fingerprint, signature algorithm — plus findings said out loud (*expired*, *self-signed*, `not a CA`, SHA-1, RSA-1024, a request that asks to be a CA). It **refuses nothing but an oversized body**, needs no CA on this host, and never signs or stores anything. A pasted private key is named and never opened: its base64 is replaced, its BEGIN/END lines kept so you can see which block was redacted. Read the limits in Known gaps — it verifies no chain and knows nothing about revocation. |
| `GET /issued` + `POST /issued/revoke` | Newest-first list of what has been signed — Status (`active`/`revoked`), serial, type, CN, SANs, validity, issue time. Revocation is **bulk**: one *Revoke Selected* control above the table with a checkbox per row, and a revoked row's Status cell carries the UTC stamp and the reason (as of 0.4.0 there is no separate Revoked column). No search, no delete. Revoking **records** the decision; see gotcha 2. |
| `GET /about` | What this host is running: version, source URL, the three profiles in words, and what this CA does not do (yet). |
| `GET /settings` | Every knob, **editable** since 0.3.0 — each numeric one behind a preset menu sitting over an input that still declares its real min/max. Secrets and key paths are masked. As of 0.4.0 a successful save is adopted by the running process, except `MYPKI_HOST` / `MYPKI_PORT` / `MYPKI_SESSION_MAX_AGE` / `MYPKI_DATA_DIR`, which need a restart and are marked rose on the page. As of 0.5.0 those four boxes show **what the file says** rather than what this process is running, with a sentence naming the value still in effect — so saving a port no longer looks like it did nothing. |
| `mypki serve` / `mypki info` | Run the app; inspect the CA and the resolved data dir from a terminal. |

Exit codes are part of the interface, so a wrapper script never has to parse stderr:

| Code | Meaning |
| --- | --- |
| 0 | success |
| 1 | validation or usage failure (bad CN, bad SAN, weak key spec) |
| 2 | **refused**: the CA already exists and `--force` was not given |
| 3 | required state missing: no CA found (`serve`, `info`) |

Exit 3 is **only** the missing-CA case. A port that is already held prints
`error: cannot start <host>:<port>: the server never bound …` and exits **1**, not 3, so a wrapper can tell
`mypki init-ca` apart from `something else has my port` without reading prose. (Before this was fixed the two
were indistinguishable: uvicorn swallowed the bind error and exited 3 on its own.)

`tools/e2e_harness.py` uses the same family: 0 passed · 1 at least one FAIL · 2 **nothing was checked** — never read as
a pass ([SMOKE_TESTING.md](SMOKE_TESTING.md)).

---

## Two gotchas that will bite you

**1. The CA private key and its passphrase cannot be recovered.** There is no backup command, no escrow, no second
copy. Lose `ca_key.pem` (or its passphrase) and the answer is `mypki init-ca --force` — which archives the old pair,
mints a brand-new root, and means **every client that trusted the old root has to be re-installed**. Treat the data
dir as something you back up offline, and treat `--encrypt` as insurance against the file being copied rather than
against you forgetting the passphrase.

**2. Revocations are recorded, published — and honoured only by clients that go looking.** `/issued` can mark a record
revoked — serial, UTC timestamp and an optional reason, stored in `issued.db`, shown in a Status column. From 0.7.0 that
decision is also **published**: `<data>/crl/mypki.crl.pem` is re-signed on startup, after every batch that stamps
something, and on the Rebuild button at `/crl`, and `POST /ocsp` answers GOOD / REVOKED / UNKNOWN for a serial. What has
**not** changed is the client side, and these four facts are measured rather than assumed:

1. certificates issued **before 0.7.0 carry no pointer** to either artifact, so nothing on them says "ask this CA";
2. new leaves do carry one (`CRLDistributionPoints` → `<crl_base_url>/crl.pem`, plus an OCSP access location), and
   **openssl never fetches it** — `openssl verify -crl_check` answers `error 3 … unable to get certificate CRL` unless you
   pass `-CRLfile` yourself;
3. a revoked certificate whose own validity has already lapsed is **dropped from the CRL** (the row stays in `issued.db`
   forever — there is no un-revoke and no delete) and OCSP answers UNKNOWN for it;
4. adding an `IssuingDistributionPoint` to scope that CRL was measured to make `openssl verify -crl_check` answer
   `error 44 … different CRL scope` for **every** certificate this CA issued before 0.7.0, so mypki publishes a plain CRL.

A certificate issued by mistake — wrong host, wrong SAN, longer validity than you meant — therefore still **stays trusted
by clients until it expires** unless those clients consult a revocation artifact they were never pointed at.

That is still why `MYPKI_VALIDITY_MAX_DAYS` exists and why over-max requests are refused naming the limit instead of
being quietly clamped: the ceiling is what bounds a certificate this host cannot effectively revoke. 0.2.0 raised it
from **825 to 1461** (4 years) because the decision is now at least *recorded*; if any client of yours refuses a
long-lived leaf, set `MYPKI_VALIDITY_MAX_DAYS=825` and nothing else about your setup changes. Issue short-lived
certificates on purpose; re-issue rather than revoke.

---

## Serving and exposure

There are no logins, so exposure is controlled by binding, TLS and network placement:

- `mypki serve` binds **127.0.0.1** by default. `--host 0.0.0.0` (or `MYPKI_HOST`) works but prints a warning
  naming what it means: anyone who can reach the port can ask this CA to sign certificates. Firewall the port to the
  subnet that needs it.
- Plain HTTP prints a banner on startup. Either pass `--ssl-cert F --ssl-key F` (uvicorn `ssl_certfile`/`ssl_keyfile`)
  or — usually simpler — leave mypki bound to loopback and run nginx/Caddy/IIS in front of it, terminating TLS there and
  forwarding to `127.0.0.1:8443`. If you take that route, keep `MYPKI_HOST` on loopback: a reverse proxy that reaches
  mypki over the network needs mypki bound somewhere that proxy can connect to, and at that point the LAN-exposure warning
  above is the sentence that applies. Session cookies become `Secure` only when **both** TLS knobs are set
  (`settings.tls_enabled`), so a proxy-terminated setup does not get `Secure` cookies from mypki itself — put them on the
  proxy instead.
- **Write a Windows TLS path with forward slashes, or with single backslashes.** In `.env` and in the file `/settings`
  saves, `MYPKI_SSL_CERTFILE=C:/root_apps/mypki-data/www/server.crt` and
  `MYPKI_SSL_CERTFILE=C:\root_apps\mypki-data\www\server.crt` both work; `C:\\root_apps\\…` does not. A dotenv line is
  not a PowerShell string — doubling the separators is passed through verbatim, so mypki resolves a path that exists
  nowhere. Since 0.4.0 `mypki serve` checks both TLS files before binding and exits 1 naming the knob and the path
  (`config error: MYPKI_SSL_CERTFILE points at a file that does not exist: …`); before that, the same mistake surfaced
  as `cannot bind 0.0.0.0:8443: [Errno 2] No such file or directory`, which sends you looking for a process holding the
  port rather than at the path you typed.
- Every POST requires a CSRF token; every response carries `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy: same-origin` and CSP `default-src 'self'` (no CDN, and no `unsafe-inline`:
  the one script this app ships is a same-origin `<script src>`, which `default-src 'self'` already permits);
  every PEM/key/CSR download is `Cache-Control: no-store`.
- The CA private key is loaded **once** at startup and never read per request. It is not a route target, it is not in
  the database, and `tests/test_no_key_leakage.py` asserts that no response body or header contains `PRIVATE KEY` or
  the CA key's actual DER bytes.

---

## Configuration

All knobs are environment-driven (`MYPKI_` prefix, `.env` supported); see [.env.example](.env.example) for the
annotated version of every one.

`cp .env.example .env` before setting any knob: `.env` is gitignored and deliberately never shipped, so the
annotated example is the file that travels with the package.

| Variable | Default | What it costs |
| --- | --- | --- |
| `MYPKI_HOST` / `MYPKI_PORT` | `127.0.0.1` / `8443` | Any non-loopback host exposes signing to that network |
| `MYPKI_DATA_DIR` | XDG on Linux, `%LOCALAPPDATA%\mypki` on Windows | Must not sit inside a web-served directory |
| `MYPKI_SSL_CERTFILE` / `MYPKI_SSL_KEYFILE` | unset (plain HTTP) | Both or neither; setting both is what makes cookies `Secure`. Forward slashes or single backslashes on Windows — and both files must exist and be readable, or `serve` exits 1 naming which one |
| `MYPKI_CA_CN` | `mypki Root CA` | Changing it later means re-issuing the CA and re-installing it everywhere |
| `MYPKI_VALIDITY_DEFAULT_DAYS` / `MYPKI_VALIDITY_MAX_DAYS` | 365 / 1461 | The main bound on a mistake that needs no cooperation from the client: a CRL entry or an OCSP answer counts only for a client that consults one, so a wrong certificate stays trusted until it expires |
| `MYPKI_CRL_BASE_URL` | `http://mypki.my.lab` | The absolute base baked into new leaves as their CRL/OCSP pointer and advertised on `/crl`. Must start with `http://` or `https://`; must resolve where the clients are; changing it changes only certificates issued **after** the change |
| `MYPKI_DEFAULT_ORGANIZATION` / `_ORGANIZATIONAL_UNIT` / `_COUNTRY` / `_STATE` / `_LOCALITY` / `_EMAIL` | `Lab` / `IT` / `AU` / `Victoria` / `Melbourne` / `it@mypki.lab` | Prefills the Generate-CSR form. Empty leaves a field blank; each value is validated at startup, not mid-signing |
| `MYPKI_MAX_SANS` / `MYPKI_MAX_CSR_CHARS` | 100 / 32000 | Caps one request's blast radius; oversized paste gets mypki's own error page |
| `MYPKI_LOG_*` | see below | Bounded at `log_max_bytes * (log_backup_count + 1)` |
| `MYPKI_SECRET_KEY` | generated into `<data>/instance/secret_key` (0600) | Explicit value is how sessions survive across hosts; it is then readable by anyone who can read `.env` |

Precedence for the data dir: `--data-dir` > `MYPKI_DATA_DIR` > OS default.

### Where the files live

```
<data>/ca/ca_key.pem         # never served, never logged, never in the DB; 0600 on POSIX
<data>/ca/ca_cert.pem        # the only certificate served
<data>/ca/archive/<UTC-ts>/  # what --force replaced; nothing is ever deleted
<data>/instance/secret_key   # session secret, 0600 on POSIX
<data>/issued.db             # SQLite (WAL): metadata only, no keys and no PEM bodies
```

**Key protection, honestly:** on Linux/macOS mypki creates `ca/` as `0700`, writes the key, chmods it to `0600`, then
re-`stat`s the mode and fails if it is group- or other-accessible. On Windows `os.chmod` only toggles the read-only
bit — **it is not an ACL** — so protection comes from the key living under per-user `%LOCALAPPDATA%`, from optional
`icacls` hardening behind `--secure-acl` (invoked as a fixed argument array with no user-supplied component, skipped
silently if `icacls` is absent), and from passphrase encryption as the cross-platform guarantee.

---

## Logging

`logs/mypki.log` by default — a relative path, resolved against the working directory, and the **resolved absolute
path is the first line written to the file**, so "where did it actually land?" is answerable from the process rather
than from reading a config file. Handlers attach to the *root* logger so uvicorn's per-request lines land in the same
file (which is also why `mypki serve` passes `log_config=None` to uvicorn — see `src/mypki/logsetup.py` for the
measured reason). Encoding is pinned to UTF-8 because a logging failure must never be able to break request handling.

Rotation is size-bounded at `MYPKI_LOG_MAX_BYTES * (MYPKI_LOG_BACKUP_COUNT + 1)` and is per-process, so run **one
worker per log file**. An empty `MYPKI_LOG_FILE=` means console-only.

A filter on the `mypki` logger tree drops any record containing `PRIVATE KEY`: this project's failure mode is not too
little in the log but too much, and an invariant you have to remember is an invariant that eventually isn't kept.

---

## Divergences we state out loud

Three things in this tree are **not** in the brief's own lists. They are additions, each one measured rather than
assumed, and they are named here so nobody has to diff the tree against the spec to find them:

- **`src/mypki/templates/error.html`.** The brief mandates "mypki's own error page" without naming a template file for
  it. A fifth template is therefore unavoidable if that sentence is to be honoured literally, so `error.html` is listed
  as a stated addition rather than presented as part of the mandated four pages. The count has grown release by release:
  0.2.0 shipped eight templates and seven HTML pages (`home.html` was removed and its prose moved to `/about`), and 0.5.0
  ships **nine templates** — those eight plus `inspect.html` — behind **nine GET-rendered HTML routes** (`/`,
  `/csr/generate`, `/csr/sign`, `/ca`, `/issued`, `/about`, `/settings`, `/inspect`, `/version`) plus two GETs that answer
  in bytes rather than HTML (`/ca/certificate` and `/download/{artifact_id}`). What counts as a *page* is a decision, so it
  is stated rather than implied: seven of the nine carry a nav link (`/inspect` is the seventh), `/version` renders
  `about.html` with no nav item of its own, and `error.html` is reachable by navigation not at all — only by a refusal or a
  bad address. `docs/page-map.md` §0 exists for the
  same reason: it is the section the brief does not have, and it is where the error page's contract lives (status code,
  the specific reason, a link back — never Starlette's JSON, never an HTML traceback).
- **`itsdangerous>=2.2` in runtime dependencies.** The brief's dependency list does not name it, on the assumption that
  SessionMiddleware pulls it in. MEASURED on starlette 1.10: `starlette.middleware.sessions` does `import itsdangerous`
  but declares it as the optional `starlette[sessions]` extra, so a plain `pip install fastapi` leaves
  `SessionMiddleware` raising `ModuleNotFoundError` at app construction — which means `mypki serve` would fail on import
  for anyone who installed this wheel from PyPI. It is present in development environments only because something else
  already installed it. The same reasoning sits as a comment above `dependencies` in `pyproject.toml`.
- **`httpx2>=2.16` in the `dev` extra.** MEASURED on starlette 1.10: `starlette.testclient` imports `httpx2` and raises
  `RuntimeError` without it, accepting plain `httpx` only as a deprecated fallback. Every page test drives the app
  through `TestClient`, so without this line `pip install -e ".[dev]" && pytest` aborts at collection on a fresh
  checkout — the same class of failure as the bullet above, caught on a clean install rather than on this machine.

---

## Known gaps (what this project deliberately does not do)

Out of scope by design, stated rather than left to be discovered:

- No external/REST API — HTML pages only, no OpenAPI, no docs routes.
- No logins, accounts, roles or approval workflow. Exposure is a binding/TLS problem instead.
- **Revocation that only consulting clients see** (0.7.0): revocations are recorded in `issued.db`, shown on `/issued`,
  published as a signed CRL at `/crl.pem` and answered over `POST /ocsp`. What is still absent is any effect on a client
  that does not consult them — mypki fetches nothing, enforces nothing, has no delete, and pre-0.7 certificates carry no
  pointer to either artifact. A revoked certificate stays trusted by clients until it expires. See gotcha 2 for all four
  measured caveats, and `/crl` for the responder's own limits (echoed CertID hashes, the two request-size limits, and the
  missing `id-kp-OCSPSigning` on a root that signs its own answers).
- No intermediate CAs, no HSM support, no ACME/SCEP/EST.
- No multi-tenancy, microservices, or a JavaScript **front end**. The UI is server-rendered HTML plus one stylesheet.
  Since 0.3.0 there is also one same-origin script (`static/app.js`) that **no page requires** — copy buttons, a select-all
  box and a confirmation dialog, each with a server-rendered route to the same result. A framework, a build step or a
  client-side rendering layer remains out of scope.
- No audit trail or compliance reporting. `GET /issued` is a convenience list, not evidence.
- **`/inspect` reads; it does not judge.** It performs **no chain verification** — there is no trust store on this host and no issuer certificate to check against, so it can name an issuer but cannot say anybody trusts it. Its findings are descriptions, not gates: the rules that refuse live on `/csr/sign`, which is the page that issues. And although this host now publishes a CRL and answers OCSP, `/inspect` consults **neither**: it reads the PEM you pasted and nothing else, so a certificate it reports as valid may have been revoked by whoever issued it — including by this very host. The page says all three things about itself, in those words.
- **Four knobs still need a restart.** Saving `MYPKI_HOST`, `MYPKI_PORT`, `MYPKI_SESSION_MAX_AGE` or `MYPKI_DATA_DIR` writes them for the next start; every other knob on `/settings` takes effect in the running process as soon as the save succeeds. The page says which is which, per knob.

---

## Development

```bash
pip install -e ".[dev]"
make gate          # lint + types + version chain + full suite with coverage
make fast K=sign   # while editing: cheap subset, targeted tests only
make zip           # release artifact (run last — a zip is a copy of what was gated)
pre-commit run --all-files
```

`Makefile` is the single source of truth for commands. CI calls the same targets, so a command that exists only in CI and
nowhere else cannot drift into being the one that actually matters. The coverage floor (`fail_under = 85`) is declared once,
in `[tool.coverage.report]`, rather than retyped onto each invocation.

`make fast K=KEYWORD` (or `python3 tools/fast_lane.py KEYWORD`) runs the cheap half — scoped ruff, the version chain and a
targeted `pytest -k` — and leaves mypy, coverage measurement and the end-to-end harness to `make gate`, which is what it
owes either way.

`tools/harness_parity.py` and `tools/harness_ledger.py` are gone with the two harness logs they compared: with a single harness
there is nothing left to line up heading for heading, and the ledger it generated from a log is now written by the harness itself.
The harness is not a separate comparison run either — `make e2e` is the last step of `make gate`, so a commit does owe it.

`docs/page-map.md` is the spec and the code cites it as `page-map §N`; if behaviour and that file disagree, fix both
in the same commit. Tests are hermetic — a fixture points `MYPKI_DATA_DIR` at a temporary directory, so no test ever
touches your real CA. CI runs lint, mypy, pytest on **ubuntu-latest and windows-latest** across Python 3.10–3.13 and the
version chain; the Windows leg is what proves the path handling and that no OpenSSL binary is required.

A harness run's totals and per-section counts are written by the harness itself into `reports/harness-ledger.json` (gitignored)
rather than being retyped into a document, because a copied measurement goes stale on the first unrelated change and nobody can
tell. Nothing in-tree quotes it; SMOKE_TESTING.md's *Reading the result* says how to read it.

Manual walkthrough: [SMOKE_TESTING.md](SMOKE_TESTING.md), automated by
`tools/e2e_harness.py` (`make e2e`, and the last step of `make gate`; tracked in git, not part of the installed package).

---

## Versions and releases

`src/mypki/__init__.py`'s single line `__version__ = "0.1.0"` is the only place the number lives; `pyproject.toml`
declares `dynamic = ["version"]` and never a static version, hatchling reads that one line, CHANGELOG.md must carry a
section for it, and releases are annotated tags `vX.Y.Z`. `tools/check_version.py` proves the chain agrees (exit 0),
reports drift (exit 1) or says it could not check (exit 2 — never read as a pass).

Version numbers are **release-time facts, not working-commit facts**: ordinary commits do not bump `__version__`; what
advances per commit is git history. See [CHANGELOG.md](CHANGELOG.md).

---

## Naming

`mypki` is the repository name, the import package and the PyPI distribution name; the console command is `mypki`.
The name was checked against PyPI before choosing it (`pypi.org/pypi/mypki/json` → 404, `pypi.org/simple/mypki/` → 404,
and every PEP 503 normalisation variant free), and PEP 503 normalisation means registering `mypki` also blocks
`MyPKI`, `my-pki` and `my_pki`. If it is ever squatted, the fallback distribution name is `mypki-ca` with repo,
package and command unchanged.

The CLI has **no** `sign`, `revoke` or `export-key` subcommand, on purpose: the GUI is the signing surface so that
validation and the extension profile cannot be bypassed — there is no path to a signature that skips step A's checks, and no
path that copies a request's own extensions into a certificate without an explicit consent box being ticked on the confirmation
page (page-map §3 rules 6-8) — revocation does not exist here (gotcha 2), and a key-export
command would be the one place this project could hand out the thing it exists to protect. The download named
`mypki-root-ca.crt` uses `.crt` rather than `.pem` because Windows' double-click installer keys off the extension.

---

## License

MIT — see [LICENSE](LICENSE).
