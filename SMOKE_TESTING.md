# Smoke testing mypki by hand

A numbered walk of the whole surface, in the order a new operator would actually meet it. The section numbers below are
the contract: `tools/e2e_harness.py` prints exactly these **sixteen** headings (plus §11 STEP F's openssl half), so a
failure on the harness names the same step this document describes, and a manual run and an automated run can be compared
line by line. 0.2.0 added three of them (§11 revocation, §12 About/Settings, §13 inline form errors) and pushed the
armour sweep from §11 to §14; 0.5.0 added §15 (Inspect PEM); **0.6.0** added §16 (Dropped extensions
need consent). Note that a harness section number and a `page-map` section number are
different numbering systems and the harness prints both: this file's §15 is `page-map §13`, its §16 is `page-map §3` rule 6, and the label text on each assertion says so.

The harness asserts **occurrences**, not lines, and exits **0** when every check passed, **1** when at least one
FAILed, and **2** when *nothing was checked* (no version readable, `init-ca` failed, or the spawned server never accepted a
connection). Exit 2 is never a pass, and
that distinction is the point of the harness: a smoke test that reports success because it could not reach the server is
worse than no smoke test.

## Before you start

```bash
python3 -m venv .venv && . .venv/bin/activate         # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

# Name the SAME data dir for BOTH commands. An env var is per-process: if you set it only on the serve
# line, init-ca writes the OS default (%LOCALAPPDATA%\mypki on Windows) and serve then looks somewhere else
# and exits 3 'No CA found at <dir>\ca\ca_cert.pem'. A measured reproduction of exactly that trap:
# `MYPKI_DATA_DIR=/tmp/doccheck/other mypki serve --port 8443` after an init-ca that named no data dir.

# POSIX shells:
mypki init-ca --data-dir /tmp/pkismoke/data          # the GUI cannot create a CA; this does
MYPKI_DATA_DIR=/tmp/pkismoke/data mypki serve --port 8443   # same dir as the line above
```

```powershell
# PowerShell: there is no `VAR=value cmd` prefix form, so the variable goes on its own line.
mypki init-ca --data-dir "C:\tmp\pkismoke\data"
$env:MYPKI_DATA_DIR = "C:\tmp\pkismoke\data"
mypki serve --port 8443
```

Open <http://127.0.0.1:8443>. Plain HTTP prints a startup banner — expected, and §2 checks the headers that make plain
HTTP safe on a loopback port.

Automated equivalent of everything below, and the reason the manual walk is not the only evidence. `tools/e2e_harness.py`
mints its own throwaway CA (`mypki init-ca`, in a scratch data dir), spawns `mypki serve` on an ephemeral port the OS
chose, drives all sixteen sections over one real socket with one cookie jar, and removes the scratch tree afterwards — so
there is nothing to start first, and nothing you care about is touched. It prints its own totals and carries no hard-coded
expected count, so what a run printed is always visible in the run rather than asserted from the document. The same run
writes `reports/harness-ledger.json` (gitignored): totals, per-section counts, and every failure and warning tagged with
its section. Read the current numbers there — see *Reading the result*. The per-section delta this build carries over the
shipped 0.7.0 is explained assertion by assertion in *Reading the result*; earlier runs' numbers are not restated here.

```bash
make e2e                                                        # the sixteen checks, in this order
.venv/bin/python tools/e2e_harness.py                           # the same thing without make
.venv/bin/python tools/e2e_harness.py --work /tmp/e2ework       # keep the fetched pages, PEMs and logs to read
.venv/bin/python tools/e2e_harness.py --keep-data               # also keep the scratch DATA dir (it holds a real CA key)
```

`make gate` runs it last, after lint, mypy, the version chain and the coverage suite: it is the only gate in this project
that can answer a question about *served bytes* rather than about source.

**Cross-platform honesty, restated for one harness.** The two shell harnesses this file used to point at — a POSIX `.sh`
and a PowerShell `.ps1` — were executed under `pwsh` 7.6.9 **on Linux**, and neither has ever been run on Windows; the only
Windows walk ever measured here was a 0.2.0-era one, quoted below as history. The Python harness inherits that honesty
rather than escaping it: it has been run on this box (Linux, Python 3.12, OpenSSL 3.5.6) and never on Windows, so "runs on
Windows" remains a claim `.github/workflows/ci.yml`'s `windows-latest` leg supports about the **package** and not one this
file can make about the **harness**. What changed is that there is now one implementation instead of two transcriptions of
each other, and the parity apparatus those two needed — a static `.ps1` audit against the `.sh`, and a tool to compare two
logs heading for heading — went with them.

It reads the expected version from `src/mypki/__init__.py` rather than carrying a literal, so a run proves *which build* it
talked to; when that file cannot be read the harness exits **2** and says so, because §3's whole job is attributing every
other result in this document to a specific build.

**It resolves no base URL, and that is a fix rather than a loss.** The shell harnesses had to find a server an operator had
already started, which is why 0.5.2 gave them the full layer chain (`--base`/`-Base` → `$BASE`/`$env:BASE` →
`MYPKI_HOST`/`MYPKI_PORT` in the environment → `<config-dir>/mypki.env`, the file `/settings` writes → `./.env` → mypki's own
defaults, host and port independently because `Settings.host` and `Settings.port` are two fields with two defaults). Before
that an operator who saved a new port on `/settings` and then ran the harness got `NOTHING WAS CHECKED:
http://127.0.0.1:8443 is not answering` — exit 2, *nothing was checked* — from a healthy server. A wildcard bind was its own
trap: `MYPKI_HOST=0.0.0.0` is what an operator writes to mean "answer on every interface of this box", and `config.py`
accepts it for exactly that reason, but it is a **bind** address rather than one anyone can dial. MEASURED here: with
`MYPKI_HOST=0.0.0.0` written into `<config>/mypki.env` and the server honestly on `:8591`, `curl http://0.0.0.0:8591/`
**does** answer on Linux, so the defect was invisible on this platform, while `http://[::1]:8591/` failed to connect against
that IPv4-only bind and on Windows the same base resolves through the route table. Both of them therefore had to keep
spelling what the operator's file says in `base resolved from:` while quietly dialing loopback — one precedence rule written
twice, in two languages, which was itself a drift risk taken on purpose. This harness cannot be pointed at a server at all:
it binds nothing, asks the OS for an ephemeral port (bind on port 0), spawns `mypki serve --host 127.0.0.1 --port <that
port> --data-dir <scratch>` and dials `127.0.0.1`. There is no base to resolve, so there is no rule to express twice.

**What the harness deliberately cannot do:** it cannot be aimed at a server you already run, at an `https://` endpoint with a
real certificate, or at an installed wheel instead of this checkout. For those, walk the sections by hand — which is what
"by hand" in this file's title still means, and each step below says what to fetch.

**Honesty note, inherited rather than dissolved.** Those two harnesses — the POSIX `scripts/smoke_test.sh` and its
PowerShell mirror `scripts/smoke_test.ps1` — were both executed under `/tmp/pwsh/pwsh` 7.6.9
**on Linux**, against live servers of their own, green and matching section for section. Neither has ever been run on
Windows: no Windows host, no `powershell` 5.1, no `%APPDATA%\mypki` path, no `certutil`, and no CRLF report has ever come out
of this box (a `pwsh` binary had to be installed here at all to execute the `.ps1`). One Windows walk *was* measured, on a
**0.2.0-era** tree (2026-10-28), where every check from §1 through §14 was answered — and what it left unsettled is recorded
honestly rather than smoothed over: which shell was used (`pwsh` 7 or `powershell` 5.1 — the report did not say), and its
terminal output (only a markdown report was shared, so the printed headings were never compared side by side). Those numbers
describe 0.2.0 and are **not this build's baseline**.

`tools/e2e_harness.py` inherits that honesty instead of escaping it: it has been run on this box (Linux, Python 3.12,
OpenSSL 3.5.6) and never on Windows. "the harness runs on Windows" is therefore **not** a claim this file makes; what CI's
`windows-latest` legs prove is that the *package* builds, imports and tests there — a different claim, and the one that
matters for path handling.

**What those two implementations established, and what still holds.** Seven harness defects were found by running them
against a correct app, and every one was fixed in the harness rather than in mypki: three from §15/§12/§9, three from §16,
and a seventh from §11 STEP F (`post_der` dropping the literal `-D` from its optional header-dump argument, so curl read the
dump path as a URL, answered status `000`, and wrote DER onto stdout inside a command substitution). Three more were caught
before any run by `bash -n` / a `pwsh` AST parse — recorded separately, because "the app proved it" and "the parser proved
it" are different claims. The `.sh` harness also proved two things about **itself** on 0.2.0: its first live walk failed two
checks, one aiming a provenance assertion at the issued card when the provenance block lives on the step-A confirm page, and
one counting every *other* record's revoke control on a host that already held twelve active certificates. Both were rewritten
against measurement (see §6 and §11). A smoke test that has never been run is a hypothesis; those failures are why the counts
in *Reading the result* come from a run rather than from a count of assertion call sites in a source file. And they are why
this harness seeds two certificates in §6 instead of letting §11 WARN-skip: a skipped assertion and a relaxed needle look
identical from the summary line, which is the single lesson worth keeping from those shell harnesses.

**What did not survive them.** The `.sh`/`.ps1` parity audit — heading text compared line for line, per-section call-site
counts, helper-definition counts, splat spellings, CR-byte and non-ASCII byte counts, `pwsh` AST parse results — was a
measurement **of those two files**, and it is not reproducible now that they are gone. Its last run reported
`sh=[263 pass, 277 fail, 7 warn]` against `ps1=[263, 282, 7]`: a +5 gap made entirely by the `.ps1`'s five helper guard
branches (`Measure-Regex`, `Get-FileState`, the settings-form reader, `Get-PemDerSha`, `Get-CrlPemDerHex`) each adding a fail
when it could not do its job, and sixteen per-section call-site pairs matching arm for arm (§1 7/7 · §2 18/19 · §3 1/1 +1 warn
· §4 1/1 · §5 9/10 +1 warn · §6 12/14 +1 warn · §7 2/2 · §8 2/2 · §9 14/15 · §10 16/16 · §11 74/75 +1 warn · §12 33/37 ·
§13 10/10 · §14 1/1 · §15 33/36 +2 warn · §16 30/31 +1 warn). Those numbers describe deleted files. They are recoverable
with `git show bc0031b:scripts/smoke_test.sh` and `git show bc0031b:scripts/smoke_test.ps1`, so they are quoted here once, as
history, and policed no more — including the byte-level findings that audit produced (the `.ps1` held 0 CR bytes under every
reading, while `grep -c $'\r'` under dash had reported 32 and `grep -c '\r'` 1,547 because `/bin/sh` on this box is dash and a
BRE `\r` is just `r`: a claim corrected by measuring bytes instead of quoting a shell pattern).

What replaced the audit is not a second implementation to keep in step but one implementation with **one** counting rule —
`count`/`count_re` over occurrences, `joined` where a template wraps a sentence mid-clause — and no line-count interpretation
left to defend. This harness counts the assertions it actually executed and prints them per section; there is no helper whose
guard branches can make one implementation's total differ from another's, because there is only one.

---

## §1 Home page (page-map §1)

**Do:** `GET /`.

**Expect:** 200. `/` **is** the sign form (page-map §1) — the harness asserts the heading `<h1>Sign a certificate</h1>` (this build's
renaming of *"Sign a certificate signing request"*, which no longer appears anywhere in the tree), the *"Paste a CSR (PEM)"*
field, and the sentence *"CSR requesting CA powers will be refused."* under the heading, because `/` and `/csr/sign`
render one shared template and a leftover `home.html` would still answer 200 while being a second document that drifts.

**As of 0.3.0 there is no CA card on `/`.** Every fact below lives on `/ca` alone (§9), and §1 asserts each of them **absent**
here: the harness fails if `/` renders the CA subject, a colon-grouped fingerprint, any `BasicConstraints` line with nothing
staged, or CA key presence. A home page that grew the card back would still answer 200 and every other §1 check would still
pass, so absence is the only way to catch the drift. MEASURED on a live 0.3.0 server: all four read 0 on `/`.

The CA facts themselves (see §9 for where they now render), built from the **public certificate only**:

- the subject (`mypki Root CA` unless `MYPKI_CA_CN` said otherwise);
- validity window and serial;
- a **colon-grouped** SHA-256 fingerprint — 32 pairs like `AA:BB:…`, not raw hex. Raw hex on a page is a fingerprint nobody
  compares by eye;
- `CA:TRUE pathLength:0`, i.e. the root's own BasicConstraints, so what you are about to trust is visible on the page rather
  than only inside the file;
- key spec (RSA 3072 / SHA-256);
- **"private key on this host"** as a *boolean*. The page reports whether the key is loaded; it never displays, links to or
  hints at the key.

**Without a CA:** still 200, with the notice *"No CA on this host yet. Run `mypki init-ca` in a terminal — the web UI cannot
create one."* A missing CA is a state, not an error page.

## §2 Security headers (page-map §0)

**Do:** fetch `/` and read the response headers — with `curl -D`, **not** `curl -I`. mypki declares GET-only routes, so HEAD
answers 405 and its headers describe a request that never happened.

**Expect on every response:**

| Header | Value |
| --- | --- |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Referrer-Policy` | `same-origin` |
| `Content-Security-Policy` | starts `default-src 'self'`, and contains **no** `unsafe-inline` |

**0.3.0 adds one script, and this section is what proves it stayed inside that CSP.** `static/app.js` is linked with
`<script src>`, which `default-src 'self'` already permits; nothing is inlined. The harness asserts both halves — no inline
`<script>` block on `/`, and a `<script src>` link present (a page that lost its link would lose its copy buttons silently while
every other check kept passing) — then fetches `/static/app.js` itself and asserts **200**, `content-type: text/javascript` (a
browser refuses a script served as `text/plain`), and the *same* CSP on the static response (a static route that bypassed the
middleware would be the hole). MEASURED on this 0.5.0 build: **14968 bytes**, `content-type: text/javascript; charset=utf-8`, `nosniff`,
`x-frame-options: DENY`, `referrer-policy: same-origin`, CSP `default-src 'self'; base-uri 'self'; frame-ancestors 'none'`. (An earlier
revision of this file said 11030 bytes; that was the 0.3.0-era `app.js`, and the number is re-read from the served response rather than
carried forward.) **`app.js` itself is byte-identical to 0.4.0's** — 0.5.0 added a page but no script, so `/inspect`'s copy button reuses the
`data-mypki-copy` wiring that has been there since 0.3.0.

**0.5.0 adds the stylesheet to this section**, because what it changed is CSS rather than markup: `.pending-saved` (the rose sentence beside a
restart-only box) and `.findings`/`.finding` (page-map §12, §13). A harness that never renders a page in a browser cannot assert what either
looks like, so the five new assertions are all about the **served asset**: `GET /static/style.css` answers 200; it is served as `text/css` (a
browser refuses a stylesheet served as `text/plain`); its response carries the same CSP as the pages; the file defines `.pending-saved {`;
and that rule reuses the palette's existing `--rose` rather than introducing a colour. MEASURED **on the 0.5.0 build**,
which is the release that added these five
assertions: 25,845 bytes served (0.4.0's was 24,292). This build serves 28,827 — MEASURED below, not inherited.

**0.5.2 adds five more assertions to this section, for the same reason.** An operator reported that `/inspect`'s PEM paste box rendered
narrower than every other section on its own page; the fix is CSS (page-map §13), and a harness with no browser cannot assert what the box
*looks like*, so these five assert the **text of the served asset** plus the one class in the markup that makes the scoping possible:
`form.stacked.inspect-form { max-width: none; }` (the 46rem cap lifted for that form only), `form.inspect-form #pem_paste { width: 100%;
max-width: none; }` (the box itself), `form.inspect-form button.save-settings { max-width: none; }` (the button follows its field), a
**zero-count** assertion that `.settings-form .field textarea` appears nowhere — the guard against a fix scoped to `/inspect` leaking into
`/settings`, which is precisely the mistake a browser-less harness cannot otherwise see — and `GET /inspect` carrying
`class="settings-form stacked inspect-form"` exactly once, because a CSS rule whose class is missing from the markup styles nothing. The GET
itself is not an assertion; only its class count is. **MEASURED on this build: `GET /static/style.css` answers 200 with
28,827 bytes** (`content-length` and the body length agree; sha256 `3d7a609619970d…`; `wc -c src/mypki/static/style.css`
is the same 28,827 at every commit in this tree). The shipped **0.7.0** zip carries a different asset —
`/tmp/extract-070/mypki-0.7.0/src/mypki/static/style.css`, **28,152 B**, sha256 `d4b7468bbaa3c8…` — 675 bytes smaller than
this tree's asset, the difference having arrived with 0.7.1 rather than with any CSS edit made here (the file is already 28,827
in this tree's baseline commit). An earlier draft of this file quoted **28,152** as "re-measured on this build" and asserted the
two assets were byte-identical. They are not, which is why the number above was measured from a request rather than copied from
the release: a "MEASURED on this build" line that had been carried over from 0.7.0 is exactly the failure mode this section warns
about, and nothing caught it because **no assertion here reads a stylesheet size** — §2's twenty assertions are rule-text and
class assertions, so a stale byte count could sit in the prose unchallenged. What remains unmeasurable is the rendering, and
these labels say "the served stylesheet defines", never "the page looks like".

**What this section does not and cannot assert:** that a copy button worked. No browser exists on the host these notes were
written on, `navigator.clipboard` needs a secure context, and on plain HTTP the script falls back to `execCommand('copy')` while
Download remains. The script is asserted as an **asset**, never as a requirement — every check in this document ran without
executing it.

The CSP has no CDN and no JavaScript on the page at all, so `unsafe-inline` would be a concession to nothing — its absence is
checked as an occurrence count of zero, which is the only way to assert it.

## §3 Version (read from __init__.py, never hard-coded here)

**Do:** `GET /version`.

**Expect:** 200, HTML containing `mypki <version>`, where `<version>` is what `src/mypki/__init__.py` declares. This step
exists so that every other result in this document can be attributed to a specific build: if §3 disagrees with the checkout
you are reading, the server you are testing is not this code.

## §4 No API surface (docs_url/redoc_url/openapi_url are None)

**Do:** `GET /docs`, `GET /redoc`, `GET /openapi.json`.

**Expect:** 404 (or 405) for all three. `FastAPI(debug=False, docs_url=None, redoc_url=None, openapi_url=None)` is hard-coded
in `app.py`, not configurable — there is no API to advertise and therefore no schema describing routes that could be called
without a CSRF token. A 200 here means someone made the app configurable, which is the defect this step exists to catch.

## §5 Generate CSR (page-map §2)

**Do:** `GET /csr/generate`, then submit the form (CN `web.internal`, SANs `web.internal`, `*.lab.local`, `10.0.0.7`,
key type RSA-2048).

**Expect:**

- a `csrf_token` field in the form;
- **POST without that token → 400**, and *no key material in the response*: nothing was generated, because the request was
  never authorised;
- POST with the token → 200, showing exactly **one** `-----BEGIN CERTIFICATE REQUEST-----` block and exactly **one**
  `-----BEGIN PRIVATE KEY-----` block, both shown once, plus download links for each;
- the page states the output is **stored nowhere**: not in `issued.db`, not on disk, not in the session;
- the IP SAN survives as an **IP general name**, not as a DNS entry typed as an IP (mypki refuses the latter outright).

**By hand:** copy both blocks into files before leaving the page. There is no second chance and no recovery command — that is
README gotcha 1 applied to a leaf key rather than the CA key.

## §6 Sign CSR (page-map §3)

**Do:** `GET /csr/sign`, paste the CSR from §5, submit. Then confirm on the panel that comes back.

**Step A (validate + show):** 200, and a confirmation panel showing what the CSR *actually asks for* — parsed CN, every SAN
including the wildcard (accepted because the wildcard is leftmost), and the key spec (`RSA 2048`). Nothing is signed yet. The
confirm page also carries the **provenance split**: "Copied from your request" (the public key, the subject, the SAN names) beside
**"Set by mypki, never from the request"** (BasicConstraints, KeyUsage/EKU, the identifiers, issuer, serial, dates, hash). 0.1.0's
line *"Only the SANs above are copied from your request"* was inaccurate and must be **absent**: CN/O/OU/C/ST/L/email do come from
the request, and in 0.2.0 they may come from your edits instead. The harness asserts both facts against **step A's page**, because
the provenance block lives inside the confirm form — step B re-renders `/csr/sign` with only the issued card (measured: 1
occurrence in the confirm body, 0 in the issued body).

**Step B (confirm + issue):** choose `cert_type=server`, `validity_days=30`, confirm → 200, with:

- a rendered `-----BEGIN CERTIFICATE-----` block;
- a **chain** download as well as the leaf;
- the issued certificate's colon-grouped fingerprint, and its **hex serial** on the card — read it here, because §11 revokes by
  that number. Scrape for it *scoped to the issued card*: this same page also renders the CA's facts strip, whose serial cell is
  spelled identically, so a page-wide search returns the **CA's** serial and every later assertion then addresses the wrong
  certificate (this exact mistake happened in `tests/test_views.py` first).

**The download names live in `Content-Disposition`, not in the page.** §6's own signing uses CN `web.internal`, and the two
downloads that card offers are named after it in filesystem-safe spelling — `attachment; filename="web-internal.crt"` and
`attachment; filename="web-internal-chain.pem"` — because `_safe_stem()` (`app.py`) turns dots into hyphens rather than trusting a
name to survive a filesystem, and `_pem_response()` is the only place that name reaches an operator. MEASURED on this build: both
headers read byte-for-byte as above. The page itself exposes neither name — the card's two anchors are `/download/<opaque id>`
(`_issued_view`), so a harness that asserts the names has to follow each link and read the header it gets back (`app.count_exactly(card,
'href="', 2)` would assert only that two links exist, which is what an earlier draft of this harness did).

**Replaying the confirmation URL** in the same session after signing → 404 *"no longer available"*: the artifact is one-shot
(page-map §10). Nothing can be issued twice by refreshing **the same page** — but a *new* signing of the same CSR is a new certificate,
and MEASURED on 0.4.0 it yields a distinct serial every time. §6 depends on that: it seeds two extra round trips before its own signing so
that §11 has three active records available to multi-select. Seeding runs **before** §6's signing because `/issued` is newest-first — seeding
afterwards would push §6's record off the first row and break `row_serial == issued_serial`. On a host that has signed before, the ledger
holds however many certificates it signed — §11's assertions are written per-serial for exactly that reason.

## §7 Rejections name their reason (never 'invalid CSR')

**Do:** submit `csr_pem=not a csr at all` **as an urlencoded form field** — the shape a browser posts. Then submit a well-formed PEM
wrapper around valid base64 that is not a CSR, and post the same garbage a second time as a **multipart file part**, which is what §5's
download links look like when an operator uploads instead of pasting.

**Expect:** 400 all three times, naming the specific reason on mypki's own page — `No PEM block found`, and *not a DER certificate
request*. Never a generic "invalid CSR". The multipart case is asserted rather than assumed: `_form_fields()` runs every posted part
through `str()`, so an uploaded file arrives at the parser as its **filename**, and the page answers with mypki's own reason anyway —
MEASURED `'No PEM block found'` once, status 400. (This is why the DER case posts urlencoded: a multipart part can never reach the DER
parser at all, so asserting the DER refusal through an upload would assert nothing.) The reason is the useful part: an operator who pasted
a key instead of a request has
to be told which one they pasted.

Also verified in the automated harness (and in `tests/test_csr_validate.py`): a tampered signature, a SHA-1-signed CSR, and a
CSR carrying `BasicConstraints CA:TRUE` / `keyCertSign` / `crlSign` — the last refused with **403** naming the extension, and
with the issued ledger still empty.

**In this build the reason is printed where the paste was typed.** Both refusals above re-render `/csr/sign` itself: a
`<section class="form-errors refused">` block sits **above** `<label for="csr_pem">Paste a CSR (PEM)</label>`, and the pasted
text comes back in its own textarea so the fix is typed in place rather than re-pasted from a clipboard. The status did not
move — 400 for garbage input, 403 for the privilege claim — and nothing was staged, which is what the fourth assertion checks
(`This is what the request says` appears **zero** times). Asserted as an ORDER, because "the reason appears
somewhere in the body" is also true of a page that mentions it only in a nav link: the harness compares **string
offsets** (MEASURED on this build: the refused block at offset 2606, the label at 2957). Before this build both POSTs rendered `templates/error.html`, which
contains no form at all, so the operator had to click back and re-paste. The oversized paste of §8 is the refusal that stays
on `error.html`: `SizeGuardMiddleware` answers it before any route runs, so there is no form to put the reason on.

## §8 Oversized input (page-map §0)

**Do:** paste ~40 000 characters of padding inside PEM armour and submit.

**Expect:** **413**, rendered as mypki's own error page naming `MYPKI_MAX_CSR_CHARS` ("the limit is 32,000"). Asserted in the
same breath: starlette's bare JSON `Field exceeded maximum size of 1024KB.` is **absent**. The guard measures the body before
parsing, so an oversized request never reaches a framework validator whose answer is not a page.

## §9 CA certificate (page-map §4)

**Do:** `GET /ca`, then `GET /ca/certificate`.

**Expect on `/ca`:** 200 with install instructions for **Windows** (`Trusted Root Certification Authorities`), **Linux**
(`update-ca-certificates`), **macOS** (`Always Trust`) and **Java** (`keytool -importcert`), plus the fingerprint to verify
the download out of band.

**As of 0.3.0 `/ca` is also the only page that carries the CA facts** (page-map §4; §1 asserts them absent from `/`). The
harness asserts all four against the **rendered** page, not the template source — `CA:TRUE pathLength:0` also sits inside a Jinja
comment in `ca_download.html`, so grepping the file would pass against a page that never renders it. MEASURED spellings on a live
0.3.0 server:

- `mypki Root CA` (in the Subject row and its own CN row — 2 occurrences);
- `<td class="mono wrap">` holding the colon-grouped SHA-256 fingerprint;
- `<td class="mono">CA:TRUE pathLength:0</td>`;
- `<th scope="row">CA private key on this host</th>` / `<td>present &mdash; this host can sign</td>` — a boolean, never a path
  to the key and never the key.

**As of 0.5.0 `/ca` also shows the certificate itself** (page-map §4), and §9 asserts four things about that block rather than trusting
that "it looks like a PEM":

| Asserted | MEASURED on a live 0.5.0 server |
| --- | --- |
| `<pre class="pem" id="pem-ca">` occurs **exactly once** | 1 |
| a copy button carrying `data-mypki-copy="pem-ca"` occurs **exactly once** | 1 — the wiring `app.js` has provided since 0.3.0, pointed at a new id |
| the block holds **exactly one** `-----BEGIN CERTIFICATE-----` … `-----END CERTIFICATE-----` pair | 1 — an accidental chain in that block would make an operator install the wrong thing |
| the DER inside that block hashes to the same SHA-256 as the body of `GET /ca/certificate` | page == download, **equal within each run** — a scratch CA is a fresh key every time, so no hex belongs in these notes; this build's four runs read `29eb90…`, `dc2c38…`, `b12513…` and `d8c6e2…` (`37b16c…` was 0.5.0's, from `/tmp/pkismoke-050b`) |

The fourth is the one that earns the other three: "the page shows the certificate" is only true if those are **the same bytes** the
download offers, and a template that re-derived the PEM from the loaded bundle instead of rendering `ca_pem` would still answer 200 with a
plausible-looking block. §15 hashes a **third** rendering of the same certificate — the paste `/inspect` reads back — so the claim is checked
from two directions.

**A needle worth knowing about before you mint a scratch CA:** §9's subject check spells `mypki Root CA`. **MEASURED on a
0.5.0-era**
run (2026-10-30, `/tmp/pkismoke-050`, whose `serve.log` reads `loaded CA C=XX,O=mypki smoke,CN=mypki Smoke CA`, and whose
§9 answered the generic FAIL "/ca does not show
the CA subject — no CA loaded, or the card is broken", misdiagnosing a name mismatch as a missing CA), a server started
from a data dir minted with `--common-name "mypki Smoke CA"` made that assertion fail against a perfectly correct
app — a harness-vs-operator-configuration mismatch, not a defect. The needle stays as written because the documented run is a plain `init-ca`
with the default CN; if you name your CA something else, expect this one check to need the same rename.

**Expect on `/ca/certificate`:** 200 with

| Header | Value |
| --- | --- |
| `Content-Type` | `application/x-pem-file` |
| `Content-Disposition` | `attachment; filename="mypki-root-ca.crt"` |
| `Cache-Control` | `no-store` |
| `X-Content-Type-Options` | `nosniff` |

`.crt` rather than `.pem` in the filename because Windows' double-click installer keys off the extension, and `no-store`
because a cached PEM is one stale root away from a confusing support ticket. The body contains **exactly one** certificate.

**Without a CA:** 503 naming the CA *certificate* path it expected — never the key path.

## §10 Issued list (page-map §5)

**Do:** `GET /issued`.

**Expect:** 200, a table with at least one data row, and the certificate signed in §6 present by CN/SAN. Columns are **select**,
**status**, serial, type, CN, SANs, not-before, not-after and issue time — and nothing else. Long SAN lists are truncated in the
cell (72 characters) with the full value in the `title=` attribute — truncation is display-only, never a lie about what was issued.

There is **no revoke column** (0.2.0's per-row control moved into the checkbox column plus the one bulk button above the table) and,
as of 0.4.0, **no Revoked column either**: 0.3.0 rendered a Status pill *and* a Revoked column saying almost the same thing about
every row, and the pair could disagree if one was misread. The **Status cell** carries the whole decision now — the pill, then for a
revoked row `revoked <YYYY-MM-DD HH:MM:SS>Z` and, when a reason was given, the reason under it.

The Status column has **two states, not three**: `active` and `revoked`. A certificate past its not-after date still reports
`active`, because this CA never revoked it; printing "expired" beside "revoked" would imply this host knows what every client
currently accepts. (A separate `past` marker may appear in the date cell — that is a statement about this host's UTC clock, not a
status.)

As of 0.3.0 an active row carries a **checkbox** named `serial_hex`, inside **one bulk form** that wraps the whole table; a
revoked row carries none, and there is no way to un-revoke. There is still no delete and no export. Revoking records the decision
on this host and publishes nothing — read §11 and README gotcha 2 before relying on it.

The harness counts these shapes rather than trusting that one exists:

| Shape asserted | MEASURED on a live server (0.3.0 figures in brackets where they differ) |
| --- | --- |
| `type="checkbox" name="serial_hex"` count **==** the `active` pill count | 19 boxes / 19 active (a stamped row loses its box) |
| `<form method="post" action="/issued/revoke">` occurs **exactly once** | 1 — the 0.2.0 per-row forms are gone |
| `data-mypki-select-all` + a `> All<` label | 1 each |
| `Revoke Selected` occurs **exactly once**, in the bar above the table (was ≥ 2) | 1 — 0.4.0 deleted the duplicate below the table and its `.select-bar.bottom` rule; two buttons for one decision invite a click on whichever is nearer |
| `data-mypki-count>0 selected` occurs **exactly once** | 1 — the server renders `0 selected`, and `app.js` writes `"N selected"` in the same shape, so untickable rows cannot be hidden behind a different sentence at zero |
| `<th scope="col">Revoked</th>` occurs **zero** times | 0 (0.3.0: 1) — the stamp lives in the Status cell; see §11 for the regex that asserts it is still there |
| `name="csrf_token"` **inside** that bulk form | 1 (with one form, the token has to live in it) |
| the sentence saying what still works with JavaScript off (`tick rows one at a time`) | present |

Counted against the checkbox attribute deliberately: a build that kept the old per-row forms would still answer 200, still carry
the right serials, and every §11 assertion would then run against a shape no browser posts any more. The zero-occurrence assertions
are held to the same standard: deleting a column is only an improvement if the information it carried survived somewhere else, which
is why §11 asserts the stamp's exact shape in the same run that asserts its column is gone.

## §11 Revocation round trip (page-map §5)

**Do:** tick a row's `serial_hex` checkbox on §10's page and submit the bulk form **twice**: once with no `confirm` field, then a
second time with `confirm=1` and the same serial plus a reason. Then do it again with **three** serials at once — two real active
rows and one serial this host never signed (`deadbeefcafebabf`) — and a third time with a serial that was already stamped.

**Expect — step A, the unconfirmed POST (this is new in 0.3.0):**

- **200**, not an error, and it stamps **nothing**: `<section class="confirm-revoke">` once, `Revoke 1 certificate?`, and
  *"Nothing has been changed yet."*
- the number of `revoked` pills on this page **equals** the number on §10's page. Records this host revoked in an earlier run
  legitimately keep their pills; what must not move is the count.
- no batch card (`Revocation batch` occurs 0 times) — nothing has been revoked yet;
- the selection survives as hidden fields (`serial_hex` × N, `confirm=1` once), and each listed serial is labelled with what it
  is right now: `active now`, `already revoked — its stamp and reason will not change`, or
  `not a record on this host — it will be reported, not revoked`;
- the page states what it cannot undo **before** consent is asked for: **"Revoking a record cannot be undone from this
  page: there is no
  un-revoke and no delete."** — the `.cannot-undo` paragraph of `templates/issued.html`, grepped from the template and confirmed
  live against `revoke-confirm.html`. This needle replaced
  the 0.6.0-era one — "the missing CRL is named before consent is asked for" — which became false the moment this host
  began publishing a CRL;
  asserted after joining newline-and-indentation runs to one space (`joined()` in `tools/e2e_harness.py`) because the template wraps
  the sentence across a line — a count over the raw body reads 0 against a page that renders it. The shell harnesses had one such
  helper each (`count_joined` and `Measure-Joined`) and this file once named both spellings; the helper here is `joined()`.

**Expect — step B, the confirmed POST:**

- **200** with the three-way batch card `<h2>Revocation batch</h2>` and its three counts on one `<p class="reason">`:
  `N stamped now,` / `N already revoked before this submit,` / `N with no record on this host.`
- `is marked revoked as of <UTC timestamp>`, the reason you typed shown back, and Status `revoked` on the row;
- **no control carries the stamped serial** (it cannot be re-revoked, and there is no delete), and the number of *checkboxes*
  falls by **exactly one**. It is *not* zero on a host holding other active certificates — each keeps its own box. The 0.2.0
  version of this assertion counted `action="/issued/revoke"` instead; with one bulk form that count is 1 before and 1 after, so
  "fell by one" could never hold (MEASURED: it failed against a correct app as 1 -> 2);
- at most **two** revoke forms on the confirmed page (one bulk + one confirmation);
- the stamp survives a plain `GET /issued` afterwards (refresh, bookmark, another browser), and the **Status cell** reads as a dated
  decision: the harness matches `class="hint">revoked YYYY-MM-DD` (**≥ 3**, one per stamped row) and separately asserts that
  `<th scope="col">Revoked</th>` occurs **zero** times. As of 0.4.0 those two are one assertion pair — the stamp moved out of its own
  column into the same cell as the pill, and only the *shape* of the stamp line (`class="hint">` plus a `YYYY-MM-DD` prefix) is pinned,
  because pinning the whole line would make it about formatting rather than about whether the decision is still visible after a refresh.

**Expect — steps C–E, multi-select and the stale tab:**

- the unconfirmed three-serial submit says **`Revoke 3 certificates?`** *before* any of them changes, and calls the unknown one
  what it is rather than hiding it;
- confirmed: `2 stamped now,` + `0 already revoked before this submit,` + `1 with no record on this host.` — and the miss is named:
  `no record with that serial in this host's database — nothing was changed`, with the serial itself printed. A miss must not 404
  away the two decisions the operator did mean to make;
- re-submitting an already-stamped serial answers `0 stamped now,` / `1 already revoked before this submit,` and says
  `already revoked — its stamp and reason were left alone`, with the **original** reason still shown back (the new one is not
  written over it).

MEASURED byte-for-byte on the apostrophe: `this host's database` uses plain ASCII U+0027 (`od` reads `h o s t ' s`). Jinja's
autoescape leaves a typographic apostrophe raw, and this one is not typographic — asserting `&#8217;` fails against a correct page.

**Measured on 0.4.0 (Linux, 2026-10-29), fresh data dir:** §11's own last fetch of `/issued` shows **3 rows with 3 revoked
pills and 0 active**, and `mypki info` afterwards reports `4 issued record(s)` — **4 issued / 3 revoked** in total on
that release, because
§13 issues a fourth certificate after §11 finishes (see §13's last bullet); from 0.6.0 on, §16's consented issue lands a
fifth, so the same walk
ends at **5 records / 3 revoked / 2 active**. `the checkbox count fell by exactly one`
passes on every stamp. Before §6 seeded two extra certificates, this same run WARN-skipped steps C–E (`only 0 other active record(s)`) and
then failed the `>= 3` needles below them — which is why seeding was added instead of those needles being relaxed. The absolute numbers move
with the ledger; what stays invariant is **the fall of exactly one per stamped row**, and the three counts naming every serial.

**Contract errors, checked by `tests/test_views.py` rather than here:** an unknown serial submitted **alone** → **404** naming the
serial and the database file (in 0.2.0 development this answered **500**, which is why the handler exists) — inside a batch it is
instead reported, as above; a blank selection → **400** naming `serial_hex`; a wrong CSRF token → **400**; duplicate serials
collapse so select-all plus a hand-ticked row is one revocation, not two.

## §12 About and Settings (page-map §12)

**Do:** `GET /about`, then `GET /settings`.

**Expect on `/about`:** 200 naming the running version, a link to the source URL (`https://github.com/madmickstar/mypki`) so a
problem can be cited against a build, the card heading **"What this CA does not do (yet)"** opening with the sentence
**"Revocation reaches only
clients that go looking for it."** — the first `<li>` of `templates/about.html`'s *What this CA does not do (yet)* card — and
the three profiles in words —
*"This is the web-server profile."* and *"It will NOT make a browser trust a web site"* are the two sentences asserted — the second
**without its period**, because what `signing.CERT_PROFILE_HELP["client"]` actually renders (MEASURED, `src/mypki/signing.py:90`) is
*"It will NOT make a browser trust a web site -- for that you want `server`."* — plus the clause that period stood in for,
*for that you want `server`*. A needle ending `web site.` read 0 against a correct app: it pinned a period that was never there. These are
the sentences users asked for after 0.1.0 shipped radio buttons with no explanation.

**Expect on `/settings`:** 200 with a `MYPKI_VALIDITY_MAX_DAYS` control; `MYPKI_SECRET_KEY` rendered as **`set (value not displayed)`**
rather than as a value; the statement that a value from `.env`, from a shell variable and from a CLI flag are
**"indistinguishable here"**; and a resolved data directory shown so you can see where your files actually went.

As of 0.4.0 those facts live in three different places on the page - the knob's own control, the Storage **status panel**,
and the *Not editable here* card - instead of one resolved-state table, which is exactly why every needle above is spelled as a
*content* (`MYPKI_VALIDITY_MAX_DAYS`, `set (value not displayed)`, `indistinguishable here`) and none of them names a table or a
column. The markup moved; the assertions did not.

**As of 0.3.0 this page writes.** What the harness asserts is a **refusal and its consequence**, not just the wording — every
refused save is compared against a sha256 fingerprint of this host's real config file (or the state `absent` for a host that has
never saved), so "nothing was written" is an assertion rather than a hope:

| Asserted | MEASURED on a live 0.5.0 server |
| --- | --- |
| `<button class="save-settings">Save Settings</button>` once | 1 |
| one control per editable knob (`name="MYPKI_*"`) | **22** controls (unchanged from 0.4.0); the only knob that renders as a checkbox is `MYPKI_LOG_TO_CONSOLE` |
| the page names the file a save writes | `saved to <code>/tmp/pkismoke-050c/xdg/config/mypki/mypki.env</code>` (state `absent` before and after — this run redirects `HOME` **and** the four `XDG_*` variables into the scratch tree, so a refusal cannot touch this box's real `~/.config/mypki`) |
| the port input declares its range, read **off the control** (`min=`/`max=`) | 1 to 65535 — so the expected refusal sentence and the input move together with `config.py`'s `Field` |
| an out-of-range save (`max+1`) answers **200** with the amber *Not saved — fix this and submit again* (not a 500) | 200, `<li>MYPKI_PORT must be 1 to 65535; you entered an invalid value.</li>`, `value="65536"` retained |
| *Nothing was written to <code>…</code>* + the file fingerprint unchanged | both true, state `absent` before and after |
| an **empty box** on a knob that has no empty value is refused, naming the knob | 200, `<li>MYPKI_HOST cannot be empty: mypki would start with an empty host, which is not a setting.</li>` |
| an **empty `csrf_token`** in the page's own body → mypki's own **400** naming the token | 400, `The CSRF token was missing or did not match this session.` |
| the restart wording (`read once at startup`), naming **`MYPKI_HOST` / `MYPKI_PORT` / `MYPKI_SESSION_MAX_AGE` / `MYPKI_DATA_DIR`** | present |
| the other half of that sentence: every *other* knob is `applied by this process as soon` as the save succeeds | present |

**0.5.0 adds three assertions to this section**, all of them about what the four restart-only boxes *display* (page-map §12):

| Asserted | MEASURED on a live 0.5.0 server |
| --- | --- |
| `<p class="pending-saved">` occurs **zero** times on a host that has never saved | 0 — the marker is earned, not decorative; this is as close to a mirror as a script that only looks can honestly get (see below) |
| the sentence *those four boxes show what the file says* is present | 1 — counted after joining newline-and-indentation runs to one space, because `settings.html` wraps it mid-clause and a count over the raw body reads 0 against a page that renders it |
| `/about` leads with the running-host card | asserted as an **offset order** (card < lede < profiles), not as a presence check — 0.5.0 moved that card to the top, and "present" was already true before the move, so only the ordering assertion can catch the move being undone |

No assertion is written on the phrase *saved for the next start*: MEASURED, it already occurs four times on every `/settings` render through
`app._knob_input`'s per-knob hints, so asserting it would pass against a page where nothing pending had ever been rendered. And note what this
section still deliberately does **not** do: the positive case — one box showing 8543 while the rose sentence names 8443 — is not here, because
producing it means performing a successful save, which this harness will not do from a script that only means to look. That half lives in
`tests/test_settings_save.py` against a temporary config dir.

Two things this section deliberately does **not** assert against a live server, because doing it from a script that only means to
look would either write into the operator's own config file or depend on JavaScript: the **preset dropdowns** (a `<select>` carrying
no `name=` sitting over each numeric box, Custom as its last option) and the green **Saved pill**, which renders only on a POST this
harness never makes. Both are asserted in `tests/test_views.py` instead - the menu markup and its option count, an out-of-preset value
that lands on Custom rather than being rounded to the nearest preset, and the pill's `just_saved` rendering - against an app built from
this same tree. A harness that has never seen a browser can still prove the server-side half.

Two measurement traps this section had to learn the hard way:

- **A knob *missing* from the body is not refused as "was not submitted".** `_submitted_settings_fields` fills every editable knob
  the body omitted with `''` (or `false` for the one checkbox), so deleting a field from a scraped body lands on a valid value and
  **writes the operator's real config file** — from a script whose job is only to look. That is why the harness posts an empty
  `MYPKI_HOST=` explicitly instead of dropping a knob, and it is why no successful save is exercised here at all.
- **The body is scraped from the page, never typed out.** Several knobs legitimately render `value=""` (`log_file`,
  `public_base_url`, the six subject defaults), and `settings.html` splits each `<input>` across five lines — without joining
  newlines first only the name line matches, most knobs vanish from the body, and the app correctly answers "was not submitted"
  for a page that did render them.

**A successful save is deliberately NOT exercised by this harness.** It would write into the operator's own
`$XDG_CONFIG_HOME/mypki/` (or `%APPDATA%\mypki\`) from a script that only means to look. The write path, the `0600` mode, the
preserved unmanaged lines and the restart wording are covered by `tests/test_settings_save.py` against a temporary config dir.

The leak check on this page is about **resolved absolute paths**, which only a live process knows. The harness reads the resolved
data directory out of the Storage **status panel** first - `Data directory (resolved)</th>\s*<td[^>]*>([^<]*)</td>` over the joined page,
so the `<td class="mono">…</td>` cell is read rather than a line number - and only then asserts that neither
`<data>/ca/ca_key.pem` nor `<data>/instance/secret_key>` appears in the body. MEASURED on this build: the resolved value is
`<scratch>/data`, and the assertion is `leaked == 0`. That scrape is fragile in a way worth writing down: `settings.html` deliberately keeps a plain
`<td class="mono">` on that row and adds a colour class *only* for an off-normal state, and says so in a comment, because putting a
status colour on every row would silently break the check that exists to prove nothing private is rendered.

Bare filenames are *not* asserted absent: two `config.py` field descriptions name those paths to explain what mypki does **not**
touch, and those descriptions render verbatim as the hint line under each editable control (`app._first_sentences`) and beside the
reasons on the *Not editable here* card. Asserting their absence fails against a correct page — an earlier draft of
`tests/test_no_key_leakage.py` did exactly that.

## §13 Inline form errors on the confirm page (page-map §3)

**Do:** run step A again (§6's signing consumed the first staged request), read the `?pending=` id out of the confirm form's action
URL, then submit a **confirm** with two deliberate edits and one bad field — a three-letter country.

**Expect:**

- **200**, not an error page: a bad *form field* returns the same page with the reason inline, while a bad *artifact* is 400/403/413;
- the reason names the field and the rule (*"exactly two letters"*), and the page says **"Nothing was signed"**;
- your other edit survives in its input — one rejected character must not cost you the work you did on the rest of the form;
- the staged request is still there under the **same `?pending=` id**, so fixing it means retyping two characters rather than
  re-pasting a PEM;
- submitting the corrected confirm issues at 200 and the issued page carries a **"Changed from your request"** block naming the
  edited value, not merely a label. That diff is the price of an editable confirm form: nothing here unwinds a signed
  certificate — the only
  correction an operator has is a revoke, and `/issued` says what that reaches, **"a revoked certificate stays trusted by
  clients until it
  expires"** — `templates/issued.html`'s closing `.note` paragraph. MEASURED on the pre-0.6.0 releases: this issue is the
  **fourth** record in §6's throwaway
  ledger — it lands
  active, which is why `mypki info` ends at 4 records there while §11's last `/issued` page showed 3. On 0.6.0 and on
  this build §16's consented
  issue lands a **fifth** after it, so the same walk ends at **5 records / 2 active** (see *Reading the result*).

## §14 No key material in any response (page-map §0)

**Do:** fetch `/`, `/csr/generate`, `/csr/sign`, `/ca`, `/issued`, `/about`, `/inspect`, `/settings` and `/version` — **nine GETs** as of
0.5.0 — and search each body for PEM armour.

**Expect:** zero occurrences of `-----BEGIN … PRIVATE KEY-----` on **every page except §5's own output**, which is the
operator's freshly generated leaf key and the one place a private key legitimately appears (the CA's key never appears
anywhere, asserted separately in `tests/test_no_key_leakage.py`).

**`/inspect` joins this sweep as a plain GET only, and that restriction is load-bearing.** A `/inspect` POSTed **with a key** renders
`-----BEGIN PRIVATE KEY-----` **twice on purpose** — the armour lines survive redaction so the operator can see *which* block was redacted,
and only the base64 body is replaced (page-map §13). Feeding a key paste to this loop would fail a correct app. The key case is asserted in
§15 against the **base64 lines** instead, which is the only version of that test that can actually catch a leak: with a real key there is no
string to search for, so §15 uses a sentinel body whose base64 the harness wrote itself and can therefore name.

The assertion is against **armour**, not against the phrase "PRIVATE KEY": `/csr/generate` legitimately *documents* the
`ENCRYPTED PRIVATE KEY` format, and a check that forbade the words would either fail on honest prose or be loosened until it
stopped catching real leaks. The same sweep also asserts the absence of key material in **response headers** (all nine) and in every **cookie value** this session
carries, and that no page contains **this host's own CA private key** — neither its DER bytes nor its bare base64 body — read from
`<data>/ca/ca_key.pem` after §9 minted it. Those two halves exist because only a live process knows its own key bytes: a unit test can
assert that a handler does not print a path, but only HTTP can show that a header or a cookie leaked the value.

---

## §15 Inspect PEM (page-map §13)

**Do:** `GET /inspect`. Then POST it the harness's own CA download (§9's `GET /ca/certificate` body, written to `ca.crt` in the scratch
work dir), then a **sentinel** private key this harness wrote itself, then 40 000 characters of padding, then the same oversized paste with
no CSRF token, then plain text with no PEM armour at all. Every paste goes as an urlencoded `pem_paste` textarea value — the shape a browser
sends for this field.

**Expect:** 200 for everything except the oversized body (413) and the tokenless POST (400). This is the one section whose posture is the
opposite of every other page in the app: `/inspect` **refuses nothing but size**, so there is no error surface to assert on and §15 asserts
the reverse — that facts appear where a refusal used to be, and that the single refusal which does exist names **mypki's** knob rather than
the framework's. Nothing about this page depends on a CA existing (page-map §13), but §15's certificate, key and oversized cases are guarded
by a check that §9 left the CA PEM in hand (`app.state["ca_pem"]`) plus a check that `/inspect`'s form carries a token, so a host whose §9
download failed **WARNs** instead of failing on nine assertions that could not have run. A missing token is a FAIL rather than a WARN: it
means the page cannot be driven at all.

| Asserted | MEASURED on a live 0.5.0 server |
| --- | --- |
| `GET /inspect` answers 200 with exactly one field, `name="pem_paste"` | 1 — the whole page is one textarea |
| *Nothing pasted yet* present; `<th scope="row">` occurs **zero** times | 1 and 0 — a GET fabricates no report |
| all four "what this page cannot tell you" sentences present | 1 each: *It does not verify a chain.* · *It does not know about revocation.* · *Its findings are not gates.* · *A private key is named and not opened.* |
| `/`, `/ca` and `/settings` each carry `class="nav-item…" href="/inspect"` | 1 each — checked on **three other pages**, not on `/inspect`, because a nav that carried the link only on `/inspect` would pass a count taken from `/inspect` alone |
| `/inspect` marks its own item active | `class="nav-item active" href="/inspect"`, 1 |
| pasting the harness's own root renders `CA:TRUE pathLength:0` and names *self-signed root* | 1 and ≥ 1 |
| **`not a CA` occurs zero times inside the findings block** | 0 — while occurring **once page-wide**, because `/inspect`'s lede legitimately quotes `not a CA` as an *example* of a finding. Asserting page-wide absence fails a correct app; asserting nothing lets it leak onto the host's own root. the harness scopes its count to the first `<ul class="findings">…</ul>` and answers FAIL outright when that element is absent rather than printing `-1` and comparing it |
| findings render as `class="findings"` once and `class="form-errors"` **zero** times | 1 and 0 — this page refused nothing, so there is nothing to "fix and submit again" |
| the parsed block comes back as `<pre class="pem" id="pem-1">` with `data-mypki-copy="pem-1"` | 1 and 1 |
| *SHA-256 of the DER* present, and the DER inside `id="pem-1"` hashes to the same value as §9's download | page == download — **scoped on purpose**, see the bug below |
| a pasted key answers 200, says it redacted (*private-key block(s) were in your paste*), and the marker appears twice (echo + self-naming) | 1 and 2 |
| **no base64 line from the pasted key survives in the response** | 0 leaks — asserted against the two wrapped base64 lines of a **sentinel body the harness wrote**, not against armour; armour is *expected* to appear (`-----BEGIN … PRIVATE KEY-----`, counted and named in the label) |
| no `SHA-256 of the DER` for the key it says it did not open | 0 |
| oversized paste → **413** naming `MYPKI_MAX_CSR_CHARS`, with starlette's *Field exceeded maximum size* **absent** | 413, knob named ≥ 1, starlette's sentence 0 |
| a tokenless POST → **400** naming CSRF, and the rejected paste is **not echoed** | 400, CSRF ≥ 1, `-----BEGIN CERTIFICATE-----` 0 |
| junk (`hello world`) → 200 with *nothing readable* and the finding *nothing to report* | 1 and 1 — described, not refused. This is the whole reason the page exists |

**Why the byte-parity assertion is scoped, and what it looked like when it was not.** The first live run of §15 handed the whole page to its PEM extractor (the shell harnesses called it `extract_pem` / `Extract-Pem`) and hashed **the textarea's placeholder**, which spells out `-----BEGIN CERTIFICATE-----&#10;MIID...&#10;-----END CERTIFICATE-----` as example text: page `1c8998b7…` against download `32d961d8…`, a byte mismatch reported against a correct app. This harness takes the range `<pre class="pem" id="pem-1">…</pre>` first and hashes only what sits inside it. The general lesson for anyone writing a new assertion against this page: **the first armour pair on `/inspect` is not the parsed block.**

**Why the key case is asserted against base64 rather than armour.** With a real key there is no string to search for, so "the key's bytes did not come back" cannot be tested with a real key. §15 writes a sentinel body — fixed text whose base64 this harness can name exactly (`MYPKI-E2E-SENTINEL-PRIVATE-KEY-BODY-not-a-real-key-…`)
— and searches for both wrapped lines by name. It is not a key, which is the point: nothing private has to exist to prove a leak did not happen. Armour counts are reported in the passing label rather than asserted as zero, because armour surviving is the documented behaviour (§14).

**What §15 does not assert:** that any of this is *verified*. It never asks whether an issuer is trusted or whether a certificate was revoked, and it must not start to imply either — the four sentences at the top of the page are asserted precisely so that a future edit cannot quietly turn a reader into a verifier (page-map §13).

---

## §16 Dropped extensions need consent (page-map §3 rule 6)

**Do:** nothing by hand except paste two CSRs. Both are real `openssl req` output, embedded in `tools/e2e_harness.py` as PEM literals
(`CONSENT_CSR` / `PRIVILEGED_CSR`) so §16 runs anywhere the other fifteen run and needs no openssl at harness time: `consent.csr` (1050 B — SAN + `CA:FALSE` +
`digitalSignature, keyEncipherment`, `CN=consent.lab.local`) is what a distro `[v3_req]` puts into **every** request an operator makes, and
`privileged.csr` (1070 B — SAN + critical `CA:TRUE pathlen:0` + `digitalSignature, keyCertSign, cRLSign`, `CN=privileged.lab.local`) is the half
that must stay refused. Both verify against their own signature.

**Expect:** the openssl-default request now **reaches** the confirmation panel instead of being refused at step 6; the panel names what it will not
copy; an unticked box answers 200 and signs nothing; a ticked box issues and lists every drop; and `CA:TRUE` is refused at 403 **even with the
consent field posted**. This is the section that exists because an operator could not sign an ordinary CSR.

| Asserted | MEASURED on a live server of this build |
| --- | --- |
| both fixtures are single, well-formed PEM blocks | 1 and 1 — 1050 B and 1070 B (the byte length of each fixture as embedded in `tools/e2e_harness.py`, asserted block by block) |
| step A on `consent.csr` answers **200**, not 403 | 200 — rule 6's ignorable half no longer refuses a signable request |
| the panel names `BasicConstraints CA:FALSE` | ≥ 1, inside `class="provenance dropped-extensions"` |
| the panel names both bits: `KeyUsage (digitalSignature, keyEncipherment)` | ≥ 1 — named by bit, never as bare `KeyUsage` |
| exactly **one** consent control (`name="ignore_extensions"`) | 1 |
| that control arrives **unticked** (`checked` absent) | 0 occurrences of `checked` on it — default OFF is markup, not a promise |
| its state word reads `class="checkbox-state state-off">off<` | 1 — a page cannot show `on` beside an unticked box |
| a **mypki-generated** CSR (`generated.csr`, §5's own output) renders no consent box | 0 — and 0 `dropped-extensions` blocks, so there is no empty list either. Guarded by the file existing: a host whose §5 failed **WARNs** rather than failing two assertions |
| step B with **no** consent field → **200**, not 403 | 200 — an input to fix, not a refused artifact (page-map §3, app.py `ERROR_SURFACE_RULE`) |
| the refusal names the missing decision (`consent to dropped extensions`) | ≥ 1, in `<p class="reason">` |
| it lists every extension at stake | ≥ 1 `KeyUsage (digitalSignature, keyEncipherment)` — no "some extensions" hand-wave |
| it states plainly that nothing was signed (`Nothing was signed`) | ≥ 1 |
| no `<h2>Issued:` card was rendered | 0 |
| the staged request survives under the **same** `?pending=` id | equal ids — "tick the box" is only fixable without re-pasting a 1 KB PEM if this holds |
| the re-rendered page offers the box again | 1, not a dead end |
| step B with `ignore_extensions=true` → **200** and an issued card | 200, `Issued: consent.lab.local` ≥ 1 |
| the dropped extensions land in the **same diff block** as an edited name | `Changed from your request` present, with exactly one `Extension not copied: BasicConstraints CA:FALSE` and one for the KeyUsage |
| the diff closes by naming where the replacements came from | ≥ 1 `The public key and every extension still came from mypki` |
| the consented signing reports **its own leaf serial** | a 40-hex serial, read from inside the `<h2>Issued:…</h2> … </table>` window rather than page-wide — the same scoping §6 needed for the same reason (the CA facts strip on that page spells its serial cell identically); an earlier shell draft used a fixed 15-line window and lost the row when §16's dropped-extension block pushed it down |
| `CA:TRUE` → **403** *with* `ignore_extensions=true` posted | 403 — consent buys the dropping of `CA:FALSE`, never the issuing of a CA |
| that 403 names `BasicConstraints CA:TRUE`, `keyCertSign` and `crlSign` | ≥ 1 each (mypyki's spelling; see the openssl note below) |
| its hint points at the box for the signable half | ≥ 1 `you tick the box` — MEASURED wording closes "… dropped only when you tick the box **there**." |
| refusing signed nothing | 0 `<h2>Issued:` on the 403 page |

**openssl spells the bit `cRLSign`; mypki names it `crlSign`.** MEASURED on openssl 3.5.6: `-addext "keyUsage=digitalSignature,keyCertSign,crlSign"`
fails with `unknown bit string argument`, while `cRLSign` is accepted — so the fixture is generated with openssl's capitalisation and asserted with
mypyki's spelling, which `cryptography` and page-map both use. Nobody should read `crlSign` in a mypki message as a spelling mypki invented.

**What §16 does not assert:** that dropping is reversible, or that the pasted bytes changed. Consent alters what mypki **copies**; the staged PEM keeps
its own extensions because its signature covers them, and `test_consent.py` proves that byte-for-byte against a deliberately stripped-and-re-signed
request. §16 also never touches a real `<config>/mypki.env`: it stages requests (which signs nothing) and issues into the scratch data dir only.

---

## Reading the result

The harness ends with a per-section block and then one summary line:

```
== per-section assertions ==
  §1 Home page (page-map §1): N pass / N fail / N warn
  …
  §16 Dropped extensions need consent (page-map §3 rule 6): N pass / N fail / N warn
  §11 STEP F (openssl): independent verification of the artifacts this walk wrote: N pass / N fail / N warn

== summary: <pass> pass, <fail> fail, <warn> warn (<total> assertions) ==
```

What those numbers are **on this build** is not written here — it comes from the run. One command, because a run already knows its own
answer:

```bash
make e2e                                       # or: .venv/bin/python tools/e2e_harness.py
…
== summary: 310 pass, 0 fail, 0 warn (310 assertions) ==
ledger written: reports/harness-ledger.json (gitignored — one machine's measurement, not the release's)
```

`reports/harness-ledger.json` is written by the harness itself (`Report.write_ledger`, called at the end of `Report.summary`) and carries
`generated_utc`, the totals, the assertions total, every section **in walk order** with its own pass/fail/warn triple, and the failures and
warnings each tagged with the section that produced it. It is written even on a failing run — the numbers that explain a FAIL are the ones
worth keeping — and it never changes the exit code, so a filesystem problem can neither turn a green harness red nor hide a red one; if the write
fails the run says `WARN could not write …` out loud. It is gitignored on purpose: a run's totals are a property of one machine on one day, and
committing them freezes them as if they described the release. Read it with `python3 -c` or `jq`:

```bash
jq '.totals, [.sections[] | {name, pass}]' reports/harness-ledger.json
```

The old arrangement needed **two** commands — `scripts/smoke_test.sh --report … > /tmp/run.log` and then `tools/harness_ledger.py /tmp/run.log
--label "build .sh" --write`, which re-parsed a log file to recover counts the harness had already printed, and wrote a markdown ledger
(`reports/harness-ledger.md`, now deleted). Both are gone: the harness is the only thing in this repo that knows which assertions it actually
executed, and a document quoted from memory is how the numbers in this file went stale three times. Dates and totals for runs that already
happened are no longer recorded anywhere in-tree — _docs/measurement-history.md_ and `docs/history/` were deleted in 0.7.1 (see CHANGELOG), so
the ledger file is the current measurement and nothing claims to be the historical one.

- **§11's STEP F reads DER two ways: parsed in §11, and through `openssl` in a separate section that SKIPs when openssl is absent.** The shell
  harnesses read these bytes with `base64 -d` + `od` (`.sh`) and `[Convert]::FromBase64String` + `ReadAllBytes`/`WriteAllBytes` (`.ps1`) because a
  shell script cannot hold a DER parser. This harness does have one — `cryptography` — so §11's CRL and OCSP halves ask the stronger question
  ("is this a CRL holding exactly these entries?", "is this CertStatus REVOKED?") instead of the weaker one ("do these octets appear?"), and that
  removes an entire flake class: measured over 300 signed REVOKED answers, `8000`/`8200` appeared somewhere in the whole body **11 / 300** on this
  build's box (7 / 300 in an earlier session, 9 / 300 with a freshly minted CA) and **0 / 300** once the search was cut at the signature's
  AlgorithmIdentifier (`30 0d 06 09`). A parsed `CertStatus` cannot be spoofed by a random RSA signature byte, so no scoping is needed any more.
  Bytes that are asserted **by position** remain asserted: the refusal body `30 03 0a 01 01` (MALFORMED_REQUEST, five bytes, unsigned) is compared
  byte-for-byte — RFC 6960 §4.2.1's outer SEQUENCE fixes the status offset and mypki does not choose it. `GOOD 80 00`, `UNKNOWN 82 00`, REVOKED
  `a1 16` carrying revokedReason `a0 03 0a 01 00` (`unspecified`, because the store's reason is prose and inventing a code from it would be a lie)
  are the shell harnesses' spellings, kept here as reference for anyone reading raw bytes; the harness asserts the enums instead.
  `30 03 0a 01 02` INTERNAL_ERROR is asserted by `tests/test_ocsp.py`, not by the harness, because no honest harness run can make a responder fail
  to sign on purpose.

  **`openssl` is now invoked — six assertions, and they WARN rather than FAIL when it is absent.** §11 STEP F's external half (`openssl_checks`) runs
  `openssl verify` on the CA root, chains §6's leaf to it, parses the published CRL with `openssl crl -noout -text`, asks that reader for every serial
  this walk stamped (3/3 matched), then runs the check that earns the section: `openssl verify -crl_check` on a certificate this CA issued, which must
  apply the CRL **without** answering `error 44 … different CRL scope` — the measured reason `crl.py` omits an IssuingDistributionPoint — and the same
  command on §6's revoked leaf, which must report it revoked. MEASURED here: OpenSSL 3.5.6, all six PASS. Absence is a WARN naming exactly what was not
  checked, never a FAIL and never a silent skip: CI's contract is that **no OpenSSL binary is required anywhere**, so a harness that needed one would be
  making a claim about the environment rather than about mypki. `--openssl PATH` names a binary explicitly; no version is asserted and none is printed as
  a requirement.
- **"No size assertion exists" was true of the shell harnesses and is not true of this one — so the rule had to be re-drawn, not repeated.** What
  this harness pins in bytes is only what **it wrote itself or what a fixed literal declares**: §16's two embedded fixtures are asserted as single
  well-formed PEM blocks at **1050 B** and **1070 B**, §5's generated CSR block at **1017 B**, §6's leaf download at **1590 B**, the OCSP refusal at
  exactly **five bytes**. What it refuses to pin is any size that depends on a key or a subject it minted minutes earlier: this build's scratch CA is
  `RSA 3072` with `CN=mypki Root CA`, its published CRL measures **934 B PEM / 653 B DER** for 3 entries, and `/ocsp` answers are bigger or smaller
  depending on the responder certificate that signs them (the library probes in plan §2 answered **1704 / 1704 / 1735 B** against a probe CA carrying a
  **1077 B** certificate, where this harness's root carries **1452 B** of PEM). A size is a property of one key plus one subject, so it belongs in a
  ledger — and here it belongs in the assertion **label**, which prints `934`, `653`, `1590 bytes` as measured text while the assertion itself is
  structural: `the decoded artifact is a real CRL of 3 entries, matching the page's number`. The same reasoning retires `'170d'` (UTCTime's tag+length)
  occurring `entries + 2` times for a 3-entry CRL: `len(crl)` and the parsed entry list say the same thing without depending on an encoding rule that
  `cryptography`, not mypki, chose.
- **The four CRL extensions are named by dotted number, and two of the four are absences.** `2.5.29.20` CRLNumber (present), `2.5.29.35`
  AuthorityKeyIdentifier (present), `2.5.29.28` IssuingDistributionPoint (**absent**), `2.5.29.27` DeltaCRLIndicator (**absent**). The harness
  asserts them over a parsed extension set (`{e.oid.dotted_string for e in crl.extensions}`) rather than by DER byte runs; the shell harnesses'
  encodings — `06 03 55 1d 14`, `…1d 23`, `…1d 1c`, `…1d 1b` — are kept here only so a raw-byte reader can find them. Naming by number is what a
  mislabelling trap was recorded for: an early draft asserted `…1d23` as CRLNumber and `…1d1c` as AKI and searched `…1d15` for an IDP — three needles
  that would have gone green while naming the wrong extension. The absences are decisions with evidence behind them: measured against openssl 3.5.6,
  an IDP-scoped CRL answers `error 44 … different CRL scope` for every certificate this CA signed before 0.7.0, which is exactly what §11 STEP F's
  `-crl_check` assertion re-derives on every run instead of quoting.
- **The seventh harness defect was found by running STEP F against a correct app, and what survives it is a rule, not a script.** The first `.sh` walk
  of §11 printed **273 pass, 10 fail, 0 warn** (exit 1) and every one of the ten traced to the harness. Nine came from `post_der()` having dropped the
  literal `-D` from its optional header-dump argument: curl read the dump path as a URL (`URL rejected: No host part in the URL`), answered status `000`,
  and wrote the DER body onto stdout inside `$(post_der …)`. A bare `$hdr` without its flag was tried first, and it is recorded as part of the same
  lesson: an optional argument needs its flag spelled in every branch that uses it. The tenth — §12's pending-sentence assertion, "renders 2 pending
  sentence(s) with nothing pending" — traced to a **stale `~/.config/mypki/mypki.env` still on this box setting `MYPKI_PORT=8444`**, which the harness read
  instead of its own scratch config. The fix was the documented arrangement: `HOME` plus the four `XDG_*` variables redirected into the scratch tree. That
  arrangement is now structural rather than a wrapper script someone had to remember (`/tmp/s11b/run_harness.sh`): `child_env()` sets `HOME`,
  `USERPROFILE`, the four `XDG_*`, `APPDATA`, `LOCALAPPDATA`, `MYPKI_CONFIG_DIR`, `MYPKI_DATA_DIR`, `MYPKI_HOST`, `MYPKI_PORT`, `MYPKI_CRL_BASE_URL` and
  `MYPKI_LOG_FILE` inside the scratch root, and pops `HTTP(S)_PROXY`/`NO_PROXY` so loopback cannot be dialled through a proxy that is not there. §12's
  refusal assertions compare against `<scratch>/config/mypki.env` (state `absent` before and after every refused save), which is the same defect made
  impossible rather than guarded against.

- The row and control counts in a report are **not** comparable between runs, because a throwaway CA's ledger grows on
  every walk. **This build adds five certificates
  per walk** (two seeded, one signed by §6 itself, one issued by §13 and one by §16's consented issue) **and stamps three
  revocations**; MEASURED on this build's kept scratch tree (`mypki info --data-dir <scratch>` after a green run): **5 issued record(s)**,
  **3 revoked / 2 active**. Adding only **four** is the pre-0.6.0 shape, measured again on 2026-10-29: the fresh
  directory `/tmp/pkismoke-040/data` held **1 issued record** before §6's walk (the single certificate its first attempt had
  signed) and ended at **4 issued / 3 revoked**: two seeded, one signed by §6 itself and revoked in §11's single round trip,
  the two seeded ones revoked in its multi-select batch, plus a fourth issued active by §13 after §11 finished. That
  four-record walk is
  what every pre-0.6.0 tree measured — `/tmp/pkismoke-040`, `/tmp/pkismoke-050f`, `/tmp/pkismoke-050g`, `/tmp/pkismoke-050h`,
  `/tmp/pkismoke-051d` and `/tmp/pkismoke-051e` each **held** **4 records / 3 revoked / 1 active** — all six are among the scratch trees deleted from
  `/tmp` on 2026-11-05, so that comparison now needs a freshly minted tree rather than those paths. 0.6.0 already ends at five, and its three trees
  are still here: `/tmp/v060/scratch-zsh`, `/tmp/v060/scratch-zps1` and `/tmp/v060/scratch-zshw` each hold **5 records / 3 revoked / 2 active**
  (re-read on 2026-11-06 with `mypki info`: unchanged), because its
  §16 consented issue adds the fifth. This build's five therefore matches 0.6.0 by measurement rather than extending it.
  For comparison, a 0.3.0-era run on a directory that had been accumulating since 0.2.0 went 18 active / 6 revoked
  before the walk and 17 active / 9+ revoked after it; those absolute numbers belong to that ledger, not this one,
  and they are history rather than this build's starting state. What is invariant is the **shape** — checkboxes
  == active rows, one bulk form, a fall of exactly one per stamped row — not the absolute numbers.
- A run that cannot read `src/mypki/__init__.py` does not degrade — it **exits 2** and says `NOTHING WAS CHECKED: no version readable at
  src/mypki/__init__.py — every §3/§12 version assertion would degrade`. The shell harnesses answered that case with a WARN and continued, reporting
  two fewer passes; this harness refuses to report anything, because §3 is what attributes every other result in this document to a build. Neither
  behaviour is a pass you should read as "version verified", but only one of them can be mistaken for one.
- The count is what the harness printed, not what its source claims. Grep counts of `pass`/`Add-Pass` call sites were never the assertion count in
  the shell harnesses either: assertions sat inside loops that ran per page or per header, and a helper's guard branch could skip one — which is how
  the `.ps1` came to report five more FAILs than the `.sh` while their call-site counts matched arm for arm. This harness tallies as it executes
  (`Report._tally`, one counter per section), so its per-section block and its JSON ledger are the same numbers by construction rather than by agreement.
- The **remaining 4 lines** are the only part a Linux run cannot reproduce, and they are unreachable rather than untested:
  those Windows rows `ca.py 190 4 98% 135-137, 288` are the bodies behind `if not _is_posix(): return` (the mode check and
  its `raise`) and `if _is_posix(): os.chmod(...)` — a Windows process cannot reach them at all, while on Linux ordinary
  `init_ca` tests do. Each platform's total is a function of how much POSIX-only code that process could physically
  execute, so no platform's table is "the" coverage number.
- **Exit 1** means at least one FAIL. After the summary line the harness prints `FAILURES:` with every label tagged `[§N …]` by the section that
  produced it (and `WARNINGS:` likewise), so a failure names the same step this document describes. Fix the code or the spec, not the test: if
  behaviour and `docs/page-map.md` disagree, both change in the same commit.
- **Exit 2** means nothing was checked, and this harness names which precondition failed instead of leaving you to guess: no version readable at
  `src/mypki/__init__.py`, `mypki init-ca` exited non-zero (its log is printed), or the spawned server never accepted a connection (the last twelve
  lines of its log are printed). There is no curl to install and no server for you to start — those were the shell harnesses' two ways of reaching
  exit 2, and each printed `NOTHING WAS CHECKED` rather than a pass. Never read this as one.
- The harness **mutates** a data directory: §11 stamps three revocations and §6/§13/§16 issue five certificates in total. It does that in a scratch
  tree it minted for the purpose (`init-ca` into `<scratch>/data`, with `MYPKI_DATA_DIR` pinned there for both children), never in the directory you
  issue real certificates from — which is the point of the arrangement the shell harnesses only recommended.
- **Scratch litter: this harness cleans up after itself, and the two flags that stop it are documented because they are how you read a run.** A default
  run creates `$(mktemp -d)`-style `/tmp/mypki-e2e.<8 chars>` holding `data/` (a real CA key at `data/ca/ca_key.pem`, mode 0600), `work/` (every fetched
  page, the CRL, the fixtures), `home/`, `xdg/`, `appdata*/`, `config/`, `logs/`, `init-ca.log` and `serve.log`, and removes the whole tree in a `finally`
  block on every exit path. MEASURED on this box: after green runs `ls -d /tmp/mypki-e2e.*` returns **nothing**. The shell
  harnesses' litter was measured here on 2026-11-05 and then removed: **5** `/tmp/mypki-smoke*` directories (**1.3M**, **3 holding a
  private-key block**) and **38** `/tmp/pkismoke*` directories (**33M**, **all 38 holding a `ca_key.pem`**). That is what "neither one removes it"
  produced over a year of runs, and it is why removal is the default here. Those counts are now a dated measurement, not a description
  of this box — `ls -d /tmp/pkismoke* /tmp/mypki-smoke*` answers *No such file or directory* for both, because 38 real CA private keys in scratch
  directories is the exact harm this bullet warns about. What `/tmp` holds today is the suite's own scratch, and it holds real keys too:
  `/tmp/pytest-of-user` is mode `0700` (so nothing under it is world-readable) and keeps pytest's last few numbered basetemps, each of which
  contains one `ca_key.pem` for every test that minted a CA — measured on 2026-11-06 as **1,742** `ca_key.pem` files across **7** basetemps,
  **1,735** of them carrying a real private-key block. That number is not citable: it grows with every run and pytest rotates the basetemps,
  so the fact worth keeping is the mode and the mechanism, not the count. Only **6** key files under all of `/tmp` are mode `000`, one
  `test_serve_rejects_a_tls_file_0/server.key` per retained basetemp: `tests/test_cli.py` writes a fake TLS key and `chmod`s it to `000` because
  there is no other portable way to make a file unreadable to its own owner. Alongside them sit **87** `/tmp/tmp????????` directories and the
  probe trees `/tmp/h060` and `/tmp/v060`, left by ad-hoc temp-dir callers that never removed their tree — **63** `ca_key.pem` files in all,
  62 of them mode `0600`. So the harness is the only one of the three that removes what it made; the suite and the probes do not, and reading
  this file on a box that has run `make gate` for a year means reading a `/tmp` full of throwaway CA keys.
  `--work DIR` keeps the tree at a path you chose and `--keep-data` keeps the scratch data dir, and in both cases the harness prints
  `scratch tree kept at <path> (it holds a real CA private key — delete it when you are done reading it)`. MEASURED on such a kept tree: **1.1M**, with
  **4** files containing a private-key block — `work/csr_generate-3.html` (§5's rendered leaf key), `work/inspect-7.html` (the sentinel paste echoed back,
  armour only), `work/sentinel.key` (not a real key) and `data/ca/ca_key.pem` (a real one). So the kept path is not harmless litter either: read it, then
  delete it. This was always a property of the harness, not of `mypki serve`, which never writes a leaf key to disk at all.
- **What this harness cannot tell you about Windows.** The `.ps1` distinguished two kinds of exit 2 — `HARNESS BUG: curl.exe rejected this script's own
  arguments (curl exit 2)` versus `NOTHING WAS CHECKED: <base> is not answering (curl exit N)` — because a curl that rejects its own arguments means the
  harness is broken while an unreachable base means the server is. This harness has no curl and no base to reach, so it has no equivalent split; its three
  exit-2 causes are printed verbatim and platform-neutral. It has also never been run on Windows. What CI's `windows-latest` legs prove is that the package
  builds, imports and tests there — including the POSIX-only branches §14 asserts and the path resolution `config.py` branches on — and that is a different
  claim from "this harness ran there", which this file does not make.

### The per-section deltas this build carries over the shipped 0.7.0 harness

The old ledger — `reports/harness-ledger.md`, generated from `/tmp/pkismoke-0711{sh,ps1}/log.txt` before those harnesses were deleted — ended at
**288 pass / 0 fail / 0 warn**: §1 8 · §2 20 · §3 1 · §4 3 · §5 9 · §6 12 · §7 6 · §8 2 · §9 17 · §10 16 · §11 76 · §12 34 · §13 10 · §14 9 · §15 35 ·
§16 30. This harness ends at **310 / 0 / 0**: §1 8 · §2 20 · §3 2 · §4 3 · §5 11 · §6 20 · §7 7 · §8 2 · §9 20 · §10 16 · §11 72 · §12 35 · §13 10 ·
§14 12 · §15 35 · §16 31, plus **§11 STEP F (openssl) 6**. Seven sections are unchanged (§1, §2, §4, §8, §10, §13, §15); nine moved and one is new.
Each delta below is one line — the choice, the reason, and what undoing it costs — so a reader who disagrees can price the disagreement rather than
re-derive it.

| Section | Δ | Choice | Reason | Undo cost |
| --- | --- | --- | --- | --- |
| §3 Version | 1 → 2 (+1) | Keep `GET /version answers 200` alongside the version-string needle. | Every status check is its own assertion in this harness, and §3 is what attributes every other result to a build; a 500 answering with the right version string should not pass. | 1 line (`expect_status`). |
| §5 Generate CSR | 9 → 11 (+2) | Keep `the generate form carries a CSRF token` and `the CSR carries the IP SAN as an IPAddress general name`. | The first is the precondition §7's rejections and §14's sweep depend on, so its absence must be named rather than implied by a later failure; the second parses the CSR with `cryptography` instead of grepping PEM text for "IP". | 2 checks. |
| §6 Sign CSR | 12 → 20 (+8) | Keep the two real download hops: follow both `/download/<id>` anchors, assert their labels and order, then assert each `Content-Disposition`. | The old assertion was `count_exactly(card, 'href="', 2)` — a placeholder that counted quote characters. It passed against a page whose downloads were misnamed or swapped, which is the exact defect class this project keeps measuring (`web-internal.crt` / `web-internal-chain.pem`, `_safe_stem()`). | Back to a 2-line count that asserts nothing about names. |
| §7 Rejections | 6 → 7 (+1) | Keep the multipart file-part probe next to the urlencoded one. | `_form_fields()` stringifies an uploaded part, so a file upload answers `No PEM block found` — worth asserting rather than assuming, and it is why the DER case must post urlencoded at all. | 1 check (delete the `multipart_files` call). |
| §9 CA certificate | 17 → 20 (+3) | Keep `CA download declares application/x-pem-file`, `the issued leaf's serial is the serial printed on its card`, `the issued leaf is signed by this CA`. | DER-level facts a shell harness with no DER parser could not state: the media type is what a client actually reads, and issuer-equals-subject plus card-serial-equals-leaf-serial are what make §11's revoke-by-serial mean something. | 3 checks. |
| §11 Revocation round trip | 76 → 72 (−4) | Accept the drop of five raw-byte probes and add one parsed entry-count assertion. | Retired: `/crl.pem decodes to 653 bytes of DER`; `3 revocationDate + thisUpdate/nextUpdate = 5 UTCTime fields`; `the REVOKED answer says nothing else about this serial` (the scoped `8000`/`8200` absence); the duplicate `SUCCESSFUL at bytes 4..6` on the unknown-serial answer; and a status+bytes pair merged into one byte-exact refusal assertion. Added: `the decoded artifact is a real CRL of 3 entries, matching the page's number`, plus three per-serial listings that replace three `DER INTEGER 0214…` hex needles 1-for-1. A parsed `CertStatus`/entry set cannot be spoofed by signature bytes, so the scoping hack goes with them. | Re-adding five probes re-imports the offset-scoping fragility (11/300 measured flakes) and a size number that changes with every fresh key. |
| §12 About and Settings | 34 → 35 (+1) | Keep `and names the profile that DOES: for that you want \`server\`` as its own needle. | The old client-profile needle ended at `web site.` and read 0 against a correct app — it pinned a period `signing.py:90` never renders. Splitting the clause into a second assertion keeps the half that matters verbatim instead of loosening the string. | Fold it back into one needle with a regex, or restore a period that does not exist. |
| §14 No key material | 9 → 12 (+3) | Keep the response-header sweep over all nine pages, the cookie-value sweep, and `no page contains the CA private key's DER or its bare base64 body`. | Only a live process knows its own key bytes: a unit test can assert that a handler does not print a path, but only HTTP can show that a header or cookie leaked the value. The shell harnesses documented these two halves and asserted neither. | 3 checks (two loops plus the key-bytes block). |
| §16 Dropped extensions | 30 → 31 (+1) | Keep `step A staged a ?pending= id for the consent checks below`. | §16's consent refusals all address that id; without asserting it exists, a failure downstream reads as "consent is broken" when the id never arrived — and a skipped assertion looks identical to a passing one from the summary line, which is the lesson both shell harnesses taught. | 1 check. |
| §11 STEP F (openssl) | 0 → 6 (+6) | Keep all six: verify the root, chain §6's leaf to it, `crl -noout -text` parses, `crl -text` names every stamped serial (3/3), `verify -crl_check` applies the CRL with no `different CRL scope`, and the same command reports §6's revoked leaf as revoked. | Only an independent verifier can re-derive `crl.py`'s decision to omit an IssuingDistributionPoint: openssl 3.5.6 answered `error 44 … different CRL scope` for every leaf this CA signed before 0.7.0, and that claim was otherwise a quoted measurement with no way to check it again. Absence WARNs, because CI says no OpenSSL binary is required anywhere. | Delete the `openssl_checks(app, find_openssl(…))` call and the whole external half disappears — including the only live re-test of the IDP decision. |

Nothing here relaxed a needle to make it pass. Four assertions were *changed* because they were measuring the wrong thing (the §6 `href="` count, §7's
posting shape, §12's trailing period, §11's unpublished serials) and five were retired because a parser answers the same question more strongly; every
one of those is named above with what it cost.
