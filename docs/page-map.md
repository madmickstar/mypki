# mypki — page map (the spec; the code cites it)

This document is the contract for every route, field, validation message and certificate extension in mypki.
Source modules cite it as `page-map §N` in comments, exactly as the reference project cites `docs/route-map.md`.
If code and this file disagree, **this file is wrong** — fix it in the same commit as the code, never silently.

Numbering note: §0 exists because the brief mandates "mypki's own error page" without naming a template for it;
`templates/error.html` is therefore a stated addition to the brief's tree, not a smuggled one (see README
"Divergences we state out loud").

---

## §0 Global rules every route obeys

| Rule | Where enforced |
| --- | --- |
| `FastAPI(debug=False, docs_url=None, redoc_url=None, openapi_url=None)` hard-coded, not configurable | `app.py` |
| Every POST requires a CSRF token; failure → 400 page, **no signing performed** — **one stated exception: `POST /ocsp` (§15), which carries no token and calls no `require_csrf`** | `csrf.py` + `app.py` |
| Oversized input is rejected through mypki's own error page, never a bare JSON `detail` — **one stated exception: `GET /ocsp`, which answers FastAPI's 405 JSON (§15)** | `app.py` (pre-parse body guard + exception handlers) |
| A **refused paste** on `/csr/sign` names its reason **on the sign page itself**, in `<section class="form-errors refused">` directly above the `Paste a CSR (PEM)` label, with the paste echoed back through `redact_private_key_bodies` and any filtered key block counted out loud — while the status stays 400 (malformed) or 403 (privilege claim). Only a refusal that had **no form to put it on** renders `error.html` | `app.py::_paste_refused` + `templates/csr_sign.html` |
| Every PEM/key/CSR response sets `Cache-Control: no-store` and `X-Content-Type-Options: nosniff` | `app.py::_pem_response` |
| Headers on every response: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: same-origin`, CSP `default-src 'self'` (no CDN, no JS) | `app.py::SecurityHeadersMiddleware` |
| Validation failures name their specific reason on the page — never "invalid CSR" | `errors.py` carries the tokens, `app.py` renders them |
| Session cookie `mypki_session`, `same_site="lax"`, `https_only=settings.tls_enabled` | `app.py` |
| No `subprocess` anywhere except fixed-argv `icacls` behind `--secure-acl` in `ca.py` | `ca.py` |
| Logs carry serial/CN/type/expiry/source IP, never PEM bodies or passphrases; a filter drops any record containing `PRIVATE KEY` | `logsetup.py` |

**Exit codes.** CLI: 0 success · 1 validation/usage failure · 2 refused (CA exists, `--force` absent) ·
3 required state missing (no CA). Smoke scripts: 0 all passed · 1 at least one FAIL · 2 **nothing was checked**.
"Not checked" is never reported as a pass.

**Error page.** `templates/error.html` renders `status`, the specific reason, and a link back. It is mypki's page,
not Starlette's JSON, and not an HTML traceback. As of this build it is reached only where there **was no form to answer**:
an oversized body (`SizeGuardMiddleware` refuses before any route runs), a missing or bad CSRF token, `/inspect`, a bad
address. A refused *paste* on `/csr/sign` no longer lands here — §3 states where it goes and why its status did not move.
Its recovery links read `Sign a certificate` to match that page's own `<h1>`, while the sidebar item stays `Sign CSR`.

---

## §1 Home — `GET /`

**As of 0.3.0 the front page *is* the Sign-CSR form and nothing else** (`templates/csr_sign.html`, rendered by `home()`
through the same `sign_page()` that serves `/csr/sign`). 0.1.0 led with prose about what mypki is; that prose moved to
`/about` (§12). 0.2.0 added a CA facts card above the form; **0.3.0 removed it — §4's `/ca` carries those facts alone**
(subject, serial, validity window, fingerprint, key type/size, BasicConstraints and key presence), sitting next to the root's
own download. Rendering them on `/`, `/csr/sign` and `/ca` was rendering them three times, and a fact shown in two places is
two facts that can disagree.

One template for both addresses — rather than a copy, or a redirect — is what makes "the front page is the sign page" one
implementation instead of two that drift.

The CA card on `/ca` is read from the **public** certificate only:

| Field | Source |
| --- | --- |
| Subject (CN / O / OU / C) | `cert.subject` |
| Not Before / Not After (UTC) | `not_valid_before_utc`, `not_valid_after_utc` |
| Serial (hex) | `cert.serial_number` |
| SHA-256 fingerprint | `cert.fingerprint(hashes.SHA256()).hex()`, colon-grouped for display |
| Key type + size | `public_key()` introspection via `keys.describe_public_key` |
| BasicConstraints | expected `CA:TRUE, pathLength:0` |
| CA private key present on host | boolean only (`app.state.ca_key is not None`) |

No CA → the card is replaced by one line: *run `mypki init-ca`*. `/csr/sign` and `/ca` show the same notice.
The home page never reads the key file; it reports presence as a boolean.

**A test that scrapes this page has to scope itself.** The CA serial cell and an issued certificate's serial cell are spelled
identically (`<td class="mono">…`), so a page-wide search for a hex serial on `/csr/sign` finds the **CA's** — MEASURED, it did,
comparing `3432f851…` against a record of `21adb4d3…`. `tests/test_views.py::_issued_serial` anchors on `<h2>Issued:` for that
reason.

---

## §2 Generate CSR — `GET` + `POST /csr/generate`

| Field | Validation |
| --- | --- |
| `common_name` **required** | ≤253 chars, no control characters; if it looks like a DNS name each label ≤63 and RFC 1123 |
| subject fields (`organization`, `organizational_unit`, `country`, `state`, `locality`, `email`) | prefilled from `MYPKI_DEFAULT_*` (§11) on a first visit and from what the operator typed on a rejected submit — the same `values=` shape both ways, so the template has exactly one way to fill an input and no path can ignore a knob |
| `sans` (textarea) | one entry per line or comma; classified DNS or IP; max `settings.max_sans` (100); dedupe preserving first-seen order |
| `organization`, `organizational_unit`, `state`, `locality` | optional, printable, ≤128 |
| `country` | exactly two letters A–Z after uppercasing |
| `email` | optional, one `@`, printable, ≤254 |
| `key_type` | allow-list only: `rsa-2048`, `rsa-3072` (default), `rsa-4096`, `ec-p256`, `ec-p384` |
| `passphrase`, `confirm` | optional pair. **Floor 8** (`csr.PASSPHRASE_MIN_LENGTH`) with a stated recommendation of 12 (`PASSPHRASE_RECOMMENDED_LENGTH`): 8–11 is accepted and an advisory says "12 or more is better", naming the length it saw and never the value. Must match when present; used **only** to encrypt the returned PEM |

**The form's own labels (0.7.1).** The visible field names are the X.501 abbreviations an operator sees in every certificate
viewer — `Common Name (CN)`, `Subject Alternative Names (SAN)`, `Organisation (O)`, `Organisation Unit (OU)`, `Country Code (C)`,
`State (S)`, `Location (L)`, `Email (E)` — and each section is a blue `.section-heading` outside a `.card.settings-section`, i.e. `/settings`'
styling rather than the `<fieldset>`/`<legend>` pair this page carried from 0.1.0 (§12). The **internal** field names in the table above did not
change, and they are what the validation reasons quote, so a refusal reads `country must be exactly two letters (got 'DEU')` beside a box labelled
`Country Code (C)`: one label in two places is exactly the drift this document warns about, and these two are deliberately different words for the
same field rather than two names for two things.

Output shown **once**. Three capsule controls sit at the **top** of the result page (0.7.1): `Download CSR and Private Key` (one file, request first
then key), `Copy CSR to clipboard` and `Copy Private Key to clipboard`. The two PEM blocks stay on the page below — a `<pre>` is the flow that works with
no script and no download, both harnesses extract *the page's* armour to prove the downloads serve what was shown, and an operator with no file transfer
reads them off the screen. The separate `Download CSR (.pem)` / `Download private key (.key)` links remain under their blocks; a key's header is
`-----BEGIN ENCRYPTED PRIVATE KEY-----` when a passphrase was supplied.

The combined file is a decision, not a convenience: **MEASURED with openssl on this box**, a request followed by a key in one file is read correctly by
`openssl req -in` and by `openssl pkey -in`, while `openssl x509 -in` refuses it. Request-first is therefore pinned by
`test_csr_generate.py::test_the_combined_download_holds_this_generation_request_and_key`, which also asserts the pair belongs to *this*
generation (the request's public key equals the private key's) and that the file holds exactly two blocks.

**Nothing is written to disk or the DB.** The key exists only in request memory and the response body. Downloads
are served from the process-memory one-shot store (§10), never from a file, and `test_csr_generate.py` asserts the
data dir is byte-for-byte unchanged across a generation — including for the third artifact, which is a third `store.put` of two strings already in memory
and not a write.

---

## §3 Sign CSR — two-step on `/csr/sign`

**Step A** (`POST /csr/sign`, no `confirm=1`) — paste `csr_pem` (≤`settings.max_csr_chars`, 32 000; exactly one
`-----BEGIN CERTIFICATE REQUEST` block) and validate **in this order**, each failure naming its reason:

1. PEM decodes (base64 of exactly one block).
2. `x509.load_der_x509_csr` accepts the bytes (a pasted certificate says so specifically).
3. `csr.is_signature_valid is True`.
4. `csr.signature_hash_algorithm.name ∈ {sha256, sha384, sha512}` — SHA-1/MD5 rejected.
5. Key policy: RSA ≥ 2048 bits, or EC on P-256/P-384. Nothing else.
6. **Extensions split into two categories** (`csr._csr_extension_problems` returns `(refused, ignorable)`), because "no CA
   privileges" and "I do not read your extensions" were one rule answering two different questions:
   * **refused** — `BasicConstraints CA:TRUE`, `KeyUsage keyCertSign`, `KeyUsage crlSign`, NameConstraints, and any extension
     the classifier does not recognise (the `else:` arm names `type(value).__name__`, so an unknown OID cannot slip through
     unclassified). Raises `CaPrivilegeRequestedError` → **403**, as before — and "403" names the *status* only: the body that
     carries it is the sign page with its own form still on it (see **Error surfaces** below), not `error.html`.
   * **ignorable** — `BasicConstraints CA:FALSE`, `KeyUsage (<bits>)` including `KeyUsage (no usages set)`, SubjectKeyIdentifier,
     AuthorityKeyIdentifier, `ExtendedKeyUsage (<names>)`, CertificatePolicies, CRLDistributionPoints, AuthorityInfoAccess. These
     do **not** raise; they are listed on the confirmation panel and dropped from what gets copied, but only with consent (rule 8).
   SAN remains the only extension read from a request into the certificate.
7. SANs valid (§9).
8. **Dropped extensions need consent** (`app._consent_problem`, step B): if the re-parsed staged request carries any ignorable
   extension and the confirm POST did not tick `ignore_extensions` (`app.CONSENT_FIELD`), the panel re-renders at **200** naming every
   extension at stake plus *Nothing was signed* — a fixable input, not a refused artifact. Consent is read from the request that was
   staged (`CsrDetails.ignored_extensions`), never from a form field, so a POST cannot claim consent for extensions it did not carry;
   `_consent_given` requires a value in `{1,true,on,yes}`, so presence alone is not consent. Ticking the box issues, and each dropped
   extension appears on the issued page as `Extension not copied: <name>`. Consent changes what is **copied**, never what is **signed**:
   the staged PEM keeps its extensions (its signature covers them) and mypki's own profile is what lands in the certificate.

Confirmation panel shows: subject attributes, SAN DNS list + IP list, key type/size, signature algorithm + hash,
`cert_type` radio (`server` default | `client` | `both`) and `validity_days`
(default `settings.validity_default_days` 365, min 1, max `settings.validity_max_days` 1461), with `confirm=1`.
**The panel now carries an extension list** (`csr_sign.html`, `<div class="provenance dropped-extensions">`) whenever the request
carried one that rule 6 classifies as ignorable: a heading *Not copied from your request — mypki sets these itself*, one
`<li><code>name</code></li>` per extension in `details.ignored_extensions`, and the byte-identity note that dropping them is a
description of what mypki will sign, not an edit of the pasted bytes. Below it sits the consent fieldset (`<fieldset class="consent">`,
default **OFF**, `name="{{ consent_field }}"` with its `checkbox-state state-off/on` word) naming the same extensions in the hint.
Both blocks render only when `details.ignored_extensions` is non-empty, so a CSR mypki generated itself shows neither — no empty list,
no box with nothing to consent about. Extensions in the **refused** category never reach this panel; they are answered at 403 on
**this same page** (`CaPrivilegeRequestedError.extension` names the extension, and `refused_hint` points at the consent box for the
half of rule 6 that *is* signable), so the refusal and the paste it is about appear in one screen.
An earlier draft of this file said "no extension list appears on this panel", and that sentence was true only while rule 6 refused
everything but SAN: it was changed by changing the rule, not by rewording the sentence.
The validated PEM is carried in a **signed session entry** (an opaque id) rather than re-posted — see §10 for why
the bytes themselves live in process memory instead of the cookie.

**Step B** (`POST /csr/sign`, `confirm=1`): issues and renders signed cert PEM in a `<pre>`,
`Download certificate (.crt)`, `Download chain (.pem)` (leaf then CA), serial hex, expiry and a link to `/issued`.
Over-max validity is **rejected with the limit named**, never silently clamped.

**Editable names (0.2.0).** Step A prefills `common_name`, `organization`, `organizational_unit`, `country`, `state`, `locality`,
`email` and `sans` from what the request said, and step B takes them from the form when the form submitted them (`in form`, not
truthiness — an empty string is how you *remove* an attribute). Each edited field passes the same `validators.py` functions the
generate form runs (§9): a second implementation of "what is a valid country" is how one page starts accepting what the other
refuses. What stays fixed: the **public key** comes only from the request — no field on this form can change it — and no field
can set an extension. A POST naming none of these fields keeps 0.1.0 behaviour and signs exactly what the request says, which is
also why "no edit submitted" must never render as "every field was removed".

**The diff.** Anything differing from the parsed request is listed under "Changed from your request" on the issued page
(`app._changed_subject_fields`), with SANs compared as **sets** rather than as text: re-typing the same names in another order or
case is not a change to what this CA vouched for, and reporting it as one trains an operator to ignore the warning. The diff is
the price of the editable form. From 0.7.0 a mis-issuance *can* be walked back — §14 publishes it in a CRL and §15
answers REVOKED for it — but only for a client that consults what this host publishes, and nothing here un-signs a certificate.

**Error surfaces** (`app.py::ERROR_SURFACE_RULE` — a constant whose value is that file's module-docstring heading, so this
spec and every test cite one name rather than retyping a sentence; there are three surfaces now, two of them on this page).
A field the operator can fix comes back on this page at **HTTP 200** with
every problem named and every typed value still in its input — over-max validity, a `server` profile with no SANs, an over-cap
SAN edit, a bad country code. The staged request survives the round trip because the form action carries `?pending=<opaque id>`
(`_staged_pem_id` prefers it over the session), so fixing a country code does not mean re-pasting a 2 KB PEM.

**A refused paste comes back to this page, at its own status.** Garbage PEM, a signature that does not verify, a weak key and a
CSR asking for CA powers are answered by `app._paste_refused`, which re-renders `csr_sign.html` with
`<section class="form-errors refused">` above `<label for="csr_pem">Paste a CSR (PEM)</label>` and the paste itself still in the
textarea — run through `inspect.redact_private_key_bodies` first, so the armour lines survive and a private key's base64 does not,
with the number of filtered blocks named on screen rather than left as a silent edit. **The status is unchanged** (400 for
malformed input, 403 for `CaPrivilegeRequestedError`), and nothing is staged or signed: status answers *what was wrong* for a
script, the block answers *what to fix* for the person at the form, and moving one did not move the other. The reason keeps its
`<p class="reason">` class, so "read mypki's stated reason" remains one selector whichever surface rendered it. What still goes to
`templates/error.html` at 400/403/413 is what had **no form of its own** — an oversized body refused before routing, a bad CSRF
token, `/inspect` — because there is nothing there that this form could edit.

---

## §4 CA certificate — `GET /ca` (page) + `GET /ca/certificate` (download)

Download response: public CA cert PEM only, `Content-Type: application/x-pem-file`,
`Content-Disposition: attachment; filename="mypki-root-ca.crt"`. The `.crt` extension is deliberate: Windows'
double-click installer keys off it.

Page shows SHA-256 fingerprint + validity for out-of-band verification, plus install instructions:

| OS | Steps |
| --- | --- |
| **Windows** | double-click → Install Certificate → Local Machine → "Place all certificates in the following store" → **Trusted Root Certification Authorities**; or `certutil -addstore -f ROOT mypki-root-ca.crt` (elevated) |
| **macOS** | Keychain Access → System keychain → Show → "When using this certificate: Always Trust" |
| **Linux** | copy to `/usr/local/share/ca-certificates/mypki-root-ca.crt`, then `sudo update-ca-certificates`; Firefox: use the system trust store; Java: `keytool -importcert -alias mypki -file mypki-root-ca.crt -keystore $JAVA_HOME/lib/security/cacerts` |

### The controls at the top of this page (0.7.1) — and why there is no PEM block on it any more

`GET /ca` renders **no certificate bytes**. Two capsule controls sit above everything else — `download root-CA cert` (an `<a>` to
`/ca/certificate`) and `copy to clipboard` (`<button class="copy-pem" data-mypki-copy-url="/ca/certificate">`, wired by
`app.js`'s `wireCopyUrl`, which fetches that URL and writes the body to the clipboard as `text/plain`). The facts card is titled with this
root's own Common Name in a `.section-heading` outside the card, and the card is `.card.settings-section` — `/settings`' styling, not a second
look-alike (§12).

0.5.0 put the certificate in a `<pre id="pem-ca">` here so an operator with no file transfer had something to paste. With the controls at the
top, one host was rendering the same certificate three times on one page: the attachment, the block, and the table describing it. Deleting the
middle one is this document's own oldest rule applied to a page copying itself — a fact in two places is two facts that can drift (§1) — so
`app.ca_page` now passes **no extra context at all** and `GET /ca/certificate` is once again the only route on this page's path that emits
certificate bytes.

What replaced the parity assertion is stronger rather than weaker. §9 used to hash the DER inside `id="pem-ca"` against the DER of the download;
it now reads the serial number and the colon-grouped SHA-256 fingerprint out of the **served** certificate and asserts both appear on the page,
which asks a DER parser instead of comparing two copies of one string. §15 keeps the same question for `/inspect`'s re-armoured paste.

`/ca` is still not §13's reader. `/ca` shows **this host's own root**, read from disk by the code that already loads it; `/inspect` takes
**whatever text an operator pasted**, parses it, and re-armours what it parsed. `/inspect` carries no opinion about whether what it read belongs
to this host, is trusted, or was ever issued here; `/ca` is the page that knows it is *this* CA.

§13 is a different kind of page and must not be confused with this one. `/ca` shows **this host's own root**, read from disk by the code
that already loads it; `/inspect` takes **whatever text an operator pasted**, parses it, and re-armours what it parsed. Those land on the
same bytes whenever the source PEM is conventionally wrapped — which is why the parity assertion passes — but the routes differ: one is a
file handed to a template, the other is base64 → DER → re-encoded base64. `/inspect` carries no opinion about whether what it read belongs
to this host, is trusted, or was ever issued here; `/ca` is the page that knows it is *this* CA, and `GET /ca/certificate` stays the only
place those bytes are offered as a file.

---

## §5 Issued certificates — `GET /issued` + `POST /issued/revoke`

Newest-first table: **Select** · **Status** · Serial (hex) · Type · CN · SANs (truncated, full value in `title=`) · Not Before
(UTC) · Not After (UTC) · Issued At (UTC). There is still no detail page and no search: a list of what one CA signed is short
enough to read, and a delete would make a valid certificate look never-issued.

**There is no Revoke column, and as of 0.4.0 no Revoked column either** (`templates/issued.html`). 0.2.0 added a Revoked column
beside Status; the two said almost the same thing about every row and could disagree if one was misread. The Status cell now carries
the whole decision: `pill active|revoked`, then — for a revoked row only — `<span class="hint">revoked <UTC> YYYY-MM-DD HH:MM:SSZ</span>`
and, when a reason was given, the reason under it. The e2e harness scrapes `class="hint">revoked YYYY-MM-DD` out of that cell, so
the *shape* of the stamp line is a contract even though its column is gone, and it also asserts that
`<th scope="col">Revoked</th>` occurs **zero** times.

**Status is two states, not three** (`store.IssuedRecord.status`): `active` or `revoked`. A certificate past its `not_after_utc`
still reports `active`, because this CA never revoked it; printing `expired` in a cell whose other value is `revoked` would imply
this host knows what every client currently accepts. The expiry fact sits in the date cell instead, as a `past` marker.

**Revocation is bulk, from one control.** Every active row carries a `serial_hex` checkbox inside **one** bulk form that wraps the
table; a stamped row carries none (it cannot be un-revoked and there is no delete). The bar above the table holds the Select-all box,
the counter — server-rendered as `0 selected`, which is the same shape `app.js` writes at zero, so one number has one spelling in both
languages — and **exactly one** *Revoke Selected* **control**. The *phrase* itself occurs three times on the rendered page:
once inside the `<button class="danger solid" type="submit">` and twice inside `<strong>` in the no-JavaScript hint. The harness
therefore asserts the split rather than a raw phrase count — exactly one button tag, exactly one
  `class="select-bar"`, and phrase == button + prose — because a count of 3 is correct here and was wrong on 0.3.0,
  where it meant two buttons. 0.4.0 deleted the duplicate button below the table and its `.select-bar.bottom` rule, because
  two buttons for one decision invite a click on whichever is nearer.

**Revoke** (`POST /issued/revoke`, CSRF-checked as the handler's first act): `serial_hex` (required, repeatable — N ticked boxes are
N values, which is why `app._form_fields_multi` exists) plus an optional `reason`
capped at `store.MAX_REVOCATION_REASON_LENGTH` (120). It stamps `revoked_at_utc` and `revocation_reason` on that row and
re-renders the list with a confirmation naming the serial, the UTC stamp and the reason. Re-revoking is a **no-op** that
preserves the original stamp — *when* the decision was made is a fact about the past, so a refresh or a double-click must not
move it to "now". An unknown serial answers 404 naming both the serial and the database file (`RevocationRecordNotFoundError`);
a blank serial answers 400. There is no delete, and `IssuedStore` carries exactly one update method for this — its narrow scope
is asserted by introspection in `tests/test_store.py`.

**What revoking does from 0.7.0, and what it still does not do.** A stamp is no longer only a row: `_stamp_revocations` re-signs
`<data>/crl/mypki.crl.pem` (§14) whenever a batch actually stamped something, and from then on the OCSP responder (§15) answers
REVOKED for that serial. A batch that stamped nothing re-signs nothing — "already revoked" must not buy a fresh CRL Number. What has
**not** changed is the client side, and `templates/issued.html` says so both next to the confirmation and in the table footer:
*Revoking stamps the row and re-signs the published CRL, which answers OCSP too — but only clients that consult either will ever see
the decision, and a certificate issued before 0.7.0 carries no pointer to them. For those, **a revoked certificate stays trusted by
clients until it expires**.* `tests/test_views.py::test_a_record_can_be_revoked_from_the_issued_page_and_says_what_that_does_not_do`
asserts the control and that sentence together, in one round trip. Through 0.6.0 the same test asserted *"no CRL is published"* in the
confirmation text; that sentence became false on release day and was rewritten in the same commit as the behaviour.

**Discoverability, deliberately not in the nav.** `/crl` is reached from this page's footer links and from `/ca`; the nav stays at seven
links (§12) rather than gaining a menu entry for an artifact a reader of `/issued` is already standing next to. `/ocsp` appears as no
control and no link on any page — `tests/test_ocsp.py` asserts `action="/ocsp"` and `href="/ocsp"` occur zero times across the eight
pages — because a client learns that URL from a certificate's `AuthorityInfoAccess`, not from a menu.

---

## §6 CLI contract (`cli.py`)

| Command | Behaviour |
| --- | --- |
| `mypki init-ca [--data-dir] [--common-name "mypki Root CA"] [--organization] [--organizational-unit] [--country XX] [--key-type rsa\|ec] [--key-size 3072] [--curve P-256\|P-384] [--days 3650] [--encrypt] [--passphrase-env MYPKI_CA_PASSPHRASE] [--force] [--secure-acl]` | Creates `<data>/ca/ca_key.pem` + `<data>/ca/ca_cert.pem`. Writes nothing to the DB. Refuses overwrite without `--force`: prints `CA already exists at <path>. Use --force to replace it.` and exits **2**. `--force` first moves the old pair to `<data>/ca/archive/<UTC-timestamp>/`; nothing is deleted. Passphrase via `getpass` or the named env var — never argv, never logged, never echoed. Prints only public facts (subject, serial hex, validity, SHA-256 fingerprint, key spec, paths). The GUI cannot create a CA: this command is the only way. |
| `mypki serve [--host 127.0.0.1] [--port 8443] [--ssl-cert F --ssl-key F] [--data-dir] [--passphrase-env]` | Exits **3** with "run `mypki init-ca` first" when no CA exists. Loads/decrypts the CA key **once** at startup; handlers never re-read it. Creates or loads `<data>/instance/secret_key` (0600). TLS params go to `uvicorn.Config(ssl_certfile=…, ssl_keyfile=…)`; without them print a plain-HTTP warning whose advice names both routes and their cost (`--ssl-cert/--ssl-key` here, or TLS terminated at a proxy — in which case Secure cookies come from the proxy, because `https_only` follows `tls_enabled`, i.e. **both** knobs on this process). Passes `log_config=None` (see `logsetup.py`). Binding to anything but localhost prints a LAN-exposure warning. A bind that fails reaches mypki as "SystemExit(3)" from uvicorn, not as an OSError; mypki turns that into **exit 1** with its own "cannot start <host>:<port>: the server never bound" line, because exit 3 is reserved for "no CA found": measured on uvicorn 0.54.0, `uvicorn.server.Server.run` catches the bind's `OSError`, logs it through `uvicorn.error` and exits with `STARTUP_FAILURE`, so the `OSError` never reaches mypki — `cli.py`'s serve branch is what turns that `SystemExit` into mypki's own exit-1 message. |
| `mypki info [--data-dir]` | CA subject/serial/validity/fingerprint/key spec + issued-record count + resolved data dir. Exit **3** if no CA. |

No `sign`, `revoke`, or `export-key` subcommands, by design: the GUI is the signing surface, `/issued` is where a revocation is
recorded (§5), and the key must not be exportable (README "Naming"). 0.2.0 added the revoke *control* on `/issued`; it did not
add a CLI command for it, so there is still exactly one way to sign and one place to mark a record revoked.

---

## §7 Certificate profiles

### Root (`init-ca`)

RSA 3072 / exponent 65537 (alternative EC P-256) · SHA-256 signature · 3650 days default · CN `mypki Root CA` ·
`BasicConstraints CA:TRUE pathLength:0` **critical** · KeyUsage digitalSignature|keyCertSign|crlSign **critical** ·
SKI present, no AKI (self-signed root), no EKU · `x509.random_serial_number()`.

`pathLength:0`, not `None`: caps the chain at one level, so a leaf that somehow gets marked CA cannot mint another
CA beneath it (RFC 5280 §4.2.1.9).

### Profiles in words (`signing.CERT_PROFILE_HELP`, rendered on `/csr/sign` and `/about`)

The three names are not self-explanatory, and 0.1.0 shipped them with no explanation at all — which produced the most common
misreading of this project. `CERT_PROFILE_HELP` is a module constant in `signing.py`, rendered verbatim next to each radio button
and again on `/about`, so a profile cannot exist in the UI without a statement of what it will not do:

| Profile | What it is | What it does NOT do |
| --- | --- | --- |
| `server` | **The web-server profile.** A service people connect to: a website, an HTTPS API, a reverse proxy, an internal dashboard. The SAN names are what a browser or client matches the URL against, so they must be exactly the names users type. | It does not authenticate a person or device logging in. |
| `client` | Proving **who is connecting**: a VPN client (OpenVPN, WireGuard with TLS auth), a smartcard or badge, mutual-TLS where a laptop presents a certificate, code-signing-style identities. Your service checks this certificate to decide who the caller is. | It will **not** make a browser trust a web site — for that you want `server`. |
| `both` | One certificate usable in either direction: a host or device that serves TLS *and* authenticates as a client. | Stricter environments keep the two separate, because a leaked `both` certificate is trusted for both jobs. |

### Leaves — server-side constants; extensions are never copied from the CSR

0.1.0 summarised this table as "only SAN is copied from the CSR", which was **inaccurate**: the subject attributes
(CN/O/OU/C/ST/L/email) come from the request — and, since 0.2.0, from the operator's edits to it (§3). What is never taken from
a request is the *extensions* below; the public key comes only from the request.

| Extension | `server` | `client` | `both` | Critical |
| --- | --- | --- | --- | --- |
| BasicConstraints | `CA:FALSE, pathLength=None` | `CA:FALSE` | `CA:FALSE` | yes |
| KeyUsage | digitalSignature + keyEncipherment (**keyEncipherment False for EC keys**) | digitalSignature only | digitalSignature + keyEncipherment (False for EC) | yes |
| ExtendedKeyUsage | `[serverAuth]` | `[clientAuth]` | `[serverAuth, clientAuth]` | no |
| SubjectAlternativeName | copied, **required** | copied, optional | copied, **required** | no |
| SubjectKeyIdentifier | `from_public_key(leaf public key)` | same | same | no |
| AuthorityKeyIdentifier | `from_issuer_public_key(CA public key)` | same | same | no |
| Serial | `x509.random_serial_number()` | same | same | — |
| Validity | tz-aware `datetime.now(timezone.utc)` → +days, via `not_valid_before_utc`/`not_valid_after_utc` | same | same | — |
| Signature hash | SHA-256 (SHA-384 when the leaf key is P-384) | same | same | — |
| Issuer | exactly the CA subject | same | same | — |

| CRLDistributionPoints | `<crl_base_url>/crl.pem` — one `DistributionPoint`, `full_name` only (`relative_name`, `reasons`, `crl_issuer` all `None`) | same | same | **no** |
| AuthorityInformationAccess | one `AccessDescription`: OCSP at `<crl_base_url>/ocsp` | same | same | **no** |

Never on a leaf: `CA:TRUE`, `keyCertSign`, `crlSign`, NameConstraints, CertificatePolicies.

**What changed in 0.7.0.** The sentence above used to name `CRLDistributionPoints` and `AuthorityInfoAccess` as things a leaf never carries;
from 0.7.0 both **do** — added by `signing.leaf_extensions()` itself, non-critical, spelled from the one configured base (`crl_base_url`,
§11), so `…/crl.pem` and `…/ocsp` have exactly one spelling each and both are routes this app actually registers. What has **not** changed is
"extensions are never copied from the CSR": a request carrying its own distribution point is still classified ignorable (§3 rule 6),
still dropped, still named on the confirmation panel and again on the issued page — the CA adds its own pointer rather than obeying the
applicant's (`tests/test_consent.py` asserts `urls == ["http://mypki.my.lab/crl.pem"]` against a request that asked for
`http://crl.internal/crl.der`, and `tests/test_csr_validate.py` keeps `CRLDistributionPoints` in the ignorable table with its name
asserted verbatim). Both extensions land only on certificates issued **from 0.7.0 onward**: no migration, no re-issue (§14).

Validity comes from `validity_days` (default 365; ceiling `settings.validity_max_days` = **1461** as of 0.2.0 — see §11). An
over-ceiling request is refused naming the limit, never clamped.

---

## §8 Storage and paths (`paths.py`, pathlib only)

Precedence `--data-dir` > `MYPKI_DATA_DIR` (or `.env`) > OS default.

| | Config dir | Data dir |
| --- | --- | --- |
| **Linux** | `$XDG_CONFIG_HOME/mypki` else `~/.config/mypki` | `$XDG_DATA_HOME/mypki` else `~/.local/share/mypki` |
| **Windows** | `%APPDATA%\mypki` | `%LOCALAPPDATA%\mypki` |

```
<data>/ca/ca_key.pem        # never served, never logged, never in the DB, mode 0600 on POSIX
<data>/ca/ca_cert.pem       # the only certificate served
<data>/ca/archive/<UTC-ts>/ # pairs archived by --force; nothing is ever deleted
<data>/crl/mypki.crl.pem   # 0.7.0: the published CRL, rebuilt rather than appended. One fixed name
                           # (`paths.crl_path`), ordinary permissions (0644 umask-respecting) because
                           # `GET /crl.pem` serves it to anyone — see §14, not PRIVATE_FILE_MODE
<data>/instance/secret_key  # SessionMiddleware secret, mode 0600 on POSIX
<data>/issued.db            # SQLite WAL: issued_certs(serial_hex, cert_type, common_name, sans_json,
                            #   not_before_utc, not_after_utc, issued_at_utc, fingerprint_sha256,
                            #   revoked_at_utc, revocation_reason)  # last two added in 0.2.0; NULL on a fresh row,
                            #   an existing 0.1.0 DB gains them on the first init_schema() call
logs/mypki.log              # relative default; resolved absolute path logged as the first line
```

Key protection, stated honestly: on POSIX `ca/` is 0700 and the key is chmod 0600 then re-stat'd and asserted. On
Windows `os.chmod` only toggles the read-only bit — it is **not** an ACL — so protection comes from (a) the key
living under per-user `%LOCALAPPDATA%`, (b) optional `icacls` hardening behind `--secure-acl` invoked as a fixed
argv array with no user-supplied component (skipped silently if the binary is absent), and (c) passphrase
encryption (`PrivateFormat.PKCS8` + `BestAvailableEncryption`) as the cross-platform guarantee.

---

## §9 Validation rules (pure functions in `validators.py`, no FastAPI import)

Exactly one PEM block; `is_signature_valid is True`; hash ∈ SHA-256/384/512 (SHA-1/MD5 rejected); RSA ≥ 2048 only;
curves P-256/P-384 only; no CA privileges (`CA:TRUE`, `keyCertSign`, `crlSign`, NameConstraints, anything unrecognised → refused);
the remaining non-SAN extensions are **disclosed and dropped with consent** rather than refused (§3 rule 6), and SAN is still the
only extension copied into a certificate.

SAN classification: bare numeric addresses become **IP general names** via `ipaddress` (IPv4 and IPv6); everything
else is a DNS name validated against RFC 1123 labels — each label ≤ 63 chars, no leading/trailing hyphen, no empty
labels, wildcard allowed only as the leftmost `*.`, total length ≤ 253. Dedupe preserving first-seen order; cap at
`settings.max_sans`. Country is exactly two letters after uppercasing.

Messages name the position and the reason, e.g. `"server..local" is not a valid DNS name (empty label at position 7)`
— the position is the zero-based offset where the offending label starts in the original string.

---

## §10 One-shot artifacts (why downloads work without storing anything)

Generated keys/CSRs and issued certs are handed to the browser twice — inline `<pre>` and a `Download` link — but
nothing may be written to disk or the DB (§2, §3). Downloads therefore read from an in-process, session-scoped,
expiring artifact store held on `app.state`.

Why not put the PEM in the signed session cookie, as an earlier draft of this plan suggested? A 3072-bit RSA key
PEM is ~3.2 KB and a max-size CSR is 32 000 characters; RFC 6265 §6.1 makes browsers free to reject cookies over
4096 octets, so the session-carry-over would silently drop the very bytes it was carrying. The cookie therefore
carries only an opaque 256-bit id per artifact; the bytes stay in process memory until they expire (TTL 15 minutes)
or the process exits. Consequences stated plainly: a restart loses pending downloads, and `--workers > 1` would make
an artifact visible to only one worker — mypki runs one worker per process (same single-worker rule as the log file,
see `logsetup.py`).

---

## §11 Configuration knobs (`config.py`, all `MYPKI_`-prefixed)

`host` · `port` · `data_dir` · `public_base_url` · `crl_base_url` · `ssl_certfile` / `ssl_keyfile` (⇒ `tls_enabled`) ·
`secret_key` · `ca_cn` · `ca_default_days` · `log_level` · `log_file` · `log_max_bytes` · `log_backup_count` ·
`log_to_console` · `validity_default_days` · `validity_max_days` · `max_sans` · `max_csr_chars` ·
`session_max_age` · `default_organization` · `default_organizational_unit` · `default_country` · `default_state` ·
`default_locality` · `default_email`.

Every knob carries a `description=` that says what it costs, and those descriptions are **rendered verbatim** onto `/settings` — as the
hint line under each editable control (`app._first_sentences`, which cuts at a sentence boundary rather than mid-word) and, for the four
knobs this page refuses to edit, in full beside the reason on the 'Not editable here' card. 0.3.0 rendered them in a resolved-state
table's description column; that table is gone (§12), and with it the only place the longest descriptions appeared whole. That is why
they read as operator-facing prose rather than as comments, and why a knob added to `config.py` appears on that page without the
template being updated in step: `app._knob_input` iterates `Settings.model_fields`, not a copy of it.

`validity_max_days = 1461` (4 years) as of 0.2.0. It was **825** for as long as this project had no revocation at all: with
nothing to revoke, the validity date was the *only* bound on a mis-issued certificate, and 825 also happened to sit inside the
window platforms apply to TLS server certificates. Revocations are now recorded (§5), so 2-, 3- and 4-year leaves become a
defensible operator choice rather than an unbounded bet. **MEASURED on cryptography 50.0.2:** the builder accepts
`not_valid_after` at 825, 1000, 1188, 1461 and even 3650 days without complaint — nothing in the library enforces 825, so the old
number was this project's own policy. The widely cited 398/825-day windows are rules applied to certificates from
publicly-trusted CAs and were **never measurable on any host in this project's environment**, which is why 1461 is a stated,
caveated product decision rather than a discovered fact. If a client refuses a long-lived leaf, lower the knob to 825 — that is
what it exists for. Over-ceiling submissions are refused naming the limit, never clamped.

`crl_base_url = "http://mypki.my.lab"` (0.7.0) is the only knob revocation gets, and it is deliberately a **base**: the paths are spelled
by `app.py` (`/crl.pem`, `/ocsp`), so the URL baked into a certificate cannot disagree with the route that serves it. Plain `str`, not
`… | None`: there is always a value, which is what makes `/settings` refuse an empty box naming this knob (`_empty_means_default`) instead
of silently reverting — and why no "unset means no CDP" branch exists anywhere in the app. A `field_validator(…, mode="before")` refuses a
value that does not start with `http://` or `https://` **at startup**, because this string is copied into every certificate issued afterwards:
`mypki.my.lab` without a scheme would be encoded faithfully, read back correctly on `/settings`, and fail at a client whose error
never mentions this knob. Trailing slashes are stripped rather than rejected (`http://host//crl.pem` is legal to encode and broken to fetch,
and invisible on the page). It sits in `SETTINGS_SECTIONS` under *Serving* beside `public_base_url`, and it is **live** — not one of
`STARTUP_ONLY_KNOBS` — because it is read at build and issue time. Live is not retroactive: the change reaches only certificates issued
after it, which the knob's own rendered description says.

`public_base_url` is re-described for the same reason: it feeds **nothing a certificate carries**. Its hint now names `crl_base_url` as what
does, because the two facts have different lifetimes — one describes how you reach this host today, the other is frozen into certificates
that outlive the change.

**No knobs exist for `CRL_LIFETIME` (24 h), `OCSP_LIFETIME` (4 h) or `OCSP_MAX_REQUEST_BYTES` (8192 B)** — module constants in `crl.py` and
`ocsp_responder.py`. A knob for any of them would need a row here, a preset entry, an empty-value rule and a story about what happens when it
is shorter than a client's refresh interval, for values whose only sensible range is "often"; the third exists to answer a malformed request
before anything is signed, which is not a preference an operator should be offered. `max_csr_chars` bounds the OCSP body **indirectly** (the
size guard's limit is `max_csr_chars + 8192`, §15), and that is stated rather than turned into a second knob.

`max_csr_chars = 32000` exists because starlette's own part limit answers 400 with a bare JSON
`Field exceeded maximum size of 1024KB.` (MEASURED on starlette 1.6) and mypki renders its own page instead.

The six `default_*` knobs prefilled on the Generate-CSR page are settings rather than constants because "Lab / IT / AU" is
somebody else's organisation: the point is that each host states its own defaults instead of everybody editing a template. An
empty value leaves the field blank, and every one passes the validators the form applies, checked at startup
(`_subject_defaults_are_valid_values`) rather than mid-signing.

---

## §12 About, Settings and the static assets (0.2.0)

### `GET /about`

What this host is and which build it is: the version (`mypki.__version__`), the source URL (`app.PROJECT_URL`), what it is
listening on, issued and revoked counts, the validity range, the SAN cap, all three entries of `signing.CERT_PROFILE_HELP` (§7),
the page list, and a "what this CA does not do (yet)" block. Through 0.6.0 that block named the absence of a published CRL and OCSP; from 0.7.0 it names what revocation still
cannot do — **revocation reaches only clients that go looking for it** (§14, §15) — next to the absence of accounts, of delete
and of an API. A version number plus a source URL is what makes a problem reportable — that is why both are on their own page
rather than in a footer.

`/version` renders this same template with `version_banner=f"mypki {__version__}"`. 0.1.0's `templates/home.html` was deleted
rather than kept beside it: the same sentences in two files are two documents that drift. The harness contract is unchanged —
`/version` answers 200 HTML containing `mypki <version>`.

### `GET` + `POST /settings`

**Editable as of 0.3.0**, read-only in 0.2.0, and **hot as of 0.4.0**. The reasoning that made it read-only — no accounts, so nobody
should change a limit from a browser — is kept by changing what the page may write rather than by refusing to write: every value is
validated against `config.py`'s own rules **before** the file is touched, `secret_key` and both `ssl_*` paths stay masked *and*
non-editable, and the save goes to a file that startup reads **below** real environment variables and CLI flags.

**As of 0.4.0 there is no resolved-state table.** 0.2.0 and 0.3.0 rendered one row per `Settings.model_fields` entry (**Knob · Value ·
Source · What it does**) below the form, built by iterating the model rather than from a hand-written table. That table restated
twenty-odd values a reader could already see in the inputs, and its `Source` column named a layer no process can identify (below), so
most of its rows were decoration while one column overclaimed. `app._settings_rows` is deleted; what each column did now lives where it
can be acted on:

* **Value** → the input's own `value=`, which shows what **this process** resolved rather than what the file says, so a Save cannot
  silently undo an operator's shell variable;
* **What it does** → the hint line under that input, from `config.py`'s `Field(description=…)`;
* **Source** → one row of the status panel, `Data directory came from`: the only provenance whose answer changes what you do next (a
  shell variable beating your saved file). `_settings_source` survived the table it used to fill for exactly this row, and reports `set
  by a mypki serve flag` when `app.state.cli_overrides` says the value arrived that way — 0.3.0 could only hint at that, because the
  flags were folded into `Settings` and then forgotten;
* **the masked-knob flags** → the 'Not editable here' card (`app._unmanaged_card`), which now states what each unmanaged knob currently
  *is*: `secret_key` as *set (value not displayed)* — or *unset — mypki generated one into the data dir at startup* — both `ssl_*` as
  *set (path not displayed)* or *not set — plain HTTP*, and `config_dir` as the directory this page's own file lives in. Presence,
  never value, and never a key path.

The Storage section's **status panel** (`app._settings_status`, five rows) shows the **resolved** data directory, the resolved log file
(or *console only — `MYPKI_LOG_FILE` is empty*), whether this is TLS or plain HTTP, the file Save writes, and the provenance row above.
The consequence for the leak tests: they assert the absence of the **resolved** `paths.ca_key_path(data_root)` /
`paths.secret_key_path(data_root)` strings, not of bare filenames — two `config.py` descriptions legitimately name
`<data>/ca/ca_key.pem` and `<data>/instance/secret_key` to explain what mypki does *not* touch, and those descriptions still render as
hint text on this page.

**Precedence is stated in a note under that panel**, not in a column, and the same breath states its own limit: the order is a real
environment variable, then `mypki serve` flags, then `<config>/mypki.env`, then `./.env`. Where a value *came from* has exactly three
labels — `mypki default`, `supplied by the operator`, or *mypki default (passed through explicitly)*, the last when a value equal to
mypki's own default arrived through an explicit route (a CLI merge, or a constructor), which is worth separating from "nobody said
anything". A value from a `.env` file, one from a shell variable and one from a command-line flag are **indistinguishable here**:
pydantic-settings resolves that precedence internally and keeps no record of which layer won. Stating the limit is the honest answer;
naming a layer this process cannot name would be a guess printed as a fact. The note renders on a plain GET, because the reader who
never pressed Save is the one most likely to be puzzled by "I saved it and nothing changed".

**Live versus startup-only is marked per knob.** `app.STARTUP_ONLY_KNOBS` is four names — `host`, `port`, `session_max_age`,
`data_dir` — each rendered with a rose *active only after reboot* marker, every other control with a green *applied now*. 0.3.0 listed
the five logging knobs as startup-only because it had no way to re-run `logsetup.configure_logging`; that is why the set used to be nine
deep and is four. Telling an operator to reboot a working service for a knob that *is* live is worse than the ambiguity the list was
written to remove.

**As of 0.5.0 those four boxes show the file's value rather than the live one**, whenever the two differ (`app._knob_input`'s
`saved_values`/`live_display` arguments, `app._pending_saved_value`, `settings.html`'s `pending_saved` macro, `style.css`'s
`.pending-saved`). Beside the box a rose sentence names what is still running — *"this process is still running MYPKI_PORT as 8443; the
saved value goes live at the next start."* Four rules keep that marker from becoming wallpaper (`_pending_saved_value`, applied in order):
not a startup-only knob → no marker, because every other knob really was re-read and a marker there would lie; a rejected or unadopted save
(`overrides`) → no marker, because the amber block above already says in words what happened to that submission and the box is showing what
was typed; nothing ever saved for that knob → no marker, because an empty box reads as "the operator cleared it"; saved equals live → no
marker, because a rose line on every startup-only box trains an operator to ignore the one that means something. The comparison is
**textual** (`8543` against `8543`) — bounds belong to `settingsfile.validate_candidate`, not to a render helper. `_publish_saved_settings`'
re-pinning of `STARTUP_ONLY_KNOBS` is unchanged, so no page claims a bind that has not happened. Before 0.5.0 these four boxes showed the
live value, which was defensible — the box then matched the bind — but it made a save look like it had done nothing, and the operator's own
report was "I typed 8444, the box still says 8443".

### `POST /settings` — what a save writes, and what it refuses

`<config-dir>/mypki.env` (`$XDG_CONFIG_HOME/mypki/mypki.env`, `%APPDATA%\mypki\mypki.env`), written by
`settingsfile.write_settings_file`: plain `KEY=VALUE` in the same `MYPKI_*` spelling as a shell variable, created `0600` on
POSIX, and read at startup by `config.get_settings()` through `_env_file=(".env", <config>/mypki.env)` — the **later** entry
wins (MEASURED on pydantic-settings 2.16.1; `Settings(env_file=…)` is swallowed by this model's `extra="ignore"`, which is why
the keyword is `_env_file`). A real environment variable beats both files and `mypki serve` flags beat the file: the page says so in
the note under the status panel, because "I saved it and nothing changed" otherwise reads as a broken page.

**A successful save is adopted by the running process** (`app._publish_saved_settings`, 0.4.0): after the write succeeds the app
rebuilds `Settings(_env_file=env_file_layers(previous), **{**overrides, **pinned})` — re-reading the file it just wrote, through the
same model validators `validate_candidate` already used — installs it as `app.state.settings`, and re-runs
`logsetup.configure_logging`. Rebuilding rather than patching is deliberate: patching fields in place skips the model validators that
keep `validity_default_days <= validity_max_days` true, and a live object violating its own model is worse than a save that needs a
reboot. The four startup-only knobs are **re-pinned** from the settings this process actually started with — load-bearing, because
without it a Save would put `port=8543` into `app.state` on a server still bound to 8443, and the page would then describe a port
nothing is listening on. If adoption raises, the save says so (`Saved to <file>, but this process could not adopt it (<exc>). The values
take effect at the next start.`) instead of claiming success; `tests/test_settings_save.py` reaches that branch by injecting a broken
`MYPKI_MAX_SANS`, which proves the message and the write-then-adopt ordering, not a concurrent hand-edit.

The config dir rather than `./.env`, because the working directory is whatever a supervisor happened to start the process from
— a settings file there moves with the service unit and lands in a web-served tree for anyone who runs `mypki serve` from a
checkout.

**Refusals, each named on the page:** out-of-range (the message quotes the bound read from the same `Ge`/`Le` objects pydantic
enforces); a contradiction between two knobs (`MYPKI_VALIDITY_DEFAULT_DAYS=400` against `…_MAX_DAYS=200`, which only a model
validator can see); an unknown `MYPKI_LOG_LEVEL` (checked through `logsetup.resolve_level`, the function that would otherwise
fail at startup an hour later); a value containing a newline; and a form that omitted a knob, which is refused rather than
answered with a partial file. A refused save writes **nothing** — asserted as a tree hash, not as "the port line still looks
right".

**Four answers for an empty text box**, each from measurement: `log_file` and the six subject defaults write an empty line
(`MYPKI_LOG_FILE=` reads back as `None`, which is what those fields document); `data_dir` and `public_base_url` write no line,
because MEASURED `MYPKI_DATA_DIR=` reads back as `PosixPath('.')`; `host`, `ca_cn` and `log_level` are refused, because an empty
line there survives into the running process (`MYPKI_HOST=` yields `''`, and `cli._is_loopback('')` is False).

**Not editable, each with its reason stated on the page** (`settingsfile.UNMANAGED_KEYS`): `secret_key` (a form would put a
session-signing secret in a POST body and a browser history), `ssl_certfile`/`ssl_keyfile` (paths to a *server* private key,
which this page already refuses to display), and `config_dir` (it is where this file lives, so the file cannot carry it). A line
an operator hand-wrote for any of them survives Save byte-for-byte. As of 0.4.0 this card also states each knob's current
**presence**, which is what the deleted table used to carry: `tests/test_views.py` asserts all four appear as `<code>MYPKI_*</code>`
and none as `name="MYPKI_*"`, so a card that grew an input fails as a decision rather than quietly becoming one.

### Static assets

`static/style.css` (one stylesheet — dark "strata" palette, left-sidebar layout), `static/logo.svg` and `static/favicon.svg`
(hand-written; no icon font, no third-party asset, no build step), and since 0.3.0 `static/app.js` (hand-written, no build
step, **required by no page**: copy-to-clipboard for PEM blocks — its success line is the single short `Copied to clipboard` as of
0.4.0, while its failure line stays verbose on purpose — the select-all box and live count on `/issued`, and a revoke confirmation
modal whose Confirm adds `confirm=1` to the same form the server-rendered confirmation block represents). 0.4.0 adds two more
enhancements, both degrading to the server-rendered control when scripting is off: `wireChoice`, which keeps a preset dropdown in step
with the authoritative number box (`select[data-mypki-select-for]`, and **no `name=` on any `<select>`** — only the input posts, so a
dropdown can never submit a value the server has not bounds-checked), and `wireCheckboxState`, which recolours the *on*/*off* word
beside `MYPKI_LOG_TO_CONSOLE`. Served
from the `StaticFiles` mount registered **last** so it cannot shadow a page route, and reached through `url_for('static', …)`
so a reverse proxy's sub-path is honoured.

0.5.0 adds no JavaScript and changes none: `/inspect` (§13) needs no script, and its copy button reuses the `data-mypki-copy`
wiring `app.js` has carried since 0.3.0. Two stylesheet rules are new — `.pending-saved` (the rose sentence beside a restart-only box,
above) and `.findings`/`.finding`, which reuse the palette's existing `--amber` rather than introducing a colour or borrowing
`.form-errors`. **0.5.2 adds no JavaScript either, and again no colour — only width**: `form.inspect-form { max-width: none; }` and
`#pem_paste { width: 100%; max-width: none; }`, scoped to `/inspect` by a class that exists for no other purpose (§13). No selector is shared with
`/settings` or with the CSR forms, which is the point of scoping it that way. The nav is **seven links** (`base.html`: Sign CSR · Generate CSR · CA certificate · Issued · About · Inspect PEM ·
Settings, still plain markup) and `tests/test_nav.py` now asserts that list, its measured order, and exactly one lit item per page — a
fact nothing asserted before a seventh link existed.

**The consequence of all of the above:** this app ships no inline styles and no JavaScript that a page depends on, so CSP stays
`default-src 'self'` with no `unsafe-inline` — `app.js` arrives through `<script src>`, which `default-src 'self'` already
permits, and the two CSP strings in `app.py` are unchanged for that reason. Anything that would otherwise be interactive is
still server-rendered: profile help is shown for all three profiles at once rather than toggled on selection; the issued list
truncates in the cell and carries the full value in `title=`; every form error re-renders from the server (§3's two error
surfaces); and `/issued`'s confirmation step is a block at the top of the page, so the flow works with scripting off. That is
also why this is not BUILD_BRIEF's excluded "JavaScript frontend" — no client-side rendering layer, no framework, no build
step; remove `app.js` and every page here still does its job.

---

## §13 Inspect PEM — `GET` + `POST /inspect` (`inspect.py`, 0.5.0)

**One field, one button, nothing refused.** `pem_paste` is the only control on the page. `app.inspect_submit` runs `require_csrf` first —
as on every POST in this app, even though this handler writes, signs and stores nothing, because a POST that skips the check is one missing
line away from being the template for a POST that does — then **one call** to `inspect.describe_pem(paste, settings.max_csr_chars)`, then
`render_inspect`. There is no `try` in the handler, and the absence of a `try` is the feature: on `/csr/sign` a bad PEM raises and lands on
mypki's error page at 400/403/413, which is right for a request about to be signed. Here an expired, SHA-1-signed, RSA-1024, self-signed
certificate is exactly what the operator came to look at, and it gets the same full table a healthy one gets.

**Why a second PEM reader exists.** `csr.parse_and_validate_csr` already parses a PEM, but it parses it **in order to sign it**, and that
order *is* a policy — PEM → DER → signature → hash policy → key policy → extension classification (refused raises, ignorable is only
counted) → SANs. An operator who is
diagnosing ("is this the expired one?", "is this the root or the leaf?", "why does my client reject this?") needs the opposite posture, so
nothing in `inspect.py` raises on content: every finding becomes a sentence on the page. That is also why it does **not** call
`ca.describe_ca` or `keys.describe_public_key`, MEASURED on this build — both end in `key_spec_for_public_key`, which raises `KeyPolicyError`
for anything mypki would not issue (`RSA-1024 is not an accepted key. Allowed: RSA 2048, RSA 3072, RSA 4096.`; `Ed25519PublicKey is not an
accepted key`). A function whose whole promise is *never refuse* cannot start by calling a policy gate, so `inspect.py` reads the public facts
straight off the object (`subject`, `serial_number`, `not_valid_*_utc`, `extensions`) and reuses only `ca.fingerprint_hex`, which performs no
policy. Key labels are built here from what `cryptography` reports (`key_size`, `curve.name`, the class name), and the *policy* question is
asked separately, in a branch that turns the refusal into a sentence.

**The one thing it refuses.** `describe_pem(paste, max_chars)` raises exactly `RequestTooLargeError(len(text), max_chars,
"MYPKI_MAX_CSR_CHARS")`, **before any parser runs** and even when a valid certificate sits inside the oversized paste. The route's body cap is
`max_csr_chars + 8192`, which is what makes the answer mypki's sentence (413, *Input is 40,001 characters; the limit is 32,000
(`MYPKI_MAX_CSR_CHARS`)*) rather than starlette's bare JSON `Field exceeded maximum size of 1024KB.` — the same reason `max_csr_chars` exists at
all (§11). Everything else becomes a report.

**How many blocks.** `MAX_BLOCKS_TO_TRY = 8`. One is what an operator pastes; two is what happens when a leaf and its root got copied
together, and the honest answer to that is "you pasted N blocks, here is each of them" rather than the sign page's "I will not guess which" —
that refusal exists because *signing* the wrong one is destructive, while describing both is the whole point here. The cap exists so a paste of
a hundred blocks cannot make the page render a hundred tables (`MYPKI_MAX_CSR_CHARS` already bounds the bytes). Surplus blocks are **counted
and named**, never silently dropped: an extra report of kind `not described`, with an `Input` fact reading *N further block(s) in the same paste
were not parsed* and a flag reading *N block(s) beyond the first 8: paste fewer at a time*. Both numbers are passed into the template
(`max_csr_chars`, `max_blocks`) so the hint on screen states the limits this process actually applies.

**Kinds.** `certificate` · `certificate request` · `private key` · `unreadable` (armour known, body not base64 or not DER) · `unrecognised`
(armour unknown — `-----BEGIN TRUSTED CERTIFICATE-----`, a GPG block, a truncated header: report the armour line and stop there) · `nothing
readable` (a paste with no armour at all, carrying the finding *nothing to report — paste a certificate or a request between its BEGIN and END
lines*) · `not described` (the surplus-block report above).

**The facts table.** `PemReport.facts` is a list of `(label, value)` pairs rather than a dict so the page renders them in an order this module
chose — what it is → whose it is → whose signature is on it → when it is valid — rather than by insertion accident. For a certificate: `Type`
(`CA certificate` / `end-entity certificate`, from its own `BasicConstraints`), `Subject`, `Issuer`, `Subject Alternative Names`, `Validity
(UTC)`, `Serial (hex)`, `SHA-256 fingerprint`, `Signature algorithm`, `Public key`, `BasicConstraints`, then the rows that appear only when the
document carries them (`Common name`, `Organisation`, *Can sign other certificates: yes — this document claims to be a CA*, *Self-issued:
subject and issuer are identical*), and finally **SHA-256 of the DER** whenever bytes were decoded. For a request, the rows it cannot have are
rendered as those rows with the reason in them: *Validity (UTC): none — a CA sets the validity dates when it signs*, *Serial (hex): none — a CA
assigns the serial when it signs*, *Issuer: none — a request names no issuer; this is not a signature check, it is what PKCS#10 carries*,
*SHA-256 fingerprint: not available — `cryptography` gives a request no `.fingerprint()` (MEASURED)*, plus *Signature verifies against its own
key: yes/no*. `PemReport.summary` is the log line and carries kind, armour, counts and flags only — never a PEM body or a base64 fragment (§0's
rule about logs).

**Findings are descriptions, not gates.** They render as `<ul class="findings">` / `<li class="finding">` in `--amber`, deliberately **not**
`.form-errors`, which promises *nothing was written, fix this and submit again* — a promise this page has no authority to make. The rules that
refuse stay on `/csr/sign`. Each finding is worded as a fact about the document rather than a verdict on it: expired with a day count computed
from the certificate (*expired 37 day(s) ago — no client should still trust this one*); not-yet-valid with its start date; `not a CA` only when
the certificate genuinely lacks `CA:TRUE`; *self-signed root — nothing above this document can vouch for it; trust is installed out of band*;
*signed with SHA-1 — mypki refuses to issue certificates signed this way*; a weak key carrying the policy sentence plus the admission *mypki
would not issue for this key, but it is reported here as it stands*; Ed25519's hash row reading `NOT MODELLED`; SAN entries mypki would not
issue named in their own row; *this request asks to be a CA — `mypki` signs end-entity certificates only, so `/csr/sign` would refuse it*; and
*signature does not verify — the request was tampered with or truncated while pasting*.

**What the page says about itself, in four sentences at the top.** *It does not verify a chain* — no trust store on this host and no issuer
certificate to check against, so it can name an issuer but cannot say anybody trusts it, and the only CA-shaped fact available is the one inside
the document. *It does not know about revocation* — from 0.7.0 this host **has** a published CRL (§14) and an OCSP responder (§15), but `describe_pem`
consults neither, has no trust store and cannot reach any other CA's artifacts, so a certificate reported valid here may have been revoked by
whoever issued it; `/issued`'s Status column has the same limit.
 *Its findings are not gates*. *A private key is named and
not opened*. SMOKE_TESTING §15 asserts all four sentences still appear on the rendered page, because a reader who assumed otherwise would be
misled by a page that looks like a verifier.

**Private keys are named, never opened.** `redact_private_key_bodies(paste)` returns the paste with each key **body** replaced by
`KEY_BODY_REDACTED`, plus a count; the armour lines stay, so the operator can see *which* block was redacted. Recognition is by armour only
(`KEY_KINDS`, plus any kind ending `PRIVATE KEY`), so an encrypted key is never prompted for and there is no `load_pem_private_key` call anywhere
in this module — no decrypt attempt, no parse, nothing from the block rendered back. The report for such a block carries `Type: private key (…)`
and `Body: not read`, **no PEM and no `sha256_of_der`** — a fingerprint for bytes the page says it never opened would contradict it.
Certificates in the same paste survive byte-identical, and the count is stated out loud above the echo (*N private-key block(s) were in your
paste*), because a page that quietly rewrites what you pasted with nothing on screen admitting it is unreadable in exactly the way a settings
page that silently dropped a line would be (`settingsfile.preserve_unmanaged`, same reasoning).

**The echo.** `render_inspect` always passes `paste` back, so the text just described stays on screen under the description — not recovery from
a mistake (there is nothing to fix) but what lets a reader line up a finding against the bytes it describes. A GET fabricates nothing: no report,
no facts table, asserted as **zero** `<th scope="row">` occurrences in §15 — the same rule `settings_page` follows by refusing to pass
`just_saved` on a GET. And because `/inspect` describes the text in the box rather than this server's state, the page works on a host with **no
CA** at all.

**Re-armouring is why byte parity is assertable.** Each parsed block is re-emitted from the bytes that were decoded, so `id="pem-1"` on
`/inspect` and `GET /ca/certificate` are two renderings of one certificate (§4; `/ca` stopped rendering a third of its own in 0.7.1). §15's parity assertion is scoped to
`<pre class="pem" id="pem-1">…</pre>` for a reason learned by running the harness: the textarea's **placeholder** spells out
`-----BEGIN CERTIFICATE-----&#10;MIID...&#10;-----END CERTIFICATE-----`, so the first armour pair on that page is an example rather than the
parsed block. Unscoped, the comparison hashed placeholder text and reported a mismatch against a correct app.

**The paste box spans its section (0.5.2).** `inspect.html` posts through `<form class="settings-form stacked inspect-form">`: the first two
classes are what 0.5.0 borrowed from `/settings` to get the uppercase label band and the hint styling, and the third exists **only** so the width
rules below can be scoped to this page. `form.stacked` caps every stacked form at `max-width: 46rem`, and `.settings-form .field input` widens
inputs to 34rem with no `textarea` equivalent — the generic `input, textarea, select` rule supplies `max-width: 100%` but never a `width`, so a
`<textarea rows="14">` fell back to the browser's own default (~21rem) between two full-width `.card` sections above a 46rem button. That is the
mismatch an operator reported. `form.inspect-form { max-width: none; }` lifts the cap for this one form and `#pem_paste { width: 100%; max-width:
none; }` makes the box span what the cards above it span, with the Inspect button following it rather than sitting half-width underneath. Two
things are deliberately **not** widened: `.settings-form` itself (its fields on `/settings` are inputs, and widening it would widen every settings
field), and the request textarea on `/csr/sign` (`csr_pem`), which stays a 46rem-capped plain `stacked` form — that box carries a request about to be
signed, and its width is part of how the sign page reads. `/csr/generate` joined this list from the other side in 0.7.1: it posts through
`form.settings-form.stacked.generate-form`, whose cap is lifted to `main`'s own 78rem because its Subject grid carries six fields side by side and a
46rem ceiling drops each one under its own label. Its `sans` textarea widens with it; `csr_pem` does not. `box-sizing: border-box` has been global since
0.1.0, so `width: 100%` on a textarea needs no padding arithmetic. Nothing here can show what this looks like: no browser exists on the host these
notes were written on, so SMOKE_TESTING §2 asserts only that **the served stylesheet carries the three rules**.

**Nav.** The seventh link (`base.html`, between About and Settings) is plain markup with an inline SVG icon, and `app.js` gained nothing for it
beyond the copy button it already provided. `tests/test_nav.py` exists because a route can be registered, render perfectly, and still be
unfindable: `base.html` decides which item is `.active` by comparing `request.url.path` against a literal written in the template.

---

## §14 CRL — `GET /crl` (page) + `GET /crl.pem` (artifact) + `POST /crl/rebuild` (`crl.py`, 0.7.0)

**One artifact, one name, rebuilt rather than appended.** `<data>/crl/mypki.crl.pem` is the only revocation file this host writes
(`paths.crl_dir()` / `paths.crl_path()`, §8). One fixed filename on purpose: the URL certificates carry is spelled by `app.py` from
`crl_base_url` (§11), and a name an operator could configure would be a second spelling of one location. Rebuilt, never appended — a
CRL is a signed statement about a set, not a journal.

A **page** as well as an artifact because the honest limits of a home-lab CRL need somewhere to be written down, and `/crl` is where
they are: four measured caveats (§below) plus the `id-kp-OCSPSigning` paragraph §15 shares. `/crl` reads its facts **from the file on
disk** (`_published_crl` → `crl.read_crl_pem` → `summarise_crl`), so it cannot describe a CRL that `GET /crl.pem` does not serve —
the same "one implementation instead of two that drift" rule §1 states for the home page.

### The artifact's shape (what `crl.py` decides, and nothing else)

| Field | Value | Why |
| --- | --- | --- |
| Issuer | exactly `bundle.cert.subject` | same rule as §7's leaves: a CRL that disagrees with its own CA certificate is unfalsifiable |
| thisUpdate | now (aware UTC; a naive value is converted, not rejected) | the same conversion `store._iso` and `ocsp_responder.py` apply, so two clients in two zones cannot disagree about freshness |
| nextUpdate | thisUpdate + **24 h** (`crl.CRL_LIFETIME`) | a module constant, deliberately not a knob (§11) |
| Entries | `store.revoked_records()`: stamped **and** `not_after_utc > now` | answer 8. Historical stamps (0.2.0–0.6.0 rows) are included; a revoked certificate past its own validity is **dropped** |
| Entry revocationDate | the original `revoked_at_utc`, never "now" | the same principle `store.revoke()` protects by refusing to move an existing stamp; DER spells it as UTCTime, so it reads back whole-second (§15's rule applies here too) |
| Entry reason | **absent** | RFC 5280 §5.3.1 defines an absent code as `unspecified`. `revocation_reason` in the DB is operator prose; encoding a code invented from prose would be a claim this CA cannot support (§15 answers the same way) |
| CRLNumber | `store.count_revoked()` — **never** `len(entries)` | entries can shrink (the drop rule), and RFC 5280 §5.2.1 requires monotonicity. `count_revoked()` counts stamps, and this store has no DELETE (§5), so the number can only hold or grow. Asserted across a rebuild that *removed* an entry |
| AuthorityKeyIdentifier | `from_issuer_public_key(CA public key)`, non-critical | carries the one `# type: ignore[arg-type]` precedent already at `signing.py` — cryptography types the argument narrower than `Certificate.public_key()` returns |

**No `IssuingDistributionPoint`, and no `DeltaCRLIndicator`.** The reason is measured, not stylistic, and it is written on `/crl` in
openssl's own words so nobody re-adds one "for completeness": against a CRL carrying
`IDP(full_name=http://mypki.my.lab/crl.pem, only_contains_user_certs=True, critical)`, `openssl verify -crl_check` answers
**`error 44 at 0 depth lookup: different CRL scope`** (rc=2) for a **perfectly valid leaf that carries no CDP at all** — i.e. every
certificate this CA issued before 0.7.0, plus anything minted elsewhere against it. The plain CRL verifies `OK` (rc=0). An IDP would make
`-crl_check` unusable on this CA's own history. Both absences are asserted in `tests/test_crl.py`, so they are checked facts rather than
the absence of code.

### Three triggers, one function

`crl.rebuild_crl()` is called from **startup** (a CA + key host publishes a valid zero-entry CRL before anyone revokes anything), from
`_publish_after_revoke` after a stamping batch that actually stamped something, and from the GUI **Rebuild** button. One function for all
three because three call sites each assembling their own builder are three chances to disagree about the entry rule or the number. A
keyless host raises `CaNotFoundError` — the same 503 `/ca/certificate` already answers, because "this host cannot sign a CRL" and "this
host has no CA" are one answer to the person holding a URL. Writing is atomic (same-directory temp file + `os.replace`, mode set before the
name exists) because a half-written CRL is worse than an old one: a client that fetches a truncated PEM cannot tell whether the CA revoked
something or the disk lied mid-write. Mode 0644 rather than `PRIVATE_FILE_MODE` — this file is served to anyone, so owner-only mode would
protect nothing and break a fetch proxy running as its own account.

### The routes

| Route | Shape |
| --- | --- |
| `GET /crl` | HTML: facts card (issuer, thisUpdate, nextUpdate, stated freshness, CRLNumber, entry count, the advertised URL and the OCSP base), the copyable PEM block (`id="pem-crl"`, same pattern as §4's CA block), *Download mypki.crl.pem*, the Rebuild form, and the four caveats. No published file → a notice naming `startup CRL build failed`, not a 500. |
| `GET /crl.pem` | The artifact: `application/pkix-crl` (RFC 5280 §7.1 — deliberately **not** `application/x-pem-file`: whoever fetched `<base>/crl.pem` out of a certificate deserves to be told what arrived), `no-store`, `nosniff`, `Content-Disposition: attachment; filename="mypki.crl.pem"` (literal, never `_safe_stem` — there is no operator input to filter). No CSRF: it is a GET and publishes nothing new. |
| `POST /crl/rebuild` | `require_csrf` as the handler's **first statement**, then re-sign, then render `/crl` at 200 with `rebuilt=1` rather than a 303: this app has no flash store, and a redirect would either re-sign a second time or render the same card without saying it had moved. The page says in the same breath as the button that **a rebuild is a re-sign of the same data** — nothing here revokes anything — because "Rebuild" on a revocation page reads to a nervous operator like "make my revocations take effect". A refused token costs no signature and no bytes (`tests/test_crl.py` compares the file byte-for-byte). |

### The four caveats `/crl` states, in order

1. **No IDP, on purpose** — `error 44 … different CRL scope`, as measured above.
2. **Certificates issued before 0.7.0 carry no pointer.** The CDP is added at signing time; a leaf minted in 0.2.0–0.6.0 says nothing about
   this file and mypki cannot edit it afterwards. No migration, no re-issue (answer 6). Those certificates are still checkable by handing the
   artifact to a client explicitly (`openssl verify -crl_check … -CRLfile mypki.crl.pem`).
3. **openssl never fetches a CDP.** Measured: with the CRL served live on a port and a leaf carrying exactly the right URL,
   `openssl verify -crl_check` answered **`error 3 at 0 depth lookup: unable to get certificate CRL`** (rc=2) and no GET appeared in this
   server's access log. A baked pointer exists for clients that *do* fetch (browsers, Go, curl-based tooling). For openssl you pass
   `-CRLfile`, which is what the e2e harness's §11 STEP F does.
4. **A revoked certificate that has already expired drops out of the CRL and answers UNKNOWN (§15).** The row stays in `issued.db` forever:
   there is no un-revoke and no delete. "Removed from the CRL" reads to a human like "un-revoked", which is why the sentence is on the page
   rather than only in this file.

**Discoverability:** `/crl` is linked from `/issued`'s footer and confirmation note (§5) and from `/ca`; the nav stays seven links (§12, U2).

---

## §15 OCSP — `POST /ocsp` (`ocsp_responder.py`, 0.7.0)

**The one route in this app where an error is a body rather than a status.** RFC 6960 §4.2 puts `OCSPResponseStatus` *inside* the response,
and a client library reads that field, not the status line. So `/ocsp` answers **HTTP 200 + DER** for a malformed request
(`30 03 0a 01 01`, MALFORMED_REQUEST) and for a host that cannot sign one (`30 03 0a 01 02`, INTERNAL_ERROR), each exactly 5 bytes. mypki's
house rule — every rejection gets mypki's own HTML page (§0) — is deliberately suspended here: HTML where a client expects DER is
indistinguishable from a broken responder. `/crl.pem` answers 503 for the same missing state and the difference is a decision rather than an
inconsistency — whoever fetches a CRL is a human's tool that benefits from mypki's hint, while an OCSP client is a library that can read only
DER.

**The CSRF exception (the §0 row).** `POST /ocsp` carries no token and calls no `require_csrf`, and this is the *only* POST in the app that
does not. A CSRF defence protects a session by requiring a token that only a page this host rendered could carry; an OCSP request is a
machine-to-machine DER body from a client that has never seen mypki's HTML and holds no cookie. Demanding a token would break every real
client while protecting nothing: there is no session state for a cross-site submit to abuse, and the handler signs **what its own store says
about a serial** — the same fact `GET /crl.pem` publishes. What makes that defensible rather than a hole is asserted in `tests/test_ocsp.py`:
a form-shaped POST (`serial_hex=…&confirm=1`) gets the 5-byte DER refusal and leaves `store.count()` unchanged, and an oversized body mints no
signature at all.

**The other §0 exception: `GET /ocsp` answers FastAPI's 405 JSON.** RFC 6960 §4.1 makes OCSP a POST; a GET carries no request body to answer,
and inventing a DER response for it would mean signing a statement about a serial nobody named. FastAPI's own 405 is left undressed-up rather
than routed into mypki's error page: whoever GETs this URL has a bug in their client recipe, not a missing feature. It is tested so the
deviation is a named one (`test_get_on_the_ocsp_route_is_not_an_ocsp_request`), and it is why `/ocsp` must **not** join `tests/test_packaging.py`'s
GET-every-page sweep — that sweep asserts 200 + `<!DOCTYPE html>`, which is exactly what this route does not do.

### The handler's four answers, in order

| Body | Answer | Notes |
| --- | --- | --- |
| over **8192 B** (`OCSP_MAX_REQUEST_BYTES`) | 200 + `30 03 0a 01 01` | Cap checked **before parsing and before anything is signed**: a hostile body cannot be turned into free signatures. Real OCSP requests are 73–101 B (MEASURED), so this is about malformed abuse, not traffic |
| unparseable DER | 200 + `30 03 0a 01 01` | `parse_ocsp_request()` folds **every** exception into `None` rather than raising — a raised error would reach mypki's handler and render HTML, the one artifact a client cannot read |
| no CA, or a CA whose key is not loaded | 200 + `30 03 0a 01 02` | INTERNAL_ERROR at 200, deliberately not 503. Writes nothing: neither state creates `<data>/crl/` (§14's startup rule) |
| a parsed request | 200 + signed DER: GOOD / REVOKED / UNKNOWN | `store.find(serial_hex_of(req))` → `answer_for()` → `render_ocsp_response()`. A builder `ValueError`/`TypeError` becomes INTERNAL_ERROR, with the reason reaching the log rather than the wire |

And one boundary that is **not** this handler's: a body over `SizeGuardMiddleware`'s limit (`max_csr_chars + 8192` = **40,192** with the
default knob) gets **mypki's HTML 413** naming `MYPKI_MAX_CSR_CHARS`, for a declared `Content-Length` and for a chunked body alike
(MEASURED, plan §2/P-OCSP-3). The guard is left unmodified and `/ocsp` is **not** exempted; the handler's cap sits far below it precisely so
that the DER answer arrives first. No legitimate OCSP request can reach that size, so what reaches the 413 is malformed traffic — which is why
this is documented rather than turned into an OCSP-specific knob.

### The decision table (U5)

| Store state | Answer | Why this answer and not the other |
| --- | --- | --- |
| no record with that serial | **UNKNOWN** | GOOD would assert something about a certificate this CA knows nothing about; REVOKED would invent a decision nobody made |
| stamped revoked, still inside its validity | **REVOKED**, `revocationTime` = the original stamp | A client reading both an OCSP answer and a CRL entry must be shown one time, not two. `revocation_time_utc` is the non-deprecated spelling |
| stamped revoked, past its own `notAfter` | **UNKNOWN** | §14's drop rule removed it from the CRL while the row remains in `issued.db`; GOOD would be this host disagreeing with its own artifact. This is the one place where "not in the CRL" and "still revoked" meet, and UNKNOWN is the answer that claims neither |
| active (never stamped), past or inside its validity | **GOOD** | The only positive claim here, and it is a claim about this store: "I signed this and I have not stamped it." OCSP reports revocation standing, not whether a validator would accept an expired certificate today — which the log reason says out loud |

`ReasonFlags.unspecified`, always (U6): the DB's `revocation_reason` is prose capped at 120 characters, and mapping prose to
`keyCompromise` would be inventing a claim about a certificate this CA only has a note about. It matches §14, which writes no reason
extension at all.

### What every response carries

`add_response_by_hash` for **all four statuses** — mypki stores no certificate PEM (§5), so `add_response(cert=…)` has nothing to hand it;
by-hash is proven for GOOD/REVOKED/UNKNOWN and openssl verifies a by-hash response against its own CertID (`Response verify OK`). Both hashes
are echoed **verbatim** from the parsed request, together with the request's own `hash_algorithm` **instance** (a SHA-1 client is not silently
upgraded). `thisUpdate` = now, `nextUpdate` = +**4 h** (`OCSP_LIFETIME`, a constant — §11), shorter than the CRL's 24 h because an OCSP answer
is cheap to mint and a client that caches one should re-ask within a working day. `responder_id(NAME, ca.cert)` with `.certificates([ca.cert])`
— **the root signs its own answers** (U3): no delegated responder certificate, no CA re-issue (the root already carries `crlSign`). A request
nonce is echoed when present and no extension is added at all when it was not; mypki never invents a nonce, because a response nonce only means
something against a request one. Signed with the CA key, SHA-256 (`sha256WithRSAEncryption`). Response headers: `application/ocsp-response`,
`no-store`, `nosniff`, **no** `Content-Disposition` — this body is not a file an operator installs.

**R-OCSP-1, stated in the words the design commits to:** *the hashes are echoed, not verified; a foreign CertID yields UNKNOWN about a serial
this host does not hold.* `issuer_key_hash` cannot be recomputed for a SHA-256 request (every candidate form mismatched under measurement), so
echoing is not a choice between two good options — it is the only workable one. This responder therefore cannot prove that a request's CertID
describes *this* CA; only the SHA-1 form could be cross-checked, via the CA's SubjectKeyIdentifier, and even that is a coincidence of form
rather than a verification. Nobody can forge a signed answer — only mypki's key signs — but mypki must not claim it validated the CertID, and
`tests/test_ocsp.py` asserts the echo under both algorithms without claiming more than that.

**A second unmeasured-client risk stacks on top of it (U3):** RFC 6960 §4.2.2.2 (*Authorized Responders*) says a client MUST reject a
response whose signing certificate is not (1) a locally configured OCSP signing authority, (2) **the certificate of the CA that issued the
certificate in question**, or (3) a certificate carrying `id-kp-OCSPSigning` issued by that CA. mypki's responder answers under criterion 2 —
the root is its own responder — so the spec permits this design, and openssl 3.5 does accept it (MEASURED, on a root with no such EKU).
What is **not** measured here is whether a browser or a Go client insists on criterion 3 anyway; that caveat is stated in words on `/crl`,
in this file and in README rather than left as an open question. (An earlier draft of this section cited "RFC 6949 §3.6" for the EKU
requirement. RFC 6949 is the RFC Editor model, not OCSP; the citation was wrong and is corrected here rather than carried
forward.) A delegated responder would mean issuing, storing and rotating a second key for a home-lab CA — accepted as larger
than the unmeasured risk.

**No cache (deliberate).** Plan §7 floated caching signed answers per (serial, status) until `nextUpdate` to blunt the fact that this is a
signing oracle reachable over HTTP, one signature per request (§12's standing-risk list names it). It is not implemented: a cache keyed on a
*request-supplied* CertID hash pair stores signatures produced for hashes this responder did not verify — which R-OCSP-1 makes worse rather
than better — and the store lookup plus an RSA-3072 signature is milliseconds on a host whose OCSP traffic is a handful of clients. The
exposure is stated instead of being half-mitigated by something nobody measured.

**Why DER, when mypki emits PEM everywhere else:** because the client at this URL is a library following RFC 6960 §4.1, not a human pasting a
block into a form. `/crl.pem` stays PEM-only (§14) and there is deliberately no `/crl.der`: two DER spellings of one artifact would be the
drift case §1 exists to prevent.
