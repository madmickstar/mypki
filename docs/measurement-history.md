# Measurement history

Dated records of what mypki's harnesses, coverage runs and label comparisons actually measured, moved verbatim out
of `SMOKE_TESTING.md` when that file was split. **Append-only.** A measurement here is a record of one run: it is
never restated, re-derived or reconciled against a newer build, because rewriting an old number invents a run
nobody performed.

Current-run numbers are not here - they are generated into `reports/harness-ledger.md` by `tools/harness_ledger.py`.

- **288 / 0 / 0** (exit 0) is the green baseline for **this build on Linux**, re-measured 2026-11-03 after the sign-page
  refusal change, against a tree that also still carries §11's STEP F block. Two runs, each against its own freshly minted
  data dir (`/tmp/pkismoke-071sh`, `.sh` served on `http://127.0.0.1:8631`; `/tmp/pkismoke-071ps1`, `.ps1` served on
  `:8633` under `/tmp/pwsh/pwsh` 7.6.9; runners `/tmp/run071_sh.sh` and `/tmp/run071_ps1.sh`): plain `init-ca` (default CN,
  RSA 3072), `HOME` plus `XDG_CONFIG_HOME`/`XDG_CACHE_HOME`/`XDG_STATE_HOME`/`XDG_DATA_HOME` redirected into the scratch
  tree and `MYPKI_DATA_DIR` pointing at it. This pair was given `--base` / `-Base` explicitly, where the 0.7.0 runs below
  handed the port through `MYPKI_PORT` instead — so these headers read `base resolved from: --base/BASE (explicit)` and
  `-Base (explicit)`, and §3 still PASSes "the running app reports version 0.7.0" (`__version__` is unmoved). Both logs are
  **307** lines with the summary at **306**, and both print the sixteen headings at the same line numbers — **1 / 10 / 31 /
  33 / 37 / 47 / 60 / 67 / 70 / 88 / 105 / 182 / 217 / 228 / 238 / 274** (§1 gained a line, §7 four, and every later heading
  shifts with them). Per-section, identical in both logs: §1 **8** · §2 20 · §3 1 · §4 3 · §5 9 · §6 12 · §7 **6** ·
  §8 2 · §9 17 · §10 16 · **§11 76** · **§12 34** · §13 10 · §14 9 · §15 35 · §16 30 = **288**. Against the shipped
  0.7.0's 283 the whole **+5** is accounted for: **+4 in §7** (the `.form-errors.refused` block is present, its line/offset
  precedes `Paste a CSR (PEM)`, the rejected paste is echoed back into its own textarea, and no confirmation panel was
  rendered) and **+1 in §1** (`/`'s new *"CSR requesting CA powers will be refused."* sentence; the renamed-heading
  assertion replaced a needle rather than adding one). Against 0.6.0's 246 that is +42, and no other section moved.

- **The shipped zip was extracted and both harnesses re-run from it: 283 / 0 / 0, exit 0 — three times now, twice on
  2026-11-03.** Measured
  from `/tmp/extract-070/mypki-0.7.0` (unzipped from `mypki-0.7.0.zip`, 79 entries = 68 files + 11 dir entries). The first
  pair used `/tmp/s11b/run_harness_x070.sh` — a copy of `/tmp/s11b/run_harness.sh` retargeted at the extracted tree: `.sh`
  on `http://127.0.0.1:8621` (`/tmp/pkismoke-070x-sh`), `.ps1` on `:8623` (`/tmp/pkismoke-070x-ps1`). The second pair is
  the **control run for this build's +5** (`/tmp/run071_control.sh`, `/tmp/pkismoke-071c-sh` on `:8651`,
  `/tmp/pkismoke-071c-ps1` on `:8653`), because the paragraph above now describes a tree that is *not* the zip. Same
  documented arrangement otherwise — plain `init-ca` (CN=mypki Root CA, RSA 3072), `HOME` plus the four `XDG_*` redirected
  into each scratch tree, `MYPKI_CONFIG_DIR`/`APPDATA` unset, `PYTHONPATH` pinned to `<extract>/src`, server cwd there.
  Both logs of both pairs are **302** lines with the summary at **301**, both print the sixteen headings at **1 / 9 / 30 /
  32 / 36 / 46 / 59 / 62 / 65 / 83 / 100 / 177 / 212 / 223 / 233 / 269**, and both read §1 7 · §2 20 · §3 1 · §4 3 ·
  §5 9 · §6 12 · §7 2 · §8 2 · §9 17 · §10 16 · **§11 76** · **§12 34** · §13 10 · §14 9 · §15 35 · §16 30 = **283**
  — byte-for-byte the same ledger as the two `build/` runs of the 0.7.0 release, which is what made the zip a copy of the
  tested tree rather than a rebuild of it. Against **this** build's 288 the zip differs by exactly the +5 above and nothing
  else: `src/` in the two trees differs only in `app.py`, `static/style.css` and six templates. Each report header reads
  `base: http://127.0.0.1:<port>` with `base resolved from: host from defaults; port from the environment`, and §3 PASSes
  "the running app reports version 0.7.0" — asserted against the extracted `__init__.py`, not the checkout's.
  **The import was pinned, and that had to be checked rather than assumed:** this venv carries an editable install of
  `/home/user/mypki/build` plus a
  stale `mypki-0.1.0.dist-info`, so an extracted tree does not import itself by accident — both runs printed
  `0.7.0 /tmp/extract-070/mypki-0.7.0/src/mypki/__init__.py` before serving, because `PYTHONPATH` was set to
  `<extract>/src` first. The gate was run
  the same way against the extracted tree (same pinned `PYTHONPATH`): **782 tests / 0 skips, TOTAL 3008 statements / 97
  missed = 96.78%**,
  `mypy` clean over 19 source files, `ruff check` clean, `tools/check_version.py` exit 0 naming the extracted paths —
  identical to the `build/` gate.
  One measured side effect of "server cwd is `<extract>/src`": the serve process writes its log to
  `<extract>/src/logs/mypki.log`, which is why
  `src/logs/` is excluded from the shipped file list and why a fresh extraction stays clean.


- **246 / 0 / 0** (exit 0) was the green baseline for **the 0.6.0 build on Linux**, re-measured 2026-11-01 with §16
  present in both scripts and in the
  tree being served, **and re-measured again the same day after `__version__` became 0.6.0** — the four runs below are the post-bump ones, so §3's
  version assertion reads the released number rather than the pre-release one. Four runs, each on its own freshly minted copy of `build/` and its own
  data dir, none given `--base` / `-Base` (`/tmp/h060/tree-{shdef,ps1def,shwild,ps1wild}`, harnesses taken from the copied `scripts/`, servers started
  from the copied `src/` with `PYTHONPATH` pinned to it, each printing `server imports: … /src/mypki/__init__.py 0.6.0` before serving):
  `.sh` on `:8571` and `.ps1` on `:8583` under `/tmp/pwsh/pwsh` 7.6.9, both after a real `POST /settings` wrote the port; then the same two walks on
  trees where `/settings` had also written **`MYPKI_HOST=0.0.0.0`** (`:8591`, `:8601`). All four printed
  `== summary: 246 pass, 0 fail, 0 warn ==`, the sixteen headings at **1 / 9 / 30 / 32 / 36 / 46 / 59 / 62 / 65 / 83 / 100 / 141 / 175 / 186 / 196 /
  232** and the summary at **264** (265 lines total) — identical in all four logs, including the two wildcard-host runs, whose reports read
  `base: http://127.0.0.1:8591` with `base resolved from: … (host '0.0.0.0' is what mypki binds, not an address to dial: probing '127.0.0.1')`.
  A run that cannot reach the server exits 2 and prints nothing else; a wildcard host no longer produces one.

- **216 / 0 / 0** (exit 0) was the green baseline for the same tree **before §16 existed**, re-measured 2026-10-31 with both harnesses finding the server
  through mypki's own dotenv layers and **neither given `--base` / `-Base`**: `.sh` against a tree whose port had been *saved through
  `/settings`* (`/tmp/pkismoke-052a`, POST to `/settings` writing `MYPKI_PORT=8571` into `<config>/mypki.env`, then a restart — 8443 refused,
  8571 answered), `.ps1` against its own freshly minted tree with `MYPKI_HOST`/`MYPKI_PORT` written into `<config>/mypki.env` by hand
  (`/tmp/pkismoke-052b`, served on `:8583`) under `/tmp/pwsh/pwsh` 7.6.9. Both reports print `base resolved from:` naming the config file that
  won; both logs still begin at line 1 with `§1 Home page` and put their fifteen headings at **1 / 9 / 30 / 32 / 36 / 46 / 59 / 62 / 65 / 83 /
  100 / 141 / 175 / 186 / 196** with the summary at **233** (234 lines total) — identical in both logs, which is what proves the resolver added
  no preamble. §2 grew from 15 to 20 assertions (§13's width fix); nothing else moved.

- **The defect was reproduced before it was fixed**, on the same tree: `--base http://127.0.0.1:8443` against the server that was honestly
  answering on 8571/8583 is what an operator got before 0.5.2 — a harness aiming at a dead port, and (against a live-but-wrong-port server)
  §12's pending-sentence assertion failing for a value disagreement the harness itself invented. Pointing the harness at the wrong server does
  not merely fail to reach it; it makes the app look wrong.
_The heading line numbers below (… 25 / 27 / 31 … summary at 228) belong to the 0.5.0 and 0.5.1 logs, which had five fewer assertions in §2.
They are kept as recorded rather than restated: a line number is a measurement of one log, and rewriting an old one to match a new build is
how a document starts describing a run nobody performed._


- **211 / 0 / 0** (exit 0) was the green baseline for **the 0.5.0 build on Linux**: measured 2026-10-30 against a live server on
  `http://127.0.0.1:8451` with `MYPKI_DATA_DIR=/tmp/pkismoke-050b/data` freshly minted by a plain `init-ca` (default CN, RSA 3072), CA loaded,
  console-only logging, plain HTTP, and `HOME`/`XDG_*` redirected into that scratch tree. **The `.ps1` printed the identical summary on the
  same day against the same server** — under `/tmp/pwsh/pwsh` 7.6.9 on Linux — with the same fifteen headings and the same per-section counts.
  No Windows number is claimed for 0.5.0, because none has been measured here.

- **Re-run green on 2026-10-31 after the banner/`.env.example` wording change** (see CHANGELOG 0.5.0 *Changed*): a fresh CA at
  `/tmp/pkismoke-050e/data`, plain `init-ca` (default CN, RSA 3072), served on `http://127.0.0.1:8453`, then `.sh` RC=0 and `.ps1` RC=0 in sequence,
  both printing `== summary: 211 pass, 0 fail, 0 warn ==`. The two run logs even put their fifteen section headings at the same line numbers
  (1 / 9 / 25 / 27 / 31 / 41 / 54 / 57 / 60 / 78 / 95 / 136 / 170 / 181 / 191, summary at 228), so the per-section list below is unchanged by that edit —
  nothing in either harness asserts the banner text. A third walk on a second fresh tree (`/tmp/pkismoke-050f`, port 8454, `.sh` only) re-measured the
  documented ledger shape end to end: **4 records / 3 revoked / 1 active** in `issued_certs`.

- **Re-run green on 2026-10-31 for 0.5.1**, with **each harness given its own freshly minted CA and its own server** (the independent-ledger
  arrangement 0.5.0's run established): `.sh` against a plain `init-ca` tree at `/tmp/pkismoke-051d/data` served on `http://127.0.0.1:8464`,
  then `.ps1` against a separate tree at `/tmp/pkismoke-051e/data` on `http://127.0.0.1:8465` under `/tmp/pwsh/pwsh` 7.6.9. Both exit 0 and both
  print `== summary: 211 pass, 0 fail, 0 warn ==`, with the fifteen headings again at line numbers 1 / 9 / 25 / 27 / 31 / 41 / 54 / 57 / 60 /
  78 / 95 / 136 / 170 / 181 and the summary at 228 in **both** logs. §3 reads the expected version out of `src/mypki/__init__.py` and reported
  **0.5.1**, which is what distinguishes this run from a stale server on an older checkout. No Windows number is claimed, because none was measured here.

- Per-section counts from **the 0.6.0 build's** runs (they sum to 246, and all four of that build's runs above printed
  the same list). Kept as
  history — this build's own per-section list is in *Reading the result* (§1 8 · §7 6 · §11 76 · §12 34, summing 288): §1 7 · §2 **20**
  · §3 1 · §4 3 ·
  §5 9 · §6 12 · §7 2 · §8 2 · §9 17 · §10 16 · §11 40 · §12 33 · §13 10 · §14 9 · §15 35 · **§16 30**. The thirty added since 216 are §16 entire:
  fixtures ×2, step A ×3, the consent control's shape ×3, the no-box case ×2 (+1 WARN branch), the unticked refusal ×7, the ticked issue ×7,
  the serial ×1 and the privilege 403 ×7. **The pre-§16 build measured 216 with the same fifteen sections unchanged**, and that ledger stays
  recorded below as a measurement of those runs rather than being restated: §1 7 · §2 20 · §3 1 · §4 3 · §5 9 · §6 12 · §7 2 · §8 2 · §9 17 ·
  §10 16 · §11 40 · §12 33 · §13 10 · §14 9 · §15 35. The five added since 0.5.1's 211 are all in §2 and
  all belong to one fix — the four served-stylesheet rules of page-map §13 (three widened, one zero-count guard) plus `/inspect`'s form class.
  **0.5.0 and 0.5.1 measured 211 with §2 at 15**, and those numbers stay recorded above as measurements of those builds rather than being
  rewritten to match this one. Against 0.4.0's 163 the older growth is accounted for rather than
  mysterious: **+5 in §2** (the served stylesheet became an assertion target: 200, `text/css`, same CSP, `.pending-saved` defined, that rule
  reusing `--rose`), **+4 in §9** (`/ca`'s PEM block: its id, its copy button, one certificate inside it, and DER parity with the download),
  **+3 in §12** (the `/about` card-order assertion, the zero-pending-sentences assertion, and the four-boxes sentence), **+1 in §14** (`/inspect`
  joins the GET sweep) and **+35 in §15**. Nothing else moved.

- **Seven harness defects have been found by running this pair against a correct app, and every one was fixed in the
  harness rather than in the app**
  — the pattern 0.2.0 and 0.4.0 each recorded for themselves repeating exactly: a first live run fails, and the failure
  traces to something in the
  harness rather than to what is being tested. The first three are 0.5.0-era; the next three came from §16's first live
  run (2026-11-01) and left the
  app untouched; the **seventh** came from §11 STEP F's first live run on this build (2026-11-02) and is told in full in
  *Reading the result* rather
  than repeated here — `post_der()` had dropped the literal `-D` of its optional header-dump argument, nine of that
  walk's ten FAILs traced to it and
  the tenth to a stale `~/.config/mypki/mypki.env`. It belongs in this count because the count is of what running the
  pair against a correct app has
  found, not of which kinds of mistakes are allowed: like the other six, the app was right and the harness was wrong.
  * §15's byte parity hashed `/inspect`'s textarea **placeholder** instead of the parsed block (§15 above).
  * §12's *those four boxes show what the file says* read 0 because `settings.html` wraps it mid-clause. **`grep` is line-based, so no pattern
    handed to `count_re` can span a newline** — MEASURED: `show\s+what` and `show[[:space:]]+what` both read 0 on text containing show-newline-what.
    `.sh` gained `count_joined` (joins newline-and-whitespace runs to one space with `python3`, then counts); `.ps1` uses `Measure-Regex` with
    `\s+`, because **.NET regex does span newlines**. That asymmetry is deliberate and now written down: a needle copied between the two scripts
    needs this decision made consciously, not discovered by a green run that was really counting nothing.
  * §9's CA-subject needle hard-codes `mypki Root CA` and failed against a scratch server minted with `--common-name`. That is the operator's
    configuration rather than a defect in either script or the app; it stays as written, because the documented run is a plain `init-ca`.
  * §16's consent hint needle read `only if you tick the box`, a phrase **no build has ever printed**: `app.py`'s hint closes "… and dropped only
    when you tick the box **there**." It failed in `.sh`, in `.ps1` *and* in `tests/test_consent.py::test_a_consent_grant_does_not_extend_to_a_privilege_claim`
    — three copies of one wrong belief about wording, which is what makes this the most instructive of the six 0.6.0-era
    findings: a needle that matches
    a sentence someone expected is not an assertion about the sentence the app writes. The seventh defect is not a needle
    but a dropped flag, and it
    taught the same class of lesson (see *Reading the result*: an optional argument needs its flag spelled in every
    branch that uses it).
  * `issued_serial()`'s `grep -A 15` window. It was wide enough while only an edited-subject diff could sit between `<h2>Issued:` and the serial row;
    §16's dropped-extension block puts that row **19 lines** below the heading, so a page rendering a perfect serial read as "no leaf serial" —
    a FAIL against correct markup. The window is now bounded by `</table>` instead of a line count. `.ps1`'s counterpart (`[regex]::Match` with
    `Singleline`) was never affected, which is the second time this pair has differed on a *scoping* mechanism rather than a needle.
  * Two `.ps1`-only output defects: `Get-Page '/csr/sign' …` in §16 left curl's `%{http_code}` text unassigned, printing three bare `200` lines into
    the log (which shifts every heading line number this file records), and `$(Get-Item $x).Length` interpolated a **FileInfo** — the label read
    "…/work/consent.csr.Length bytes" rather than 1050. Both fixed; both LF-clean, verified by re-running.

- **Helper inventories differ between the two scripts, and which ones differ is a per-release fact.** Measured on
  **0.6.0** (kept as history):
  `.sh` defined 28 helpers; `.ps1` **27** top-level functions (31 at any depth, measured from its AST —
  `Resolve-MypkiBase` joined them in 0.5.2).
  Three of the `.sh` helpers had **no `.ps1` counterpart** because the `.ps1` did not need them:
  `count_joined` (.NET regex spans newlines already), `findings_count` (`[regex]::Match` returns the captured block directly, so scoping a needle
  inside an element needs no helper) and `offset_of`'s role in §12's ordering check. On **this build** the inventories
  are equal — **35 == 35**, 39 at any
depth — because 0.7.0 added DER read/write helpers to both scripts and reversed the `count_joined` asymmetry with
`Measure-Joined` (see the re-audit
paragraph above); what still has no counterpart is `findings_count`, for the reason stated there. What *was* added to
both in 0.5.0 is one: `post_pem_field`
  (`.sh`, `--data-urlencode <field>@<file>` with the field name spelled out, because `post_pem` hard-codes `csr_pem@file` and `post_form`'s `-F`
  truncates a PEM at the first newline) mirrored by `Send-PemField` (`.ps1`). Both §15 POSTs need it: `pem_paste` is not `csr_pem`.

- The **pre-edit** 0.2.0 harness, run unchanged against this same 0.3.0 app on the same day, printed
  **88 pass, 7 fail, 0 warn** (exit 1). Those seven failures were the harness being wrong, not the app: §1's four CA needles
  aimed at `/` after 0.3.0 moved them to `/ca`, and §11's three asserted a confirmation block that did not exist yet and a
  control-count fall that one bulk form makes impossible (1 -> 2). Recording that baseline matters: it is the evidence that the
  rewritten section actually tests something, rather than having been written into a green run.

- **The two harnesses' reports have been compared label by label on every release since 0.5.0, and twice in that release,
  and the second of those is the one to trust** —
  because the first was measured against a *shared* data dir and its numbers were contaminated by that. The two dated
  runs below are **the 0.5.0 build's**,
  kept verbatim as history; this build's own comparison is the bullet that follows them.
  * **2026-10-30, shared ledger**: both scripts against one server on `http://127.0.0.1:8452` with `/tmp/pkismoke-050c/data`, run in sequence so the
    second walked a ledger the first had already stamped → 211 labels each, same order, **184 identical**, 27 differing.
  * **2026-10-31, independent ledgers**: two freshly minted trees and two servers (`/tmp/pkismoke-050g` on `:8456` for `.sh`, `/tmp/pkismoke-050h` on
    `:8457` for `.ps1`), each harness walking an empty ledger of its own → 211 labels each, same order, **186 identical**, **25 differing**, and
    **every §11 count-difference disappeared** (revoked pills 0→1→2 on the `.sh` side and the same 0→1→2 on the `.ps1` side, row counts and checkbox
    counts equal). The 25 are 14 wording-only after normalising `section`→`§`, `§N's`→`§N` and em dash→hyphen; 7 further wordings the two scripts simply
    phrase differently (`(page-map §1)` vs `(page-map 1)`, `class="findings"` vs "the findings class", "README's known gap" vs "the documented known
    gap") plus the resolved-path labels, which necessarily differ because each scratch tree has its own name; and **4 host facts**: §6's CSR byte count
    (1017 vs 1016, the trailing-LF asymmetry below), the leaf serial, and the CA DER fingerprint reported twice (§9's parity label and §15's echo label,
    equal *within* each script and different across the two because the two scratch CAs are different keys).
  So the honest statement is: **no label difference in any of those comparisons reflects a product difference**, and the
  shared-ledger comparison's extra
  "content" differences were an artifact of running twice against one directory. **Comparing labels across the two scripts is only meaningful after
  normalising `§`/`section`, dashes, numbers, serials and scratch paths — and only after giving each harness its own fresh data dir.**

- **This build's own label-by-label comparison** (2026-11-03, `/tmp/g071/labelcmp_final.py`): a copy of
  `/tmp/s11b/labelcmp070.py` whose scratch-path pattern was widened from `/tmp/pkismoke-070x?[-_](sh|ps1)` to
  `/tmp/pkismoke-[0-9A-Za-z_-]+`, because the new scratch dirs are named `pkismoke-071c-sh` / `-071sh` and the old pattern
  silently leaves their two resolved-path labels in the residual. The widening changes nothing else — same needles, same
  order, same status comparison. **It reproduces the shipped release exactly**: over the control pair the fresh run reports
  **230 identical byte-for-byte / 53 differing / 269 of 283 matching after normalisation**, which is what 0.7.0 recorded,
  line for line. (`/tmp/s11b/labelcmp070.py` itself was re-run too: on these trees it prints **267** rather than 269, purely
  because of that scratch-path pattern — a naming artifact of this run, not a product difference. It cannot be re-run over
  the release's own `build/` reports at all: `/tmp/pkismoke-070sh` and `-070ps1` no longer hold `report.md`. Everything
  below uses the widened script on both pairs.) This build: **288 labels each, in the same order, with the same status on
  every label**, **233 identical byte-for-byte**, **55 differing**, and **272 of 288 match** after normalising
  `section`→`§`, em dash→hyphen, apostrophes, backtick-vs-single-quote needle style, scratch paths, ports, timestamps and
  the §6/§16 byte counts. The residual is 16 and it decomposes honestly: **thirteen are wording** — the twelve recorded
  against 0.7.0 (`class="findings"` vs "the findings class", `od` + `base64` vs `FromBase64String` + `ReadAllBytes`,
  `?pending=` vs "pending id", `/inspect's form` vs `/inspect form`, "not 'KeyUsage'" vs "not just KeyUsage",
  "measured:" vs "plan 4 measured why", `RFC 5280 §5.2.1` vs `RFC 5280 5.2.1`, the 46rem-cap pair, the checkbox pair, the
  CRLNumber/IDP/DeltaCRL needle-style pairs and the truncated-OCSP pair) **plus one new pair**: "the refusal sits above
  'Paste a CSR (PEM)' (**line 83 vs 89**) against the same fact printed as **offset 2603 vs 2954** — `.sh` measures the
  ORDER by line number and `.ps1` by string offset, which is the only way each can measure it. **Two are `.ps1`
  label-formatting defects** of the kind already recorded here: labels written in single quotes so `($n)` reaches the
  report as the literal `$n` — §11's no-Content-Disposition label (this build `scripts/smoke_test.ps1` :1603, recorded at :1580 in the 0.7.0
  harness before §1/§7 grew) and
  **the §7 label this build added** (:1091, "a refused paste staged nothing (no confirmation panel, `$n`)"), which is the
  same mistake repeated in new code and is recorded rather than fixed silently. **One labels the same assertion with
  different content**: `.sh` prints the occurrence count `(1)` and `.ps1` prints the status bytes `(0a0100)` for §11's
  unknown-serial answer. No residual is a host fact this time — the fingerprint, serial and DER labels all normalise away,
  because each scratch tree mints its own CA and those facts are equal *within* a script. The added label count is
  identical in both scripts (§1 +1, §7 +4), so no residual here reflects a product difference.
  **No §11 count-difference appears anywhere**: the three pill labels read `0 … 1 … 3` identically in both scripts and
  every checkbox and row count matches, so what 0.5.0
  concluded is re-measured here rather than inherited.

- **Run both harnesses against the *same* data dir in sequence and §11's counts change**, which is not a bug in either script: the second walk
  starts from 4 issued / 3 revoked instead of an empty ledger, so its "N revoked pills" labels read higher. Re-measured
  on **the 0.5.0 build** — that shared
  `/tmp/pkismoke-050c/data`, `expected version: 0.5.0` in both reports: after one `.sh` walk it held **4 records / 3
  revoked / 1 active**, and the `.ps1` walk that followed
  printed 211/0/0 regardless (the directory afterwards: 8 records / 6 revoked), because every
  §11 assertion is written per-serial and counts *relative* to whatever ledger exists. Run them against **separate** fresh dirs when you want the
  documented per-section numbers to mean what they say. This build, four trees, one walk each: **5 records / 3 revoked /
  2 active**, and §11's pill labels read
  `0 … 1 … 3` in both scripts.

- **§6's CSR byte count is not comparable across the two harnesses**: 1017 on Linux, 1016 on Windows, for the same PEM. Both
  extract the identical block with the same regex; `.sh` writes it with `print()` (which appends a newline) and reports `wc -c`,
  while `.ps1` writes it with `[System.IO.File]::WriteAllText` (no trailing newline). It is one trailing LF in each harness's own
  scratch file — step B signed successfully both ways. **Confirmed on this build** (2026-11-03):
  `/tmp/pkismoke-070x-sh/work/generated.csr` is **1017 B** under `wc -c`, and
  that tree's report prints 1017 at line 50; its `.ps1` counterpart `/tmp/pkismoke-070x-ps1/work/generated.csr` is **1016
  B**, and the two `build/` trees read the same pair.
  The numbers also match 0.5.0's (`/tmp/pkismoke-050g/work-sh` 1017, `/tmp/pkismoke-050h/work-ps1` 1016), so the
  asymmetry has not moved in four releases; the
  Windows half is 0.2.0-era, from the only Windows report we ever received.

- **A report written by the `.ps1` is CRLF on Windows and LF when the same script runs under `pwsh` on Linux**, because it joins with
  `[Environment]::NewLine` — which is that platform's newline. **MEASURED on this build** (2026-11-03, counting bytes
  rather than quoting a shell pattern): the `.ps1`'s report written here has **0 CRLF pairs**, **294 LF**,
  no lone CR and no BOM, against the `.sh` report's **293 LF** — and all four of this build's reports agree:
  `/tmp/pkismoke-070sh` 293 LF / 20,331 B,
  `/tmp/pkismoke-070ps1` 294 LF / 20,409 B, `/tmp/pkismoke-070x-sh` 293 LF / 20,337 B, `/tmp/pkismoke-070x-ps1` 294 LF /
  20,415 B. The one-line gap is the `.ps1`'s trailing
  `== summary: … ==`, which the `.sh` *report* does not write (both console logs carry it, at line 301). **The 221 LF
  (.ps1) / 220 LF (.sh) pair is the 0.5.0 build's**
  (`/tmp/pkismoke-050h/report-ps1.md` and `/tmp/pkismoke-050g/report-sh.md`, both `expected version: 0.5.0`, 211 labels
  each); the 0.6.0 pair is 256 / 257
  (`/tmp/v060/scratch-zsh`, `/tmp/v060/scratch-zps1`). The dash `$'\r'` trap recorded above repeats on these reports too:
  `grep -c 'r$'` reads **11** on each while the
  byte count is **0**. The 105-CRLF-pairs figure belongs to the 0.2.0-era Windows
  report and is kept as evidence of what a real Windows run produced, not as a property of this script. Compare labels, or normalise line endings
  before diffing — on Linux the two reports diff cleanly today, and that would not survive a Windows run.

- **This build's own coverage numbers are in the third bullet of this pair (the 0.7.0 one).** The bullet immediately
  below is **the 0.6.0 build's**,
  kept verbatim as history rather than restated.

- **The 0.6.0 build's coverage numbers** came from one command, run on Linux: `pytest -q -p no:cacheprovider --cov=mypki
  --cov-report=term-missing
  --cov-fail-under=85` collected and ran **704 tests with ZERO skips**, TOTAL **2730 statements / 78 missed
  = 97.14%** (`src/mypki/inspect.py` 234/0 = 100%; the standing misses are `__main__.py` 17-21, `paths.py` 161, 166-167 and `csr.py`
  569-570). The **+32 over 0.5.2's measured 672 / 2700 / 84 = 96.89%** is entirely two files: `tests/test_consent.py` 15 (new) and
  `tests/test_csr_validate.py` 50 → 67; every other test file collects exactly what it collected in the shipped `mypki-0.5.2.zip`, re-measured
  from an extracted copy on 2026-11-01. Against 0.4.0's published 554 / 2345 / 82 = 96.50% **that build** is **+150
  tests**. There is no
  passed-plus-skipped split to reconcile here, because every skip in that tree is a `@pytest.mark.skipif(not POSIX)` site
  and this box *is*
  POSIX: **eight** of them — `tests/test_ca_init.py` :275 / :490 / :653, `tests/test_cli.py` :405 / :417 / :451 / :1350 and
  `tests/test_settings_save.py` :220 — plus `tests/test_version.py`'s separate `requires_git` marker (:465, used at :533 / :551 / :568 /
  :585 / :620), which does not fire here either because a git binary exists (git 2.47.3). On Windows those eight would skip; **that split
  has never been measured by us**, because no Windows run of this suite has ever been performed from this box.

- **The 0.7.0 (this build) numbers come from the same single command, on Linux**: `pytest -q -p no:cacheprovider --cov=mypki
  --cov-report=term-missing
  --cov-fail-under=85` collects and runs **782 tests with ZERO skips**, TOTAL **3008 statements / 97 missed
  = 96.78%**. The **+78 tests / +278 statements over the 0.6.0 bullet above** is accounted file by file against an
  extracted copy of
  `mypki-0.6.0.zip` re-collected on this box: `tests/test_crl.py` 0 → **41**, `tests/test_ocsp.py` 0 → **31**,
  `test_no_key_leakage.py` 14 → **17**
  (its sweep now fetches `/crl` and `/crl.pem`) and `test_signing.py` 34 → **37**; every other test file collects exactly
  what it collected in 0.6.0,
  including `test_packaging.py`, which stays at **25** while its existing sweep and asset list gain `/crl` and
  `templates/crl.html`. The misses moved rather than
  only grew: **`src/mypki/crl.py` 86 statements / 4 missed (293-297)** and **`src/mypki/ocsp_responder.py` 77 / 1 missed
  (355)** are the two new
  files' uncovered lines, `app.py` is now **834 / 49**, and `inspect.py` still reads 234/0 = 100%. The standing misses
  elsewhere are unchanged
  (`__main__.py` 17-21, `paths.py` 161, 166-167 and `csr.py` 569-570), so this build is *down* 0.36 points from 0.6.0's
  97.14% — a lower total
  because new code has lines no test reaches yet, which is the honest reading rather than a regression to hide. The rest
  of the gate this release
  was cut against: `mypy` clean over **19** source files (0.6.0 measured 17), `ruff check` and `ruff format` clean over
  the same tree, and
  `tools/check_version.py` **exit 0**. Zero skips again for the same reason as 0.6.0: every skip site in this tree is a
  `@pytest.mark.skipif(not POSIX)` marker or `test_version.py`'s `requires_git`, and neither fires on this box.

- **The coverage history in the next four bullets is 0.2.0-era or 0.3.0-era, not this build's baseline.** Re-measured today
  from the shipped `mypki-0.2.0.zip` on this box: that tree collects **476 tests**, TOTAL **1991 statements / 70 missed
  = 96.48%**, its `cli.py` row is **286** statements, and it carries exactly **six** `@pytest.mark.skipif(not POSIX)`
  sites — three in `test_ca_init.py`, three in `test_cli.py`. That is where "collection is identical (476 both sides:
  476 passed here; 470 passed + 6 skipped there)" comes from, and re-running that suite with the six deselected still
  reproduces it today: **TOTAL 1991/74 = 96.28%**, and `cli.py` becomes `286 15 95% 313-320, 354-356, 383-385, 478-479,
  560` — byte for byte the row the old text claimed matched the Windows table line for line. The full run lists
  `314-315` at that spot instead, so part of that block is covered only when those six tests run.

- **One gotcha when you re-run an archived zip in this checkout's venv — and it is not the one this file used to name.** This venv holds an
  **editable install of `/home/user/mypki/build`**, so an unpacked archive does not import its own package: MEASURED, running the extracted
  `mypki-0.4.0.zip` here resolves `import mypki` to `/home/user/mypki/build/src/mypki/__init__.py` — **0.5.0 code under 0.4.0's tests**. That run
  printed **2 failed, 552 passed**, and neither failure is a version assertion: `test_packaging.py`'s 25 tests all pass (the console script reports
  `mypki 0.5.0`, matching the imported `__version__`), while `test_cli.py::test_serve_warns_in_plain_http_and_not_at_all_with_tls` fails because
  0.4.0's version of it hands junk PEM to a `_tls_file_problem` that now parses contents (exit 1 instead of reaching the banner), and
  `test_settings_save.py::test_a_plain_get_after_a_save_does_not_claim_that_a_save_just_happened` fails because 0.4.0 expects `value="8443"` in a box
  that 0.5.0 fills with the saved value (page-map §12). Both are **newer code under older tests**, which is what you get from an editable install —
  not defects in the archived tree, and not something to "fix" by editing the archive. If you need an archived tree to test itself, unpack it and run
  it in a venv where *that* version is installed.

- **Every Windows number quoted below is a transcription of the operator's own report — this box has never run mypki
  on Windows** (no PowerShell, no Windows). They are kept because they are the only cross-platform evidence we have, not
  because anything here verified them.

- **What we hold verbatim from Windows is 0.3.0.** The operator's run (`platform win32, python 3.13.12-final-0`) reported
  `2 failed, 529 passed, 7 skipped` — 538 collected, exactly what this box collects from `mypki-0.3.0.zip` — with
  TOTAL **2283/88 = 96.15%**, `ca.py 190 4 98% 135-137, 288` and `cli.py 287 15 95%`. Both failures were Windows-only
  *test* bugs: a config-home assertion that assumed `$XDG_CONFIG_HOME` on a branch of `paths.resolve_config_dir` which
  returns `%APPDATA%\mypki`, and a separator-sensitive comparison of a written `MYPKI_LOG_FILE`. Both are fixed in 0.4.0's
  tests; no product defect came out of that report.

## 0.7.0 release evidence (moved out of `CHANGELOG.md` verbatim)

The measurements the 0.7.0 release was cut against, and the harness runs against the extracted shipped zip. They sat
inside the live `[0.7.0]` section; they are records of particular runs, so they live here instead, and the changelog
entry links to this file rather than restating them.

### The gate 0.7.0 was cut against, and its harness runs

trusted by clients that never consult an artifact until it expires. The gate this release was cut against: 782 tests, 3008
statements / 97 missed = 96.78%, `ruff check` clean, `mypy` clean over 19 source files, `tools/check_version.py` exit 0, and
`ruff format` clean over the same tree. **Both smoke harnesses were re-run and re-measured on this build** (2026-11-02), each against its
own freshly minted tree and data dir — `.sh` at `/tmp/pkismoke-070sh/data` served on `http://127.0.0.1:8611`, `.ps1` at
`/tmp/pkismoke-070ps1/data` on `:8613` under `/tmp/pwsh/pwsh` 7.6.9, plain `init-ca` (default CN, RSA 3072), `HOME`/`XDG_*` redirected into
each scratch tree — and both printed **`== summary: 283 pass, 0 fail, 0 warn ==`** at exit 0, with the sixteen section headings at the same
line numbers in both logs (1 / 9 / 30 / 32 / 36 / 46 / 59 / 62 / 65 / 83 / 100 / 177 / 212 / 223 / 233 / 269) and the summary at **301**
(302 lines total). Against 0.6.0's measured 246 that is **+37**: +36 in §11, all of it the new STEP F block (CRL + OCSP, asserted after the
revocations that create its subject), and +1 in §12 (`/about`'s rewritten revocation caveat now asserts two sentences where the dead one
asserted one). `openssl` was still never invoked by either harness. Their counts live in SMOKE_TESTING.md's ledger, which keeps 0.6.0's
**246 / 0 / 0** as history rather than overwriting it.

### Both harnesses run from the extracted shipped zip

  paths. **Both harnesses were then run from the extracted tree against their own freshly minted data dirs** (2026-11-03, `/tmp/s11b/run_harness_x070.sh`
  retargeted at `<extract>`): `.sh` on `http://127.0.0.1:8621`, `.ps1` on `:8623` under `/tmp/pwsh/pwsh` 7.6.9, plain `init-ca` (CN=mypki Root CA,
  RSA 3072), `HOME` + the four `XDG_*` redirected, `MYPKI_CONFIG_DIR`/`APPDATA` unset, no `--base` / `-Base`, server cwd `<extract>/src` — and both printed
  **`== summary: 283 pass, 0 fail, 0 warn ==`** at exit 0 with the sixteen headings at 1 / 9 / 30 / 32 / 36 / 46 / 59 / 62 / 65 / 83 / 100 / 177 / 212 /
  223 / 233 / 269 and the summary at **301** (302 lines), §11 **76** and §12 **34**. The extracted ledger is identical to the `build/` ledger above,
  which is what makes the zip a copy of the tested tree rather than a rebuild of it.

## Dated records moved out of `SMOKE_TESTING.md`'s preamble and honesty note (verbatim)

These paragraphs sat in the living document but quote particular runs. They are kept here unchanged; `SMOKE_TESTING.md`
now says what a run is for and links to this file instead of restating its numbers.

### The 2026-10-30 0.5.0 run, both harnesses, on Linux

means what it says). On 2026-10-30 `scripts/smoke_test.sh` printed **211 assertions** (211 pass,
0 fail, 0 warn, exit 0) against a live 0.5.0 server on a **fresh** data dir - `MYPKI_DATA_DIR=/tmp/pkismoke-050b/data`, a CA minted
for the run by a plain `init-ca` (default CN, RSA 3072) - with `HOME` and the four `XDG_*` variables redirected into that scratch tree,
so §12's config-file fingerprint checks compare against a throwaway home rather than this box's real `~/.config/mypki`. The count is
printed by the harness itself, never written into either script as an invariant — see *Reading the result*. `scripts/smoke_test.ps1`
carries **the same 193 pass labels across the same 15 sections** (per-section call-site counts matching in all fifteen) and on the same
day printed the identical **211 pass, 0 fail, 0 warn** — under `pwsh` 7.6.9 **on Linux**. It has still never been run on Windows; see the

### The `.ps1` measured against the 0.6.0 build

its own, printing the identical `== summary: 246 pass, 0 fail, 0 warn ==` (exit 0) with the same sixteen headings at the
same line numbers and
the same per-section counts — **that 246 is the 0.6.0 build's measurement**, kept here as history; this build re-measured
as the identical
**288 / 0 / 0** in both scripts (283 for the extracted shipped 0.7.0 zip, re-measured the same day as a control), each against its own freshly minted tree. That is progress against 0.4.0's "never

### The 0.2.0-era run measured on Windows

What *was* measured on Windows was the **0.2.0-era** tree (2026-10-28, coverage header
`platform win32, python 3.13.12-final-0`, data dir `C:\tmp\pkismoke\data`): **95 pass, 0 fail, 0 warn**, every check from
§1 through §14 answered there — including that build's §12 leak check, which read the resolved directory off the card as
`C:\tmp\pkismoke\data` while naming no CA-key or secret-key path. That mattered more than the count at the time: it was the
first time PowerShell had *executed* the splat fix (`& curl.exe @probeArgs`) instead of a static reading of it being checked,
and the run reached 95 assertions rather than dying at exit 2 with "NOTHING WAS CHECKED". **Those 95 numbers describe 0.2.0
and are not this build's baseline.**



## The two counts this pass had to resolve (measured 2026-11-04, ruff 0.17.2 / pytest 9.1.1 / mypy 2.4.0 on CPython 3.12.13)

Neither was tuned away. Each looked like a regression against an earlier figure and neither is; both are recorded with the
measurements that decided them.

### `ruff format --check .` reports 59 where the plan expected 48

The expectation was Python-file arithmetic: 46 files in the pre-split tree + `tools/check_docs.py` + `tools/harness_ledger.py` = 48.
That arithmetic is right about Python and silent about everything else. Measured on this tree, by enumerating every `.py`/`.pyi`/`.md`
outside `.venv`, `__pycache__`, `.mypy_cache`, `.pytest_cache` and `.ruff_cache`:

- `ruff format --check .` → **59 files already formatted**, exit 0. Decomposition: **44 Python** (`src` 19 · `tests` 22 · `tools` 3)
  + **15 Markdown**.
- Reconstructed state at the earlier 46-file sweep: **42 Python + 4 Markdown = 46**, which is the number that log reported. Those four
  were `README.md`, `SMOKE_TESTING.md`, `CHANGELOG.md` and `docs/page-map.md`. Since then **+2 Python** (`tools/check_docs.py`,
  `tools/harness_ledger.py`) and **+11 Markdown**: the eight `docs/history/0.*.md`, `docs/measurement-history.md`,
  `docs/CHANGE_POLICY.md` and `reports/harness-ledger.md`. **46 + 2 + 11 = 59.** The arithmetic closes on both sides.
- One correction, recorded rather than smoothed over: an earlier draft of this bullet listed `docs/page-map.md` as one of the eleven
  new Markdown files. It is not new. It was already policed before the split (its findings appear as `docs/page-map.md:273` in the
  pre-split baseline) and it was already in the sdist `include` list in the 0.7.0-era `pyproject.toml`. What the split changed about
  page-map was its **content**, not its existence, and a file count moves on existence. The substitution that makes the arithmetic
  close is `docs/CHANGE_POLICY.md`, which this pass created.
- Two separate reasons the bare `.` count is not a project fact. First, ruff 0.17's `.` walk visits Markdown for *format* — so the
  number moves whenever a document is added or removed, and this refactor added eleven. Second, ruff applies `.gitignore` **only
  inside a git repository**, and this checkout has no `.git`. Measured with a throwaway tree holding a `.gitignore` that names two
  Markdown files and one directory: `ruff format --check .` counted **3** files before `git init` and **1** after it. So here the
  gitignored generated ledger is walked. Moving `reports/` aside took this tree's count from 59 to 58, which locates that file rather
  than inferring it.
- **Lint and format are not symmetric about Markdown.** `ruff check .` reported "All checks passed!" while `CHANGELOG.md` carried 155
  lines longer than the configured `line-length = 120` with `E501` selected. Asked directly, `ruff check CHANGELOG.md` answers
  `warning: No Python files found under the given path(s)` and exits 0. A clean `ruff check .` therefore says nothing about the
  documents; `tools/check_docs.py` is the only gate that reads them.
- **Canonical for this project's sweep: the scoped form.** CI runs `ruff format --check src tests tools` → **44 files already formatted**,
  exit 0 — the same 44 Python files, stable across releases. Both figures are recorded rather than one declared and the other deleted;
  the difference between them is a property of ruff's walker, not a finding about this tree.
- The hazard worth testing rather than asserting: ruff formats Python inside Markdown fences, so a fenced Python block in a frozen
  history file would be rewritten by a future `ruff format .` — an edit to an append-only record. A probe holding a badly formatted
  fence confirmed ruff proposes a rewrite inside Markdown. **Today the whole walked corpus is clean:** `--diff` proposes zero edits for
  all eight `docs/history/0.*.md`, `docs/measurement-history.md`, `CHANGELOG.md`, `SMOKE_TESTING.md`, `README.md`, `docs/page-map.md`,
  `docs/CHANGE_POLICY.md` and `reports/harness-ledger.md`, and none of them contains a single `python`/`py`/`py3`/`pycon` fence. The
  exemption that protects history from *this* gate is `tools/check_docs.py`'s; protection from ruff is currently incidental, because no
  document in the tree happens to hold a Python fence.

### Collection moved 786 → 790

- Two entries joined the sdist `include` list (`docs/history`, `docs/measurement-history.md`) and `REQUIRED_INCLUDES` in the same edit.
  `tests/test_packaging.py` parametrizes **two** assertions over that list — `test_every_include_entry_exists_on_disk` and
  `test_no_include_entry_can_reach_anything_forbidden` — so 2 entries × 2 decorators = **+4 tests**. Arithmetic from the file itself:
  13 test definitions, of which 2 are parametrized and 11 plain → 11 + 9×2 = **29** collected, against 11 + 7×2 = **25** before.
- Per-file collection confirms the growth is confined to that file: `tests/test_packaging.py` **25 → 29**; the other **20** test files are
  identical (`test_views.py` 87, `test_cli.py` 84, `test_csr_validate.py` 67, `test_inspect.py` 58 …). File sums: **786 → 790**.
- Intended, not incidental. The module docstring names it — "adding an entry adds a param to each parametrized assertion below; that
  growth is the point rather than a cost to avoid" — and `test_include_names_everything_a_release_needs` asserts the list as a set in
  both directions, so the +4 is the price of the guard that makes a config-only edit fail instead of pass.
- Coverage TOTAL is unmoved by it: **3024 statements / 103 missed = 96.59%** on both sides. `tests/` is not measured by `--cov=mypki`,
  so tests added to a test file move the test count and not the denominator.

### Ordering of this file's own bullet list (measured 2026-11-04, same run)

`docs/CHANGE_POLICY.md` originally claimed new entries land at the **top** of this file. The two append steps that assembled it
wrote at the bottom: `split_history.py` built the document whole in one write, and `append_release_evidence.py` read the file,
stripped trailing newlines and concatenated its block onto the end — so the claim was wrong as written.

The sentence drafted to replace it claimed the bullet list "reads oldest-first". Measuring the list disproved that too, and both
errors are recorded rather than smoothed over:

- The bullet-list half runs from line 1 to the first `## ` heading; there are **24** top-level bullets in it, **13** of which name a
  date. Taking each bullet's newest date, the sequence down the document is neither ascending nor descending — the first five dated
  bullets run newest-first (11-03, 11-03, 11-01, 10-31, 10-30), and exactly **three** later bullets name a newer date than the one
  before them (10-30 → 10-31, 10-31 → 11-02, 10-31 → 11-03).
- So no chronological ordering rule can honestly be stated for this list. Its order is a *provenance* order — where each paragraph
  came from when it was moved out of `SMOKE_TESTING.md` and `CHANGELOG.md` — which is why the head looks newest-first while the middle
  does not.
- Why this matters more than it looks: a policy document that asserts a false ordering gets followed. A contributor told the list is
  oldest-first will move or re-date a frozen entry to make the dates line up, and editing a frozen measurement is the single thing
  "append-only" exists to forbid. Stating no order is safer than stating a wrong one.

## Docstring census before the D2 rewrite (measured 2026-11-04, pre-edit tree)

Baseline for the src/ docstring pass. Every number here was produced by a read-only script over the tree **before** any
line was rewritten, and none of them is re-derived afterwards: they exist so the rewrite can be compared against what it
started from rather than against a remembered figure.

### The two census scripts disagree, and both counts are kept

| Script | `src/` files | docstrings | docstring lines |
|---|---|---|---|
| `g0_census.py` (`ast.get_docstring(..., clean=False)`) | 19 | 300 | **2946** |
| `g0_census2.py` (`ast.get_docstring(...)`, i.e. `clean=True`) | 19 | 300 | **2713** |

Same files, same docstrings, same count of them — and a 233-line gap in what counts as a *line* of one. The gap is not an
error to be resolved: `clean=True` strips the leading indentation that this project's docstrings carry on every line after
the first, and for a docstring written as an indented block inside a nested function the raw spelling has more physical
lines than the deduplicated one. A census that reports one number is reporting its own normalisation choice, so both are
recorded and neither is declared canonical. `g0_census2.py` additionally counts `>4 lines` and `>8 lines` docstrings, which
`g0_census.py` does not, and it is the script whose `>8` figure matches the tests/ half below.

### `src/` (19 files)

- 300 docstrings; **2946** raw lines / **2713** deduplicated lines.
- Docstring lines naming a `0.x.y` version: **60** (`app.py` 26, `store.py` 9, `cli.py` 6, `signing.py` 6, `csr.py` 3,
  `validators.py` 3, `settingsfile.py` 2, and one each in `__main__.py`, `config.py`, `crl.py`, `inspect.py`,
  `ocsp_responder.py`).
- Docstrings longer than eight lines: **122** by the raw count, **111** by the deduplicated count. The longest are module
  docstrings, not function docstrings.

### Longest docstrings in `src/` (lines, as counted by each script's own rule)

| Docstring | lines |
|---|---|
| `ocsp_responder.py::<module>` | 60 |
| `app.py::<module>` | 59 |
| `logsetup.py::<module>` | 53 |
| `crl.py::<module>` | 48 |
| `settingsfile.py::<module>` | 46 |
| `signing.py::<module>` | 42 |
| `store.py::<module>` | 41 |
| `app.py::issued_revoke` | 39 |
| `inspect.py::<module>` | 39 |

Eight of the nine longest are module docstrings. That is the shape this pass had to respect: a module docstring is where a
project explains *why* a module exists, and it is also where history accumulates fastest, because "why" tends to be written
as "what used to be wrong".

### `tests/` (23 files)

- 797 docstrings, **4494** lines, **111** longer than eight lines, **101** lines naming a `0.x.y` version.
- Tests carry **more** version-naming prose than the package does (101 against 60) while being excluded from coverage
  measurement entirely. A docstring policy aimed only at `src/` would leave the larger half of the corpus untouched, which is
  why this pass scoped the *rewrite* to `src/` and recorded the tests/ figure instead of silently adopting it as a target.

### The 165 lines selected for rewriting

Derived by AST rather than by grep, so that a version number inside a string literal or a URL cannot be counted as prose:
a line is in scope only if it is a **comment** or a line **inside a docstring**, and it matches at least one of three
patterns.

- **165 lines total**: 108 docstring lines, 57 comment lines.
- By pattern: version-citation **95**, one-run-probe (`MEASURED`, or a `/tmp/...` probe path) **69**, release-plan-tag
  (`answer N`, `U<N>`, `(0.x.y)`) **8**. **7** lines match more than one pattern, so the pattern counts sum to 172 rather
  than 165 — an overlap, not a discrepancy.

### Why docstring text is (almost) invisible to coverage

Measured on this tree with coverage's own parser: `src/` parses to **3050** statements before pragma exclusion, and the
reported TOTAL is lower than that because of parse-time exclusions rather than anything about docstrings. Docstring lines
are not statements at all, so rewording one cannot move a denominator — with exactly two exceptions in `src/`, where a
docstring is the *only* thing in a class body (`errors.py::MypkiError` and `errors.py::OneShotExpiredError`). Any claim that
a docstring rewrite "changed coverage" has to name those two or say plainly that it changed nothing.

### Version-naming lines not already recorded in frozen history

The 60 version-naming docstring lines were checked line by line against `docs/history/`. **59 are unrecorded**; the only one
already carried by a frozen entry is `settingsfile.py::<module>`'s "Why a file at all (0.3.0)". Those 59 lines are moved,
verbatim, into `docs/history/narrative.md` rather than paraphrased out of the source — which is what makes it safe to strip
the version citations from living code without deleting the record they carry.

## 0.7.1 release evidence (measured 2026-11-05, ruff 0.17.2 / pytest 9.1.1 / mypy 2.4.0 on CPython 3.12.13, PowerShell 7.6.9)

The measurements this release was cut against, recorded once, here. `CHANGELOG.md`'s `[0.7.1]` section links to this
section and to the generated `reports/harness-ledger.md` rather than restating any of it. Nothing below is re-derived for a
later build, and the **3024 statements / 103 missed** figure in *Collection moved 786 → 790* above is left exactly as that
pass measured it: this release's run reports the TOTAL below, which is a newer measurement rather than a correction of that
record.

### The gate this release was cut against (2026-11-05)

Nine gates in `/tmp/g072/`, every one exit 0: `ruff format .` → **65 files already formatted**; scoped
`ruff format --check src tests tools` → **49 files already formatted**; scoped `ruff check src tests tools` → *All checks
passed!*; `mypy src` → *Success: no issues found in 19 source files*; `tools/check_version.py` → version chain consistent
at **0.7.1** (module → manifest → CHANGELOG heading); `tools/check_docs.py` → docs clean over README, SMOKE_TESTING,
CHANGELOG, `docs/page-map.md` and `docs/CHANGE_POLICY.md`; its `--self-test` → **7 violations caught, 6 clean lines
passed**; `tools/check_docstrings.py` → clean over **19 files** under `src/` for **3 rules**; its `--self-test` →
**5 violations caught, 7 clean lines passed**.

`.venv/bin/python -m pytest --cov=mypki --cov-report=term-missing --cov-fail-under=85` (`h_pytest.log`, 265 s wall): the
progress block holds **11 rows of 72** plus a final row of **27** = **819** result characters, with no `F`, `E` or `s` among
them, and reports **TOTAL 3025 statements / 103 missed = 96.60%** with `src/mypki/app.py` at **851 / 55**.

Collection was measured module by module as well (`--collect-only -q`, `h_collect.log`): **23** modules, summing to the same
**819**. Against the surviving diag of the previous pass (`/tmp/g071/cd2_collect_diag.log`, written 2026-11-04 09:45,
**22** modules summing to **799**) exactly two rows differ — `tests/test_docstrings.py` absent → **14**, and
`tests/test_fast_lane.py` **10 → 16** — which is the whole **+20**. Against the 2026-11-03 collect log beside it (**786**,
before `tests/test_fast_lane.py` existed and while `tests/test_ocsp.py` still carried its two page-map transcription tests)
the movement is +16 for `tests/test_fast_lane.py` (ten at the diag pass, sixteen now), −2 for those dropped needles, +5 for
`tests/test_packaging.py` as the include list now stands, and +14 for the prose-gate module: −2 +5 +16 +14 = **+33**,
786 → 819. The coverage TOTAL is **unchanged** from that same previous pass:
`/tmp/g071/cd_pytest.log` (09:42) and `ef_pytest.log` (23:07) both read **3025 / 103** with `app.py` at **851 / 55**, rows
identical to this release's. The 3024 record above belongs to the runs at 03:57 and 06:41 on 2026-11-04, whose `app.py` row
reads **850 / 55** — kept as what those two runs measured.

### The two harness runs this release was cut against (2026-11-05)

Both harnesses were driven against `build/` itself, each in its own scratch tree with a freshly minted data dir, plain
`init-ca` (the scratch `init-ca.log` confirms the default `CN=mypki Root CA`), RSA 3072, `HOME` plus the four `XDG_*`
redirected into the scratch tree and `MYPKI_DATA_DIR` pointing at it. Both sides were given their base explicitly. The
`.ps1` side resolves `curl.exe` by name first, so `/tmp/winbin/curl.exe` (a shim that execs `/usr/bin/curl`) was prepended
to `PATH`, and pwsh ran `-NoProfile`. Ports: this pass bound **8641** (`.sh`) and **8643** (`.ps1`) only. 8611 / 8613 /
8621 / 8623 — the ports the 0.7.0-era records above name — were bound by nothing in this pass, and `ss -ltnp` before and
after shows no listener on any of them.

- `/tmp/pkismoke-0711sh/log.txt` — `scripts/smoke_test.sh`, runner `/tmp/g072/run_0711_sh.sh`, wrapper log
  `h_harness_sh.log`: header `base resolved from: --base/BASE (explicit)`, `expected version: 0.7.1`, run at
  2026-11-05T03:51:44Z, **82** work files.
- `/tmp/pkismoke-0711ps1/log.txt` — `scripts/smoke_test.ps1` under `/tmp/pwsh/pwsh` 7.6.9, runner
  `/tmp/g072/run_0711_ps1.sh`, wrapper log `h_harness_ps1.log`: header `base resolved from: -Base (explicit)`,
  `expected version: 0.7.1`, run at 2026-11-05T04:04:45Z, **79** work files.

Both logs are **307 lines** with the summary at line **306**, both print the sixteen headings at **1 / 10 / 31 / 33 / 37 /
47 / 60 / 67 / 70 / 88 / 105 / 182 / 217 / 228 / 238 / 274**, and both read §1 **8** · §2 20 · §3 1 · §4 3 · §5 9 · §6 12 ·
§7 **6** · §8 2 · §9 17 · §10 16 · **§11 76** · **§12 34** · §13 10 · §14 9 · §15 35 · §16 30 = **288 pass / 0 fail / 0
warn**, at exit 0. `python3 tools/harness_ledger.py <the two logs> --write` regenerated `reports/harness-ledger.{md,json}`
(exit 0); `python3 tools/harness_parity.py` on the same pair printed sixteen `ok` rows and *parity: OK - 16 sections match
heading-for-heading, 288/0/0 on both sides* at exit 0.

Against the 2026-11-03 pair in the bullet list above — the same build's earlier runs, also **288** on 307-line logs with
§7 at **6** and §11 at **76** — neither harness script moved: `scripts/smoke_test.sh` and `scripts/smoke_test.ps1` are
byte-identical to the hashes in `/tmp/g072/h_baseline.log`, taken before any edit in this pass. The only difference from the
0.7.0 release's ledger is the **+5** (§7 +4, §1 +1) that record already accounts for.

### `tools/fast_lane.py`'s interpreter choice (what this release carries)

Measured through the tool rather than read off its source. Invoked as `python3 tools/fast_lane.py interpreter venv` —
i.e. through the **system** interpreter, `/usr/local/bin/python3`, with `.venv` on disk — it printed
`interpreter: /home/user/mypki/build/.venv/bin/python — this checkout's .venv; invoked through /usr/local/bin/python3`
before any step ran, and finished `fast lane clean. Full gates remain required at commit.` in **2.96 s** (ruff check 0.05 s,
ruff format --check 0.05 s, version chain 0.10 s + 0.18 s, `pytest -k interpreter or venv` 2.58 s), exit 0
(`h_fastlane_ok.log`). Every step now runs under `.venv/bin/python` when that file exists — `step_interpreter()` returns
the venv python or falls back to `sys.executable`, `step_command()` prefixes the chosen interpreter once, and
`interpreter_note()` prints the choice rather than leaving it inferred.

One honesty note about the "before" evidence, recorded rather than tidied: the two failing runs kept in `/tmp/g072/` are
*not* the `ModuleNotFoundError`-at-conftest failure that the tool's module docstring describes. What those logs actually
show is the lane half-green under a system interpreter while the new prose was still unlinted — `h_fastlane_system.log`:
**4** E501 findings across `tests/test_fast_lane.py` and `tools/fast_lane.py`, plus `ERROR: Wrong expression passed to
'-k': interpreter or or or venv` at pytest exit **4**, lane exit 1; `h_fastlane_system2.log`: **2** E501 findings after the
wrapping was fixed, lane exit 1. Both already print the interpreter line, which is how the fix showed up while the rest of
the run was still red. The interpreter-mismatch class of failure those runs were meant to reproduce was not reproduced in
this pass; what is measured here is narrower and stated as such — the lane no longer runs its steps under whichever
interpreter happened to invoke it, a step's own exit code (pytest's **5** included) reaches the report instead of being
flattened, and the choice is printed.

### Packaging measured for this release (2026-11-05)

No sdist and no wheel: `hatchling` and `python -m build` are not installed in `.venv`, so this cut ships a zip of the
source tree, built from an explicit path list rather than a directory walk — `tar cf - -T <list>` piped into a staging
directory named `mypki-0.7.1/`, then `zip -q -r -X`. The list (`/tmp/g072/pkg_list_final.txt`) names **86** paths: **33**
under `src/` (19 modules, 4 static assets, 10 templates), **24** under `tests/`, **6** under `tools/`, **12** under `docs/`
(`page-map.md`, `CHANGE_POLICY.md`, `measurement-history.md` and the nine `docs/history/` files), **9** top-level
(`README.md`, `SMOKE_TESTING.md`, `CHANGELOG.md`, `LICENSE`, `pyproject.toml`, `.env.example`, `.gitignore`,
`.pre-commit-config.yaml`, `.github/workflows/ci.yml`) and **2** harness scripts under `scripts/`. The archive holds
**98** entries: **86** files and **12** directory entries, and the 86 file entries are *the same set* as the list —
`diff` of the two is empty, which is the check that matters rather than two counts that happen to agree.

Two things that look like a contradiction and are not. First, `pyproject.toml`'s sdist `exclude` names `scripts`, while this
archive carries both harness scripts — because they are different artifacts with different jobs: the sdist is what an
install reads, the zip is a copy of the tree that was actually tested, and it carried `scripts/` in 0.7.0 too.
Second, the scan this cut is judged on looks for key material and runtime state — `^logs/`, `^src/logs/`, `\.pem$`, `\.key$`,
`\.crt$`, plus `nohup.out`, `.coverage`, `.venv`, `__pycache__` and `reports/` — and it returned **1**, which for that grep
means no entry matched. The `src/logs/` spelling is not decoration: `build/src/logs/mypki.log` sits in this tree from the
day the 0.7.0-era runs served with cwd `src`, and a directory walk would have picked it up — measured, by listing what the
first draft of the list contained before it was corrected. `reports/harness-ledger.{md,json}` are deliberately absent for the
same reason they are exempt from `tools/check_docs.py`: they are generated from a harness log on this machine.

Per-file sha256 aggregates (each file's digest paired with its path, sorted, then digested again) are identical across the
three states the bytes passed through — the build tree as the list reads it, the staged tree inside the tar, and the freshly
extracted zip: **87** files in each state, one aggregate digest per state, three aggregates equal.
