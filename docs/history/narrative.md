# Release-time prose moved out of `src/` (verbatim)

Append-only record. This file exists so that version citations and one-run probe notes can be removed from living
code without deleting the claim they carry: every line below is a docstring line copied **byte for byte** out of
`src/mypki/`, together with the docstring it belonged to. Nothing here is paraphrased, reordered or merged, and
nothing here is re-derived from a later build.

## Why this file exists

`docs/CHANGE_POLICY.md` says version numbers are release-time facts rather than working-commit facts, and the same
applies to the evidence attached to them. Living code states invariants; history states what used to be broken and
which release proved it. A docstring that reads "changed in `0.x.y`" is a sentence about a release sitting inside a
file that outlives it: it goes stale the moment behaviour moves again, and it forces every later edit to renegotiate
a version number that the code no longer means.

So the rewrite of `src/` docstrings strips those citations **only after** copying them here. The record is kept in
`docs/history/`, which `tools/check_docs.py` treats as exempt: a past measurement restated by hand is drift, but a
past measurement recorded once is history. That exemption is what makes the strip safe rather than lossy.

## How these lines were selected

By AST rather than by grep, so that a version-shaped token inside a string literal, a URL or an IP address could be
seen for what it is. A line was in scope only if it was a comment or a line inside a docstring, and matched at least
one of three patterns: a `0.x.y` citation (including `pre-0.x` phrasing), a one-run probe marker (`MEASURED`, or a
`/tmp/...` probe path), or a release-plan tag (`answer N`, `(0.x.y)`). Each copied line is shown with the docstring
that carried it, named as `<module>::<owner>`, and its position **in the pre-rewrite tree** — that position is where
it was, not where anything is now, and no living document cites it.

Of the version-citing docstring lines in `src/`, 59 were checked against `docs/history/` and found
absent from it; they are copied below. The one line already carried by a frozen history entry is named at the end of
this file rather than duplicated into a section.

## Sections (12 modules)

- `src/mypki/__main__.py`
- `src/mypki/app.py`
- `src/mypki/cli.py`
- `src/mypki/config.py`
- `src/mypki/crl.py`
- `src/mypki/csr.py`
- `src/mypki/inspect.py`
- `src/mypki/ocsp_responder.py`
- `src/mypki/settingsfile.py`
- `src/mypki/signing.py`
- `src/mypki/store.py`
- `src/mypki/validators.py`

## src/mypki/__main__.py

`src/mypki/__main__.py::<module>` — pre-rewrite docstring:

```text
`init-ca --key-type ec` ship broken in 0.1.0 (see CHANGELOG *Fixed*).
```

## src/mypki/app.py

`src/mypki/app.py::<module>` — pre-rewrite docstring:

```text
"Two error surfaces instead of one" (0.2.0) — the name is kept, the count is not: there are three now -- page-map §0
What changed in 0.2.0 was a refusal of something the operator typed into a form field: mistyping `AUSTRALIA` into the
`src/mypki/app.py::_form_fields_multi` — pre-rewrite docstring:

```text
0.3.0's bulk revoke needs this because `/issued` posts N checkboxes all named `serial_hex`, and MEASURED on
`src/mypki/app.py::_dropped_extension_fields` — pre-rewrite docstring:

```text
this CA's CRL or OCSP, which leaves issued before 0.7.0 give no pointer to,
`src/mypki/app.py::_unmanaged_card` — pre-rewrite docstring:

```text
0.4.0 moved this from "a reason list beside the form" to "the place that also states what each knob currently
`src/mypki/app.py::_knob_input` — pre-rewrite docstring:

```text
Which value goes in the box, and why it changed in 0.5.0:
    running, and the field carries `pending_saved` with it so the template can say so in rose. Before 0.5.0 these
`src/mypki/app.py::_settings_status` — pre-rewrite docstring:

```text
0.4.0: the fifth row is why `_settings_source` survived the resolved-state table it used to fill. The table stated
in force may have arrived from the command line rather than from the file this page writes — 0.3.0 could only hint
`src/mypki/app.py::_publish_saved_settings` — pre-rewrite docstring:

```text
Rebuild `Settings` from the layers on disk and make this process use them (0.4.0 hot-reload).
`src/mypki/app.py::_settings_source` — pre-rewrite docstring:

```text
0.4.0 keeps this function while dropping the resolved-state table it used to fill, because it is now what the
anything; comparing the live value against that default is what catches `mypki serve --host 0.0.0.0`, whose Settings
`src/mypki/app.py::home` — pre-rewrite docstring:

```text
0.1.0 led with prose about what mypki is; 0.2.0 led with the signing form plus a CA facts card above it; 0.3.0
`src/mypki/app.py::_issue_from_confirmation` — pre-rewrite docstring:

```text
The subject and SANs, by contrast, now come from the form when the form supplied them (0.2.0). That is the
`src/mypki/app.py::ca_page` — pre-rewrite docstring:

```text
The CA page, now showing the certificate itself next to the facts about it (0.5.0).
its subject, serial and fingerprint here since 0.3.0.
`src/mypki/app.py::crl_artifact` — pre-rewrite docstring:

```text
The URL every certificate issued from 0.7.0 onward carries in its `CRLDistributionPoints`
`src/mypki/app.py::render_issued` — pre-rewrite docstring:

```text
`pending` is the 0.3.0 server-side confirmation step: what the operator selected, named as serial **and** common
`src/mypki/app.py::issued_revoke` — pre-rewrite docstring:

```text
Two steps, both server-side (0.3.0)
`RevocationRecordNotFoundError` and answers 404. That is 0.2.0's measured contract (a single unknown serial was
somewhere keeps working until its own client consults one of those, and a leaf issued before 0.7.0 carries no
`src/mypki/app.py::render_settings` — pre-rewrite docstring:

```text
or the file's own contents after a save. Since 0.4.0 that is also what this process runs with, because a
`src/mypki/app.py::settings_page` — pre-rewrite docstring:

```text
0.2.0 shipped this page read-only, on the reasoning that a page which could edit a limit would need the
logins this project deliberately does not have. 0.3.0 keeps the reasoning and changes the conclusion: the login
`src/mypki/app.py::version_page` — pre-rewrite docstring:

```text
0.2.0 renders `about.html` with the version line as a banner rather than keeping a dedicated home template:
0.1.0's home prose (what mypki is, which pages exist, what it does not do) moved verbatim to `/about`, and a
```

## src/mypki/cli.py

`src/mypki/cli.py::_cli_flag_overrides` — pre-rewrite docstring:

```text
`app.state.cli_overrides` so that `/settings`' hot-reload (0.4.0) can re-apply it after rebuilding from those same
`src/mypki/cli.py::_tls_file_problem` — pre-rewrite docstring:

```text
and `cmd_serve`'s `except OSError` reported it as `error: cannot bind 0.0.0.0:8443: [Errno 2] No such file or
0.5.0 adds the second half: **what the files contain**, not only whether they exist. The operator's next report was
`error: cannot bind 0.0.0.0:8443: [SSL] PEM lib (_ssl.c:4122)` with both knobs pointing at real, readable files.
`src/mypki/cli.py::_tls_spelling` — pre-rewrite docstring:

```text
`Path` has nothing to report beyond `str(path)`, which is the pre-0.5.0 behaviour and still correct on POSIX.
`src/mypki/cli.py::_separator_hint` — pre-rewrite docstring:

```text
0.5.0: this takes the **raw configured text**, not `str(path)`. MEASURED (/tmp/probe5.py): pathlib collapses
```

## src/mypki/config.py

`src/mypki/config.py::get_settings` — pre-rewrite docstring:

```text
0.3.0 adds the second dotenv layer, `<config-dir>/mypki.env`, which is what `/settings` writes (page-map §12). The
```

## src/mypki/crl.py

`src/mypki/crl.py::<module>` — pre-rewrite docstring:

```text
all* — i.e. every certificate this CA issued before 0.7.0, and anything minted elsewhere against it. The plain-CRL
```

## src/mypki/csr.py

`src/mypki/csr.py::_csr_extension_problems` — pre-rewrite docstring:

```text
    for a CA and quietly receives `CA:FALSE` deploys something that does not do what they asked. From 0.7.0 this CA
`src/mypki/csr.py::_key_usage_words` — pre-rewrite docstring:

```text
`keyEncipherment` was absent from 0.1.0 through 0.5.0 (MEASURED: each shipped archive's `csr.py` mentions it zero
`src/mypki/csr.py::_validated_passphrase` — pre-rewrite docstring:

```text
The floor is 8 as of 0.2.0 and the recommendation is 12 (`PASSPHRASE_RECOMMENDED_LENGTH` plus
```

## src/mypki/inspect.py

`src/mypki/inspect.py::<module>` — pre-rewrite docstring:

```text
  * **No revocation lookup.** From 0.7.0 this host publishes a CRL and answers OCSP (`crl.py`, `ocsp_responder.py`,
```

## src/mypki/ocsp_responder.py

`src/mypki/ocsp_responder.py::render_ocsp_response` — pre-rewrite docstring:

```text
the fact that this is a signing oracle reachable over HTTP. It is not implemented in 0.7.0 for two honest reasons:
```

## src/mypki/settingsfile.py

`src/mypki/settingsfile.py::env_file_layers` — pre-rewrite docstring:

```text
exactly as it did in 0.1.0 and 0.2.0; `<config>/mypki.env` is appended, so what `/settings` wrote wins over it.
```

## src/mypki/signing.py

`src/mypki/signing.py::<module>` — pre-rewrite docstring:

```text
Operator-edited subject and SANs (0.2.0) ----------------------------------------- `issue_certificate` now takes
    and walking it back needs a client that consults this CA's CRL or OCSP — which leaves issued before 0.7.0
`src/mypki/signing.py::leaf_extensions` — pre-rewrite docstring:

```text
What changed in 0.7.0 (answer 6 + U4) --------------------------------------------------------
through 0.6.0 and is false from 0.7.0, so it is rewritten in the same commit as the behaviour rather than left as a
certificate it could otherwise honour. And both land only on certificates issued **after** 0.7.0 — no migration, no
`src/mypki/signing.py::issue_certificate` — pre-rewrite docstring:

```text
`subject` and `sans` (0.2.0) replace what the CSR states, for the confirm step where the operator edited those
```

## src/mypki/store.py

`src/mypki/store.py::<module>` — pre-rewrite docstring:

```text
Revocation (0.2.0): what this table records, and what it emphatically is not
an existing row are also the smallest possible migration -- see `init_schema`, which adds them in place so a 0.1.0
`src/mypki/store.py::_ensure_revocation_columns` — pre-rewrite docstring:

```text
Add the two revocation columns to a database created before 0.2.0.
are skipped, missing ones are added nullable, which is what makes every pre-0.2.0 row read back as `active`.
`src/mypki/store.py::init_schema` — pre-rewrite docstring:

```text
it. The two halves answer different releases: a fresh install needs the CREATE, and a 0.1.0 `<data>/issued.db`
`src/mypki/store.py::count_revoked` — pre-rewrite docstring:

```text
§5). That is exactly what 0.7.0's `CRLNumber` needs — RFC 5280 §5.2.1 wants a number that only increases for a
`src/mypki/store.py::revoked_records` — pre-rewrite docstring:

```text
Two rules in one read, both answering 0.7.0's answer 8:
* `revoked_at_utc IS NOT NULL` — including revocations stamped in 0.2.0 through 0.6.0, which is the half of that
`src/mypki/store.py::find` — pre-rewrite docstring:

```text
Added in 0.3.0 for `/issued`'s bulk revoke: the confirmation step has to name every certificate about to be
```

## src/mypki/validators.py

`src/mypki/validators.py::<module>` — pre-rewrite docstring:

```text
and a regex that guesses at IPv6 will both accept invalid addresses and reject valid ones (`::1`, `::ffff:10.0.0.1`).
`src/mypki/validators.py::_is_ip_literal` — pre-rewrite docstring:

```text
not accept as hostnames — which is why `10.0.0.1` becomes an `IPAddress` here rather than a DNS name that a client
would then refuse to match (page-map §9). Leading-zero octets ("10.0.0.01") are rejected by `ipaddress` on purpose:
```

## The one version-citing docstring line already held by frozen history

`src/mypki/settingsfile.py::<module>` carried, pre-rewrite:

```text
Why a file at all (0.3.0)
```

That line is **not** copied above: `docs/history/` already records it, and a record duplicated into a second file is
two records that can disagree. It is listed here so the count of version-citing docstring lines and the count of
lines moved out of `src/` can be reconciled without inventing a third number.

## What this file does not claim

- It does not order these lines by date, severity or importance. They appear in module order because that is how they
  were read out of the tree; a sentence moved out of `app.py` has no rank against one moved out of `store.py`.
- It does not restate any harness total, coverage figure or test count. Those live in the gate output and in
  `reports/harness-ledger.md`, which regenerates.
- It does not say that the stripped citations were wrong. Most of them were accurate when written; they are gone
  because a working-commit file should not be where an accurate statement about a release lives.
