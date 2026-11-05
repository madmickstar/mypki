"""e2e_harness.py — automated walk of SMOKE_TESTING.md §1-§16 against a REAL mypki server.
WHAT THIS IS
  One Python program that boots `mypki init-ca` and `mypki serve` as real subprocesses on an ephemeral port inside a
  throwaway data dir, drives them over a real socket with httpx (imported as `httpx2`, the name starlette's own
  TestClient imports), walks all sixteen numbered sections of SMOKE_TESTING.md in order, and prints a pass/fail/warn
  summary. It replaces `scripts/smoke_test.sh` and `scripts/smoke_test.ps1`: those were one precedence chain and one set
  of needles written twice, in two languages, plus two tools whose only job was to compare the logs they produced. The
  mirror was a drift risk that had to be "taken on purpose" and every release paid for it; one harness has nothing to
  drift against.

WHY PYTHON AND NOT SHELL + CURL
  Both old harnesses carried comments about defects in their own HTTP layer that had to be worked around: curl's `-F`
  silently truncates a multi-line value at its first newline (so every PEM needed the urlencoded form), a TTY-styled
  header dump injected ANSI escapes into the strings being counted, and dash's `printf` has no `\\xNN` escape at all.
  Each of those was a harness bug that read as an app bug until the harness was run. httpx posts urlencoded and
  multipart bodies directly and hands back parsed headers, so the workaround class is gone rather than documented.

WHY THIS IS NOT `tests/`
  The pytest suite drives TestClient — an in-process ASGI call with no socket, no subprocess, no uvicorn bind and no
  real size-guard behaviour. Every assertion here needs the layer TestClient fakes: a server that had to bind a port, a
  cookie jar that survived three POSTs, a middleware that answered 413 before any route ran, and bytes on disk that a
  second process (`openssl`) can read. The suite proves handlers; this proves the running app.

WHY openssl IS PRESENT BUT SKIPPABLE
  `openssl verify` and `openssl crl -noout -text` are the two checks an external toolchain could add, and they SKIP
  (warn) rather than FAIL when openssl is absent: CI's windows-latest legs carry no contract for an OpenSSL binary — "NO
  OpenSSL binary is required anywhere" is a design claim, not an environment accident — so a harness that needed openssl
  would fail on the platform whose green run is the point. Everything else here needs no toolchain: `cryptography` reads
  the same DER.

THE EXIT CODES (the repo's convention: "not checked" is NOT "checked and clean")
  0  every check passed (warnings allowed, and listed in the summary)
  1  at least one FAIL — a real defect in what you are testing
  2  NOTHING WAS CHECKED: the server never came up. Never read this as a pass.

WHAT IS COUNTED
  Every assertion is one count, and the summary prints what actually ran. No expected total appears anywhere in this
  file: a hand-copied number would be a second copy of a fact that only a run can answer — which is exactly what the
  deleted measurement-history layer existed to police.

USAGE
  tools/e2e_harness.py                 # boots its own CA + server in a throwaway tree, cleans up after itself
  tools/e2e_harness.py --work DIR      # keep the scratch tree (pages, PEMs, logs) for inspection
  tools/e2e_harness.py --keep-data     # also keep the scratch DATA dir (it holds a real CA key — delete it yourself)
  tools/e2e_harness.py --openssl PATH  # name an openssl binary explicitly
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import html as html_module
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import httpx2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp as ocsp_api

BUILD_ROOT = Path(__file__).resolve().parent.parent
VERSION_FILE = BUILD_ROOT / "src" / "mypki" / "__init__.py"

#: Where this harness writes the numbers it just measured. `reports/` is gitignored (.gitignore), which is the point:
#: a run's totals are a property of one machine on one day, and committing them freezes them as if they described the
#: release. The old arrangement wrote a *markdown* ledger through a separate tool, now deleted, that had to be pointed
#: at a log file by hand — two commands where one run already knows the answer. This writes JSON,
#: because the harness is the only thing in the repo that knows which assertions it actually executed, and a document
#: quoted from memory is how SMOKE_TESTING.md's numbers went stale three times. `make gate` runs this harness, so on any
#: gated tree the file is the current measurement rather than a note about an old one.
LEDGER_PATH = BUILD_ROOT / "reports" / "harness-ledger.json"

#: mypki's own default CA subject. §9's needle is this string because the documented run is a plain `init-ca`; naming a
#: scratch CA something else makes that one check need the same rename (SMOKE_TESTING.md §9 records exactly that trap).
CA_CN = "mypki Root CA"

CSR_BEGIN = "-----BEGIN CERTIFICATE REQUEST-----"
CSR_END = "-----END CERTIFICATE REQUEST-----"

#: The two §16 fixtures, embedded rather than minted with openssl so this section runs wherever the other fifteen run.
# Both are real `openssl req` output (their self-signatures verify under `openssl req -verify`): `consent.csr` is what a
# distro `[v3_req]` puts into **every** request an operator makes, and `privileged.csr` is the half that must stay
# refused.
CONSENT_CSR = """-----BEGIN CERTIFICATE REQUEST-----
MIICzzCCAbcCAQAwQzEaMBgGA1UEAwwRY29uc2VudC5sYWIubG9jYWwxGDAWBgNV
BAoMD29wZW5zc2wgZGVmYXVsdDELMAkGA1UEBhMCWFgwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCZxiYiBOydULHFDfITyPMKCbYftXoi1+iXdq6ZQVxb
p8WFTqhtRAZSSWxOYDT+HTkqKLz0bl6lLXt1xRll4JAfw5FpRcNbIsG0HWyv5MBR
bdjnwQ/KA6fnB3dsrvxT/5QgnPEDPMRNLx+nR8bsEHj4mkbHaHRlyEqttZr4joxj
H5yTzVEA2TwYX5YTLcejdu1Q2vol2zhDUknbmff6N69L0x/hzNjkebXysmfAMzJa
kJMr2+giRRwOQWnWGwD+YurozPmMp+Z4L+S6u5JOs2Lh0iQ49l/UYZ1cPe2AwFhH
AgMo2zV9k9VIpjdmhONqETvBrt8SNTjniNeWeTnB3mSJAgMBAAGgRzBFBgkqhkiG
9w0BCQ4xODA2MAkGA1UdEwQCMAAwCwYDVR0PBAQDAgWgMBwGA1UdEQQVMBOCEWNv
bnNlbnQubGFiLmxvY2FsMA0GCSqGSIb3DQEBCwUAA4IBAQBc/pBoCSms9OXT3s8r
/1vXm16EOzcdibE45e5o6F+GuNWUpKJhSn7CytQK6jdZmsBe2b+HP4uNOJq/j5pi
2X/owzhJiGV8B7otIdZYzhn6IwtHsr9terJbPg1I2jWx1cOI7dm3SMm/HnLTa2wJ
jEPR617x2yWnD0XqS86Cm8MrK6VPzxcNNUIx/m4ZdyhRn6OoLgFwF+NSfOgXF2RY
VUbIthxS1uQSXDx9k1+PNx6HtrcrodcxEDFwXKdS3XbCWTwXVuTkK34X1z0zMJwm
ngr0+3PvgxfvkvfGb7wx9FbIVeXhXq1pRlIpgpAE0D/zvVQbDklLzHiZLD0dMwPF
Q9sq
-----END CERTIFICATE REQUEST-----
"""

PRIVILEGED_CSR = """-----BEGIN CERTIFICATE REQUEST-----
MIIC3jCCAcYCAQAwRjEdMBsGA1UEAwwUcHJpdmlsZWdlZC5sYWIubG9jYWwxGDAW
BgNVBAoMD29wZW5zc2wgZGVmYXVsdDELMAkGA1UEBhMCWFgwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQCoU9Mt0/5pjUGTvFaO0WgSzenVrUDlRC+WIsK2
nwNhteUTGu7+fnQHp2onMUqRb+GajibefxJ1Rz8hRIApTq/phzx/NGLnT2DHCv0Q
BxUwHbpti+s8nPkf5pVghFC4/5pnGnHFa/5kmX1PMttbQ7v8RfeiYoXt/F57J/la
KFNemvd5mAGzF9HPZdwEeV8QgzwZVg3O3FFuZ4eU8JR/H2SOkRRVoaSEeoF4I4Qu
fRaHoyZoHoiaDHcAkGfOfYZKek5796/8yJSevf1p1dJJNqZabrbcg8RUneLURytK
Pvi5UgxCNk3W9Ct+rRc7XccxL72eRUmnkb5O2Qy0xHZP5s8JAgMBAAGgUzBRBgkq
hkiG9w0BCQ4xRDBCMA8GA1UdEwQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMB8G
A1UdEQQYMBaCFHByaXZpbGVnZWQubGFiLmxvY2FsMA0GCSqGSIb3DQEBCwUAA4IB
AQCMAFypNU0iOfLfA7gSJMN02qtIgyy5c4OxBdkZLfjv0VXUFxCBbyoJlwBtufjo
qCjsh2d+faWeEY1sEWhNO520GDNaXqDunPE74vpropSss4I403taVX0uKmiYqlJt
N5QYDenFqz2eF9HUyI6V1ERgPJjr0KpDBkdBOfLR5jmllWs40atMyykTONZ477pN
iQYN5d9+9/9ZUo2mRaukoWo0wN73c8X15wd3jZmow4/q/WyMZ+p+Avvxj+MmzZVk
OB/RRUN4VT4keEGyIW3ulyHKtubkMnv6I0zO7WF9aRxXXj090bKuFbQWaH+cFrDi
LzMxM2kqfEvWhd9fj53CKi5Z
-----END CERTIFICATE REQUEST-----
"""

#: §11's deliberately-unknown serial. It is only ever submitted **inside a batch**: a lone unknown serial keeps its own
# 404 contract, which `tests/test_views.py` asserts.
BOGUS_SERIAL = "deadbeefcafebabf"


# ============================================================================================== counting helpers


def joined(text: str) -> str:
    """Newlines-plus-indentation collapsed to one space. Several needles are sentences the Jinja templates wrap
    mid-clause, and a plain `str.count` on the raw body reads 0 against a page that renders them. This is the
    normalisation the shell harness called `count_joined`, kept because the wrapping is a property of the template files
    rather than of the harness."""
    return re.sub(r"\n\s*", " ", text)


def count(hay: str, needle: str) -> int:
    """Occurrence count, never line count: `grep -c` answers "how many lines contain it", which reads 1 for a full table
    and for an empty `<pre>` alike depending on where the pattern sits."""
    return hay.count(needle)


def count_re(hay: str, pattern: str) -> int:
    return len(re.findall(pattern, hay))


def count_joined(text: str, needle: str) -> int:
    return joined(text).count(needle)


def pem_block(text: str, marker: str) -> str | None:
    """The first `-----BEGIN marker----- … -----END marker-----` block in `text`, HTML entities un-escaped first.
    Jinja's autoescape is pinned on in app.py, so a PEM inside `<pre>` arrives as `&lt;`/`&gt;`. Unescaping the whole
    page before slicing (rather than the slice) is what keeps `&amp;lt;` from decoding twice into a character that was
    never there."""
    unescaped = html_module.unescape(text)
    match = re.search(
        r"-----BEGIN " + re.escape(marker) + r"-----.*?-----END " + re.escape(marker) + r"-----",
        unescaped,
        re.DOTALL,
    )
    return match.group(0) if match else None


def pem_der_sha(block: str, marker: str = "CERTIFICATE") -> str | None:
    """sha256 of the DER **inside** a PEM block, not of the text of the block. Comparing text would report a difference
    that is only a trailing newline: the page copy arrives through an HTML decoder and the download through httpx, and
    their newline handling differs. Decoding asks the question that matters — "is this the same certificate?" — and
    answers it identically on both halves of the comparison."""
    match = re.search(
        r"-----BEGIN " + re.escape(marker) + r"-----(.*?)-----END " + re.escape(marker) + r"-----",
        block,
        re.DOTALL,
    )
    if not match:
        return None
    try:
        der = base64.b64decode(re.sub(r"\s+", "", match.group(1)))
    except Exception:  # a malformed block is an assertion result, not a traceback from the harness
        return None
    return hashlib.sha256(der).hexdigest()


def scoped_serial(page: str) -> str | None:
    """The leaf serial from the issued card, scoped to that card. `/csr/sign` also renders the CA facts strip, whose
    serial cell is spelled identically (`<td class="mono">…`), so a page-wide search returns the **CA's** serial and
    every later assertion then addresses the wrong certificate — this exact mistake happened in `tests/test_views.py`
    first. The window runs from `<h2>Issued:` to the card's own `</table>` rather than a fixed line count: §16's
    dropped-extension block puts the serial row further down than an earlier 15-line window allowed, and a failed
    assertion against a page that renders the serial is worse than no assertion."""
    match = re.search(r"<h2>Issued:.*?</table>", page, re.DOTALL)
    if not match:
        return None
    found = re.search(r'<td class="mono">([0-9a-f]{8,})<', match.group(0))
    return found.group(1) if found else None


def checkbox_serials(page: str) -> list[str]:
    """Every `type="checkbox" name="serial_hex"` value in page order. §11 needs a second and third one to prove
    multi-select is real rather than a single-row form wearing a checkbox."""
    return re.findall(r'type="checkbox" name="serial_hex" value="([0-9a-f]+)"', page)


def pending_id(page: str) -> str | None:
    """The staged request's opaque id, read out of the confirm form's action URL (not out of a cookie)."""
    match = re.search(r'action="/csr/sign\?pending=([^"]+)"', page)
    return match.group(1) if match else None


def csrf_token(page: str) -> str | None:
    match = re.search(r'name="csrf_token" value="([^"]+)"', page)
    return match.group(1) if match else None


def settings_form_body(page: str, overrides: dict[str, str]) -> dict[str, str]:
    """Rebuild the /settings POST body from the page that rendered it, with named overrides applied afterwards.
    Two traps this exists to avoid, both measured by the harness it replaces:

    * **A knob *missing* from the body is not refused as "was not submitted".** `app._submitted_settings_fields` fills
      every editable knob the body omitted with `''` (or `false` for the one checkbox), so deleting a field lands on a
      valid value and **writes the operator's real config file** — from a script whose job is only to look. That is why
      knobs are posted empty explicitly rather than dropped, and why no successful save is exercised here at all.
    * **The body has to be scraped from the page, never typed out.** Several knobs legitimately render `value=""`
      (log_file, public_base_url, the six subject defaults), and `settings.html` splits each `<input>` across five lines
      — without joining newlines first only the name line matches, most knobs vanish from the body, and the app
      correctly answers "was not submitted" for a page that did render them.
    """
    joined_page = joined(page)
    fields: dict[str, str] = {}
    for tag in re.findall(r"<input\b[^>]*>", joined_page):
        name = re.search(r'name="(MYPKI_[A-Za-z0-9_]+|csrf_token)"', tag)
        if not name:
            continue
        value = re.search(r'value="([^"]*)"', tag)
        fields[name.group(1)] = value.group(1) if value else ""
    for checkbox in re.findall(r'<input type="checkbox"[^>]*name="(MYPKI_[A-Za-z0-9_]+)"', joined_page):
        # An unticked checkbox posts nothing at all; app.py turns that into an explicit `false` for the one bool knob.
        fields.setdefault(checkbox, "")
    fields.update(overrides)
    return fields


def knob_bound(page: str, knob: str, which: str) -> str | None:
    """A bound read off the control the page itself renders (`min=`/`max=`), which app.py fills from the same
    `Field(ge=…, le=…)` metadata pydantic enforces. Asserting a refusal against THIS number rather than a literal keeps
    the harness and config.py on one fact: move the knob in config.py and both the input's `max=` and the expected
    sentence move with it."""
    joined_page = joined(page)
    for tag in re.findall(r"<input\b[^>]*>", joined_page):
        if re.search(r'name="' + re.escape(knob) + r'"', tag):
            match = re.search(which + r'="([0-9]+)"', tag)
            return match.group(1) if match else None
    return None


def file_state(path: Path) -> str:
    """The state of the file a save writes, fingerprinted so "nothing was written" is an assertion rather than a hope.
    `absent` is a real state (a host that has never saved anything), and comparing two fingerprints catches both a
    change and a creation."""
    if not path.exists():
        return "absent"
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ==================================================================================================== reporting


class Report:
    """Counts what ran. No expected total appears anywhere in this file. `warn` is a real third state and not a soft
    pass: it names an assertion that could not run because an earlier section left nothing to assert about. The shell
    harness's most valuable lesson (SMOKE_TESTING.md §11) was that a WARN-skip and a relaxed needle look identical from
    the summary line — which is why §6 seeds two certificates rather than §11 relaxing its `>= 3` needles. A skip has to
    stay visible as a skip."""

    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0
        self.warned = 0
        self.failures: list[str] = []
        self.warnings: list[str] = []
        self.section_names: list[str] = []
        self.totals: dict[str, list[int]] = {}
        self.current = ""

    def section(self, name: str) -> None:
        self.current = name
        self.section_names.append(name)
        self.totals.setdefault(name, [0, 0, 0])
        print(name)

    def _tally(self, kind: int) -> None:
        self.totals[self.current][kind] += 1

    def check(self, label: str, ok: bool) -> bool:
        if ok:
            self.passed += 1
            self._tally(0)
            print(f"  PASS  {label}")
        else:
            self.failed += 1
            self._tally(1)
            self.failures.append(f"[{self.current}] {label}")
            print(f"  FAIL  {label}")
        return ok

    def warn(self, label: str) -> None:
        self.warned += 1
        self._tally(2)
        self.warnings.append(f"[{self.current}] {label}")
        print(f"  WARN  {label}")

    def summary(self) -> int:
        total = self.passed + self.failed + self.warned
        print()
        print("== per-section assertions ==")
        for name in self.section_names:
            passed, failed, warned = self.totals[name]
            print(f"  {name}: {passed} pass / {failed} fail / {warned} warn")
        print()
        print(f"== summary: {self.passed} pass, {self.failed} fail, {self.warned} warn ({total} assertions) ==")
        if self.failures:
            print("FAILURES:")
            for failure in self.failures:
                print(f"  - {failure}")
        if self.warnings:
            print("WARNINGS:")
            for warning in self.warnings:
                print(f"  - {warning}")
        self.write_ledger()
        return 1 if self.failed else 0

    def write_ledger(self) -> None:
        """Write this run's counts to `reports/harness-ledger.json`, then say where they are.

        Written even on a failing run: the numbers that explain a FAIL are the ones worth keeping. Nothing here is
        asserted — this is a record, not a gate, and it never changes the exit code, so a filesystem problem cannot turn
        a green harness red (or hide a red one). The section list keeps insertion order rather than sorting, because the
        order *is* the walk: §11's counts only mean something after §6 seeded the records they revoke.
        """
        payload = {
            "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "harness": "tools/e2e_harness.py",
            "totals": {"pass": self.passed, "fail": self.failed, "warn": self.warned},
            "assertions": self.passed + self.failed + self.warned,
            "sections": [
                {"name": name, "pass": counts[0], "fail": counts[1], "warn": counts[2]}
                for name, counts in ((name, self.totals[name]) for name in self.section_names)
            ],
            "failures": self.failures,
            "warnings": self.warnings,
        }
        try:
            LEDGER_PATH.parent.mkdir(parents=True, exist_ok=True)
            LEDGER_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        except OSError as exc:
            # Named rather than swallowed: a run whose numbers were not written is a run nobody can quote later.
            print(f"  WARN  could not write {LEDGER_PATH}: {exc}")
            return
        print(f"ledger written: {LEDGER_PATH} (gitignored — one machine's measurement, not the release's)")


# ==================================================================================================== the harness


class Harness:
    """Everything a section needs: the live base URL, one cookie jar, the scratch work dir and the counter."""

    def __init__(self, report: Report, base: str, work: Path, version: str) -> None:
        self.report = report
        self.base = base
        self.work = work
        self.version = version
        # trust_env=False: with it httpx reads HTTP(S)_PROXY / NETRC out of the ambient environment and could dial the
        # loopback server through a proxy that is not there. The point of this harness is that these bytes crossed one
        # socket, so the route has to be the direct one. follow_redirects=False: a redirect would hide a 3xx where a
        # section expects a status.
        self.client = httpx2.Client(
            base_url=base, cookies=httpx2.Cookies(), follow_redirects=False, timeout=60.0, trust_env=False
        )
        self.state: dict[str, Any] = {}
        self._page_keys: dict[str, list[str]] = {}

    def close(self) -> None:
        self.client.close()

    # --------------------------------------------------------------------------------------------- request plumbing

    def get(self, path: str) -> httpx2.Response:
        response = self.client.get(path)
        self._save(path, response)
        return response

    def post(
        self,
        path: str,
        fields: dict[str, Any] | None = None,
        *,
        multipart_files: dict[str, str] | None = None,
        raw_body: bytes | None = None,
        content_type: str | None = None,
    ) -> httpx2.Response:
        """One POST, shaped the way a browser or a protocol client shapes it. `fields` is always sent urlencoded, which
        is what a browser posts for every form in this app (no template sets an `enctype`), and it is also the only
        shape that carries a multi-line PEM intact. The shell harness needed two helpers because curl's `-F` truncates a
        multi-line value at its first newline — a defect in the tool that read as "the sign page is broken" and had to
        be documented above both `post_form` and `post_pem`. Here there is one default and it cannot be picked wrongly.
        `multipart_files` sends named fixtures as multipart parts alongside `fields`, which is the other body shape
        `_form_fields` accepts (it is what curl's `-F` produced). It is used at exactly one call site, §7's
        file-part probe, so both shapes are exercised over a real socket rather than assumed — and that probe records
        what the shape costs: a part arrives as an `UploadFile`, `_form_fields` stringifies it, and no PEM is parsed.
        A field whose value is a **list** is
        sent as repeated form fields, which is what a browser's own checkbox group posts (§11's bulk revoke of three
        serials)."""
        if raw_body is not None:
            response = self.client.post(
                path, content=raw_body, headers={"content-type": content_type or "application/octet-stream"}
            )
            self._save(path, response)
            return response

        data: dict[str, Any] = {}
        for name, value in (fields or {}).items():
            data[name] = [str(item) for item in value] if isinstance(value, list) else str(value)

        files: dict[str, tuple[str, str, str]] = {}
        for name, filename in (multipart_files or {}).items():
            body = Path(filename).read_text(encoding="utf-8")
            files[name] = (Path(filename).name, body, "application/octet-stream")

        response = self.client.post(path, data=data, files=files) if files else self.client.post(path, data=data)
        self._save(path, response)
        return response

    def _save(self, path: str, response: httpx2.Response) -> None:
        """Keep every fetched body on disk. §14's armour sweep and §15's block-scoping are more useful while the pages
        that were actually served can be opened and read; a failure saying "the page did not contain X" should be
        checkable."""
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", path.split("?")[0].lstrip("/")) or "root"
        keys = self._page_keys.setdefault(safe, [])
        key = f"{safe}-{len(keys) + 1}"
        keys.append(key)
        (self.work / f"{key}.html").write_text(response.text, encoding="utf-8")

    def body_of(self, path: str) -> str:
        """The most recent body fetched from `path` (query strings ignored): sections reuse the page a browser would
        still be showing rather than re-fetching it."""
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", path.split("?")[0].lstrip("/")) or "root"
        keys = self._page_keys.get(safe, [])
        if not keys:
            return ""
        return (self.work / f"{keys[-1]}.html").read_text(encoding="utf-8")

    def write_fixture(self, name: str, content: str) -> Path:
        path = self.work / name
        path.write_text(content, encoding="utf-8")
        return path

    # --------------------------------------------------------------------------------------------- assertions

    def check(self, label: str, ok: bool) -> bool:
        return self.report.check(label, ok)

    def warn(self, label: str) -> None:
        self.report.warn(label)

    def expect_status(self, label: str, response: httpx2.Response, *codes: int) -> bool:
        """One assertion per status check. On a miss the actual code is printed inside the same label, because "answered
        500" and "answered 404" are different diagnoses and a bare FAIL makes the reader guess."""
        got = response.status_code
        wanted = "/".join(str(code) for code in codes)
        return self.check(f"{label} answers {wanted} (got {got})", got in codes)

    def count_at_least(self, label: str, hay: str, needle: str, minimum: int = 1) -> bool:
        found = count(hay, needle)
        return self.check(
            label if found >= minimum else f"{label} (found {found}, expected >= {minimum})", found >= minimum
        )

    def count_exactly(self, label: str, hay: str, needle: str, expected: int) -> bool:
        found = count(hay, needle)
        return self.check(
            label if found == expected else f"{label} (found {found}, expected exactly {expected})", found == expected
        )

    def count_zero(self, label: str, hay: str, needle: str) -> bool:
        found = count(hay, needle)
        return self.check(label if found == 0 else f"{label} (found {found}, expected zero)", found == 0)

    def joined_at_least(self, label: str, text: str, needle: str) -> bool:
        found = count_joined(text, needle)
        return self.check(label if found >= 1 else f"{label} (found {found}, expected >= 1)", found >= 1)


# ================================================================================================= §1 home page


def section_1(app: Harness) -> None:
    app.report.section("§1 Home page (page-map §1)")
    response = app.get("/")
    if not app.expect_status("GET /", response, 200):
        return
    home = response.text

    # As of 0.3.0 there is no CA card on `/`: every fact lives on `/ca` alone (§9), and §1 asserts each of them ABSENT
    # here. A home page that grew the card back would still answer 200 and every other §1 check would still pass, so
    # absence is the only way to catch the drift. 'BasicConstraints' rather than 'CA:TRUE pathLength:0': csr_sign.html
    # legitimately renders `BasicConstraints CA:FALSE` for a STAGED request — what must be absent is any
    # BasicConstraints line with nothing staged.
    app.count_zero("home no longer prints the CA subject (page-map §1: /ca carries the CA facts alone)", home, CA_CN)
    fingerprint = count_re(home, r"([0-9A-F]{2}:){31}[0-9A-F]{2}")
    app.check(
        f"home shows no fingerprint (a leaf's own appears on /csr/sign after a signing; §6 asserts it) — found"
        f" {fingerprint}",
        fingerprint == 0,
    )
    app.count_zero("home prints no BasicConstraints line with nothing staged", home, "BasicConstraints")
    app.count_zero(
        "home does not report CA key presence (that boolean lives on /ca, §9)", home, "private key on this host"
    )

    # `/` IS the sign form rather than a prose page: `/` and `/csr/sign` render one shared template, and a leftover
    # home.html would still answer 200 while being a second document that drifts.
    app.count_at_least(
        "home is the sign form, not prose (page-map §1; heading renamed from 'Sign a certificate signing request')",
        home,
        "<h1>Sign a certificate</h1>",
    )
    app.count_at_least(
        "the sign page states the CA-power refusal in one line under the heading",
        home,
        "CSR requesting CA powers will be refused.",
    )
    app.count_at_least("home offers the paste form directly", home, "Paste a CSR (PEM)")


# ============================================================================== §2 security headers over real HTTP


def section_2(app: Harness) -> None:
    app.report.section("§2 Security headers (page-map §0)")
    # GET, not HEAD: mypki declares GET-only routes, so HEAD answers 405 and its headers describe a request that never
    # happened.
    response = app.get("/")
    headers = {key.lower(): value for key, value in response.headers.items()}

    for name, value in (
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "same-origin"),
    ):
        app.check(f"response carries {name}: {value}", headers.get(name) == value)

    csp = headers.get("content-security-policy", "")
    app.check("CSP starts with default-src 'self'", csp.startswith("default-src 'self'"))
    app.check("CSP contains no unsafe-inline (page-map §0 forbids it)", "unsafe-inline" not in csp)

    # 0.3.0 ships exactly ONE script, same-origin, linked with <script src>. Both halves are asserted because they are
    # two different promises: `default-src 'self'` with no unsafe-inline only holds if nothing is inlined, and a page
    # that lost its link would lose its copy buttons silently while every flow in this harness kept passing. The script
    # is asserted as an ASSET and never as a requirement — everything here ran without executing it.
    home = response.text
    app.count_zero("no inline <script> on the home page (its own CSP forbids unsafe-inline)", home, "<script>")
    app.count_at_least("the home page links its script with <script src>", home, "<script src=")

    static = app.get("/static/app.js")
    if app.expect_status("GET /static/app.js", static, 200):
        js_headers = {key.lower(): value for key, value in static.headers.items()}
        app.check(
            "app.js is served as text/javascript (a browser refuses a script served as text/plain)",
            js_headers.get("content-type", "").startswith("text/javascript"),
        )
        app.check(
            "the static response carries the same CSP as the pages (a static route bypassing the middleware would be"
            " the hole)",
            js_headers.get("content-security-policy", "").startswith("default-src 'self'"),
        )

    css = app.get("/static/style.css")
    if not app.expect_status("GET /static/style.css", css, 200):
        return
    css_headers = {key.lower(): value for key, value in css.headers.items()}
    app.check(
        "style.css is served as text/css (a browser refuses a stylesheet served as text/plain)",
        css_headers.get("content-type", "").startswith("text/css"),
    )
    app.check(
        "the stylesheet response carries the same CSP as the pages",
        css_headers.get("content-security-policy", "").startswith("default-src 'self'"),
    )

    # What CANNOT be asserted from here is what any of this looks like on screen: no browser has ever rendered a page in
    # this harness. Every assertion below is about the text of the served asset, never about its rendering — the labels
    # say "the served stylesheet defines", never "the page looks like".
    body = css.text
    app.count_exactly(
        "the served stylesheet defines .pending-saved — the 0.5.0 pending sentence is styled",
        body,
        ".pending-saved {",
        1,
    )
    app.count_at_least(
        ".pending-saved reuses the existing --rose colour rather than introducing one", body, "var(--rose)"
    )
    app.count_exactly(
        "the served stylesheet lifts the 46rem cap for /inspect's form only (scoped by .inspect-form, not by"
        " .settings-form)",
        body,
        "form.stacked.inspect-form { max-width: none; }",
        1,
    )
    app.count_exactly(
        "the served stylesheet widens #pem_paste to its section",
        body,
        "form.inspect-form #pem_paste { width: 100%; max-width: none; }",
        1,
    )
    app.count_exactly(
        "/inspect's submit button follows its field instead of sitting half-width under it",
        body,
        "form.inspect-form button.save-settings { max-width: none; }",
        1,
    )
    app.count_zero(
        "no rule widens .settings-form textareas globally (a fix scoped to /inspect did not leak into /settings)",
        body,
        ".settings-form .field textarea",
    )

    # The template half, fetched here rather than borrowed from §15: a CSS rule whose class is missing from the markup
    # styles nothing, and the two halves of this fix live in different files. The GET is not an assertion — only its
    # class count is.
    inspect_page = app.get("/inspect")
    if inspect_page.status_code != 200:
        app.check(
            f"GET /inspect answered {inspect_page.status_code} while checking the stylesheet's scoping target", False
        )
    else:
        app.count_exactly(
            "/inspect's form carries the class those three rules are scoped to",
            inspect_page.text,
            'class="settings-form stacked inspect-form"',
            1,
        )


# ==================================================================================================== §3 version


def section_3(app: Harness) -> None:
    app.report.section("§3 Version (read from __init__.py, never hard-coded here)")
    # The expected version comes from src/mypki/__init__.py — the same anchored line hatchling reads. A literal here
    # would be a second copy of a fact that has exactly one source, and it rots on the first release. This step exists
    # so every other result in this run can be attributed to a specific build: if §3 disagrees with the checkout you are
    # reading, the server you are testing is not this code.
    response = app.get("/version")
    app.expect_status("GET /version", response, 200)
    app.count_at_least(f"the running app reports version {app.version}", response.text, f"mypki {app.version}")


# ============================================================================================ §4 no API surface


def section_4(app: Harness) -> None:
    app.report.section("§4 No API surface (docs_url/redoc_url/openapi_url are None)")
    # FastAPI(debug=False, docs_url=None, redoc_url=None, openapi_url=None) is hard-coded in app.py, not configurable:
    # there is no API to advertise and therefore no schema describing routes that could be called without a CSRF token.
    # A 200 here means someone made the app configurable, which is the defect this step exists to catch.
    for path in ("/docs", "/redoc", "/openapi.json"):
        response = app.get(path)
        app.check(f"{path} is not served ({response.status_code})", response.status_code in (404, 405))


# =================================================================================================== §5 generate CSR


def section_5(app: Harness) -> None:
    app.report.section("§5 Generate CSR (page-map §2)")
    form = app.get("/csr/generate")
    token = csrf_token(form.text)
    if not app.check("the generate form carries a CSRF token", token is not None):
        return

    refused = app.post("/csr/generate", {"common_name": "nocsrf.internal", "key_type": "rsa-2048"})
    app.expect_status("POST without a CSRF token", refused, 400)
    app.count_zero("the CSRF-rejected POST returned no key material", refused.text, "PRIVATE KEY")

    generated = app.post(
        "/csr/generate",
        {
            "csrf_token": token,
            "common_name": "web.internal",
            # A newline-separated textarea value posted urlencoded — exactly what the browser sends for this field.
            "sans": "web.internal\n*.lab.local\n10.0.0.7",
            "organization": "Acme",
            "country": "DE",
            "key_type": "rsa-2048",
        },
    )
    if not app.expect_status("POST /csr/generate", generated, 200):
        return
    body = generated.text
    app.count_exactly("exactly one CSR PEM block shown", body, CSR_BEGIN, 1)
    app.count_exactly("exactly one private key block shown", body, "-----BEGIN PRIVATE KEY-----", 1)
    if not (
        app.count_at_least("the page states the output is stored nowhere", body, "stored nowhere")
        or app.count_at_least("the page states the output is stored nowhere", body, "not stored anywhere")
    ):
        app.warn("the page lacks the 'stored nowhere' warning")
    app.count_exactly("a private-key download link is offered", body, "Download private key", 1)
    app.count_at_least("the IP SAN survived generation as an IP general name", body, "10.0.0.7")

    csr = pem_block(body, "CERTIFICATE REQUEST")
    if csr is None:
        app.check("could not extract the generated CSR from the page", False)
        return
    text = csr + "\n"
    app.write_fixture("generated.csr", text)
    app.state["generated_csr"] = text
    app.check(
        f"the extracted CSR is a single well-formed block ({len(text.encode())} bytes)",
        count(csr, CSR_BEGIN) == 1 and count(csr, CSR_END) == 1,
    )
    try:
        request = x509.load_pem_x509_csr(text.encode())
        # `Extensions`, not `Attributes`: a CSR's extension block is reached through `.extensions`, and the shell
        # harness never had to make this call because it only ever grepped the PEM text.
        sans = request.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        app.check(
            "the CSR carries the IP SAN as an IPAddress general name, not a DNS entry typed as an IP",
            any(isinstance(item, x509.IPAddress) for item in sans),
        )
    except Exception as exc:  # a fixture that will not parse is a result to report, not a traceback to raise
        app.check(f"the extracted CSR does not parse as a certificate request: {exc}", False)


# ===================================================================================================== §6 sign CSR


def _sign_round_trip(app: Harness, csr_text: str) -> tuple[httpx2.Response | None, httpx2.Response | None]:
    """Step A (stage + show) then step B (confirm + issue). Returns both pages; staging signs nothing. The PEM goes
    urlencoded so a multi-line block arrives whole — the property the shell harness had to encode in a helper name and
    could get wrong by calling the other helper."""
    sign_form = app.get("/csr/sign")
    token = csrf_token(sign_form.text)
    if token is None:
        return None, None
    app.state["token"] = token
    app.write_fixture("paste.csr", csr_text)
    step_a = app.post("/csr/sign", {"csrf_token": token, "csr_pem": csr_text})
    if step_a.status_code != 200:
        return step_a, None
    staged = pending_id(step_a.text)
    if staged is None:
        return step_a, None
    confirm = app.post(
        f"/csr/sign?pending={staged}",
        {"csrf_token": token, "confirm": "1", "cert_type": "server", "validity_days": "30"},
    )
    return step_a, confirm


def section_6(app: Harness) -> None:
    app.report.section("§6 Sign CSR (page-map §3)")
    generated = app.state.get("generated_csr")
    if not generated:
        app.warn("§5 produced no CSR, so the whole signing round trip could not run")
        return

    # SEED, before anything is asserted about the ledger. §11 needs THREE active records on this host: one for its own
    # round trip and two more for multi-select. On a fresh data dir exactly one record exists by this point, so steps
    # C-E used to WARN-skip and then the `>= 3` needles below them failed against a correct app. Signing is idempotent
    # per request (re-signing this same CSR yields distinct serials), so two extra round trips cost four POSTs and no
    # key generation. Done BEFORE §6's own signing on purpose: /issued is newest-first, so seeding afterwards would push
    # §6's record off the first row and break `row_serial == issued_serial`.
    seeded = 0
    for seed in (1, 2):
        step_a, issue = _sign_round_trip(app, generated)
        if issue is not None and issue.status_code == 200:
            seeded += 1
        else:
            app.check(f"seed {seed} did not complete — §11's multi-select checks will WARN-skip", False)
    if seeded == 2:
        app.check(f"two extra certificates seeded so §11 has a real multi-select ledger ({seeded})", True)
    else:
        app.warn(
            f"seeded only {seeded} extra certificate(s); §11's multi-select checks may WARN-skip instead of asserting"
        )

    step_a, issued = _sign_round_trip(app, generated)
    if step_a is None:
        app.warn("the sign form carried no CSRF token, so §6 could not run")
        return
    app.expect_status("step A (validate + show details)", step_a, 200)
    confirm = step_a.text
    app.count_at_least("the confirmation panel shows the parsed CN/SAN", confirm, "web.internal")
    app.count_at_least("the wildcard SAN is shown as validated, not rejected", confirm, "*.lab.local")
    app.count_at_least("the confirmation panel reports the key spec (RSA 2048)", confirm, "RSA 2048")

    # The provenance split lives inside the confirm form; step B re-renders /csr/sign with only the issued card.
    # Asserting it on the issued card fails against a correct app (measured: 1 occurrence in the confirm body, 0 in the
    # issued body). 0.1.0's line "Only the SANs above are copied from your request" was inaccurate and must be absent:
    # CN/O/OU/C/ST/L/email DO come from the request, and since 0.2.0 they may come from the operator's edits instead.
    app.count_at_least(
        "the confirm form states which parts never come from the request",
        confirm,
        "Set by mypki, never from the request",
    )
    app.count_zero(
        "the inaccurate 'only the SANs' wording is gone from the confirm form",
        confirm,
        "Only the SANs above are copied",
    )

    if issued is None:
        app.warn("step B produced no response, so the issued-card assertions could not run")
        return
    app.expect_status("step B (confirm + issue)", issued, 200)
    card = issued.text
    app.count_at_least("a signed certificate is rendered", card, "-----BEGIN CERTIFICATE-----")
    app.count_exactly("a chain download is offered as well as the leaf", card, "Download chain", 1)
    app.check(
        "the issued certificate's fingerprint is displayed (colon-grouped)",
        count_re(card, r"([0-9A-F]{2}:){31}[0-9A-F]{2}") >= 1,
    )

    serial = scoped_serial(card)
    if not app.check(f"the issued card reports a leaf serial ({(serial or 'none')[:12]}…)", serial is not None):
        return
    app.state["issued_serial"] = serial
    leaf = pem_block(card, "CERTIFICATE")
    if leaf is not None:
        app.state["leaf_pem"] = leaf + "\n"
        app.write_fixture("leaf.pem", leaf + "\n")

    # THE NAME IS IN THE HEADER, NOT THE PAGE. SMOKE_TESTING.md §6 records the measured leaf/chain filenames as
    # `web-internal.crt` / `web-internal-chain.pem`, and a page-wide search for that hyphenated stem can only ever read
    # 0 against a correct app: `_issued_view` renders the links as `/download/<opaque id>` (app.py:3093-3094), and the
    # name is produced later, per request, by `_safe_stem(issued.common_name)` (app.py:2277-2279) and put on the wire as
    # `Content-Disposition` by `_pem_response` (app.py:726). So both links are followed and the header is read where it
    # actually exists. Two properties, asserted separately:
    #   * which link is which — the card's first download link is the leaf and its second the chain, because that is the
    #     order `csr_sign.html:265,272` renders them in, and the labels are what the operator reads. Binding a name to a
    #     label is also what keeps a swap visible: leaf bytes behind the chain link would still count 2.
    #   * the name itself — `<stem>.crt` and `<stem>-chain.pem`, i.e. the CN's dots turned into hyphens. Not cosmetic:
    #     Windows' double-click installer keys off the extension, so a leaf served as `-chain.pem` installs as a chain.
    # `OneShotStore.take` looks an id up without consuming it (app.py:258-266), so both links stay live for §10.
    links = re.findall(r'<a class="button" href="(/download/[^"]+)">([^<]+)</a>', card)
    app.count_exactly("the issued card offers exactly two downloads", card, 'href="/download/', 2)
    labels = [label for _, label in links]
    if not app.check(
        f"the first download is the certificate and the second the chain ({labels})",
        labels == ["Download certificate (.crt)", "Download chain (.pem)"],
    ):
        return
    names = ("web-internal.crt", "web-internal-chain.pem")
    for (path, label), wanted in zip(links, names, strict=True):
        fetched = app.get(path)
        if not app.expect_status(f"GET {path} ({label})", fetched, 200):
            continue
        headers = {key.lower(): value for key, value in fetched.headers.items()}
        disposition = headers.get("content-disposition", "")
        if wanted.endswith(".crt"):
            app.check(
                f"the leaf download is named from the CN with dots turned into hyphens ({disposition})",
                disposition == f'attachment; filename="{wanted}"',
            )
        else:
            app.check(
                f"the chain download is named {wanted} and not the bare leaf name ({disposition})",
                disposition == f'attachment; filename="{wanted}"',
            )
        # The bytes behind each name: a correct name over the wrong body is exactly the swap this section exists to
        # catch, and it is only visible against the PEM the card itself displayed.
        if wanted.endswith(".crt"):
            served = pem_block(fetched.text, "CERTIFICATE")
            shown = app.state.get("leaf_pem", "")
            app.check(
                f"the leaf download serves the certificate the card showed ({len(fetched.text.encode())} bytes)",
                served is not None and pem_der_sha(served) == pem_der_sha(shown),
            )
        else:
            app.count_exactly(
                "the chain download carries a leaf and a CA, in that order",
                fetched.text,
                "-----BEGIN CERTIFICATE-----",
                2,
            )


# ============================================================================ §7 rejections name their reason


def section_7(app: Harness) -> None:
    app.report.section("§7 Rejections name their reason (never 'invalid CSR')")
    token = app.state.get("token")
    if token is None:
        app.warn("no CSRF token carried from §5/§6, so the rejection cases could not run")
        return

    garbage = app.post("/csr/sign", {"csrf_token": token, "csr_pem": "not a csr at all"})
    body = garbage.text
    named = count(body, "No PEM block found")
    app.check(
        f"garbage input is refused naming the reason (status {garbage.status_code}, 'No PEM block found' x{named})",
        garbage.status_code == 400 and named >= 1,
    )

    bogus = f"{CSR_BEGIN}\nYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=\n{CSR_END}\n"
    fixture = app.write_fixture("bogus.csr", bogus)
    # URLENCODED, exactly as `scripts/smoke_test.sh:334-344,898-902` posts this paste with `post_pem` /
    # `--data-urlencode csr_pem@file`, and for the same measured reason. A multipart part is not a string by the time a
    # handler sees it: `_form_fields` (app.py:823-841) flattens every part with `str(value)`, and starlette hands an
    # uploaded file part back as an `UploadFile`, so the paste mypki validates is the literal text
    # `UploadFile(filename='bogus.csr', size=115, headers=Headers({…}))` — a body with no PEM armour in it at all. The
    # page then answers 'No PEM block found', a correct answer about the wrong bytes: the DER-reason needle reads 0, and
    # the case measured `str()` on an UploadFile instead of mypki's CSR parser.
    # WHAT THIS CASE IS FOR, stated so it is not lost again: valid base64 inside real armour that is NOT a DER
    # certificate request must be refused naming THAT (`not a DER certificate request`), not with the generic 'No PEM
    # block found' the line above asserts. A multipart posting returns 400 while proving nothing about that distinction.
    second = app.post("/csr/sign", {"csrf_token": token, "csr_pem": bogus})
    named = count(second.text, "not a DER certificate request")
    app.check(
        f"valid base64 that is not a CSR is refused naming it (status {second.status_code}, reason x{named})",
        second.status_code == 400 and named >= 1,
    )
    # THE OTHER SHAPE, asserted as what it actually does rather than assumed to be equivalent. Same bytes, posted as a
    # multipart part: mypki still refuses with 400 and its own reason, but that reason is 'No PEM block found' because
    # the armour never reached the parser — `str(UploadFile(...))` contains no BEGIN line (measured: the echoed textarea
    # reads `UploadFile(filename='bogus.csr', size=115, headers=Headers({…}))`). Asserted so that a route reaching for a
    # file part fails here, where the difference is named, not in a section expecting the DER reason and reading 0.
    as_part = app.post("/csr/sign", {"csrf_token": token}, multipart_files={"csr_pem": str(fixture)})
    part_named = count(as_part.text, "No PEM block found")
    app.check(
        f"the same paste posted as a multipart part is still refused with mypki's own reason (status"
        f" {as_part.status_code}, 'No PEM block found' x{part_named}) — a file part is stringified before parsing,"
        f" which is why the DER case above posts urlencoded",
        as_part.status_code == 400 and part_named >= 1,
    )

    # In this build the reason is printed where the paste was typed. Asserted as an ORDER, because "the reason appears
    # somewhere in the body" is also true of a page that mentions it only in a nav link. Before this build both POSTs
    # rendered templates/error.html, which contains no form at all, so the operator had to click back and re-paste. The
    # oversized paste of §8 is the refusal that stays on error.html: SizeGuardMiddleware answers it before any route
    # runs, so there is no form to put the reason on.
    blocks = [match.start() for match in re.finditer(r'class="form-errors refused"', body)]
    if app.check(
        f"the refusal is rendered on the sign page itself ({len(blocks)} block(s), not a separate error document)",
        len(blocks) >= 1,
    ):
        label = body.find('<label for="csr_pem">Paste a CSR (PEM)</label>')
        app.check(
            f"the refusal sits above 'Paste a CSR (PEM)' (offset {blocks[0]} before {label})",
            label != -1 and blocks[0] < label,
        )
    app.count_at_least(
        "the rejected paste is echoed back into its own textarea, so the fix is typed in place",
        body,
        "not a csr at all",
    )
    app.count_zero("a refused paste staged nothing (no confirmation panel)", body, "This is what the request says")


# =================================================================================================== §8 oversized input


def section_8(app: Harness) -> None:
    app.report.section("§8 Oversized input (page-map §0)")
    token = app.state.get("token")
    if token is None:
        app.warn("no CSRF token carried from §5/§6, so the oversized case could not run")
        return
    padding = "A" * 40_000
    huge = f"{CSR_BEGIN}\n{padding}\n{CSR_END}\n"
    app.write_fixture("huge.csr", huge)
    response = app.post("/csr/sign", {"csrf_token": token, "csr_pem": huge})
    body = response.text
    named = count(body, "the limit is 32,000")
    app.check(
        f"oversized paste answers 413 with mypki's own page naming the limit (status {response.status_code}, limit"
        f" named x{named})",
        response.status_code == 413 and named >= 1,
    )
    # The guard measures the body before parsing, so an oversized request never reaches a framework validator whose
    # answer is not a page.
    app.count_zero("starlette's bare JSON size error did not surface", body, "Field exceeded maximum size")


# ============================================================================================== §9 CA certificate


def section_9(app: Harness) -> None:
    app.report.section("§9 CA certificate (page-map §4)")
    response = app.get("/ca")
    if not app.expect_status("GET /ca", response, 200):
        return
    page = response.text

    # Asserted against the RENDERED page rather than the template source: 'CA:TRUE pathLength:0' also sits inside a
    # Jinja comment in ca_download.html, so grepping the file would pass against a page that never renders it.
    app.count_at_least("/ca shows the CA subject", page, CA_CN)
    app.check(
        "/ca shows a colon-grouped SHA-256 fingerprint",
        count_re(page, r"([0-9A-F]{2}:){31}[0-9A-F]{2}") >= 1,
    )
    app.count_at_least(
        "/ca reports BasicConstraints CA:TRUE pathLength:0 (the root's own, so what you are about to trust is visible)",
        page,
        "CA:TRUE pathLength:0",
    )
    app.count_at_least(
        "/ca reports whether the CA private key is present (a boolean, never a path to the key)",
        page,
        "private key on this host",
    )

    for needle, label in (
        ("Trusted Root Certification Authorities", "Windows instructions"),
        ("update-ca-certificates", "Linux instructions"),
        ("Always Trust", "macOS instructions"),
        ("keytool -importcert", "Java instructions"),
    ):
        app.count_at_least(f"{label} present on /ca", page, needle)

    download = app.get("/ca/certificate")
    if not app.expect_status("GET /ca/certificate", download, 200):
        return
    headers = {key.lower(): value for key, value in download.headers.items()}
    app.check(
        "CA download is an attachment named mypki-root-ca.crt (Windows' double-click installer keys off the extension)",
        headers.get("content-disposition") == 'attachment; filename="mypki-root-ca.crt"',
    )
    app.check(
        "PEM response sets Cache-Control: no-store (a cached PEM is one stale root away from a confusing ticket)",
        headers.get("cache-control") == "no-store",
    )
    app.check(
        "CA download declares application/x-pem-file",
        headers.get("content-type", "").startswith("application/x-pem-file"),
    )
    body = download.text
    app.count_exactly("the CA download contains exactly one certificate", body, "-----BEGIN CERTIFICATE-----", 1)
    app.write_fixture("ca.crt", body)
    app.state["ca_pem"] = body

    # 0.5.0 shows the certificate itself on /ca. Three assertions because there are three ways this feature could rot
    # without any of them turning red today: the block vanishes, the button stops pointing at it, or the page's copy
    # drifts from the download's. The fourth is the one that earns the other three — "the page shows the certificate" is
    # only true if those are the same bytes the download offers.
    app.count_exactly("/ca renders the CA PEM block (pre id=pem-ca)", page, 'id="pem-ca"', 1)
    app.count_exactly("/ca's copy button points at that block", page, 'data-mypki-copy="pem-ca"', 1)

    page_block = pem_block(page, "CERTIFICATE")
    if page_block is None:
        app.check("/ca renders no extractable CERTIFICATE block to compare", False)
        return
    app.count_exactly(
        "/ca's PEM block holds exactly one certificate (an accidental chain would make an operator install the wrong"
        " thing)",
        page_block,
        "-----BEGIN CERTIFICATE-----",
        1,
    )
    page_sha = pem_der_sha(page_block)
    download_sha = pem_der_sha(body)
    app.check(
        f"the certificate shown on /ca is the same bytes as the download ({page_sha})",
        page_sha is not None and page_sha == download_sha,
    )

    try:
        ca_cert = x509.load_pem_x509_certificate(body.encode())
        app.state["ca_cert"] = ca_cert
        leaf_pem = app.state.get("leaf_pem")
        if leaf_pem is not None:
            leaf = x509.load_pem_x509_certificate(leaf_pem.encode())
            app.check(
                f"the issued leaf's serial is the serial printed on its card ({format(leaf.serial_number, 'x')[:12]}…)",
                format(leaf.serial_number, "x") == app.state.get("issued_serial"),
            )
            app.check(
                "the issued leaf is signed by this CA (its issuer equals the CA subject)",
                leaf.issuer == ca_cert.subject,
            )
    except Exception as exc:
        app.check(f"the CA download does not parse as a certificate: {exc}", False)


# =================================================================================================== §10 issued list


def section_10(app: Harness) -> None:
    app.report.section("§10 Issued list (page-map §5)")
    response = app.get("/issued")
    if not app.expect_status("GET /issued", response, 200):
        return
    listing = response.text
    app.state["issued_list"] = listing

    rows = count_re(listing, r"<tr>")
    app.check(f"the issued table has at least one data row ({rows} <tr> including the header)", rows >= 2)
    app.count_at_least("the certificate signed in §6 appears in the list by CN/SAN", listing, "web.internal")
    app.count_at_least("a fresh record reports Status 'active'", listing, '<span class="pill active">active</span>')
    app.count_at_least(
        "/issued offers a revoke control for an active record (page-map §5)", listing, 'action="/issued/revoke"'
    )

    # Two states, not three: the list reports active/revoked and leaves expiry to the date cell, because printing
    # "expired" beside "revoked" would imply this host knows what every client currently accepts.
    app.count_zero("the Status column does not claim an 'expired' state", listing, ">expired<")

    # Counted against the checkbox attribute deliberately: a build that kept the old per-row forms would still answer
    # 200, still carry the right serials, and every §11 assertion would then run against a shape no browser posts any
    # more. The checkbox count matching the ACTIVE-row count is the same contract from the other side — a stamped row
    # carries no box.
    boxes = count(listing, 'type="checkbox" name="serial_hex"')
    active = count(listing, '<span class="pill active">active</span>')
    app.check(
        f"one checkbox per active row and none on a revoked row ({boxes} boxes, {active} active)",
        boxes == active and boxes >= 1,
    )

    app.count_exactly(
        "/issued posts ONE bulk revoke form — the 0.2.0 per-row forms are gone",
        listing,
        '<form method="post" action="/issued/revoke"',
        1,
    )
    app.count_exactly("the Select column offers the All box", listing, "data-mypki-select-all", 1)
    app.count_at_least("the select-all control is labelled 'All'", listing, "> All<")

    # Counted on the BUTTON TAG, not on the phrase: measured against a live server the bare phrase occurs three times on
    # /issued (1 button + 2 <strong> mentions in the no-JavaScript hint), so `== 1` on the phrase fails against a
    # correct page. What has to be singular is the CONTROL and the BAR, and both are asserted separately; the prose
    # count is then reported rather than guessed at.
    buttons = count(listing, '<button class="danger solid" type="submit">Revoke Selected</button>')
    bars = count(listing, 'class="select-bar"')
    phrase = count(listing, "Revoke Selected")
    prose = count(listing, "<strong>Revoke Selected</strong>")
    app.check(f"'Revoke Selected' is offered exactly once, as one control ({buttons} button)", buttons == 1)
    app.check(f"exactly one select bar survives above the table ({bars}) — 0.4.0 deleted the bottom bar", bars == 1)
    app.check(
        f"every other 'Revoke Selected' is prose, inside <strong> ({phrase} mentions = {buttons} control + {prose}"
        f" prose)",
        phrase == buttons + prose and prose >= 1,
    )

    app.count_exactly(
        "the selection counter starts at '0 selected' and is live from the first paint (app.js writes 'N selected' in"
        " the same shape, so untickable rows cannot hide behind a different sentence at zero)",
        listing,
        "data-mypki-count>0 selected",
        1,
    )
    app.count_exactly(
        "the bulk form carries the CSRF token inside itself (with one form the token has to live in it)",
        listing,
        'name="csrf_token"',
        1,
    )
    app.count_at_least(
        "/issued says what still works with JavaScript off (tick rows one at a time)",
        listing,
        "tick rows one at a time",
    )


# ============================================================================================ §11 revocation round trip


def section_11(app: Harness) -> None:
    app.report.section("§11 Revocation round trip (page-map §5)")
    listing = app.state.get("issued_list", "")
    serials = checkbox_serials(listing)
    issued_serial = app.state.get("issued_serial")
    if not serials or not issued_serial:
        app.warn("no revokable row was available, so the whole revocation round trip could not run")
        return
    token = csrf_token(listing)
    if token is None:
        app.warn("/issued carried no CSRF token, so the revoke POSTs could not run")
        return

    row_serial = serials[0]
    # Read from the checkbox rather than the visible cell because the input is what the POST actually submits: asserting
    # against the displayed value would pass even if the form dropped it.
    app.check("the checkbox carries §6's leaf serial, not a row position", row_serial == issued_serial)

    def revoke(fields: dict[str, Any]) -> httpx2.Response:
        return app.post("/issued/revoke", fields)

    # STEP A — the unconfirmed POST. As of 0.3.0 this stamps NOTHING: it re-renders /issued with the confirmation block
    # at the top. The 0.2.0 harness asserted a revoked pill here, and that assertion is now wrong by construction:
    # against a correct app it fails. Both halves are asserted — what the block says, and that the ledger is untouched.
    confirm_page = revoke({"csrf_token": token, "serial_hex": row_serial, "reason": "e2e harness: retired on purpose"})
    app.expect_status("POST /issued/revoke without confirm (the confirmation step, not an error)", confirm_page, 200)
    body = confirm_page.text
    app.count_exactly(
        "the unconfirmed POST renders the confirmation block", body, '<section class="confirm-revoke">', 1
    )
    app.count_at_least("the block counts what is at stake ('Revoke 1 certificate?')", body, "Revoke 1 certificate?")
    app.count_at_least("the block states that nothing has been changed yet", body, "Nothing has been changed yet.")
    before_pills = count(listing, '<span class="pill revoked">revoked</span>')
    after_pills = count(body, '<span class="pill revoked">revoked</span>')
    # Records this host revoked in an earlier run legitimately keep their pills; what must not move is the COUNT. The
    # naive "zero revoked pills" check is wrong against a ledger that already holds revoked records.
    app.check(
        f"nothing was stamped before confirmation ({after_pills} revoked pills, same as the list page's"
        f" {before_pills})",
        after_pills == before_pills,
    )
    app.count_zero(
        "the unconfirmed POST reports no batch (nothing has been revoked yet)", body, "<h2>Revocation batch</h2>"
    )
    app.count_at_least(
        "the selection is carried forward into the confirm form", body, f'name="serial_hex" value="{row_serial}"'
    )
    app.count_exactly("the confirm form carries confirm=1", body, '<input type="hidden" name="confirm" value="1">', 1)
    app.count_at_least("the block states what that certificate is right now ('active now')", body, "active now")
    # The needle here used to be `no CRL is published`, and NO template says that any more. What the page has to say
    # instead is what it cannot undo, stated BEFORE consent is asked for. Asserted through joined text because the
    # template wraps the sentence.
    app.joined_at_least(
        "the confirmation page states what it cannot undo before asking for consent",
        body,
        "Revoking a record cannot be undone from this page: there is no un-revoke and no delete.",
    )

    # STEP B — the confirmed POST, mirroring tests/test_bulk_revoke.py. This is what actually stamps, and it is also the
    # shape static/app.js's modal submits, so both paths are proven against one handler.
    stamped = revoke(
        {"csrf_token": token, "serial_hex": row_serial, "confirm": "1", "reason": "e2e harness: retired on purpose"}
    )
    app.expect_status("POST /issued/revoke with confirm=1", stamped, 200)
    batch = stamped.text
    app.count_exactly(
        "the confirmed submit answers with the three-way batch card", batch, "<h2>Revocation batch</h2>", 1
    )
    app.count_at_least("the batch card counts what it stamped now", batch, "stamped now,")
    app.count_at_least(
        "the batch card counts records already revoked before this submit", batch, "already revoked before this submit"
    )
    app.count_at_least(
        "the batch card counts serials with no record on this host", batch, "with no record on this host"
    )
    app.count_at_least("the row now reports Status 'revoked'", batch, '<span class="pill revoked">revoked</span>')
    app.count_at_least("the card confirms the stamp with a UTC timestamp", batch, "is marked revoked as of")
    app.count_at_least("the reason is stored and shown back", batch, "e2e harness: retired on purpose")

    # Revoking now also re-signs a CRL this host publishes (STEP F below proves it), so the old framing — "mypki
    # publishes no CRL and no OCSP" — is false as written. What is still true, and what the page still has to say, is
    # the client half. Asserted on BOTH steps now: the step that asks and the step that acts.
    app.count_at_least(
        "the page still states the client-side caveat — a revoked certificate stays trusted by clients until it"
        " expires",
        batch,
        "stays trusted by clients until it expires",
    )
    app.joined_at_least(
        "the page names the CRL/OCSP it now publishes instead of claiming revocation reaches clients",
        batch,
        "From 0.7.0 this host also signs a CRL and answers OCSP",
    )

    # A stamped row offers no checkbox: it cannot be re-revoked (store.revoke preserves the stamp on purpose) and there
    # is no delete. The assertion this replaces counted `action="/issued/revoke"` instead, and with ONE bulk form that
    # count is 1 before and 1 after, so "fell by one" could never hold — measured, it failed against a correct app as 1
    # -> 2. Counted against every row on the page, which legitimately keeps its own checkbox for every other active
    # certificate this host signed.
    app.count_zero(
        "no control carries the stamped serial (it cannot be re-revoked, and there is no delete)",
        batch,
        f'name="serial_hex" value="{row_serial}"',
    )
    before_boxes = count(listing, 'type="checkbox" name="serial_hex"')
    after_boxes = count(batch, 'type="checkbox" name="serial_hex"')
    app.check(
        f"the checkbox count fell by exactly one ({before_boxes} -> {after_boxes}): the stamped row lost its box, no"
        f" other row did",
        after_boxes == before_boxes - 1,
    )
    forms = count_re(batch, r'<form method="post" action="/issued/revoke"')
    app.check(f"the confirmed page posts at most one bulk form plus the confirmation form ({forms} forms)", forms <= 2)

    # STEP C-E — multi-select and the stale tab. The bogus serial is only ever submitted inside a batch: a lone unknown
    # serial keeps its own 404 contract (asserted in tests/test_views.py).
    others = [item for item in checkbox_serials(listing) if item != row_serial][:2]
    stamped_serials = [row_serial]
    if len(others) < 2:
        app.warn(f"only {len(others)} other active record(s) on this host — the multi-select checks cannot run")
    else:
        multi_confirm = revoke({"csrf_token": token, "serial_hex": [others[0], others[1], BOGUS_SERIAL]})
        multi_body = multi_confirm.text
        named_three = count(multi_body, "Revoke 3 certificates?")
        app.check(
            f"a three-serial submit confirms THREE before stamping any (status {multi_confirm.status_code}, 'Revoke 3"
            f" certificates?' x{named_three})",
            multi_confirm.status_code == 200 and named_three >= 1,
        )
        app.count_exactly(
            "the confirmation calls the unknown serial what it is (reported, not revoked)",
            multi_body,
            "not a record on this host &mdash; it will be reported, not revoked",
            1,
        )
        # Compared against STEP B's page, not §10's list: STEP B legitimately stamped one record on the way here, so the
        # starting point for THIS submit is the count the operator last saw. Comparing back to §10 would report a
        # correct app as stamping something it did not stamp.
        pills_multi = count(multi_body, '<span class="pill revoked">revoked</span>')
        pills_batch = count(batch, '<span class="pill revoked">revoked</span>')
        app.check(
            f"an unconfirmed multi-select stamps nothing ({pills_multi} revoked pills, unchanged from {pills_batch})",
            pills_multi == pills_batch,
        )
        app.count_zero(
            "the confirmation lists no already-stamped serial (all three are active here)",
            multi_body,
            "already revoked &mdash; its stamp and reason will not change",
        )

        mixed = revoke({"csrf_token": token, "serial_hex": [others[0], others[1], BOGUS_SERIAL], "confirm": "1"})
        mixed_body = mixed.text
        stamped_serials.extend(others)
        two = count(mixed_body, "2 stamped now,")
        app.check(
            f"a mixed batch stamps the two records it owns (status {mixed.status_code}, '2 stamped now,' x{two})",
            mixed.status_code == 200 and two >= 1,
        )
        app.count_at_least(
            "the batch counts zero already-revoked (true here, and stated rather than left blank)",
            mixed_body,
            "0 already revoked before this submit",
        )
        app.count_at_least(
            "the batch counts the one serial with no record here", mixed_body, "1 with no record on this host"
        )
        # MEASURED byte-for-byte: the apostrophe in `this host's database` is plain ASCII U+0027 (`od` reads h o s t '
        # s). Jinja's autoescape leaves a typographic apostrophe raw and this one is not typographic — asserting &#8217;
        # fails against a correct page. A miss must not 404 away the two decisions the operator did mean to make.
        app.count_at_least(
            "the batch names the missed serial plainly, with what it did NOT do",
            mixed_body,
            "no record with that serial in this host's database &mdash; nothing was changed",
        )
        app.count_at_least("the missed serial is printed, not hidden behind a count", mixed_body, BOGUS_SERIAL)

        again = revoke(
            {"csrf_token": token, "serial_hex": row_serial, "confirm": "1", "reason": "second submit from a stale tab"}
        )
        again_body = again.text
        zero = count(again_body, "0 stamped now,")
        one = count(again_body, "1 already revoked before this submit")
        app.check(
            f"re-submitting a stamped serial stamps nothing (status {again.status_code}, '0 stamped now,' x{zero}, '1"
            f" already revoked' x{one})",
            again.status_code == 200 and zero >= 1 and one >= 1,
        )
        app.count_at_least(
            "the original stamp and reason survive a second submit (not overwritten by the new one)",
            again_body,
            "e2e harness: retired on purpose",
        )
        app.count_at_least(
            "the card says what it did NOT do to that record",
            again_body,
            "already revoked &mdash; its stamp and reason were left alone",
        )

    # And it survives a plain GET, which is what an operator does next (refresh, bookmark, another browser). Three
    # stamps is the precondition §6's seeding now guarantees, so `>= 3` is a real expectation rather than a hope that
    # the host held extra records.
    after_get = app.get("/issued")
    after_body = after_get.text
    pills = count(after_body, '<span class="pill revoked">revoked</span>')
    app.check(
        f"the revoked state survives a plain GET /issued (status {after_get.status_code}, {pills} revoked pills after"
        f" at least three stamps)",
        after_get.status_code == 200 and pills >= 3,
    )
    app.count_zero(
        "a plain GET still offers no control for a stamped serial",
        after_body,
        f'name="serial_hex" value="{row_serial}"',
    )
    dated = count_re(after_body, r'class="hint">revoked [0-9]{4}-[0-9]{2}-[0-9]{2}')
    # Only the SHAPE of the stamp line is pinned (class="hint"> plus a YYYY-MM-DD prefix): pinning the whole line would
    # make this about formatting rather than about whether the decision is still visible after a refresh.
    app.check(f"the Status cell reads as a dated decision ('revoked YYYY-MM-DD…', {dated})", dated >= 3)
    app.count_zero(
        "the list has no separate Revoked column any more (the stamp lives in the Status cell)",
        after_body,
        '<th scope="col">Revoked</th>',
    )

    # PUBLISH THE SERIALS THIS WALK ACTUALLY STAMPED. `openssl_checks` (§11 STEP F's external half) reads
    # app.state["stamped_serials"] to ask openssl's CRL reader for every serial this harness revoked; without this line
    # the list stays the empty one main() installs and the assertion degenerates into `bool([])` — a FAIL reading "0/0
    # matched" against an app that published every stamp correctly. This is the same list §11's CRL half already proved
    # is inside the artifact, so openssl is asked for what mypki's parser confirmed, not for a second claim to drift.
    app.state["stamped_serials"] = list(stamped_serials)

    section_11_crl(app, stamped_serials)


def section_11_crl(app: Harness, stamped_serials: list[str]) -> None:
    """§11 STEP F — the CRL this walk earned, read back from the artifact rather than from what the build was told. The
    shell harness read these bytes with `base64 -d` + `od` because plan U7 kept openssl a permanent outsider and no DER
    parser could live in a shell script. Here `cryptography` parses the same DER, which answers the stronger question —
    "is this a CRL holding exactly these entries" rather than "does its hex contain these octets" — and still needs no
    toolchain, so it holds on windows-latest where the openssl half below does not."""
    page = app.get("/crl")
    if not app.expect_status("GET /crl (the page, not just the artifact)", page, 200):
        return
    body = page.text
    app.count_exactly(
        "/crl renders exactly one CRL armour block (the page shows the artifact it is describing)",
        body,
        "-----BEGIN X509 CRL-----",
        1,
    )
    app.count_exactly("/crl's PEM block has its own id, so the copy button can point at it", body, 'id="pem-crl"', 1)
    app.count_exactly("/crl's copy button points at that block", body, 'data-mypki-copy="pem-crl"', 1)

    entries = re.search(r"<td>(\d+) revoked certificate", body)
    if not app.check(
        f"/crl states its entry count once, in words ({entries.group(1) if entries else 'no number'})",
        entries is not None,
    ):
        return
    reported = int(entries.group(1))
    app.check(
        f"the published CRL lists exactly the {len(stamped_serials)} revocation(s) this walk stamped ({reported}"
        f" entries)",
        reported == len(stamped_serials),
    )
    app.count_exactly(
        "/crl carries the honest-limits card (page-map §14's four measured caveats)",
        body,
        "What this CRL does not do",
        1,
    )
    app.count_exactly(
        "/crl carries the OCSP limits card (echoed hashes, the two size caps, no CSRF)",
        body,
        "What the OCSP responder does not do",
        1,
    )

    download = app.get("/crl.pem")
    if not app.expect_status(
        "GET /crl.pem (the URL certificates issued from 0.7.0 carry in their CRLDistributionPoints)", download, 200
    ):
        return
    headers = {key.lower(): value for key, value in download.headers.items()}
    app.check(
        "/crl.pem declares application/pkix-crl, so a client need not guess from the filename",
        headers.get("content-type") == "application/pkix-crl",
    )
    app.check(
        "/crl.pem is an attachment named mypki.crl.pem",
        headers.get("content-disposition") == 'attachment; filename="mypki.crl.pem"',
    )
    app.check(
        "/crl.pem is not cacheable (a proxy replaying a 24 h-old CRL keeps a revoked certificate trusted for the"
        " length of that cache)",
        headers.get("cache-control") == "no-store",
    )
    pem_body = download.text
    app.count_exactly("the download contains exactly one armour block", pem_body, "-----BEGIN X509 CRL-----", 1)
    app.write_fixture("crl.pem", pem_body)
    app.state["crl_pem"] = pem_body

    try:
        crl = x509.load_pem_x509_crl(pem_body.encode())
    except Exception as exc:
        app.check(f"/crl.pem's body could not be parsed as a CRL: {exc}", False)
        return
    app.check(
        f"the decoded artifact is a real CRL of {len(crl)} entries, matching the page's number", len(crl) == reported
    )

    # Every serial this walk stamped has to be IN the artifact. This is the assertion that makes the revoke -> publish
    # link real: a CRL that says "3 entries" and lists three other serials would pass every count above.
    listed = {format(entry.serial_number, "x") for entry in crl}
    for serial in stamped_serials:
        app.check(f"the published CRL lists the stamped serial {serial[:12]}…", serial in listed)

    oids = {extension.oid.dotted_string for extension in crl.extensions}
    # The two extensions crl.py adds, and the two it refuses to add. The absences are decisions with evidence behind
    # them: measured against openssl 3.5.6, an IDP-scoped CRL answers `error 44 … different CRL scope` for every
    # certificate this CA signed before 0.7.0. Naming by dotted number is what a mislabelling trap was recorded for:
    # 2.5.29.20 is CRLNumber (NOT 2.5.29.35), which is AKI (NOT 2.5.29.28, which is IDP's number), and 2.5.29.27 is
    # DeltaCRLIndicator.
    app.check(
        "the CRL carries CRLNumber, OID 2.5.29.20 (RFC 5280 §5.2.1: it counts stamps, so it never decreases)",
        "2.5.29.20" in oids,
    )
    app.check(
        "the CRL carries an AuthorityKeyIdentifier, OID 2.5.29.35, so a client can tell which CA signed it",
        "2.5.29.35" in oids,
    )
    app.check(
        "the CRL carries no IssuingDistributionPoint, OID 2.5.29.28 (an IDP-scoped CRL would make -crl_check unusable"
        " on this CA's own history)",
        "2.5.29.28" not in oids,
    )
    app.check(
        "the CRL carries no DeltaCRLIndicator, OID 2.5.29.27 (no delta CRLs are published, so none may be claimed)",
        "2.5.29.27" not in oids,
    )

    section_11_ocsp(app, stamped_serials)


def section_11_ocsp(app: Harness, stamped_serials: list[str]) -> None:
    """§11 STEP F's other half — POST /ocsp, DER in, DER out, HTTP 200 whatever the answer is. The answers are read with
    `cryptography` rather than by hex offsets: the shell harness anchored on bytes because it had no DER parser, and it
    had to scope the search at the signature's AlgorithmIdentifier because random RSA signature bytes carried
    `8000`/`8200` in 7 of 300 measured answers. Parsing removes that flake class entirely — a parsed CertStatus is
    either REVOKED or it is not, and no signature byte can be mistaken for one."""
    ca_cert = app.state.get("ca_cert")
    leaf_pem = app.state.get("leaf_pem")
    if ca_cert is None or leaf_pem is None:
        app.warn(
            "no CA certificate and issued leaf in hand, so the OCSP answers could not be asked about a real certificate"
        )
        return

    def ask(cert: x509.Certificate) -> tuple[httpx2.Response, ocsp_api.OCSPResponse | None]:
        request = ocsp_api.OCSPRequestBuilder().add_certificate(cert, ca_cert, hashes.SHA1()).build()
        response = app.post(
            "/ocsp", raw_body=request.public_bytes(serialization.Encoding.DER), content_type="application/ocsp-request"
        )
        try:
            return response, ocsp_api.load_der_ocsp_response(response.content)
        except Exception:  # a body that is not DER is a finding to report, not a traceback to raise
            return response, None

    leaf = x509.load_pem_x509_certificate(leaf_pem.encode())
    response, parsed = ask(leaf)
    app.check(
        f"POST /ocsp answers 200 for the serial §11 revoked (got {response.status_code}: a protocol answer is not an"
        f" HTTP error)",
        response.status_code == 200,
    )
    headers = {key.lower(): value for key, value in response.headers.items()}
    app.check(
        "/ocsp answers application/ocsp-response (DER, not mypki's HTML) — a client that expects DER cannot read HTML",
        headers.get("content-type") == "application/ocsp-response",
    )
    app.check(
        "/ocsp answers are not cacheable (a replayed GOOD outlives the revocation it used to describe)",
        headers.get("cache-control") == "no-store",
    )
    app.check(
        "/ocsp sends no Content-Disposition (these bytes are consumed by a library, not saved)",
        "content-disposition" not in headers,
    )
    if parsed is None:
        app.warn(
            "the revoked-serial answer could not be parsed as an OCSP response, so its status could not be asserted"
        )
        return
    app.check(
        f"the revoked answer reports OCSPResponseStatus SUCCESSFUL ({parsed.response_status.name})",
        parsed.response_status is ocsp_api.OCSPResponseStatus.SUCCESSFUL,
    )
    if parsed.response_status is ocsp_api.OCSPResponseStatus.SUCCESSFUL:
        app.check(
            f"the revoked serial answers REVOKED (not GOOD, which would claim knowledge this CA cannot have) — got"
            f" {parsed.certificate_status.name}",
            parsed.certificate_status is ocsp_api.OCSPCertStatus.REVOKED,
        )
        reason = parsed.revocation_reason
        # RFC 5280 §5.3.1: an absent code means `unspecified`. The store's reason is operator prose and inventing a code
        # from it would be a lie (plan U6), so the honest spelling of this answer is unspecified-or-absent, never a
        # guessed keyCompromise.
        app.check(
            f"the REVOKED answer states its revocation reason as unspecified or absent (got"
            f" {reason.name if reason else 'absent'})",
            reason is None or reason is x509.ReasonFlags.unspecified,
        )

    # A serial this host never signed. The certificate below is the CA's own leaf, whose serial is not in the issued
    # store, so the answer must be UNKNOWN rather than GOOD: GOOD would claim knowledge of a certificate this CA never
    # signed into its ledger.
    response, parsed = ask(ca_cert)
    app.check(
        f"POST /ocsp answers 200 for a serial this host never signed (got {response.status_code})",
        response.status_code == 200,
    )
    if parsed is not None and parsed.response_status is ocsp_api.OCSPResponseStatus.SUCCESSFUL:
        app.check(
            f"a serial with no record here answers UNKNOWN — not GOOD, which would claim knowledge of a certificate"
            f" this CA never issued (got {parsed.certificate_status.name})",
            parsed.certificate_status is ocsp_api.OCSPCertStatus.UNKNOWN,
        )
    else:
        app.warn(
            "the unknown-serial answer did not parse as a SUCCESSFUL OCSP response, so its CertStatus could not be"
            " asserted"
        )

    # Two refusals, both inside the body at HTTP 200 — the one place in mypki where the usual "every rejection gets an
    # HTML page with a telling status" rule is suspended on purpose.
    truncated = bytes.fromhex("30423040303e303c303a300906052b0e03021a05000414")
    response = app.post("/ocsp", raw_body=truncated, content_type="application/ocsp-request")
    ok = False
    detail = ""
    if response.status_code == 200:
        try:
            refusal = ocsp_api.load_der_ocsp_response(response.content)
            detail = f"{refusal.response_status.name}, {len(response.content)} bytes"
            ok = (
                refusal.response_status is ocsp_api.OCSPResponseStatus.MALFORMED_REQUEST
                and response.content == bytes.fromhex("30030a0101")
            )
        except Exception as exc:
            detail = f"unparseable body ({exc})"
    app.check(
        f"a truncated request is refused byte-exact MALFORMED_REQUEST `30 03 0a 01 01`, five bytes, unsigned (status"
        f" {response.status_code}; got {detail})",
        ok,
    )
    response = app.post("/ocsp", raw_body=b"not-an-ocsp-request", content_type="application/ocsp-request")
    detail = ""
    ok = False
    if response.status_code == 200:
        try:
            refusal = ocsp_api.load_der_ocsp_response(response.content)
            detail = refusal.response_status.name
            ok = refusal.response_status is ocsp_api.OCSPResponseStatus.MALFORMED_REQUEST
        except Exception as exc:
            detail = f"unparseable body ({exc})"
    app.check(
        f"text where DER was expected gets the same MALFORMED_REQUEST answer (status {response.status_code}; got"
        f" {detail})",
        ok,
    )


# ================================================================================================= §12 about + settings


def section_12(app: Harness) -> None:
    app.report.section("§12 About and Settings (page-map §12)")
    response = app.get("/about")
    if not app.expect_status("GET /about", response, 200):
        return
    about = response.text

    app.count_at_least(f"/about names the running version ({app.version})", about, f"mypki {app.version}")
    app.check(
        "/about links the source URL, so a problem can be cited against a build",
        count_re(about, r'<a href="https://github\.com/[^"]*/mypki"') >= 1,
    )

    # The "what this host is running" card moved to the TOP of /about in 0.5.0. Asserted as offsets rather than presence
    # for the same reason other moves are: every one of these needles was already on that page somewhere, so a presence
    # check stayed green through the very change being checked. -1 means absent and must be handled rather than compared
    # (`-1 < 5` is True in bash and would silently pass an assertion about a heading that vanished).
    card = about.find("What this host is running")
    lede = about.find('<p class="lede">')
    profiles = about.find("What the three profiles mean")
    if card == -1:
        app.check("/about no longer renders the 'what this host is running' card", False)
    else:
        app.check(
            f"/about leads with the running-host card (card {card} < lede {lede} < profiles {profiles})",
            lede != -1 and profiles != -1 and card < lede and card < profiles,
        )

    # 0.7.0 prose sweep: the old needle `No published CRL or OCSP` is gone from about.html. The card is still there and
    # its first row now opens with the sentence that replaced the claim.
    app.count_at_least("/about still carries the 'does not do (yet)' card", about, "What this CA does not do (yet)")
    app.joined_at_least(
        "/about states the 0.7.0 revocation caveat: a CRL and an OCSP answer exist here, and consulting them is the"
        " client's side",
        about,
        "Revocation reaches only clients that go looking for it.",
    )
    # The three profiles in words, from signing.CERT_PROFILE_HELP — the sentences users asked for after 0.1.0 shipped
    # radio buttons with no explanation at all.
    app.count_at_least("the server profile says what it IS", about, "This is the web-server profile.")
    # No trailing period: what `signing.CERT_PROFILE_HELP["client"]` actually renders is
    # "It will NOT make a browser trust a web site -- for that you want `server`." (src/mypki/signing.py:90, measured in
    # the saved /about body). The old needle ended at 'web site.' and read 0 against a correct app — it pinned a period
    # that was never there. The half that matters is kept verbatim, and the clause that period stood in for becomes its
    # own needle, so a rewrite dropping "for that you want `server`" cannot pass on the first needle alone.
    app.count_at_least(
        "the client profile says what it does NOT do", about, "It will NOT make a browser trust a web site"
    )
    app.count_at_least(
        "and names the profile that DOES: for that you want `server`", about, "for that you want `server`"
    )

    settings = app.get("/settings")
    if not app.expect_status("GET /settings", settings, 200):
        return
    page = settings.text

    app.count_at_least("/settings lists MYPKI_VALIDITY_MAX_DAYS", page, "MYPKI_VALIDITY_MAX_DAYS")
    # Both honest spellings are accepted because which one a live server shows depends on whether the OPERATOR set a
    # secret. What has to hold is exactly ONE of them, so a page cannot hedge by printing both.
    present = count(page, "set (value not displayed)")
    generated = count(page, "generated one into the data dir at startup (not displayed)")
    app.check(
        f"MYPKI_SECRET_KEY renders as a presence flag, not a value (present={present} generated-one={generated})",
        present + generated == 1,
    )
    app.count_at_least(
        "/settings states that .env vs shell vs CLI flag cannot be told apart", page, "indistinguishable here"
    )

    app.count_exactly(
        "/settings renders its Save button",
        page,
        '<button class="save-settings" type="submit">Save Settings</button>',
        1,
    )
    knobs = count_re(page, r'name="MYPKI_[A-Z0-9_]+"')
    # A knob that lost its input is a save that posts nothing for it, so this counts controls rather than trusting the
    # list.
    app.check(f"/settings renders one control per editable knob ({knobs})", knobs >= 20)

    card_block = re.search(r"Not editable here.*?</section>", page, re.DOTALL)
    if card_block is not None:
        block = card_block.group(0)
        card_present = count(block, "set (value not displayed)")
        card_generated = count(block, "generated one into the data dir at startup (not displayed)")
        app.check(
            f"the unmanaged card states the secret's presence once, masked ({card_present} + {card_generated})",
            card_present + card_generated == 1,
        )
        app.count_zero("the card carries no control for MYPKI_SECRET_KEY", block, 'name="MYPKI_SECRET_KEY"')
    else:
        app.warn("/settings rendered no 'Not editable here' card, so its two assertions could not run")

    config_file = re.search(r"saved to <code>([^<]*)</code>", page)
    if config_file is None:
        app.check(
            "/settings never names the file a save writes — the refusal checks below have nothing to compare against",
            False,
        )
        return
    config_path = Path(config_file.group(1))
    app.check(f"/settings names the file a save writes ({config_path})", True)
    before = file_state(config_path)

    def assert_no_write(label: str) -> None:
        after = file_state(config_path)
        app.check(f"{label} left the config file untouched (state {after})", after == before)

    # The bound in the refusal is read from the SAME control the page renders, which app.py fills from the same
    # Field(ge=…, le=…) metadata pydantic enforces. This check cannot drift from config.py: move the knob there and both
    # the input's max= and the expected sentence move together.
    port_min = knob_bound(page, "MYPKI_PORT", "min")
    port_max = knob_bound(page, "MYPKI_PORT", "max")
    if not app.check(
        f"the port input declares its allowed range ({port_min} to {port_max}, read off config.py's Field)",
        port_min and port_max,
    ):
        return

    bad_port = int(port_max) + 1
    body = settings_form_body(page, {"MYPKI_PORT": str(bad_port)})
    refused = app.post("/settings", body)
    text = refused.text
    amber = count(text, "Not saved &mdash; fix this and submit again")
    app.check(
        f"an out-of-range save answers 200 with the amber 'Not saved' block, not a 500 (status {refused.status_code},"
        f" block x{amber})",
        refused.status_code == 200 and amber >= 1,
    )
    app.count_at_least(
        f"the refusal names the knob and the bound it failed (MYPKI_PORT must be {port_min} to {port_max})",
        text,
        f"MYPKI_PORT must be {port_min} to {port_max}; you entered an invalid value.",
    )
    app.count_at_least(
        f"the rejected value is still filled in ({bad_port}) rather than lost", text, f'value="{bad_port}"'
    )
    app.count_at_least(
        "the refusal states plainly that nothing was written",
        text,
        f"Nothing was written to <code>{config_path}</code>",
    )
    assert_no_write("a refused save")

    # An EMPTY box, not a missing knob. `_submitted_settings_fields` fills any knob the body omitted with '' (or 'false'
    # for the one checkbox), so deleting a field would NOT reach validate_candidate's "was not submitted" arm — it would
    # land on a valid value and WRITE the operator's real config file from a script whose job is only to look. The knob
    # chosen is one of `_EMPTY_IS_NOT_A_VALUE`, where an empty box is refused rather than silently reverting to a
    # default behind the operator's back.
    body = settings_form_body(page, {"MYPKI_HOST": ""})
    refused = app.post("/settings", body)
    text = refused.text
    empty_refusals = count(text, "cannot be empty")
    app.check(
        f"an empty box on a knob that has no empty value is refused (status {refused.status_code}, 'cannot be empty'"
        f" x{empty_refusals})",
        refused.status_code == 200 and empty_refusals >= 1,
    )
    app.check(
        "the refusal names the knob it refused (an operator cannot fix what is not named)",
        count_re(text, r"<li>MYPKI_[A-Z0-9_]+ cannot be empty") >= 1,
    )
    assert_no_write("the empty-knob refusal")

    # A stale tab posting the page's own values with an EMPTY token: mypki's own 400, naming the token, and again no
    # write.
    body = settings_form_body(page, {"csrf_token": ""})
    refused = app.post("/settings", body)
    named = count(refused.text, "CSRF token")
    app.check(
        f"a save with an empty CSRF token answers mypki's own 400 naming the token (status {refused.status_code},"
        f" named x{named})",
        refused.status_code == 400 and named >= 1,
    )
    assert_no_write("a CSRF-rejected save")

    app.count_at_least(
        "/settings says which knobs need a restart ('read once at startup')", page, "read once at startup"
    )
    # 0.4.0 shrank the restart list to four knobs and made everything else live, so the page has to say BOTH halves: a
    # page that still tells an operator to reboot for a logging change is a page that asks for an unnecessary outage.
    app.count_at_least(
        "/settings states that every other knob is applied without a restart", page, "applied by this process as soon"
    )

    # The negative half of the pending-marker rule. This harness performs NO successful save (see the two notes above),
    # so the positive case — one box showing 8543 while the rose sentence names 8443 — lives in
    # tests/test_settings_save.py against a temporary config dir and nowhere else. Deliberately NO assertion on 'saved
    # for the next start': measured, it already occurs four times on every /settings render through app._knob_input's
    # per-knob hints, so asserting it would pass forever and prove nothing, which is worse than no assertion.
    app.count_zero(
        "/settings shows no pending sentence on a host that has never saved (the marker is earned, not decorative)",
        page,
        '<p class="pending-saved">',
    )
    app.joined_at_least(
        "/settings states the 0.5.0 rule for the four restart-only boxes",
        page,
        "those four boxes show what the file says",
    )

    # The leak question here is about RESOLVED ABSOLUTE paths, which only a live process knows. Bare filenames are NOT
    # asserted absent: two config.py field descriptions name `<data>/ca/ca_key.pem` and `<data>/instance/secret_key` to
    # explain what mypki does NOT touch, and those descriptions render verbatim as hint lines — asserting their absence
    # fails against a correct page, which an earlier draft of tests/test_no_key_leakage.py did exactly.
    resolved = re.search(r"Data directory \(resolved\)</th>\s*<td[^>]*>([^<]*)</td>", joined(page))
    if resolved is None:
        app.check("/settings does not show a resolved data directory — the leak check below cannot run", False)
        return
    data_root = resolved.group(1).strip()
    app.check(f"/settings shows the resolved data directory ({data_root})", data_root != "")
    leaked = 0
    for suffix in ("/ca/ca_key.pem", "/instance/secret_key"):
        found = count(page, f"{data_root}{suffix}")
        if found >= 1:
            app.check(f"/settings renders the resolved key path {data_root}{suffix}", False)
            leaked += 1
    app.check("/settings names no resolved CA-key or secret-key path", leaked == 0)


# ==================================================================================== §13 inline form errors on confirm


def section_13(app: Harness) -> None:
    app.report.section("§13 Inline form errors on the confirm page (page-map §3)")
    generated = app.state.get("generated_csr")
    if not generated:
        app.warn("§5 produced no CSR, so the confirm-page error case could not run")
        return

    # A fresh step A: §6's signing consumed the staged request, so nothing is pending now.
    sign_form = app.get("/csr/sign")
    token = csrf_token(sign_form.text)
    if token is None:
        app.warn("the sign form carried no CSRF token, so §13 could not run")
        return
    app.write_fixture("paste.csr", generated)
    step_a = app.post("/csr/sign", {"csrf_token": token, "csr_pem": generated})
    if not app.expect_status("step A again (the signing in §6 consumed the first staged request)", step_a, 200):
        return
    pending = pending_id(step_a.text)
    if not app.check(
        "the confirm form carries the staged request in its action URL (?pending= id)", pending is not None
    ):
        return

    # One bad field (a three-letter country) alongside two deliberate edits. Everything else is left as the request said
    # it.
    edited = {
        "csrf_token": token,
        "confirm": "1",
        "cert_type": "server",
        "validity_days": "30",
        "common_name": "web.internal",
        "organization": "Renamed By E2E",
        "organizational_unit": "",
        "country": "XXL",
        "state": "",
        "locality": "",
        "email": "ops@example.test",
        "sans": "web.internal\n*.lab.local\n10.0.0.7",
    }
    rejected = app.post(f"/csr/sign?pending={pending}", edited)
    body = rejected.text
    # A bad *form field* returns the same page with the reason inline, while a bad *artifact* is 400/403/413. That
    # distinction is the whole point of this section: the status says what was wrong, the surface says where the fix can
    # be typed.
    app.check(
        f"a bad edited country returns the same page at 200, not an error page (got {rejected.status_code})",
        rejected.status_code == 200,
    )
    app.count_at_least("the reason names the field and the rule ('exactly two letters')", body, "exactly two letters")
    app.count_at_least(
        "the other edit is preserved in its input — one rejected character must not cost the rest of the form",
        body,
        'value="Renamed By E2E"',
    )
    app.count_at_least("the page says plainly that nothing was signed", body, "Nothing was signed")

    # The staged request must still be there, under the SAME id — otherwise fixing one character means re-pasting a PEM.
    again = pending_id(body)
    if not app.check(
        f"the staged request survives with the same ?pending= id ({(again or 'none')[:12]}…)",
        again == pending and again is not None,
    ):
        return

    token = csrf_token(body) or token
    edited["country"] = "DE"
    edited["csrf_token"] = token
    issued = app.post(f"/csr/sign?pending={pending}", edited)
    if not app.expect_status("the corrected confirm issues", issued, 200):
        return
    card = issued.text
    # That diff is the price of an editable confirm form: nothing here unwinds a signed certificate — the only
    # correction an operator has is a revoke, and `/issued` says what that reaches.
    app.count_at_least(
        "the issued page names what the operator changed (page-map §3's diff)", card, "Changed from your request"
    )
    app.count_at_least("the diff carries the edited value, not just a label", card, "Renamed By E2E")


# =============================================================================================== §14 key material sweep


def section_14(app: Harness) -> None:
    app.report.section("§14 No key material in any response (page-map §0)")
    # The assertion is against PEM ARMOUR, not the phrase "PRIVATE KEY": /csr/generate legitimately DOCUMENTS the
    # ENCRYPTED PRIVATE KEY format, and a check that forbade the words would either fail on honest prose or be loosened
    # until it stopped catching real leaks. Nine GETs as of 0.5.0 — and `/inspect` joins only as a plain GET, which is
    # load-bearing: /inspect POSTed with a key renders `-----BEGIN PRIVATE KEY-----` twice ON PURPOSE (the armour
    # survives redaction so the operator can see which block was redacted). Feeding a key paste to this loop would fail
    # a correct app; §15 asserts that case against base64 instead.
    pages = ("/", "/csr/generate", "/csr/sign", "/ca", "/issued", "/about", "/inspect", "/settings", "/version")
    for path in pages:
        response = app.get(path)
        found = count_re(response.text, r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
        app.check(f"{path} contains no private-key armour (status {response.status_code})", found == 0)

    # Response HEADERS and cookie VALUES are swept too: a key that leaks into a filename or a cookie is still a leak,
    # and this is the only place in the repo that looks at those two carriers over real HTTP.
    header_leaks = 0
    for path in pages:
        response = app.get(path)
        for name, value in response.headers.items():
            if re.search(r"PRIVATE KEY|BEGIN [A-Z ]*PRIVATE", value, re.IGNORECASE):
                app.check(f"{path} leaks key material into the {name} header", False)
                header_leaks += 1
    app.check(f"no response header on any of the {len(pages)} pages carries key material", header_leaks == 0)

    cookies = "; ".join(f"{name}={value}" for name, value in app.client.cookies.items())
    app.check("no cookie value in this session carries key material", "PRIVATE KEY" not in cookies.upper())

    # The CA key's actual DER bytes must not appear on any page either. Armour-counting cannot catch a raw dump of the
    # same key, and only a live process knows what its own key looks like — the harness reads it out of the scratch data
    # dir it created.
    key_path = app.state.get("ca_key_path")
    if key_path is None or not Path(key_path).is_file():
        app.warn(
            "the scratch CA's private key file was not readable, so its bytes could not be searched for on the pages"
        )
        return
    try:
        pem_bytes = Path(key_path).read_bytes()
        key = serialization.load_pem_private_key(pem_bytes, password=None)
        der = key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    except Exception as exc:
        app.warn(f"the scratch CA key could not be loaded to search for its bytes ({exc})")
        return
    body_b64 = base64.b64encode(der).decode("ascii")
    wrapped = "\n".join(body_b64[i : i + 64] for i in range(0, len(body_b64), 64))
    leaks = 0
    for path in pages:
        text = app.get(path).text
        if body_b64 in text or wrapped in text:
            app.check(f"{path} echoes the CA key's own base64 body", False)
            leaks += 1
    app.check(
        "no page contains the CA private key's DER or its bare base64 body (checked against this host's real key)",
        leaks == 0,
    )


# ====================================================================================================== §15 inspect PEM


def section_15(app: Harness) -> None:
    app.report.section("§15 Inspect PEM (page-map §13)")
    # The posture this section exists to hold: /inspect is a READER. It describes what a PEM says and refuses exactly
    # one thing, an oversized body. Every other page in this app refuses input it dislikes; a page that never refuses
    # has no error surface to assert on, so §15 asserts the opposite — that facts appear where a refusal used to be, and
    # that the one refusal which does exist names mypki's knob rather than the framework's.
    response = app.get("/inspect")
    if not app.expect_status("GET /inspect", response, 200):
        return
    page = response.text
    app.count_exactly(
        "/inspect posts exactly one field, pem_paste (the whole page is one textarea)", page, 'name="pem_paste"', 1
    )
    app.count_exactly("/inspect says plainly that nothing has been pasted yet", page, "Nothing pasted yet", 1)
    app.count_zero(
        "/inspect inventories no facts on an empty paste (a GET fabricates no report)", page, '<th scope="row">'
    )

    for needle, label in (
        ("It does not verify a chain.", "/inspect states that it cannot verify a chain"),
        # The NEEDLE is unchanged and still true; what was stale is the label, which said "no CRL, no OCSP" as if this
        # host published neither. It publishes both now — /inspect just never consults either.
        (
            "It does not know about revocation.",
            "/inspect states that it consults nothing: it reports no CRL or OCSP answer even though this host now"
            " publishes both",
        ),
        ("Its findings are not gates.", "/inspect states that its findings are descriptions, not refusals"),
        ("A private key is named and not opened.", "/inspect promises a pasted key will be named, not opened"),
    ):
        app.count_exactly(label, page, needle, 1)

    # The nav has to reach this page from pages that existed before it, or the page does not exist in practice. Checked
    # on THREE OTHER pages rather than on /inspect, because a nav that carried the link only on /inspect would pass a
    # count taken from /inspect alone.
    for path in ("/", "/ca", "/settings"):
        other = app.body_of(path)
        if not other:
            app.warn(
                f"{path} was not fetched earlier in this run, so its nav could not be checked for the /inspect link"
            )
            continue
        found = count_re(other, r'class="nav-item[^"]*" href="/inspect"')
        app.check(f"{path}'s nav links to /inspect ({found})", found == 1)
    app.count_exactly("/inspect marks its own nav item active", page, 'class="nav-item active" href="/inspect"', 1)

    ca_pem = app.state.get("ca_pem")
    token = csrf_token(page)
    if not ca_pem:
        app.warn(
            "§9 left no CA download in hand, so /inspect's certificate, key and oversized cases were not exercised"
        )
        return
    if token is None:
        app.check("/inspect's form carries no CSRF token — every §15 POST below would be untestable", False)
        return

    app.write_fixture("ca.crt", ca_pem)

    def paste(body_text: str, out_name: str, *, with_token: bool = True) -> httpx2.Response:
        # The paste goes as a urlencoded textarea value, which is what the browser sends for this field — and it is the
        # shape where curl's `-F` truncated a multi-line PEM at its first newline. `post_pem_field` existed in the shell
        # harness only to dodge that; here it is simply the default.
        app.write_fixture(out_name, body_text)
        fields = {"pem_paste": body_text}
        if with_token:
            fields["csrf_token"] = token
        return app.post("/inspect", fields)

    # A real certificate: the CA this harness runs on, read back off the download §9 already fetched. This makes §15
    # self-referential in the useful direction — the bytes §9 asserted as a download and §9 asserted as an on-screen
    # block are handed to a THIRD page, and the answer has to agree with both. No fixture is hard-coded here, so a host
    # whose CA is EC, or RSA-4096, or named differently, still passes: the assertions are about structure plus the rows
    # §9 already proved.
    parsed = paste(ca_pem, "ca.crt")
    if not app.expect_status("POST /inspect with a real CA certificate", parsed, 200):
        return
    read = parsed.text
    app.count_exactly(
        "/inspect reads BasicConstraints out of the paste and renders it", read, "CA:TRUE pathLength:0", 1
    )
    app.count_at_least("/inspect names a self-signed root as a finding", read, "self-signed root")

    # Scoped on purpose. The lede legitimately contains `not a CA` as an EXAMPLE of what findings look like (measured:
    # page-wide 1, findings block 0). Asserting page-wide absence would fail a correct app; asserting nothing at all
    # would let "not a CA" leak onto the host's own root. -1 (no findings block at all) is itself a failure rather than
    # an absence to compare.
    block = re.search(r'<ul class="findings">(.*?)</ul>', read, re.DOTALL)
    if block is None:
        app.check(
            "/inspect rendered no findings block for a self-signed root, so 'not a CA' could not be scoped", False
        )
    else:
        inside = block.group(1).count("not a CA")
        app.check(
            f"the host's own root is not called 'not a CA' inside its findings block ({inside} inside,"
            f" {count(read, 'not a CA')} page-wide)",
            inside == 0,
        )
    app.count_exactly('a finding renders as class="findings", not as a form error', read, 'class="findings"', 1)
    app.count_zero(
        "/inspect reports nothing as a form error (it refused nothing, so there is nothing to fix)",
        read,
        'class="form-errors"',
    )
    app.count_exactly("/inspect echoes the parsed block as an addressable PEM block", read, 'id="pem-1"', 1)
    app.count_exactly("/inspect wires the copy button to that block", read, 'data-mypki-copy="pem-1"', 1)
    app.count_exactly("/inspect reports a SHA-256 of the DER it decoded", read, "SHA-256 of the DER", 1)

    # Byte parity — the same question §9 asks of /ca's block, asked of a THIRD rendering of the same certificate. Scoped
    # to the report block rather than handed straight to pem_block, because measured on the first live run: /inspect's
    # textarea carries a PLACEHOLDER that spells out `-----BEGIN CERTIFICATE----- … -----END CERTIFICATE-----` as
    # example text, so the FIRST armour pair on this page is an example, not the parsed block. Unscoped, the assertion
    # hashed placeholder text and reported a byte mismatch against a correct app — a harness bug found by running the
    # harness.
    scoped = re.search(r'<pre class="pem" id="pem-1">(.*?)</pre>', read, re.DOTALL)
    if scoped is None:
        app.check("/inspect echoed no extractable CERTIFICATE block to compare against the download", False)
    else:
        echoed = pem_block(scoped.group(0), "CERTIFICATE")
        if echoed is None:
            app.check("/inspect's pem-1 block holds no PEM to hash", False)
        else:
            echo_sha = pem_der_sha(echoed)
            download_sha = pem_der_sha(ca_pem)
            app.check(
                f"the block /inspect echoed is the same bytes as the CA download ({echo_sha})",
                echo_sha is not None and echo_sha == download_sha,
            )

    # A private key pasted by accident: named, redacted, and asserted against the BASE64 rather than the armour. The
    # sentinel body is not a key — it is fixed text whose base64 this harness can name exactly. With a real key there is
    # no string to search for, so the only honest version of this leak test uses material the harness wrote itself.
    sentinel = "MYPKI-E2E-SENTINEL-PRIVATE-KEY-BODY-not-a-real-key-0123456789abcdef"
    key_body = base64.b64encode(sentinel.encode()).decode("ascii")
    folded = "\n".join(key_body[i : i + 64] for i in range(0, len(key_body), 64))
    key_text = f"-----BEGIN PRIVATE KEY-----\n{folded}\n-----END PRIVATE KEY-----\n"
    app.write_fixture("sentinel.key", key_text)

    keyed = paste(key_text, "sentinel.key")
    if not app.expect_status("POST /inspect with a private key (it refuses nothing, including this)", keyed, 200):
        return
    redacted_page = keyed.text
    app.count_exactly(
        "/inspect says out loud that it redacted a key — no quiet edit of what was pasted",
        redacted_page,
        "private-key block(s) were in your paste",
        1,
    )
    app.count_exactly(
        "the redaction marker appears twice: once in the echoed paste, once naming itself",
        redacted_page,
        "redacted by mypki",
        2,
    )
    app.count_at_least(
        "/inspect names the block as a key and says it was not opened",
        redacted_page,
        "this is a private key. mypki did not open it",
    )

    leaked = [line for line in folded.split("\n") if line and line in redacted_page]
    armour = count_re(redacted_page, r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
    # Armour counts are REPORTED in the passing label rather than asserted as zero: armour surviving is documented
    # behaviour (§14), and asserting its absence here would fail a correct app. What must be absent is the base64 body.
    app.check(
        f"no base64 line from the pasted key survives in the response (armour lines present x{armour}, by design)",
        not leaked,
    )
    app.count_zero(
        "/inspect hashed nothing it refused to read (no fingerprint for a key it never opened)",
        redacted_page,
        "SHA-256 of the DER",
    )

    # The one refusal this page makes, and whose sentence it is.
    oversized = paste("y" * 40_000, "big.txt")
    named = count(oversized.text, "MYPKI_MAX_CSR_CHARS")
    app.check(
        f"an oversized paste answers 413 naming MYPKI_MAX_CSR_CHARS (status {oversized.status_code}, knob named"
        f" x{named})",
        oversized.status_code == 413 and named >= 1,
    )
    app.count_zero(
        "/inspect's size refusal is mypki's page, not starlette's JSON", oversized.text, "Field exceeded maximum size"
    )

    # A missing token: refused BEFORE the paste is read, so the paste never reaches the page.
    no_token = paste(ca_pem, "ca.crt", with_token=False)
    named = count(no_token.text, "CSRF")
    app.check(
        f"/inspect refuses a tokenless POST at 400 naming CSRF (status {no_token.status_code}, named x{named})",
        no_token.status_code == 400 and named >= 1,
    )
    app.count_zero(
        "the rejected paste is not echoed back (a refusal is not an echo chamber)",
        no_token.text,
        "-----BEGIN CERTIFICATE-----",
    )

    # Junk: described, not refused. This is the whole reason the page exists.
    junk = paste("hello world", "junk.txt")
    if app.expect_status("text with no PEM armour answers rather than a refusal", junk, 200):
        app.count_at_least(
            "/inspect names junk as 'nothing readable' instead of refusing it", junk.text, "nothing readable"
        )
        app.count_at_least(
            "the finding says what is missing rather than 'invalid input'", junk.text, "nothing to report"
        )


# ================================================================================================ §16 consent for drops


def section_16(app: Harness) -> None:
    app.report.section("§16 Dropped extensions need consent (page-map §3 rule 6)")
    # Both fixtures are single, well-formed PEM blocks that verify against their own signatures. They are embedded
    # rather than minted with openssl so §16 runs wherever the other fifteen run and needs no openssl at harness time.
    app.check(
        f"the consent fixture is a single PEM block ({len(CONSENT_CSR.encode())} bytes)",
        count(CONSENT_CSR, CSR_BEGIN) == 1,
    )
    app.check(
        f"the privileged fixture is a single PEM block ({len(PRIVILEGED_CSR.encode())} bytes)",
        count(PRIVILEGED_CSR, CSR_BEGIN) == 1,
    )

    token = app.state.get("token")
    if token is None:
        app.warn("no CSRF token carried from §5/§6, so the consent flow could not run")
        return

    def step_a(csr_text: str, extra: dict[str, str] | None = None) -> httpx2.Response:
        sign_form = app.get("/csr/sign")
        live_token = csrf_token(sign_form.text) or token
        app.state["token"] = live_token
        app.write_fixture("paste.csr", csr_text)
        fields = {"csrf_token": live_token, "csr_pem": csr_text}
        fields.update(extra or {})
        return app.post("/csr/sign", fields)

    # STEP A: a request carrying ignorable extensions now REACHES the confirmation panel instead of being refused at
    # step 6. This is the section that exists because an operator could not sign an ordinary CSR.
    confirm = step_a(CONSENT_CSR)
    if not app.expect_status(
        "a CA:FALSE + keyUsage CSR reaches the confirmation panel (not a 403 refusal)", confirm, 200
    ):
        return
    panel = confirm.text
    app.count_at_least(
        "the panel names BasicConstraints CA:FALSE as something it will not copy", panel, "BasicConstraints CA:FALSE"
    )
    app.count_at_least(
        "the panel names both KeyUsage bits by name, not bare 'KeyUsage'",
        panel,
        "KeyUsage (digitalSignature, keyEncipherment)",
    )
    app.count_exactly("exactly one consent box is offered", panel, 'name="ignore_extensions"', 1)
    # Default OFF is markup, not a promise: the control must arrive unticked AND say so in its own state word.
    consent_tags = re.findall(r'<input type="checkbox"[^>]*name="ignore_extensions"[^>]*>', joined(panel))
    app.check(
        f"the consent box arrives UNTICKED — default OFF is markup, not a promise ({len(consent_tags)} tag(s),"
        f" {count(' '.join(consent_tags), 'checked')} 'checked')",
        len(consent_tags) >= 1 and all("checked" not in tag for tag in consent_tags),
    )
    app.count_exactly(
        "the word beside the unticked box reads 'off' in the off colour (a page cannot show 'on' beside an unticked"
        " box)",
        panel,
        'class="checkbox-state state-off">off<',
        1,
    )

    # The reverse case, which is what makes "no box" unambiguous: a CSR mypki generated itself has SAN and nothing else,
    # so it must render no list and no box rather than an empty one. Asserted on its own step A POST rather than on §6's
    # page, so this section does not depend on what earlier sections left in a variable — and staging signs nothing, so
    # no ledger count moves here.
    generated = app.state.get("generated_csr")
    if generated:
        plain = step_a(generated)
        plain_body = plain.text
        app.count_zero(
            "a mypki-generated CSR renders no consent box at all (nothing to consent about)",
            plain_body,
            'name="ignore_extensions"',
        )
        app.count_zero(
            "and no empty dropped-extension block either", plain_body, 'class="provenance dropped-extensions"'
        )
    else:
        app.warn("§5 left no generated CSR in hand, so the no-consent-box case was not exercised")

    pending = pending_id(panel)
    if not app.check("step A staged a ?pending= id for the consent checks below", pending is not None):
        return

    # STEP B, consent WITHHELD: an input to fix, not a refused request. 200, everything named, nothing signed.
    withheld = app.post(
        f"/csr/sign?pending={pending}",
        {"csrf_token": token, "confirm": "1", "cert_type": "server", "validity_days": "30"},
    )
    if not app.expect_status("confirming without the box (nothing was refused)", withheld, 200):
        return
    body = withheld.text
    app.count_at_least("the refusal names the decision that is missing", body, "consent to dropped extensions")
    app.count_at_least(
        "the unticked refusal lists every extension at stake (no 'some extensions' hand-wave)",
        body,
        "KeyUsage (digitalSignature, keyEncipherment)",
    )
    app.count_at_least("the unticked refusal states plainly that nothing was signed", body, "Nothing was signed")
    app.count_zero("no certificate card was rendered while consent was withheld", body, "<h2>Issued:")
    # 'tick the box' is only fixable without re-pasting a 1 KB PEM if the staged request survives under the SAME id.
    survived = pending_id(body)
    app.check(
        f"the staged request survives the unticked refusal (same ?pending= id: {(survived or 'none')[:12]}…)",
        survived == pending and survived is not None,
    )
    app.count_exactly(
        "the re-rendered page offers the box again rather than a dead end", body, 'name="ignore_extensions"', 1
    )

    # STEP B, consent GRANTED: issue, and name every dropped extension on the issued page.
    token = csrf_token(body) or token
    granted = app.post(
        f"/csr/sign?pending={pending}",
        {
            "csrf_token": token,
            "confirm": "1",
            "cert_type": "server",
            "validity_days": "30",
            "ignore_extensions": "true",
        },
    )
    if not app.expect_status("confirming with the box issues", granted, 200):
        return
    card = granted.text
    app.count_at_least(
        "the certificate the operator consented to is the one that was issued", card, "Issued: consent.lab.local"
    )
    # A dropped extension lands in the SAME diff block as an edited name (page-map §3), so one mechanism reports both
    # ways a request and its certificate can differ.
    app.count_at_least(
        "a dropped extension lands in the same diff block as an edited name", card, "Changed from your request"
    )
    app.count_exactly(
        "the diff names the dropped BasicConstraints", card, "Extension not copied: BasicConstraints CA:FALSE", 1
    )
    app.count_exactly(
        "the diff names the dropped KeyUsage with its bits",
        card,
        "Extension not copied: KeyUsage (digitalSignature, keyEncipherment)",
        1,
    )
    app.count_at_least(
        "the diff closes by stating where the extensions actually came from",
        card,
        "The public key and every extension still came from mypki",
    )

    # Consent changes what is COPIED, never what is SIGNED: the staged PEM keeps its own extensions because its
    # signature covers them (test_consent.py proves that byte-for-byte), so the only visible trace of the request's own
    # BasicConstraints is on this diff block — and the certificate itself has to read as mypki's profile. The serial is
    # what proves a real leaf exists behind the card.
    serial = scoped_serial(card)
    if not app.check(
        f"the consented signing reports its own leaf serial ({(serial or 'none')[:12]}…)", serial is not None
    ):
        return
    # Carried for the openssl half: this certificate is still ACTIVE, while §6's leaf has been revoked by §11. `openssl
    # verify -crl_check` needs a certificate that is *not* on the CRL — on a revoked one, "no scope error" and
    # "certificate revoked" arrive as the same exit code and the scope assertion would mean nothing.
    consented_leaf = pem_block(card, "CERTIFICATE")
    if consented_leaf is not None:
        app.state["active_leaf_pem"] = consented_leaf + "\n"
        app.write_fixture("consent-leaf.pem", consented_leaf + "\n")

    # A privilege claim is not a consent question, and ticking the box does not make it one. Consent buys the dropping
    # of CA:FALSE, never the issuing of a CA.
    refused = step_a(PRIVILEGED_CSR, {"ignore_extensions": "true"})
    body = refused.text
    if not app.expect_status("CA:TRUE is refused even with the consent field posted", refused, 403):
        return
    app.count_at_least("the refusal names BasicConstraints CA:TRUE", body, "BasicConstraints CA:TRUE")
    app.count_at_least("the refusal names keyCertSign", body, "keyCertSign")
    # openssl spells this bit `cRLSign` and rejects `crlSign` as an unknown bit string; mypki names it `crlSign`, which
    # is the spelling `cryptography` and page-map use. Nobody should read mypki's spelling as one mypki invented.
    app.count_at_least("the refusal names crlSign (mypki's spelling of openssl's cRLSign)", body, "crlSign")
    # MEASURED wording closes "… dropped only when you tick the box there." An earlier draft read "only if you tick the
    # box", which no build ever printed — it failed here against a correct 403 page, so the NEEDLE was the bug, not the
    # page.
    app.count_at_least(
        "the hint points at the consent box for the extensions that are ignorable", body, "you tick the box"
    )
    app.count_zero("refusing signed nothing", body, "<h2>Issued:")


# =================================================================================================== openssl (optional)


def find_openssl(explicit: str | None) -> str | None:
    """Locate an openssl binary, or answer None. No version is asserted and none is printed as a requirement: the only
    contract CI carries about openssl is that nothing needs it, so a harness that pinned a version would be inventing
    one."""
    candidate = explicit or shutil.which("openssl")
    if not candidate:
        return None
    path = Path(candidate)
    if not path.is_absolute():
        resolved = shutil.which(candidate)
        if not resolved:
            return None
        path = Path(resolved)
    return str(path) if path.is_file() else None


def openssl_checks(app: Harness, openssl: str | None) -> None:
    """§11 STEP F's external half, re-expressed for a Python harness. WHY THESE SKIP AND EVERYTHING ELSE FAILS. `openssl
    verify` and `openssl crl -noout -text` are the only checks in this file that depend on a toolchain, and
    windows-latest carries no contract for one — CI's own claim is "NO OpenSSL binary is required anywhere". A FAIL on a
    runner that legitimately has no openssl would be a statement about the environment rather than about mypki, so
    absence is a WARN naming exactly what was not checked. Everything else here runs with no toolchain at all. WHY THESE
    CHECKS ARE WORTH ADDING AT ALL: `crl.py`'s decision not to add an IssuingDistributionPoint exists because openssl
    3.5.6 answered `error 44 … different CRL scope` for every certificate this CA signed before 0.7.0. That is the one
    measured fact behind a design decision no amount of in-process parsing can re-derive — only an independent verifier
    can say whether this CA's own CRL is usable against its own history. Runs last rather than inside §11: by then §13
    and §16 have issued two certificates that are still ACTIVE, and `-crl_check` needs a certificate that is *not* on
    the CRL. On every leaf §11 stamped, "no scope error" and "certificate revoked" would arrive as the same exit code,
    which would make the scope assertion mean nothing."""
    app.report.section("§11 STEP F (openssl): independent verification of the artifacts this walk wrote")
    if openssl is None:
        app.warn(
            "openssl is not installed here: `openssl verify` and `openssl crl -noout -text` were NOT run. Skipped"
            " rather than failed, "
            "because windows-latest carries no contract for an OpenSSL binary — CI's claim is that nothing needs one."
        )
        return

    version = subprocess.run([openssl, "version"], capture_output=True, text=True, check=False)
    output = (version.stdout or version.stderr).strip()
    label = output.splitlines()[0] if output else "openssl (version unreadable)"

    ca_pem = app.state.get("ca_pem")
    leaf_pem = app.state.get("leaf_pem")
    crl_pem = app.state.get("crl_pem")
    active_pem = app.state.get("active_leaf_pem")
    if not ca_pem:
        app.warn("no CA PEM in hand from §9, so openssl had nothing to verify against")
        return

    ca_file = app.write_fixture("openssl-ca.pem", ca_pem)
    result = subprocess.run(
        [openssl, "verify", "-CAfile", str(ca_file), str(ca_file)], capture_output=True, text=True, check=False
    )
    verdict = ((result.stdout or result.stderr).strip().splitlines() or ["no output"])[-1]
    app.check(f"{label}: `openssl verify` accepts this CA's own root ({verdict})", result.returncode == 0)

    if leaf_pem:
        leaf_file = app.write_fixture("openssl-leaf.pem", leaf_pem)
        result = subprocess.run(
            [openssl, "verify", "-CAfile", str(ca_file), str(leaf_file)], capture_output=True, text=True, check=False
        )
        verdict = ((result.stdout or result.stderr).strip().splitlines() or ["no output"])[-1]
        app.check(f"`openssl verify` chains the leaf §6 signed to this CA ({verdict})", result.returncode == 0)
    else:
        app.warn("no issued leaf in hand from §6, so openssl could not verify a chain")

    if not crl_pem:
        app.warn("no published CRL PEM in hand from §11 STEP F, so openssl had no CRL to read")
        return

    crl_file = app.write_fixture("openssl-crl.pem", crl_pem)
    result = subprocess.run(
        [openssl, "crl", "-in", str(crl_file), "-noout", "-text"], capture_output=True, text=True, check=False
    )
    detail = (result.stdout or result.stderr).strip()
    app.check(f"`openssl crl -noout -text` parses the published CRL ({label})", result.returncode == 0 and bool(detail))

    listed = re.findall(r"Serial Number:\s*([0-9A-Fa-f:]+)", detail)
    normalised = {item.replace(":", "").lstrip("0").lower() for item in listed}
    stamped = app.state.get("stamped_serials", [])
    missing = [serial for serial in stamped if serial.lstrip("0").lower() not in normalised]
    app.check(
        f"`openssl crl -text` names every serial this walk revoked ({len(stamped) - len(missing)}/{len(stamped)}"
        f" matched; "
        f"{len(listed)} serial(s) read from its text)",
        bool(stamped) and not missing,
    )

    # THE check that earns this whole section. openssl refuses to apply a CRL whose scope differs from the certificate
    # being checked. `crl.py` omits IssuingDistributionPoint for exactly this measured reason: an IDP-scoped CRL
    # answered `error 44 … different CRL scope` against openssl 3.5.6 for every leaf this CA signed before 0.7.0. A
    # future `.add_extension(x509.IssuingDistributionPoint(…))` would look correct in the OID census above and break
    # here instead — which is why it is asserted with the external tool rather than only by parsing.
    if active_pem:
        active_file = app.write_fixture("openssl-active-leaf.pem", active_pem)
        result = subprocess.run(
            [openssl, "verify", "-CAfile", str(ca_file), "-CRLfile", str(crl_file), "-crl_check", str(active_file)],
            capture_output=True,
            text=True,
            check=False,
        )
        combined = f"{result.stdout}\n{result.stderr}"
        verdict = (combined.strip().splitlines() or ["no output"])[-1]
        scope_error = "different CRL scope" in combined or "CRL scope" in combined
        app.check(
            "`openssl verify -crl_check` applies this CA's CRL to a certificate it issued, with no 'different CRL"
            " scope' error — the "
            f"measured reason crl.py omits an IssuingDistributionPoint ({verdict})",
            not scope_error and result.returncode == 0,
        )

        # The mirror of the same command on a serial §11 revoked: openssl must call it revoked. This is the one
        # assertion in this file that compares mypki's store against an outside reader of the published artifact rather
        # than against mypki's own parser.
        if leaf_pem:
            leaf_file = app.write_fixture("openssl-leaf.pem", leaf_pem)
            revoked = subprocess.run(
                [openssl, "verify", "-CAfile", str(ca_file), "-CRLfile", str(crl_file), "-crl_check", str(leaf_file)],
                capture_output=True,
                text=True,
                check=False,
            )
            text = f"{revoked.stdout}\n{revoked.stderr}"
            verdict = (text.strip().splitlines() or ["no output"])[-1]
            app.check(
                f"the same command reports §6's revoked leaf as revoked to openssl ({verdict}) — the published CRL is"
                f" readable by a "
                "client that never asked mypki anything",
                revoked.returncode != 0 and "revoked" in text.lower(),
            )
        else:
            app.warn("no revoked leaf in hand, so openssl's reading of a revocation could not be asserted")
    else:
        app.warn(
            "no ACTIVE issued certificate was available (§13 and §16 issue the two that stay unrevoked), so"
            " `-crl_check` scope "
            "behaviour could not be asserted — on a revoked leaf 'no scope error' and 'certificate revoked' share one"
            " exit code"
        )


# ==================================================================================================== server lifecycle


def free_port() -> int:
    """Bind port 0 and let the OS choose, then release it. Ephemeral on purpose: a hard-coded port would collide with
    whatever a previous run left behind (SMOKE_TESTING.md records a stale ~/.config/mypki/mypki.env setting
    MYPKI_PORT=8444 and making a harness read that instead of its own scratch config), and a collision reads as 'the
    server is broken' when it is only this box being busy."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def read_version() -> str | None:
    """The expected version, from the one line that declares it (the same anchored pattern hatchling reads)."""
    try:
        for line in VERSION_FILE.read_text(encoding="utf-8").splitlines():
            match = re.match(r'^__version__ = "([^"]+)"$', line)
            if match:
                return match.group(1)
    except OSError:
        return None
    return None


def child_env(root: Path, port: int) -> dict[str, str]:
    """An environment with every mypki-visible location redirected into the scratch tree. HOME plus the four XDG
    variables plus APPDATA/LOCALAPPDATA are all set inside `root`, and MYPKI_CONFIG_DIR is pinned to a directory that
    does not exist yet. This is the arrangement SMOKE_TESTING.md records as the fix for the harness defect that read a
    stale ~/.config/mypki/mypki.env instead of its own scratch config: without it, §12's assertions run against whatever
    the operator's real box happens to hold, and a refused save could write into it. Windows-style variables are set on
    every platform because app.py's path resolution branches on them, and setting one costs nothing."""
    env = dict(os.environ)
    env["HOME"] = str(root / "home")
    env["USERPROFILE"] = str(root / "home")
    env["XDG_CONFIG_HOME"] = str(root / "xdg" / "config")
    env["XDG_DATA_HOME"] = str(root / "xdg" / "data")
    env["XDG_CACHE_HOME"] = str(root / "xdg" / "cache")
    env["XDG_STATE_HOME"] = str(root / "xdg" / "state")
    env["APPDATA"] = str(root / "appdata")
    env["LOCALAPPDATA"] = str(root / "appdata-local")
    env["MYPKI_CONFIG_DIR"] = str(root / "config")
    env["MYPKI_DATA_DIR"] = str(root / "data")
    env["MYPKI_HOST"] = "127.0.0.1"
    env["MYPKI_PORT"] = str(port)
    # The pointer baked into issued leaves. A real host name would be honest for a human and unreachable from this run;
    # the CDP is asserted structurally in §9/§11 rather than by fetching it, so what matters here is that it is a valid
    # absolute URL.
    env["MYPKI_CRL_BASE_URL"] = f"http://127.0.0.1:{port}"
    env["MYPKI_LOG_LEVEL"] = "INFO"
    env["MYPKI_LOG_FILE"] = str(root / "logs" / "mypki.log")
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "NO_PROXY", "no_proxy"):
        env.pop(name, None)
    for directory in ("home", "xdg/config", "xdg/data", "xdg/cache", "xdg/state", "appdata", "appdata-local", "logs"):
        (root / directory).mkdir(parents=True, exist_ok=True)
    return env


def spawn(args: list[str], env: dict[str, str], cwd: Path, log_path: Path) -> subprocess.CompletedProcess[str]:
    """One CLI invocation as a real child process, with its environment replaced rather than patched. cwd is the scratch
    root, never the repository: mypki also reads `./.env`, and running from BUILD_ROOT would let a stray .env in the
    checkout steer this run — which is exactly what `python-dotenv`'s find_dotenv walk-up was measured to do when serve
    ran from src/."""
    with log_path.open("ab") as handle:
        return subprocess.run(args, env=env, cwd=str(cwd), stdout=handle, stderr=handle, check=False)


def wait_for_server(process: subprocess.Popen[str], port: int, deadline_seconds: float = 45.0) -> bool:
    """Poll the real socket until something accepts, or give up. A fixed sleep would be a guess about how long an
    RSA-3072 key takes to mint on the machine running this; a refused connection after the deadline is a FAIL naming the
    child's own output rather than a timeout dressed as one."""
    deadline = time.monotonic() + deadline_seconds
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def interpreter() -> str:
    """The interpreter the child processes run under: this checkout's venv python when there is one, else the invoking
    one — the same rule tools/fast_lane.py and the Makefile use, stated once more because a subprocess cannot inherit
    it."""
    venv = BUILD_ROOT / ".venv" / "bin" / "python"
    return str(venv) if venv.exists() else sys.executable


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Drive a real mypki server through SMOKE_TESTING.md §1-§16.")
    parser.add_argument(
        "--work", default=None, help="scratch directory for fetched pages and fixtures (kept when named)"
    )
    parser.add_argument(
        "--keep-data", action="store_true", help="keep the scratch DATA dir too (it holds a real CA key)"
    )
    parser.add_argument("--openssl", default=None, help="path to an openssl binary (default: whatever PATH resolves)")
    args = parser.parse_args(argv)

    report = Report()

    version = read_version()
    if version is None:
        print(
            "NOTHING WAS CHECKED: no version readable at src/mypki/__init__.py — every §3/§12 version assertion would"
            " degrade.",
            file=sys.stderr,
        )
        return 2

    own_work = args.work is None
    root = Path(tempfile.mkdtemp(prefix="mypki-e2e.")) if own_work else Path(args.work)
    root.mkdir(parents=True, exist_ok=True)
    work = root / "work"
    work.mkdir(parents=True, exist_ok=True)

    port = free_port()
    env = child_env(root, port)
    base = f"http://127.0.0.1:{port}"

    print("== mypki end-to-end harness ==")
    print(f"base: {base} (ephemeral port chosen by the OS)")
    print(f"data dir: {root / 'data'}")
    print(f"work dir: {work}")
    print(f"expected version: {version} (read from src/mypki/__init__.py)")

    # init-ca first, as a real subprocess. The web UI cannot create a CA; this does, and naming the SAME data dir for
    # both commands is the trap SMOKE_TESTING.md's opening block records — an env var is per-process, so setting it on
    # serve alone would have init-ca write somewhere else and serve then exit 3 'No CA found'. Here both children get
    # the same environment dict.
    init_log = root / "init-ca.log"
    completed = spawn([interpreter(), "-m", "mypki", "init-ca", "--data-dir", str(root / "data")], env, root, init_log)
    if completed.returncode != 0:
        print(f"NOTHING WAS CHECKED: `mypki init-ca` exited {completed.returncode}. Its output:", file=sys.stderr)
        print(init_log.read_text(encoding="utf-8", errors="replace"), file=sys.stderr)
        if own_work and not args.keep_data:
            shutil.rmtree(root, ignore_errors=True)
        return 2

    serve_log = root / "serve.log"
    handle = serve_log.open("ab")
    server = subprocess.Popen(
        [
            interpreter(),
            "-m",
            "mypki",
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--data-dir",
            str(root / "data"),
        ],
        env=env,
        cwd=str(root),
        stdout=handle,
        stderr=handle,
    )

    try:
        if not wait_for_server(server, port):
            tail = serve_log.read_text(encoding="utf-8", errors="replace").strip().splitlines()[-12:]
            print("NOTHING WAS CHECKED: the server never accepted a connection. Its last lines:", file=sys.stderr)
            for line in tail:
                print(f"  {line}", file=sys.stderr)
            return 2

        app = Harness(report, base, work, version)
        try:
            # The scratch CA's own key path is needed by §14's "no page contains the CA key's DER" sweep. It is read
            # from the tree this harness created rather than hard-coded, because it is where this run's env put it.
            ca_key = root / "data" / "ca" / "ca_key.pem"
            app.state["ca_key_path"] = str(ca_key)
            app.state["stamped_serials"] = []

            for section in (section_1, section_2, section_3, section_4, section_5, section_6, section_7, section_8):
                section(app)
            section_9(app)
            section_10(app)
            section_11(app)
            for section in (section_12, section_13, section_14, section_15, section_16):
                section(app)
            # Last, not inside §11: §13 and §16 issue the two certificates that stay ACTIVE, and `openssl verify
            # -crl_check` needs a certificate that is not on the CRL. See openssl_checks' docstring for why the order is
            # load-bearing.
            openssl_checks(app, find_openssl(args.openssl))
            exit_code = report.summary()
        finally:
            app.close()
    finally:
        if server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
        handle.close()
        if own_work and not args.keep_data:
            shutil.rmtree(root, ignore_errors=True)
        else:
            print(
                f"scratch tree kept at {root} (it holds a real CA private key — delete it when you are done reading it)"
            )

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
