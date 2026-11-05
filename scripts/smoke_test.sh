#!/usr/bin/env bash
# smoke_test.sh — automated walk of SMOKE_TESTING.md §1-§16, with expectations asserted by the script instead of by eye.
#
# WHAT THIS IS
#   Every manual step in SMOKE_TESTING.md, run in order against a live `mypki serve`, then reported (console + optional
#   markdown file). It is the Linux counterpart of scripts/smoke_test.ps1; both walk the same numbered document, so a
#   failure on either OS names the same step.
#
# WHY THE ASSERTIONS ARE NOT `grep -c`
#   `grep -c` counts LINES. mypki's pages put several facts on one line and repeat others across lines, so "1" is the
#   answer for a full table and for an empty <pre> alike depending on where the pattern sits — it never answers the real
#   question, which is HOW MANY OCCURRENCES. Every count here is an occurrence count (count_all / count_re), and 0 is a
#   FAIL wherever the honest expectation is at least one.
#
# WHY THE HTTP LAYER IS curl AND NOT wget/python
#   Header-level assertions (`Content-Disposition`, `Cache-Control`, CSP) are the point of §2 and §8, and they have to be
#   read from the same client a browser would use. The PowerShell counterpart drives real curl.exe for the same reason
#   (STYLE §12): cmdlet wrappers normalise headers and hide exactly the defects this script exists to catch.
#
# WHY ONE PART OF THIS USES PYTHON
#   Extracting the generated CSR from the confirmation page means un-escaping HTML entities (`&lt;` → `<`) that Jinja's
#   autoescape deliberately added. Doing that with sed is a chain of substitutions that silently mis-orders `&amp;` and
#   produces a PEM that fails validation — which would read as "the sign page is broken" rather than "the harness is
#   broken". One small helper does it properly. Everything else stays bash + curl.
#
# WHERE THIS LIVES, AND WHY THAT MATTERS
#   scripts/smoke_test.sh, tracked in git and deliberately NOT shipped in the sdist or wheel (pyproject's sdist `exclude`
#   names `scripts`). An installed CA has no business carrying a curl harness; a source checkout does.
#
# USAGE (from the repository root, or from inside scripts/ — both work)
#   scripts/smoke_test.sh                                       # finds the server the way mypki would (see below)
#   scripts/smoke_test.sh --base https://localhost:8443 --insecure    # TLS run
#   scripts/smoke_test.sh --work /tmp/mypki-smoke --report /tmp/report.md
#   scripts/smoke_test.sh --version 0.1.0                        # override the expected version
#   BASE=... WORK=... scripts/smoke_test.sh                      # env form also works
#   MYPKI_PORT=8543 scripts/smoke_test.sh                        # a saved or exported port is FOUND, not guessed
#
# WHICH SERVER YOU ARE TESTING (and why the port is not written in this file)
#   The base URL comes from, in order — the same order mypki's own settings use:
#     1. --base / BASE                       explicit wins, always
#     2. MYPKI_HOST and MYPKI_PORT           a real environment variable beats any file
#     3. <config-dir>/mypki.env              what /settings wrote
#     4. ./.env                              the project-directory layer mypki also reads
#     5. http://127.0.0.1:8443               mypki's own defaults, ASSIGNED on exactly one line below (DEFAULT_PORT); every other
#        8443 in this file is prose or a usage example, never a second default
#   Layer 3 outranks layer 4 because settingsfile.env_file_layers() returns ('.env', <config>/mypki.env) and the later entry
#   wins; the config dir is resolved as paths.resolve_config_dir resolves it (MYPKI_CONFIG_DIR, then %APPDATA%\mypki, then
#   $XDG_CONFIG_HOME/mypki, then ~/.config/mypki). Before 0.5.2 this script read only layers 1 and 5, so an operator who saved
#   a new port on /settings got "NOTHING WAS CHECKED: http://127.0.0.1:8443 is not answering" from a healthy server — the worst
#   answer this script can give, because exit 2 means 'nothing was checked' while reading as 'the app is broken'.
#   A WILDCARD HOST IS DIALLED AS LOOPBACK: `MYPKI_HOST=0.0.0.0` (or `::`) is a bind address — it says "listen on every
#   interface of this box", and `config.py` accepts it for exactly that reason. It is not an address anyone can connect to:
#   MEASURED here, curl happens to accept http://0.0.0.0:8591/ and reaches the server, so this defect is INVISIBLE on Linux,
#   while the same base on Windows/macOS resolves through the route table and the reachability gate reports NOTHING WAS
#   CHECKED from a healthy server (and an IPv6-preferring client dials ::1 against an IPv4-only bind). So the layer note keeps
#   spelling what the operator's file says, and only the host this harness dials becomes 127.0.0.1 / [::1]. Explicit --base is
#   never rewritten: if you name an address, you mean that address.
#   WHY THIS HALF USES python3 AND THE .ps1 DOES NOT: this script already shells out to python3 seven times for HTML entity
#   decoding, so a dotenv reader adds no new dependency here. scripts/smoke_test.ps1 keeps its own header's promise that
#   "everything else stays PowerShell + curl" and implements the same chain in PowerShell. One rule, expressed twice, on purpose:
#   the two chains are mirrors and must be edited together or they drift. That is the cost of a mirror, written down now rather
#   than discovered in a later release.
#   WHAT IS NOT PRINTED: nothing is printed before §1. Both logs start at line 1 with '§1 Home page' and SMOKE_TESTING.md records
#   heading line numbers for both logs; the resolved base and the layer that won are recorded in the markdown report header instead.
#
# EXIT CODES (the repo's convention: "not checked" is NOT "checked and clean")
#   0  every check passed (warnings allowed, and listed in the report)
#   1  at least one FAIL — a real defect in what you are testing
#   2  NOTHING WAS CHECKED: server unreachable, curl missing, or bad usage. Never read this as a pass.
#
# WHICH BUILD YOU ARE TESTING (and why the expected version is not written in this file)
#   The version a run expects comes from, in order:
#     1. --version / MYPKI_EXPECTED_VERSION      explicit wins, always
#     2. src/mypki/__init__.py next to this script (the same anchored line hatchling reads)
#     3. nothing — the version check then reports WARN and says to pass --version
#   A literal here would be a second copy of a fact that has exactly one source, and it rots on the first release.

set -uo pipefail

# --------------------------------------------------------------------------- options

# Empty on purpose: the default is applied by the resolver below (see WHICH SERVER YOU ARE TESTING), which has to be able to
# tell "the operator said nothing" from "the operator said 8443". A default written here would outrank every dotenv layer.
BASE="${BASE:-}"
WORK="${WORK:-}"
REPORT=""
EXPECTED_VERSION="${MYPKI_EXPECTED_VERSION:-}"
# A scalar, not an array: expanding an *empty* array as "${ARR[@]}" under `set -u` is the classic bash portability trap,
# and when it degrades it hands curl an empty argument ("no URL specified") — every request then fails silently and a
# healthy server reports as thirty failures. The only value this ever holds is `-k` or nothing.
CURL_EXTRA=""

# The range is the header's own usage-and-precedence block (USAGE through the two "WHICH …" sections). It is a line range
# rather than a here-doc copy so the text a `--help` reader sees is the text above, and cannot drift from it.
# The range is the header's own usage-and-precedence block (USAGE through the two "WHICH …" sections). It is a line range
# rather than a here-doc copy so the text a `--help` reader sees is the text above, and cannot drift from it. Widened for the
# wildcard-host rule; `sed -n '31,$p'`-style open-ended ranges are avoided because they would also print the exit-code block.
usage() { sed -n '31,76p' "$0" | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base) BASE="$2"; shift 2 ;;
    --work) WORK="$2"; shift 2 ;;
    --report) REPORT="$2"; shift 2 ;;
    --version) EXPECTED_VERSION="$2"; shift 2 ;;
    --insecure) CURL_EXTRA="-k"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if ! command -v curl >/dev/null 2>&1; then
  echo "NOTHING WAS CHECKED: curl is not installed." >&2
  exit 2
fi
if [[ -z "$WORK" ]]; then
  WORK="$(mktemp -d "${TMPDIR:-/tmp}/mypki-smoke.XXXXXX")" || { echo "NOTHING WAS CHECKED: cannot create a work dir." >&2; exit 2; }
fi
mkdir -p "$WORK" || { echo "NOTHING WAS CHECKED: cannot create $WORK." >&2; exit 2; }
JAR="$WORK/cookies.txt"
rm -f "$JAR"

# --------------------------------------------------------------------------- version from the single source of truth

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION_FILE="$SCRIPT_DIR/../src/mypki/__init__.py"
if [[ -z "$EXPECTED_VERSION" && -f "$VERSION_FILE" ]]; then
  EXPECTED_VERSION="$(sed -n 's/^__version__ = "\([^"]*\)"$/\1/p' "$VERSION_FILE")"
fi

# --------------------------------------------------------------------------- which server to talk to (mypki's own precedence)

# The one place this file spells a port: DEFAULT_PORT below, which is mypki's own default rather than a copy of one. Everything
# above it is an override, everything below it is a fallback — the same single-source discipline --version follows a few lines up.
# Host and port resolve INDEPENDENTLY, because `config.py` resolves them independently: `Settings.host` and `Settings.port` are two
# fields with two defaults, so a file that saves a host and not a port binds the default port, and an operator who exported only a
# port keeps 127.0.0.1. Resolving them as a pair would send this harness to a server mypki is not running.
# A value that `config.py` would reject is not a candidate either: `MYPKI_PORT=abc` or `MYPKI_PORT=0` fails pydantic's `ge=1` at
# startup, so here it falls back to the default AND SAYS SO — silently guessing while reporting the operator's file as the source is
# how a harness ends up testing its own invention.
BASE_RESOLVED_FROM=""
if [[ -n "$BASE" ]]; then
  BASE_RESOLVED_FROM="--base/BASE (explicit)"
else
  RESOLVED="$(python3 - <<'PY'
import os
import re
from pathlib import Path

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = "8443"
CONFIG_FILE_NAME = "mypki.env"
LINE_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")


def dotenv(path):
    """The shape `settingsfile.read_saved_values` parses: comments, blanks and `export ` prefixes tolerated, a matching
    pair of surrounding quotes dropped, a later line beating an earlier one. Values stay raw strings, because `config.py`
    validates them — and a value that would not validate is no answer to "where is the server" either."""
    values = {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return values
    for raw in text.splitlines():
        match = LINE_RE.match(raw.strip())
        if match is None:
            continue
        name, value = match.group(1), match.group(2)
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[name.upper()] = value.strip()
    return values


def config_dir():
    """`paths.resolve_config_dir`, read from outside: MYPKI_CONFIG_DIR, then %APPDATA%/mypki, then $XDG_CONFIG_HOME/mypki,
    then ~/.config/mypki. The APPDATA arm is kept so a bash under WSL lands on the directory scripts/smoke_test.ps1 uses."""
    explicit = os.environ.get("MYPKI_CONFIG_DIR", "")
    if explicit.strip():
        return Path(explicit.strip()).expanduser()
    appdata = os.environ.get("APPDATA", "")
    if appdata.strip():
        return Path(appdata.strip()) / "mypki"
    config_home = os.environ.get("XDG_CONFIG_HOME", "")
    base = Path(config_home.strip()) if config_home.strip() else Path.home() / ".config"
    return base / "mypki"


def usable_host(value):
    return bool(value) and not any(character.isspace() for character in value)


def usable_port(value):
    return value.isdigit() and 1 <= int(value) <= 65535


# mypki's own order, weakest first: `config.py`'s Field defaults, then `settingsfile.env_file_layers()` — ('.env',
# <config>/mypki.env), the LATER entry winning — then a real environment variable, which is measured to beat both files.
cfg_file = config_dir() / CONFIG_FILE_NAME
layers = [
    ("defaults", {"MYPKI_HOST": DEFAULT_HOST, "MYPKI_PORT": DEFAULT_PORT}),
    ("./.env", dotenv(Path(".env"))),
    (str(cfg_file), dotenv(cfg_file)),
    ("the environment", {key: value.strip() for key, value in os.environ.items() if key.upper() in ("MYPKI_HOST", "MYPKI_PORT")}),
]

winners = {}
for knob, is_usable, fallback in (("MYPKI_HOST", usable_host, DEFAULT_HOST), ("MYPKI_PORT", usable_port, DEFAULT_PORT)):
    for name, values in layers:
        raw = values.get(knob, "")
        if is_usable(raw):
            winners[knob] = (raw, name)
        elif raw:
            # The layer said something this harness cannot use. Falling back quietly would read as "the file said nothing",
            # which is the opposite of what an operator needs to hear when their server is on another port.
            winners[knob] = (fallback, f"{name} ({knob}={raw!r} does not validate)")

host, host_layer = winners["MYPKI_HOST"]
port, port_layer = winners["MYPKI_PORT"]

# A wildcard is a BIND address, not a reachable one: `MYPKI_HOST=0.0.0.0` is how an operator says "answer on every interface
# of this box", and it is a perfectly valid value for `config.py` (uvicorn binds it happily). It is NOT a URL anyone can dial.
# MEASURED on this box: curl happens to accept http://0.0.0.0:8591/ and connects, so the failure is invisible here — but the
# same base on Windows/macOS resolves through the route table and the reachability gate answers "NOTHING WAS CHECKED", exit 2,
# from a healthy server. And even where it does connect, a host that prefers IPv6 dials ::1 while an IPv4-only bind is not
# listening there. So the layer choice is reported verbatim (that is what the operator's file says) while the HOST THIS HARNESS
# DIALS becomes loopback, which is the same process on the machine this script is running on.
WILDCARD_TO_LOOPBACK = {"0.0.0.0": "127.0.0.1", "::": "[::1]", "[::]": "[::1]"}

probe_host = host
dial_note = ""
if host in WILDCARD_TO_LOOPBACK:
    probe_host = WILDCARD_TO_LOOPBACK[host]
    dial_note = f" (host {host!r} is what mypki binds, not an address to dial: probing {probe_host!r})"

print(f"http://{probe_host}:{port}")
if host_layer == port_layer:
    print(f"{host_layer}{dial_note}")
else:
    print(f"host from {host_layer}; port from {port_layer}{dial_note}")
PY
)"
  BASE="$(printf '%s\n' "$RESOLVED" | sed -n '1p')"
  BASE_RESOLVED_FROM="$(printf '%s\n' "$RESOLVED" | sed -n '2p')"
fi

# --------------------------------------------------------------------------- reachability gate: exit 2, never 0

if ! curl -fsS $CURL_EXTRA -o /dev/null "$BASE/" 2>/dev/null; then
  echo "NOTHING WAS CHECKED: $BASE is not answering. Start it with:" >&2
  echo "    mypki serve            # then re-run this script" >&2
  echo "Exit 2 means 'no assertions ran', not 'everything passed'." >&2
  exit 2
fi

# --------------------------------------------------------------------------- report plumbing

PASS=0; FAIL=0; WARN=0
declare -a FAILURES=() WARNINGS=()
REPORT_BODY=""

emit() { REPORT_BODY+="$1"$'\n'; echo "$1"; }
pass() { PASS=$((PASS+1)); emit "  PASS  $1"; }
warn() { WARN=$((WARN+1)); WARNINGS+=("$1"); emit "  WARN  $1"; }
fail() { FAIL=$((FAIL+1)); FAILURES+=("$1"); emit "  FAIL  $1"; }

# Occurrence counting, never line counting. Each `local` gets its own statement: `local a=1 b=$a` on one line is not
# legal under `set -u` ($a is unfinished when it is read), and the resulting abort hands callers an empty count that
# reads as "the page has no matches" instead of "the counter broke".
count_all() {
  local hay="$1"
  local needle="$2"
  local n=0
  local rest="$hay"
  while [[ "$rest" == *"$needle"* ]]; do
    n=$((n+1))
    rest="${rest#*"$needle"}"
  done
  printf '%s' "$n"
}
count_re() {
  local hay="$1"
  local pattern="$2"
  # `--` before the pattern: some assertions pass a pattern that starts with `-` (PEM armour begins with dashes), and
  # without the end-of-options marker grep reads it as a flag and dies with "unrecognized option" -- which this function
  # swallows into a count of 0, i.e. a leak reported as clean.
  printf '%s' "$hay" | grep -oE -- "$pattern" 2>/dev/null | grep -c . || true
}
# Occurrence counting ACROSS a wrapped line. count_re cannot do this: grep is line-based, so no pattern it is handed can
# ever span a newline, whatever escape is written in it (MEASURED: `grep -oE 'show\s+what'` and `grep -oE
# 'show[[:space:]]+what'` both read 0 on text that contains "show<newline>what"). count_all can span one, because bash
# pattern matching runs over the whole string including its newlines — but count_all needs the exact bytes, and a template
# that re-wraps a sentence changes those bytes without changing the sentence. This helper joins `\n\s*` to one space first,
# which is the same normalisation knob_bound() and settings_form_body() already apply to tags for the same reason.
count_joined() {
  local page="$1"
  local needle="$2"
  python3 - "$page" "$needle" <<'PY'
import re, sys

text = re.sub(r"\n\s*", " ", open(sys.argv[1], encoding="utf-8", errors="replace").read())
print(text.count(sys.argv[2]))
PY
}

# --------------------------------------------------------------------------- request helpers

# `"$@"` is the whole point of this helper: it exists to inject $CURL_EXTRA into every call, and a body that names only
# $CURL_EXTRA silently discards the caller's arguments -- curl then reports "no URL specified", every request fails, and
# a healthy server is reported as 40 failures. Mutation check: delete "$@" and this script fails everywhere at once.
curl_base() { curl -sS $CURL_EXTRA "$@"; }

get() { # path outfile -> status code on stdout
  local path="$1"
  local out="$2"
  curl_base -b "$JAR" -c "$JAR" -o "$out" -w "%{http_code}" "$BASE$path"
}

# `-F` (multipart) is used for ordinary single-line fields and urlencoded for anything multi-line. The reason is a trap
# in curl itself: `--form 'name=<text containing newlines>'` submits only the FIRST line of that text. A PEM CSR posted
# with -F therefore arrives truncated to its BEGIN line, mypki correctly answers "not valid base64", and the failure reads
# as a bug in the sign page when it is a bug in the harness.
post_form() { # path outfile field=value...   (multipart; single-line values only)
  local path="$1"
  local out="$2"
  shift 2
  local args=()
  local field
  for field in "$@"; do args+=(-F "$field"); done
  curl_base -b "$JAR" -c "$JAR" -o "$out" -w "%{http_code}" -X POST "${args[@]}" "$BASE$path"
}

post_pem() { # path outfile csr-file   (urlencoded, so a multi-line PEM survives intact)
  local path="$1"
  local out="$2"
  local csr_file="$3"
  shift 3
  local args=()
  local field
  for field in "$@"; do args+=(--data-urlencode "$field"); done
  args+=(--data-urlencode "csr_pem@$csr_file")
  curl_base -b "$JAR" -c "$JAR" -o "$out" -w "%{http_code}" -X POST "${args[@]}" "$BASE$path"
}

# 0.5.0 (§15): the same request shape as post_pem with the FIELD NAME spelled out, because `/inspect` posts
# `pem_paste` while post_pem hard-codes `csr_pem@file`. `--data-urlencode name@file` is what keeps a multi-line PEM
# intact; post_form's -F truncates it at the first newline (see the comment above post_form), so a §15 written with
# post_form would test "does curl mangle a PEM" rather than "does /inspect read one".
post_pem_field() { # path outfile field pem-file   (urlencoded; any field name)
  local path="$1"
  local out="$2"
  local field_name="$3"
  local pem_file="$4"
  shift 4
  local args=()
  local field
  for field in "$@"; do args+=(--data-urlencode "$field"); done
  args+=(--data-urlencode "${field_name}@${pem_file}")
  curl_base -b "$JAR" -c "$JAR" -o "$out" -w "%{http_code}" -X POST "${args[@]}" "$BASE$path"
}

csrf_token() { # page file -> token
  local page="$1"
  sed -n 's/.*name="csrf_token" value="\([^"]*\)".*/\1/p' "$page" | head -1
}

# The leaf serial from the issued card, scoped to that card on purpose. `/csr/sign` (and `/`) also render the CA facts strip,
# whose serial cell is spelled identically (`<td class="mono">…`), so a page-wide search returns the **CA's** serial and every
# later assertion silently compares against the wrong certificate. MEASURED: it did, in tests/test_views.py first, and the
# harness has to make the same mistake impossible. `grep -A` after `<h2>Issued:` is what scopes it; the window is wide because
# the 0.2.0 "Changed from your request" block can sit between the heading and the serial row.
issued_serial() { # page file -> leaf serial hex (or empty when the card is absent)
  local page="$1"
  # Bounded by the facts table rather than a fixed number of lines. `grep -A 15` was wide enough while the only thing that
  # could sit between `<h2>Issued:` and the serial row was an edited-subject diff; §16 adds a dropped-extension block, and
  # MEASURED a two-extension request puts the serial row 19 lines below the heading — outside a 15-line window. A failed
  # assertion against a page that renders the serial is worse than no assertion.
  sed -n '/<h2>Issued:/,/<\/table>/p' "$page" \
    | sed -n 's/.*<td class="mono">\([0-9a-f]\{8,\}\)<.*/\1/p' | head -1
}

# The serial a row's Revoke control carries. Read from the hidden input rather than from the visible cell because the input is
# what the POST actually submits: asserting against the displayed value would pass even if the form dropped it.
row_serial() { # page file -> first row's serial_hex (or empty)
  local page="$1"
  sed -n 's/.*name="serial_hex" value="\([0-9a-f]*\)".*/\1/p' "$page" | head -1
}

pending_id() { # page file -> the staged request's opaque id from the confirm form's action URL
  local page="$1"
  sed -n 's/.*action="\/csr\/sign?pending=\([^"]*\)".*/\1/p' "$page" | head -1
}

headers_of() { # path -> header block read from a file
  # Two deliberate choices. (1) GET, not `curl -I`: mypki declares GET-only routes, so HEAD answers 405 with FastAPI's
  # JSON body and the headers asserted would be the 405 response's — present, but describing a request that never
  # happened. (2) `-D <file>`, not `-D -`: curl styles header dumps with ANSI escapes when stdout is a TTY, and those
  # escape bytes land inside the strings counted below, so a header that IS present can be reported missing.
  local path="$1"
  curl_base -b "$JAR" -o /dev/null -D "$WORK/headers.txt" "$BASE$path" >/dev/null
  cat "$WORK/headers.txt"
}

lower() { tr 'A-Z' 'a-z'; }
# The state of the file a save writes, fingerprinted so "nothing was written" is an assertion rather than a hope. `absent`
# is a real state (a host that has never saved anything), and comparing two fingerprints catches both a change and a creation.
file_state() { # path -> 'absent' | sha256
  local p="$1"
  if [[ ! -e "$p" ]]; then printf 'absent'; return; fi
  sha256sum "$p" | sed 's/ .*//'
}

# The /settings form posts ONE control per editable knob (MEASURED: 22 on 0.3.0) and several of them are legitimately EMPTY
# — log_file, public_base_url and the six subject defaults all render value="". That is why this body is scraped from the
# page rather than typed out here: a knob that arrives MISSING is refused ("was not submitted"), so a hand-written list
# would report a product bug every time config.py gained a knob. Overrides are applied after scraping, which is how the
# harness posts an out-of-range port while leaving every other field exactly as the page rendered it.
settings_form_body() { # page_file out_file override=VALUE...
  local page="$1"
  local out="$2"
  shift 2
  python3 - "$page" "$out" "$@" <<'PY'
import re
import sys
from urllib.parse import urlencode

page = open(sys.argv[1], encoding="utf-8", errors="replace").read()
# settings.html renders each <input> across five lines (name, type, min, max, value). Joining first is what makes the tags
# match at all: without it only the name line is seen, most knobs vanish from the body, and the app correctly answers
# 'was not submitted' for a page that did render them.
joined = re.sub(r"\n\s*", " ", page)
fields: dict[str, str] = {}
for tag in re.findall(r"<input\b[^>]*>", joined):
    match = re.search(r'name="(MYPKI_[A-Za-z0-9_]+|csrf_token)"', tag)
    if not match:
        continue
    value = re.search(r'value="([^"]*)"', tag)
    fields[match.group(1)] = value.group(1) if value else ""
if len(fields) < 20:
    sys.exit(f"settings page carried only {len(fields)} MYPKI_* controls")
for pair in sys.argv[3:]:
    name, _, value = pair.partition("=")
    fields[name] = value
open(sys.argv[2], "w", encoding="utf-8").write(urlencode(fields))
PY
}

# A bound read off the control the page itself renders (min= / max=), which app.py fills from the same Field(ge=…, le=…)
# metadata pydantic enforces. Asserting a refusal against THIS number rather than a literal keeps the harness and config.py
# on one fact: move the knob in config.py and both the input's max= and the expected sentence move with it.
knob_bound() { # page_file KNOB min|max -> attribute value (empty when absent)
  local page="$1"
  local knob="$2"
  local which="$3"
  python3 - "$page" "$knob" "$which" <<'PY'
import re
import sys

joined = re.sub(r"\n\s*", " ", open(sys.argv[1], encoding="utf-8", errors="replace").read())
for tag in re.findall(r"<input\b[^>]*>", joined):
    if re.search('name="%s"' % re.escape(sys.argv[2]), tag):
        match = re.search('%s="([0-9]+)"' % sys.argv[3], tag)
        print(match.group(1) if match else "")
        break
PY
}

post_body() { # path outfile body_file   (urlencoded, the shape a browser's form actually posts)
  local path="$1"
  local out="$2"
  local body_file="$3"
  curl_base -b "$JAR" -c "$JAR" -o "$out" -w "%{http_code}" -X POST \
    --data-binary "@$body_file" -H "Content-Type: application/x-www-form-urlencoded" "$BASE$path"
}

# Every checkbox the bulk form offers, in page order. §11 needs a SECOND and THIRD one to prove multi-select is real rather
# than a single-row form wearing a checkbox.
all_row_serials() { # page file -> every name="serial_hex" checkbox value, one per line
  local page="$1"
  sed -n 's/.*type="checkbox" name="serial_hex" value="\([0-9a-f]*\)".*/\1/p' "$page"
}


# --------------------------------------------------------------------------- 0.7.0 helpers (§11): DER read and written
# without a DER parser
#
# `od` turns bytes into hex, `base64 -d` turns the CRL's armour into bytes, and bash's own `printf %b` turns hex back into
# bytes. That is the whole toolkit: no openssl (plan U7 makes openssl a permanent outsider here) and no ASN.1 code in a
# shell script, which would be a second, worse DER parser to maintain.
#
# WHY THE BYTE PRINTER IS BASH-ONLY: MEASURED on this box, `bash` 5.2 prints `printf '%b' '\x30\x42'` as 30 42 while
# `/bin/sh` (dash here) prints the literal characters `\x30\x42` -- dash's printf has no \xNN escape at all. A request
# built under dash would therefore be a 14-byte ASCII string that parses as nothing and reports MALFORMED for a perfectly
# good request. `xxd` is not installed here either, so it is not an option even in the bash half.
der_hex_of() { # file -> lowercase hex of every byte in the file
  od -An -tx1 -v < "$1" | tr -d ' \n'
}

crl_pem_der_hex() { # pem file -> hex of the DER inside its first `X509 CRL` armour block
  sed -n '/-----BEGIN X509 CRL-----/,/-----END X509 CRL-----/p' "$1" \
    | grep -v -- '-----' | tr -d ' \t\r\n' | base64 -d | od -An -tx1 -v | tr -d ' \n'
}

# The DER INTEGER content of a serial, exactly as `cryptography` writes it: leading zeros stripped, even length restored,
# and a 0x00 prepended when the top bit of the leading byte is set (otherwise an INTEGER reads as negative). MEASURED with
# cryptography's own OCSPRequestBuilder: serial 0xff -> `02 02 00 ff`, 0x8000 -> `02 03 00 80 00`, and a real 159-bit
# random serial -> `02 21 00 …`. Getting this wrong answers UNKNOWN for a certificate that exists, which is the worst way
# for an OCSP check to be wrong.
der_integer_hex() { # serial hex -> DER INTEGER content octets, lowercase
  local digits
  digits="$(printf '%s' "$1" | sed 's/^0*//')"
  [[ -z "$digits" ]] && digits="0"
  if (( ${#digits} % 2 )); then digits="0$digits"; fi
  case "$digits" in [89abcdefABCDEF]*) digits="00$digits" ;; esac
  printf '%s' "$digits"
}

# One complete OCSP request as hex, spelled the way both `cryptography`'s OCSPRequestBuilder and `openssl ocsp -reqout`
# spell it: five nested SEQUENCE wrappers with content lengths L5+8, L5+6, L5+4, L5+2, L5 (where L5 is the CertID itself:
# 11 for AlgorithmID+Parameters, 22+22 for the two OCTET STRING hashes, 2+len for the serial INTEGER), then the SHA-1
# AlgorithmID `30 09 06 05 2b 0e 03 02 1a 05 00`, two 20-byte hashes, and the serial.
# THE HASHES ARE ZEROED ON PURPOSE. This responder echoes them without verifying them (risk R-OCSP-1: it stores no
# certificate bytes and cannot recompute a SHA-256 issuerKeyHash), so the answer depends only on the SERIAL -- which is
# exactly what these assertions are about, and it keeps this harness free of any need to hash the scratch CA. MEASURED in
# plan §2: every explicit [1]/[2]/[3]-tagged CertID spelling FAILS to parse; do not "improve" this shape by hand-tagging
# anything. A request built this way is byte-identical to what a real client sends apart from the hash bytes.
ocsp_request_der_hex() { # serial hex -> DER hex of an OCSP request asking about that serial
  local value len l5 zeros
  value="$(der_integer_hex "$1")"
  len=$(( ${#value} / 2 ))
  l5=$(( 11 + 22 + 22 + 2 + len ))
  zeros="$(printf '00%.0s' $(seq 1 20))"
  printf '30%02x30%02x30%02x30%02x30%02x' $((l5 + 8)) $((l5 + 6)) $((l5 + 4)) $((l5 + 2)) "$l5"
  printf '300906052b0e03021a0500'
  printf '0414%s0414%s' "$zeros" "$zeros"
  printf '02%02x%s' "$len" "$value"
}

der_bytes_from_hex() { # hex string -> those bytes on stdout (bash printf %b; see the dash note above)
  local hx="$1" i out=""
  for ((i = 0; i < ${#hx}; i += 2)); do out+="\x${hx:i:2}"; done
  printf '%b' "$out"
}

post_der() { # path outfile body_file media_type [header_dump_file] -> status code on stdout (raw body, the shape a protocol client posts)
  # The 5th argument is optional on purpose: §11's three refusal posts never read their headers and must not touch
  # $WORK/headers.txt, while the two answer posts do. `-D <file>` rather than `-D -` for the reason headers_of() spells
  # out (a TTY-styled header dump injects ANSI escapes into the strings being counted).
  local path="$1" out="$2" body_file="$3" media="$4" hdr="${5:-}"
  # Two branches rather than one conditional argument, and `-D` spelled in both. A bare `$hdr` without its flag is the bug
  # this comment exists for: MEASURED on the first live run of STEP F, curl read the dump PATH as a URL ("URL rejected: No
  # host part in the URL"), answered 000, and wrote the DER body onto stdout - which landed inside `$(post_der ...)` where
  # the status code was being read. Eight assertions then failed against a healthy responder, and the harness itself was the
  # only thing that was broken. An array holding zero or one element is not used here either: "${args[@]}" on an empty array
  # under `set -u` is the trap this file's header tells every later editor to avoid.
  if [[ -n "$hdr" ]]; then
    curl_base -b "$JAR" -c "$JAR" -o "$out" -D "$hdr" -w "%{http_code}" -X POST \
      --data-binary "@$body_file" -H "Content-Type: $media" "$BASE$path"
  else
    curl_base -b "$JAR" -c "$JAR" -o "$out" -w "%{http_code}" -X POST \
      --data-binary "@$body_file" -H "Content-Type: $media" "$BASE$path"
  fi
}

# What follows the request's own serial INTEGER inside a response body. This is where CertStatus lives, and its POSITION
# moves with the CA key size (MEASURED with a 3072-bit harness CA: 84 -> 1778 bytes for UNKNOWN, 87 -> 1781 GOOD,
# 87 -> 1805 REVOKED, 146 -> 1841/1863 with SHA-256 + nonce), so an absolute offset would be a measurement of one CA key
# pretending to be a protocol rule. Anchoring on the serial field is what makes this portable.
after_serial_hex() { # response-file hex, serial hex [, window] -> hex following that serial's DER INTEGER
  local hx="$1" value="$2" window="${3:-0}" field
  field="02$(printf '%02x' $(( ${#value} / 2 )))${value}"
  local at="${hx#*"$field"}"
  [[ "$at" == "$hx" ]] && { printf ''; return; }   # the serial is not in the body at all
  if (( window > 0 )); then printf '%s' "${at:0:$window}"; else printf '%s' "$at"; fi
}

# --------------------------------------------------------------------------- §5 helper: HTML <pre> back to PEM

extract_pem() { # page_file BEGIN_MARKER -> PEM text on stdout, entities un-escaped
  python3 - "$1" "$2" <<'PY'
import html, re, sys

page = open(sys.argv[1], encoding="utf-8", errors="replace").read()
marker = sys.argv[2]
# Jinja autoescape is pinned on in app.py, so the PEM inside <pre> carries &lt; &gt; &amp;. Unescaping the whole page
# before slicing is what keeps `&amp;lt;` from being decoded twice into a character that was never there.
text = html.unescape(page)
match = re.search(r"-----BEGIN " + marker + r"-----.*?-----END " + marker + r"-----", text, re.DOTALL)
if not match:
    sys.exit(1)
print(match.group(0))
PY
}

# --------------------------------------------------------------------------- 0.5.0 helper: a PEM file's certificate bytes hashed
#
# Hashes the DER inside a PEM file, not the text of the file. That is deliberate: the page copy of a certificate arrives
# through an HTML decoder and the download arrives through curl, their trailing-newline handling differs, and comparing
# text would report a difference that is only a newline. Comparing the decoded bytes asks the question that actually
# matters -- "is this the same certificate?" -- and answers it identically on both halves of the comparison.
pem_sha() { # path -> sha256 of the first certificate's DER
  python3 - "$1" <<'PY'
import base64, hashlib, re, sys

body = open(sys.argv[1], "rb").read().decode("utf-8", "replace")
match = re.search(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", body, re.DOTALL)
if not match:
    sys.exit(1)
print(hashlib.sha256(base64.b64decode(re.sub(r"\s+", "", match.group(1)))).hexdigest())
PY
}

# --------------------------------------------------------------------------- 0.5.0 helper: where a string first appears
#
# Position, not presence. The /about ordering assertion needs it: every needle in the "what this host is running" card
# was already on that page, so a presence check stayed green through the change being checked. -1 means absent, which
# the caller must handle rather than compare -- `-1 < 5` is True in bash and would silently pass an assertion about a
# heading that vanished.
offset_of() { # page_file needle -> byte offset of first occurrence, or -1
  python3 - "$1" "$2" <<'PY'
import sys

page = open(sys.argv[1], encoding="utf-8", errors="replace").read()
print(page.find(sys.argv[2]))
PY
}

# --------------------------------------------------------------------------- 0.5.0 helper (§15): count inside ONE element
#
# `/inspect` needs this, and it is why §15 cannot reuse count_all for `not a CA`: the page's own lede names that phrase as
# an example of what a finding looks like (`<em>not a CA</em>`), so a page-wide absence check fails against a correct app.
# MEASURED on a live 0.5.0 server: page-wide 1, inside `<ul class="findings">` 0. What has to be empty is the findings
# block, not the document. -1 means the element itself is absent, which the caller must handle rather than compare.
findings_count() { # page_file needle [open] [close] -> occurrences inside the first such element, or -1
  python3 - "$1" "$2" "${3:-<ul class=\"findings\">}" "${4:-</ul>}" <<'PY'
import re, sys

page = open(sys.argv[1], encoding="utf-8", errors="replace").read()
match = re.search(re.escape(sys.argv[3]) + r"(.*?)" + re.escape(sys.argv[4]), page, re.DOTALL)
if not match:
    print(-1)
else:
    print(match.group(1).count(sys.argv[2]))
PY
}

# =========================================================================== §1 home page
echo "§1 Home page (page-map §1)"
status=$(get "/" "$WORK/home.html")
[[ "$status" == "200" ]] && pass "GET / answers 200" || fail "GET / answered $status (expected 200)"

HOME=$(cat "$WORK/home.html")
# 0.3.0 moved every CA fact to /ca (page-map §1 vs §4): `/` is the signing form and nothing else. These are the same four
# needles §9 asks for on /ca, asked here as ABSENT — a home page that grew the CA card back would still answer 200 and every
# other §1 check would still pass, so absence is the only way to catch the drift. MEASURED against a live 0.3.0 server: all
# four read 0 on `/`. 'BasicConstraints' replaces the old 'CA:TRUE pathLength:0' needle because csr_sign.html renders
# 'BasicConstraints CA:FALSE' for a STAGED request, and that one is legitimately on this address after a paste (page-map §3)
# — what must be absent is any BasicConstraints line with nothing staged.
n=$(count_all "$HOME" "mypki Root CA")
[[ "$n" == "0" ]] && pass "home no longer prints the CA subject (page-map §1: /ca carries the CA facts alone)" \
  || fail "home still renders a CA card ($n occurrence(s) of the CA subject)"

n=$(count_re "$HOME" "([0-9A-F]{2}:){31}[0-9A-F]{2}")
[[ "$n" == "0" ]] && pass "home shows no fingerprint (a leaf's own appears on /csr/sign after a signing, §6 asserts it)" \
  || fail "home carries a colon-grouped fingerprint ($n) where page-map §1 says none belongs"

n=$(count_all "$HOME" "BasicConstraints")
[[ "$n" == "0" ]] && pass "home prints no BasicConstraints line with nothing staged" \
  || fail "home renders BasicConstraints ($n) on a fresh page"

n=$(count_all "$HOME" "private key on this host")
[[ "$n" == "0" ]] && pass "home does not report CA key presence (that boolean lives on /ca, §9)" \
  || fail "home still reports CA key presence ($n)"

# 0.2.0: `/` IS the sign form rather than a prose page (page-map §1). Asserted because the two addresses must render the same
# template, and a home.html that survived would still answer 200 while being a second document that drifts.
n=$(count_all "$HOME" "<h1>Sign a certificate</h1>")
[[ "$n" -ge 1 ]] && pass "home is the sign form, not prose (page-map §1; heading renamed from 'Sign a certificate signing request')" \
  || fail "home is not rendering the sign form with this build's renamed heading ($n)"
n=$(count_all "$HOME" "CSR requesting CA powers will be refused.")
[[ "$n" -ge 1 ]] && pass "the sign page states the CA-power refusal in one line under the heading" \
  || fail "the sign page carries no CA-power refusal sentence ($n)"
n=$(count_all "$HOME" "Paste a CSR (PEM)")
[[ "$n" -ge 1 ]] && pass "home offers the paste form directly" || fail "home has no paste form"

# =========================================================================== §2 headers on every page
echo "§2 Security headers (page-map §0)"
HDRS=$(headers_of "/")
# Every needle here is already lower-case because the haystack goes through `lower`. Comparing against "DENY" after
# tr() guarantees a miss for every value, not just this one -- which reports a correctly configured response as missing
# the header.
for header in "x-content-type-options: nosniff" "x-frame-options: deny" "referrer-policy: same-origin"; do
  n=$(count_all "$(printf '%s' "$HDRS" | lower)" "$header")
  [[ "$n" -ge 1 ]] && pass "response carries $header" || fail "response is missing $header"
done
n=$(count_all "$(printf '%s' "$HDRS" | lower)" "content-security-policy: default-src 'self'")
[[ "$n" -ge 1 ]] && pass "CSP starts with default-src 'self'" || fail "CSP missing, or does not start with default-src 'self'"
n=$(count_all "$(printf '%s' "$HDRS" | lower)" "unsafe-inline")
[[ "$n" == "0" ]] && pass "CSP contains no unsafe-inline" || fail "CSP contains unsafe-inline (page-map §0 forbids it)"

# 0.3.0 ships exactly ONE script, same-origin, linked with <script src>. Both halves are asserted because they are two
# different promises: `default-src 'self'` with no unsafe-inline only holds if nothing is inlined, and a page that lost its
# link would lose the copy buttons silently while every flow in this harness kept passing. The script is asserted as an
# ASSET and never as a requirement — everything here ran without executing it, which is what page-map §0 promises.
n=$(count_all "$HOME" "<script>")
[[ "$n" == "0" ]] && pass "no inline <script> on the home page (its own CSP forbids unsafe-inline)" \
  || fail "the home page inlines $n <script> block(s) while its CSP says no unsafe-inline"
n=$(count_all "$HOME" "<script src=")
[[ "$n" -ge 1 ]] && pass "the home page links its script with <script src> ($n)" || fail "the home page links no script at all"

status=$(get "/static/app.js" "$WORK/app.js")
[[ "$status" == "200" ]] && pass "GET /static/app.js answers 200" || fail "GET /static/app.js answered $status"
JS_HDRS=$(headers_of "/static/app.js")
n=$(count_all "$(printf '%s' "$JS_HDRS" | lower)" "content-type: text/javascript")
[[ "$n" == "1" ]] && pass "app.js is served as text/javascript (a browser refuses a script served as text/plain)" \
  || fail "app.js has the wrong content type for a script"
n=$(count_all "$(printf '%s' "$JS_HDRS" | lower)" "content-security-policy: default-src 'self'")
[[ "$n" == "1" ]] && pass "the static response carries the same CSP as the pages" || fail "/static/app.js bypasses the CSP"

# 0.5.0: /settings gained `.pending-saved`, the rose sentence beside a restart-only box whose saved value and live value
# disagree. It is CSS, so it lives in the stylesheet and not in the page — and this harness never renders a page in a browser,
# so the only honest assertion available is that the served asset carries the rule (MEASURED: /static/style.css answers 200 as
# text/css with the same CSP as the pages). What CANNOT be asserted from here is what the sentence looks like on screen; no
# browser on this host has ever rendered it, and this script says so out loud rather than implying otherwise.
CSS_STATUS=$(get "/static/style.css" "$WORK/style.css")
[[ "$CSS_STATUS" == "200" ]] && pass "GET /static/style.css answers 200" || fail "GET /static/style.css answered $CSS_STATUS"
CSS_HDRS=$(headers_of "/static/style.css")
n=$(count_all "$(printf '%s' "$CSS_HDRS" | lower)" "content-type: text/css")
[[ "$n" == "1" ]] && pass "style.css is served as text/css (a browser refuses a stylesheet served as text/plain)" \
  || fail "style.css has the wrong content type for a stylesheet"
n=$(count_all "$(printf '%s' "$CSS_HDRS" | lower)" "content-security-policy: default-src 'self'")
[[ "$n" == "1" ]] && pass "the stylesheet response carries the same CSP as the pages" || fail "/static/style.css bypasses the CSP"
CSS_BODY="$(cat "$WORK/style.css")"
n=$(count_all "$CSS_BODY" ".pending-saved {")
[[ "$n" == "1" ]] && pass "the served stylesheet defines .pending-saved ($n) — the 0.5.0 pending sentence is styled" \
  || fail ".pending-saved is not defined in the served stylesheet ($n): settings.html renders a class nothing styles"
n=$(count_all "$CSS_BODY" "var(--rose)")
[[ "$n" -ge 1 ]] && pass ".pending-saved reuses the existing --rose colour rather than adding one ($n rose uses)" \
  || fail "the stylesheet no longer uses --rose anywhere — the restart language lost its one colour"
# 0.5.2: the same posture for the /inspect width fix (page-map §13). An operator reported that the PEM paste box rendered narrower
# than every other section on its own page; the fix is three CSS rules plus one class in the template, and this harness renders no
# page in a browser, so what can honestly be asserted is that the served asset carries each rule — including the SCOPING selector,
# because a rule that widened `.settings-form` instead would 'fix' /inspect by widening every field on /settings. That difference is
# invisible without a browser and plainly visible in the text of the file, which is exactly why it is asserted here.
n=$(count_all "$CSS_BODY" "form.stacked.inspect-form { max-width: none; }")
[[ "$n" == "1" ]] && pass "the served stylesheet lifts the 46rem cap for /inspect's form only ($n) — scoped by .inspect-form, not by .settings-form" \
  || fail "form.stacked.inspect-form is not defined in the served stylesheet ($n): /inspect's paste box is still clipped at 46rem"
n=$(count_all "$CSS_BODY" "form.inspect-form #pem_paste { width: 100%; max-width: none; }")
[[ "$n" == "1" ]] && pass "the served stylesheet widens #pem_paste to its section ($n) — the box an operator saw at ~21rem" \
  || fail "#pem_paste has no width rule in the served stylesheet ($n): the textarea falls back to the browser default again"
n=$(count_all "$CSS_BODY" "form.inspect-form button.save-settings { max-width: none; }")
[[ "$n" == "1" ]] && pass "the Inspect button follows its field instead of sitting half-width under it ($n)" \
  || fail "/inspect's submit button is not widened with its form ($n): a full-width box over a 46rem button is the same mismatch, moved"
n=$(count_all "$CSS_BODY" ".settings-form .field textarea")
[[ "$n" == "0" ]] && pass "no rule widens .settings-form textareas globally ($n) — /settings keeps its fields as they are" \
  || fail ".settings-form grew $n global textarea rule(s): a fix scoped to /inspect leaked into /settings"
# And the template half, fetched here rather than borrowed from §15: a CSS rule whose class is missing from the markup styles
# nothing, and the two halves of this fix live in different files. The GET is not an assertion — only its class count is.
INSPECT_FORM_STATUS=$(get "/inspect" "$WORK/inspect-form.html")
if [[ "$INSPECT_FORM_STATUS" != "200" ]]; then
  fail "GET /inspect answered $INSPECT_FORM_STATUS while checking the stylesheet's scoping target"
else
  n=$(count_all "$(cat "$WORK/inspect-form.html")" 'class="settings-form stacked inspect-form"')
  [[ "$n" == "1" ]] && pass "/inspect's form carries the class those three rules are scoped to ($n)" \
    || fail "/inspect's form does not carry inspect-form ($n): the width rules above would style nothing"
fi

# =========================================================================== §3 the version chain, read from the running app
echo "§3 Version (read from __init__.py, never hard-coded here)"
if [[ -z "$EXPECTED_VERSION" ]]; then
  warn "no expected version available: pass --version or run from a checkout"
else
  get "/version" "$WORK/version.html" >/dev/null
  n=$(count_all "$(cat "$WORK/version.html")" "mypki $EXPECTED_VERSION")
  if [[ "$n" -ge 1 ]]; then pass "the running app reports version $EXPECTED_VERSION"
  else fail "the running app does not report $EXPECTED_VERSION — you are testing a different build than this checkout"; fi
fi

# =========================================================================== §4 no API surface advertised
echo "§4 No API surface (docs_url/redoc_url/openapi_url are None)"
for path in "/docs" "/redoc" "/openapi.json"; do
  status=$(get "$path" "$WORK/api-probe.html")
  if [[ "$status" == "404" || "$status" == "405" ]]; then pass "$path is not served ($status)"
  else fail "$path answered $status — an API surface exists where page-map §0 says none may"; fi
done

# =========================================================================== §5 generate a key + CSR
echo "§5 Generate CSR (page-map §2)"
get "/csr/generate" "$WORK/gen-form.html" >/dev/null
TOKEN=$(csrf_token "$WORK/gen-form.html")
if [[ -z "$TOKEN" ]]; then fail "the generate form carries no CSRF token"; TOKEN="absent"; fi

status=$(post_form "/csr/generate" "$WORK/gen-no-csrf.html" "common_name=nocsrf.internal" "key_type=rsa-2048")
if [[ "$status" == "400" ]]; then pass "POST without a CSRF token answers 400"
else fail "POST without a CSRF token answered $status (expected 400)"; fi
n=$(count_all "$(cat "$WORK/gen-no-csrf.html")" "PRIVATE KEY")
[[ "$n" == "0" ]] && pass "the CSRF-rejected POST returned no key material" || fail "a CSRF-rejected POST contained key material"

status=$(post_form "/csr/generate" "$WORK/gen.html" \
  "csrf_token=$TOKEN" "common_name=web.internal" \
  "sans=web.internal, *.lab.local"$'\n'"10.0.0.7" "organization=Acme" "country=DE" "key_type=rsa-2048")
[[ "$status" == "200" ]] && pass "POST /csr/generate answers 200" || fail "POST /csr/generate answered $status"

GEN=$(cat "$WORK/gen.html")
n=$(count_all "$GEN" "-----BEGIN CERTIFICATE REQUEST-----")
[[ "$n" == "1" ]] && pass "exactly one CSR PEM block shown" || fail "expected exactly 1 CSR block, found $n"
n=$(count_all "$GEN" "-----BEGIN PRIVATE KEY-----")
[[ "$n" == "1" ]] && pass "exactly one private key block shown" || fail "expected exactly 1 key block, found $n"
n=$(count_all "$GEN" "stored nowhere")
[[ "$n" -ge 1 ]] || n=$(count_all "$GEN" "not stored anywhere")
[[ "$n" -ge 1 ]] && pass "the page states the output is stored nowhere" || warn "the page lacks the 'stored nowhere' warning"
n=$(count_all "$GEN" "Download private key")
[[ "$n" == "1" ]] && pass "a private-key download link is offered" || fail "no private-key download link"
n=$(count_all "$GEN" "10.0.0.7")
[[ "$n" -ge 1 ]] && pass "the IP SAN survived generation as an IP general name" || fail "the IP SAN did not survive generation"

if ! extract_pem "$WORK/gen.html" "CERTIFICATE REQUEST" > "$WORK/generated.csr"; then
  fail "could not extract the generated CSR from the page"
else
  n=$(count_all "$(cat "$WORK/generated.csr")" "-----BEGIN CERTIFICATE REQUEST-----")
  [[ "$n" == "1" ]] && pass "the extracted CSR is a single well-formed block ($(wc -c < "$WORK/generated.csr") bytes)" \
    || fail "extracted CSR is malformed"
fi

# =========================================================================== §6 sign the generated CSR, two steps
echo "§6 Sign CSR (page-map §3)"
get "/csr/sign" "$WORK/sign-form.html" >/dev/null
TOKEN=$(csrf_token "$WORK/sign-form.html")

# SEED, before anything is asserted about the ledger. §11 needs THREE active records on this host: one for its own
# round trip and two more for multi-select. On a FRESH data dir there is exactly one record in existence by this
# point, so STEPS C-E used to WARN-skip and the `>= 3` needles below them failed against a correct app — MEASURED on
# 0.4.0, where the whole run ended 142/5 with three of the five failures traceable to that one missing precondition.
# Signing is idempotent per request (MEASURED: re-signing this same CSR twice yields two DISTINCT serials), so two
# extra round trips here cost four POSTs and no key generation, and they make every §11 assertion actually run.
# Done BEFORE §6's own signing on purpose: /issued is newest-first, so seeding afterwards would push §6's record off
# the first row and break `row_serial == issued_serial`.
SEEDED=0
for seed in 1 2; do
  status=$(post_pem "/csr/sign" "$WORK/seed-confirm-$seed.html" "$WORK/generated.csr" "csrf_token=$TOKEN")
  if [[ "$status" != "200" ]]; then fail "seed $seed step A answered $status — §11's multi-select checks will WARN-skip"; continue; fi
  seed_pending=$(pending_id "$WORK/seed-confirm-$seed.html")
  if [[ -z "$seed_pending" ]]; then fail "seed $seed step A staged no ?pending= id — nothing was issued for it"; continue; fi
  status=$(post_form "/csr/sign?pending=$seed_pending" "$WORK/seed-issue-$seed.html" \
    "csrf_token=$TOKEN" "confirm=1" "cert_type=server" "validity_days=30")
  if [[ "$status" == "200" ]]; then SEEDED=$((SEEDED + 1)); else fail "seed $seed step B answered $status"; fi
done
if [[ "$SEEDED" == "2" ]]; then pass "two extra certificates seeded so §11 has a real multi-select ledger ($SEEDED)" \
  else warn "seeded only $SEEDED extra certificate(s); §11's multi-select checks may WARN-skip instead of asserting"
fi

status=$(post_pem "/csr/sign" "$WORK/confirm.html" "$WORK/generated.csr" "csrf_token=$TOKEN")
[[ "$status" == "200" ]] && pass "step A (validate + show details) answers 200" || fail "step A answered $status"

CONF=$(cat "$WORK/confirm.html")
n=$(count_all "$CONF" "web.internal")
[[ "$n" -ge 1 ]] && pass "the confirmation panel shows the parsed CN/SAN" || fail "confirmation panel omits the parsed subject"
n=$(count_all "$CONF" "*.lab.local")
[[ "$n" -ge 1 ]] && pass "the wildcard SAN is shown as validated, not rejected" || fail "the wildcard SAN was not accepted"
n=$(count_all "$CONF" "RSA 2048")
[[ "$n" -ge 1 ]] && pass "the confirmation panel reports the key spec (RSA 2048)" || fail "confirmation panel omits the key spec"

status=$(post_form "/csr/sign" "$WORK/issued.html" "csrf_token=$TOKEN" "confirm=1" "cert_type=server" "validity_days=30")
[[ "$status" == "200" ]] && pass "step B (confirm + issue) answers 200" || fail "step B answered $status"

ISS=$(cat "$WORK/issued.html")
n=$(count_all "$ISS" "-----BEGIN CERTIFICATE-----")
[[ "$n" -ge 1 ]] && pass "a signed certificate is rendered ($n block(s))" || fail "no certificate was rendered"
n=$(count_all "$ISS" "Download chain")
[[ "$n" == "1" ]] && pass "a chain download is offered" || fail "no chain download link"
n=$(count_re "$ISS" "([0-9A-F]{2}:){31}[0-9A-F]{2}")
[[ "$n" -ge 1 ]] && pass "the issued certificate's fingerprint is displayed" || fail "the issued certificate shows no fingerprint"

# Scoped by `issued_serial` (see the helper's comment): this page also carries the CA's serial in an identical cell.
ISSUED_SERIAL=$(issued_serial "$WORK/issued.html")
if [[ -z "$ISSUED_SERIAL" ]]; then
  fail "the issued card shows no hex serial — §10 and §11 cannot address a certificate"
else
  pass "the issued card reports a leaf serial (${ISSUED_SERIAL:0:12}…)"
fi
# The 0.2.0 provenance split replaces 0.1.0's inaccurate "Only the SANs above are copied from your request": the subject DOES
# come from the request, only the extensions never do (page-map §7). Asserted against step A's confirm page, NOT against the
# issued card: the provenance block sits inside the confirm form, and step B re-renders /csr/sign with only the issued card
# (MEASURED — 1 occurrence in confirm.html, 0 in issued.html). Asserting it on the issued card fails against a correct app.
n=$(count_all "$CONF" "Set by mypki, never from the request")
[[ "$n" -ge 1 ]] && pass "the confirm form states which parts never come from the request" || fail "the confirm form omits the provenance split"
n=$(count_all "$CONF" "Only the SANs above are copied")
[[ "$n" == "0" ]] && pass "the inaccurate 'only the SANs' wording is gone from the confirm form" || fail "the inaccurate 'only the SANs' wording is still on the page"

# =========================================================================== §7 rejections name a specific reason
echo "§7 Rejections name their reason (never 'invalid CSR')"
status=$(post_form "/csr/sign" "$WORK/bad1.html" "csrf_token=$TOKEN" "csr_pem=not a csr at all")
n=$(count_all "$(cat "$WORK/bad1.html")" "No PEM block found")
if [[ "$status" == "400" && "$n" -ge 1 ]]; then pass "garbage input is refused naming the reason"
else fail "garbage input: status $status (expected 400), reason occurrences $n"; fi

printf -- '-----BEGIN CERTIFICATE REQUEST-----\nYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=\n-----END CERTIFICATE REQUEST-----\n' > "$WORK/bogus.csr"
status=$(post_pem "/csr/sign" "$WORK/bad2.html" "$WORK/bogus.csr" "csrf_token=$TOKEN")
n=$(count_all "$(cat "$WORK/bad2.html")" "not a DER certificate request")
if [[ "$status" == "400" && "$n" -ge 1 ]]; then pass "valid base64 that is not a CSR is refused naming it"
else fail "bogus-CSR case: status $status (expected 400), reason occurrences $n"; fi

# --- Unreleased (this build): a refused paste is named ON the sign page, above the box it belongs to, and the status did not move.
# Asserted as an ORDER: "the reason appears somewhere in the body" is also true of a page that mentions it in a nav link
# while showing nothing else, so the refusal block's line number has to precede the paste label's. MEASURED on 0.7.0 and
# earlier: these two POSTs rendered templates/error.html, which contains no form at all — the operator had to click back
# and re-paste.
BAD1=$(cat "$WORK/bad1.html")
n=$(count_all "$BAD1" 'class="form-errors refused"')
if [[ "$n" -ge 1 ]]; then pass "the refusal is rendered on the sign page itself ($n block(s), not a separate error document)"
else fail "the refusal left the sign page: no .form-errors.refused block in the 400 body"; fi
refusal_line=$(grep -n 'class="form-errors refused"' "$WORK/bad1.html" | head -1 | cut -d: -f1)
label_line=$(grep -n '<label for="csr_pem">Paste a CSR (PEM)</label>' "$WORK/bad1.html" | head -1 | cut -d: -f1)
if [[ -n "$refusal_line" && -n "$label_line" && "$refusal_line" -lt "$label_line" ]]; then
  pass "the refusal sits above 'Paste a CSR (PEM)' (line $refusal_line vs $label_line)"
else fail "the refusal is not above the paste box (refusal line '$refusal_line', label line '$label_line')"
fi
n=$(count_all "$BAD1" "not a csr at all")
[[ "$n" -ge 1 ]] && pass "the rejected paste is echoed back into its own textarea, so the fix is typed in place ($n)" \
  || fail "the rejected paste was thrown away: it is not in the re-rendered form"
n=$(count_all "$BAD1" "This is what the request says")
[[ "$n" == "0" ]] && pass "a refused paste staged nothing (no confirmation panel, $n)" \
  || fail "a refused paste rendered a confirmation panel ($n)"
# The oversized case is the one refusal that stays on error.html: SizeGuardMiddleware answers it before any route runs,
# so there is no form to put the reason on (§8 asserts the 413 and the knob).

# =========================================================================== §8 oversized input gets mypki's own page
echo "§8 Oversized input (page-map §0)"
head -c 40000 /dev/zero | tr '\0' 'A' > "$WORK/huge.txt"
{ echo "-----BEGIN CERTIFICATE REQUEST-----"; cat "$WORK/huge.txt"; echo "-----END CERTIFICATE REQUEST-----"; } > "$WORK/huge.csr"
status=$(post_pem "/csr/sign" "$WORK/huge.html" "$WORK/huge.csr" "csrf_token=$TOKEN")
BODY=$(cat "$WORK/huge.html")
n=$(count_all "$BODY" "the limit is 32,000")
if [[ "$status" == "413" && "$n" -ge 1 ]]; then pass "oversized paste answers 413 with mypki's own page naming the limit"
else fail "oversized paste: status $status (expected 413), limit named $n time(s)"; fi
n=$(count_all "$BODY" "Field exceeded maximum size")
[[ "$n" == "0" ]] && pass "starlette's bare JSON size error did not surface" || fail "the framework's own size message surfaced instead of mine"

# =========================================================================== §9 CA certificate download
echo "§9 CA certificate (page-map §4)"
status=$(get "/ca" "$WORK/ca.html")
[[ "$status" == "200" ]] && pass "GET /ca answers 200" || fail "GET /ca answered $status"
CA_PAGE=$(cat "$WORK/ca.html")
# The four CA facts 0.2.0 printed on `/` live here and only here (page-map §1 vs §4). Written against what the RENDERED
# page says rather than the template source: 'CA:TRUE pathLength:0' also sits inside a Jinja COMMENT in ca_download.html,
# so a grep of the file would pass against a page that never renders it. MEASURED spellings on a live 0.3.0 server:
# <td class="mono">CA:TRUE pathLength:0</td>, and 'CA private key on this host' / 'present — this host can sign'.
n=$(count_all "$CA_PAGE" "mypki Root CA")
if [[ "$n" -ge 1 ]]; then pass "/ca shows the CA subject ($n occurrence(s))"
else fail "/ca does not show the CA subject — no CA loaded, or the card is broken"; fi

n=$(count_re "$CA_PAGE" "([0-9A-F]{2}:){31}[0-9A-F]{2}")
if [[ "$n" -ge 1 ]]; then pass "/ca shows a colon-grouped SHA-256 fingerprint ($n)"
else fail "/ca shows no 32-byte colon-grouped fingerprint"; fi

n=$(count_all "$CA_PAGE" "CA:TRUE pathLength:0")
[[ "$n" -ge 1 ]] && pass "/ca reports BasicConstraints CA:TRUE pathLength:0" || fail "/ca omits the root's BasicConstraints"

n=$(count_all "$CA_PAGE" "private key on this host")
[[ "$n" -ge 1 ]] && pass "/ca reports whether the CA private key is present (boolean only)" || fail "/ca does not report key presence"

for pair in "Trusted Root Certification Authorities:Windows instructions" "update-ca-certificates:Linux instructions" "Always Trust:macOS instructions" "keytool -importcert:Java instructions"; do
  needle="${pair%%:*}"
  label="${pair#*:}"
  n=$(count_all "$CA_PAGE" "$needle")
  [[ "$n" -ge 1 ]] && pass "$label present" || fail "$label missing"
done

status=$(get "/ca/certificate" "$WORK/ca.crt")
[[ "$status" == "200" ]] && pass "GET /ca/certificate answers 200" || fail "CA download answered $status"
curl_base -b "$JAR" -o /dev/null -D "$WORK/dl-headers.txt" "$BASE/ca/certificate" >/dev/null
DL_HDRS=$(cat "$WORK/dl-headers.txt")
n=$(count_all "$(printf '%s' "$DL_HDRS" | lower)" 'content-disposition: attachment; filename="mypki-root-ca.crt"')
[[ "$n" == "1" ]] && pass "CA download is an attachment named mypki-root-ca.crt" || fail "CA download Content-Disposition is wrong (Windows double-click depends on it)"
n=$(count_all "$(printf '%s' "$DL_HDRS" | lower)" "cache-control: no-store")
[[ "$n" == "1" ]] && pass "PEM response sets Cache-Control: no-store" || fail "PEM response is cacheable (page-map §0 forbids it)"
n=$(count_all "$(cat "$WORK/ca.crt")" "-----BEGIN CERTIFICATE-----")
[[ "$n" == "1" ]] && pass "the CA download contains exactly one certificate" || fail "CA download contains $n certificates (expected 1)"

# 0.5.0: /ca now shows the certificate itself with a copy button (page-map §4). Three separate assertions, because there
# are three ways this feature could rot without any of them turning red today: the block vanishes, the button stops
# pointing at it, or the page's copy drifts from the download's. The third is the one this project cares about -- 0.3.0
# deleted the home-page CA card for exactly that reason ("a fact shown in two places is two facts that can disagree"),
# and 0.5.0 puts a second copy of the root back on screen, so the parity check is what makes that safe.
n=$(count_all "$CA_PAGE" 'id="pem-ca"')
[[ "$n" == "1" ]] && pass "/ca renders the CA PEM block (pre id=pem-ca)" || fail "/ca renders no PEM block with id pem-ca"

n=$(count_all "$CA_PAGE" 'data-mypki-copy="pem-ca"')
[[ "$n" == "1" ]] && pass "/ca's copy button points at that block" || fail "/ca has no copy button wired to pem-ca"

if extract_pem "$WORK/ca.html" "CERTIFICATE" > "$WORK/ca-page.pem"; then
  n=$(count_all "$(cat "$WORK/ca-page.pem")" "-----BEGIN CERTIFICATE-----")
  [[ "$n" == "1" ]] && pass "/ca's PEM block holds exactly one certificate" || fail "/ca's PEM block holds $n certificates (expected 1)"

  PAGE_SHA=$(pem_sha "$WORK/ca-page.pem")
  DL_SHA=$(pem_sha "$WORK/ca.crt")
  if [[ -n "$PAGE_SHA" && "$PAGE_SHA" == "$DL_SHA" ]]; then
    pass "the certificate shown on /ca is the same bytes as the download ($PAGE_SHA)"
  else
    fail "/ca's certificate differs from /ca/certificate (page $PAGE_SHA vs download $DL_SHA)"
  fi
else
  fail "/ca renders no extractable CERTIFICATE block to compare"
fi

# =========================================================================== §10 issued list
echo "§10 Issued list (page-map §5)"
status=$(get "/issued" "$WORK/issued-list.html")
[[ "$status" == "200" ]] && pass "GET /issued answers 200" || fail "GET /issued answered $status"
LIST=$(cat "$WORK/issued-list.html")
n=$(count_re "$LIST" "<tr>")
if [[ "$n" -ge 2 ]]; then pass "the issued table has at least one data row ($n <tr> including the header)"
else fail "the issued table has no data rows after a successful signing"; fi
n=$(count_all "$LIST" "web.internal")
[[ "$n" -ge 1 ]] && pass "the certificate signed in §6 appears in the list" || fail "the §6 certificate is missing from /issued"
n=$(count_all "$LIST" "<span class=\"pill active\">active</span>")
[[ "$n" -ge 1 ]] && pass "a fresh record reports Status 'active'" || fail "no 'active' status pill on a freshly issued record"
n=$(count_all "$LIST" "action=\"/issued/revoke\"")
if [[ "$n" -ge 1 ]]; then pass "the row carries a revoke control ($n)"
else fail "/issued offers no revoke control for an active record (page-map §5)"; fi
# Two states, not three: the list reports `active`/`revoked` and leaves expiry to the date cell, because printing "expired"
# beside "revoked" would imply this host knows what every client currently accepts.
n=$(count_all "$LIST" ">expired<")
[[ "$n" == "0" ]] && pass "the Status column does not claim an 'expired' state" || fail "the Status column renders an 'expired' state (page-map §5 says two states)"
# 0.3.0 replaced one hidden input per row with CHECKBOXES inside ONE bulk form. Counted against
# `type="checkbox" name="serial_hex"` deliberately: a build that kept the old per-row forms would still answer 200, still
# carry the right serials, and every §11 assertion would then run against a shape no browser posts any more. The checkbox
# count matching the ACTIVE-row count is the same contract seen from the other side — a stamped row carries no box.
BOXES=$(count_all "$LIST" 'type="checkbox" name="serial_hex"')
ACTIVE=$(count_all "$LIST" '<span class="pill active">active</span>')
if [[ "$BOXES" == "$ACTIVE" && "$BOXES" -ge 1 ]]; then pass "one checkbox per active row and none on a revoked row ($BOXES boxes, $ACTIVE active)"
else fail "/issued offers $BOXES checkboxes for $ACTIVE active records (they must match exactly)"; fi
n=$(count_re "$LIST" '<form method="post" action="/issued/revoke"')
[[ "$n" == "1" ]] && pass "/issued posts ONE bulk revoke form ($n) — the 0.2.0 per-row forms are gone" \
  || fail "/issued carries $n revoke form(s); 0.3.0 has one bulk form around the table"
n=$(count_all "$LIST" 'data-mypki-select-all')
[[ "$n" == "1" ]] && pass "the Select column offers the All box ($n)" || fail "no select-all control on /issued ($n)"
n=$(count_all "$LIST" '> All<')
[[ "$n" -ge 1 ]] && pass "the select-all control is labelled 'All'" || fail "the select-all box carries no label"
# 0.4.0 deleted the bar below the table: ONE 'Revoke Selected' CONTROL, in the bar above the rows, and the sentence it
# carried moved into the hint under the table. Counted on the BUTTON TAG, not on the phrase: MEASURED against a live
# server, the bare phrase occurs 3 times on /issued (1 button + 2 <strong> mentions in the no-JavaScript hint), so an
# `== 1` on the phrase fails against a correct page. What actually has to be singular is the CONTROL and the BAR, and
# both are asserted separately here; the prose count is then reported rather than guessed at.
BTN=$(count_all "$LIST" '<button class="danger solid" type="submit">Revoke Selected</button>')
BARS=$(count_all "$LIST" 'class="select-bar"')
PHRASE=$(count_all "$LIST" 'Revoke Selected')
PROSE=$(count_all "$LIST" '<strong>Revoke Selected</strong>')
if [[ "$BTN" == "1" ]]; then pass "'Revoke Selected' is offered exactly once, as one control ($BTN button)" \
  else fail "'Revoke Selected' rendered $BTN submit button(s); 0.4.0 has exactly one bulk control"
fi
if [[ "$BARS" == "1" ]]; then pass "exactly one select bar survives above the table ($BARS) — 0.3.0's bottom bar is gone" \
  else fail "/issued renders $BARS select bars; 0.4.0 keeps only the one above the rows"
fi
if [[ "$PHRASE" == "$((BTN + PROSE))" && "$PROSE" -ge 1 ]]; then
  pass "every other 'Revoke Selected' is prose, inside <strong> ($PHRASE mentions = $BTN control + $PROSE prose)" \
  else fail "'Revoke Selected' appears $PHRASE time(s) but only $BTN in a button and $PROSE in <strong>: an unexplained mention is a second control wearing prose's clothes"
fi
n=$(count_all "$LIST" 'data-mypki-count>0 selected')
[[ "$n" == "1" ]] && pass "the selection counter starts at '0 selected' and is live from the first paint ($n)" \
  || fail "the counter above the table does not start at '0 selected' ($n) — a page that cannot count itself is guessing"
n=$(count_all "$LIST" 'name="csrf_token"')
[[ "$n" == "1" ]] && pass "the bulk form carries the CSRF token inside itself ($n)" \
  || fail "the revoke form's token count is $n: with one bulk form the token has to live inside it"
n=$(count_all "$LIST" 'tick rows one at a time')
[[ "$n" -ge 1 ]] && pass "/issued says what still works with JavaScript off (tick rows one at a time)" \
  || fail "/issued no longer states that revoking works without JavaScript"

# =========================================================================== §11 revocation round trip (page-map §5)
echo "§11 Revocation round trip (page-map §5)"
ROW_SERIAL=$(row_serial "$WORK/issued-list.html")
if [[ -z "$ROW_SERIAL" ]]; then
  fail "no revoke control carried a serial — cannot run the revocation checks"
else
  [[ "$ROW_SERIAL" == "$ISSUED_SERIAL" ]] \
    && pass "the checkbox carries §6's leaf serial, not a row position" \
    || fail "the revoke control carries $ROW_SERIAL but §6 issued $ISSUED_SERIAL"

  TOKEN=$(csrf_token "$WORK/issued-list.html")

  # STEP A — the unconfirmed POST. As of 0.3.0 this stamps NOTHING: it re-renders /issued with the confirmation block at
  # the top (page-map §5). The 0.2.0 harness asserted a revoked pill here, and that assertion is now wrong by construction:
  # against a correct 0.3.0 app it fails. Both halves are asserted — what the block says, and that the ledger is untouched.
  status=$(post_form "/issued/revoke" "$WORK/revoke-confirm.html" \
    "csrf_token=$TOKEN" "serial_hex=$ROW_SERIAL" "reason=smoke harness: retired on purpose")
  if [[ "$status" == "200" ]]; then pass "POST /issued/revoke without confirm answers 200 (the confirmation step, not an error)"
  else fail "POST /issued/revoke without confirm answered $status (expected 200)"; fi

  CONF=$(cat "$WORK/revoke-confirm.html")
  n=$(count_all "$CONF" '<section class="confirm-revoke">')
  [[ "$n" == "1" ]] && pass "the unconfirmed POST renders the confirmation block ($n)" \
    || fail "no <section class=\"confirm-revoke\"> after an unconfirmed POST ($n)"
  n=$(count_all "$CONF" 'Revoke 1 certificate?')
  [[ "$n" -ge 1 ]] && pass "the block counts what is at stake ('Revoke 1 certificate?')" \
    || fail "the confirmation block does not name how many records it is about to change"
  n=$(count_all "$CONF" 'Nothing has been changed yet.')
  [[ "$n" -ge 1 ]] && pass "the block states that nothing has been changed yet" \
    || fail "an unconfirmed POST reads as though it had already revoked"
  # Nothing new was stamped: the confirm page shows the SAME revoked pills the list page already showed (records this host
  # revoked in an earlier run legitimately keep their pills). MEASURED, and it is why the naive 'zero revoked pills' check is
  # wrong — against a ledger that already holds revoked records it fails on a correct app. What must not move is the COUNT.
  n=$(count_all "$CONF" '<span class="pill revoked">revoked</span>')
  m=$(count_all "$LIST" '<span class="pill revoked">revoked</span>')
  [[ "$n" == "$m" ]] && pass "nothing was stamped before confirmation ($n revoked pills, same as the list page's $m)" \
    || fail "an unconfirmed POST changed the revoked count ($m -> $n) — the confirmation step would be decorative"
  n=$(count_all "$CONF" '<h2>Revocation batch</h2>')
  [[ "$n" == "0" ]] && pass "the unconfirmed POST reports no batch (nothing has been revoked yet)" \
    || fail "an unconfirmed POST already rendered the batch card ($n)"
  n=$(count_all "$CONF" "name=\"serial_hex\" value=\"$ROW_SERIAL\"")
  [[ "$n" -ge 1 ]] && pass "the selection is carried forward into the confirm form ($n)" \
    || fail "the confirmation page lost the serial it was confirming"
  n=$(count_all "$CONF" '<input type="hidden" name="confirm" value="1">')
  [[ "$n" == "1" ]] && pass "the confirm form carries confirm=1 ($n)" || fail "no confirm=1 control on the confirmation form ($n)"
  n=$(count_all "$CONF" 'active now')
  [[ "$n" -ge 1 ]] && pass "the block states what that certificate is right now ('active now')" \
    || fail "the confirmation names no current state for the serial it lists"
  # 0.7.0 prose sweep. The needle here was `no CRL is published`, and NO template says that any more — grep -rn over
  # src/mypki/ returns zero hits for it. The sentence this page actually renders is issued.html:35 (grepped out of the
  # template, then confirmed live against $WORK/revoke-confirm.html): the confirmation must still state what it cannot
  # undo before it asks for consent.
  n=$(count_joined "$WORK/revoke-confirm.html" 'Revoking a record cannot be undone from this page: there is no un-revoke and no delete.')
  [[ "$n" -ge 1 ]] && pass "the confirmation page states what it cannot undo before asking for consent ($n)" \
    || fail "the confirmation page asks to revoke without stating that revoking cannot be undone ($n)"

  # STEP B — the confirmed POST, mirroring tests/test_bulk_revoke.py: the same serial plus confirm=1. This is what actually
  # stamps, and it is also the shape static/app.js's modal submits, so both paths are proven against one handler.
  status=$(post_form "/issued/revoke" "$WORK/revoke.html" \
    "csrf_token=$TOKEN" "serial_hex=$ROW_SERIAL" "confirm=1" "reason=smoke harness: retired on purpose")
  if [[ "$status" == "200" ]]; then pass "POST /issued/revoke with confirm=1 answers 200"
  else fail "POST /issued/revoke with confirm=1 answered $status (expected 200)"; fi

  REV=$(cat "$WORK/revoke.html")
  n=$(count_all "$REV" '<h2>Revocation batch</h2>')
  [[ "$n" == "1" ]] && pass "the confirmed submit answers with the three-way batch card ($n)" \
    || fail "no 'Revocation batch' card after a confirmed revoke ($n)"
  n=$(count_all "$REV" 'stamped now,')
  [[ "$n" -ge 1 ]] && pass "the batch card counts what it stamped now" || fail "the batch card reports no 'stamped now' count"
  n=$(count_all "$REV" 'already revoked before this submit')
  [[ "$n" -ge 1 ]] && pass "the batch card counts records already revoked before this submit" \
    || fail "the batch card omits the 'already revoked' count — a stale tab would look like fresh revocations"
  n=$(count_all "$REV" 'with no record on this host')
  [[ "$n" -ge 1 ]] && pass "the batch card counts serials with no record here" \
    || fail "the batch card omits the 'no record on this host' count"
  n=$(count_all "$REV" "<span class=\"pill revoked\">revoked</span>")
  [[ "$n" -ge 1 ]] && pass "the row now reports Status 'revoked'" || fail "no 'revoked' status pill after a confirmed revoke"
  n=$(count_all "$REV" 'is marked revoked as of')
  [[ "$n" -ge 1 ]] && pass "the card confirms the stamp with a UTC timestamp" || fail "no confirmation naming the stamp"
  n=$(count_all "$REV" 'smoke harness: retired on purpose')
  [[ "$n" -ge 1 ]] && pass "the reason is stored and shown back" || fail "the revoke reason did not survive the round trip"

  # THE load-bearing assertion of this section, re-worded for 0.7.0. Revoking now also re-signs a CRL this host publishes
  # (STEP F proves it), so the old framing — "mypki publishes no CRL and no OCSP" — is false as written, and its two needles
  # (`no CRL is published`) are dead: grep -rn over src/mypki/ finds neither phrase in any template. What is still true, and
  # what the page still has to say, is the client half: issued.html:230 keeps `a revoked certificate stays trusted by clients
  # until it expires`, because consulting a CRL or asking an OCSP responder is the client's side of the job. Asserted on BOTH
  # steps now: the step that asks and the step that acts.
  n=$(count_all "$REV" "stays trusted by clients until it expires")
  [[ "$n" -ge 1 ]] && pass "the page still states the client-side caveat — a revoked certificate stays trusted by clients until it expires (issued.html:230)" \
    || fail "/issued revokes without stating the client-side caveat (this sentence is the feature's honest half)"
  # And the replacement for the dead needle, measured on the live page rather than invented: issued.html:107 names what this
  # host DOES publish now. A page that promises a CRL it does not sign would be as dishonest as one that hid the caveat.
  n=$(count_joined "$WORK/revoke.html" 'From 0.7.0 this host also signs a CRL and answers OCSP')
  [[ "$n" -ge 1 ]] && pass "the page names the CRL/OCSP it now publishes instead of claiming revocation reaches clients ($n)" \
    || fail "/issued does not say what 0.7.0 publishes ($n): STEP F checks the artifact, but the page has to name it too"

  # A stamped row offers no checkbox: it cannot be re-revoked (store.revoke preserves the stamp on purpose) and there is no
  # delete. Rewritten for 0.3.0 because the assertion this replaces was false by construction — with ONE bulk form the old
  # `action="/issued/revoke"` count is 1 before and 1 after, so "fell by exactly one" could never hold (MEASURED: it failed
  # against a correct app, 1 -> 2). The real contract is about the SERIAL and about CHECKBOXES: no control carries the stamped
  # serial, and exactly one checkbox disappears. Counted against every row on the page, which legitimately keeps its own
  # checkbox for every other active certificate this host signed.
  n=$(count_all "$REV" "name=\"serial_hex\" value=\"$ROW_SERIAL\"")
  [[ "$n" == "0" ]] && pass "no control carries the stamped serial (it cannot be re-revoked, and there is no delete)" \
    || fail "a revoked record still offers a control for $ROW_SERIAL ($n)"
  BEFORE=$(count_all "$LIST" 'type="checkbox" name="serial_hex"')
  AFTER_N=$(count_all "$REV" 'type="checkbox" name="serial_hex"')
  [[ "$AFTER_N" == "$((BEFORE - 1))" ]] \
    && pass "the checkbox count fell by exactly one ($BEFORE -> $AFTER_N): the stamped row lost its box, no other row did" \
    || fail "revoking changed the checkbox count by $((BEFORE - AFTER_N)) instead of 1 ($BEFORE -> $AFTER_N)"
  FORMS=$(count_re "$REV" '<form method="post" action="/issued/revoke"')
  [[ "$FORMS" -le 2 ]] && pass "the confirmed page posts at most one bulk form plus the confirmation form ($FORMS forms)" \
    || fail "/issued rendered $FORMS revoke forms — 0.3.0 has one bulk form, not a form per row"

  # STEP C — multi-select, which is what 0.3.0 added: two real active rows plus one serial this host never signed, all in
  # ONE submit. Unconfirmed first, because the confirmation must name all three (including the unknown one) before any of
  # them changes. The bogus serial is only ever submitted inside a batch: a lone unknown serial keeps its own 404 contract.
  mapfile -t OTHERS < <(all_row_serials "$WORK/issued-list.html" | grep -v "^$ROW_SERIAL$" | head -2)
  if [[ "${#OTHERS[@]}" -lt 2 ]]; then
    warn "only ${#OTHERS[@]} other active record(s) on this host — the multi-select checks cannot run"
  else
    status=$(post_form "/issued/revoke" "$WORK/revoke-multi-confirm.html" \
      "csrf_token=$TOKEN" "serial_hex=${OTHERS[0]}" "serial_hex=${OTHERS[1]}" "serial_hex=deadbeefcafebabf")
    MULTI=$(cat "$WORK/revoke-multi-confirm.html")
    n=$(count_all "$MULTI" 'Revoke 3 certificates?')
    if [[ "$status" == "200" && "$n" -ge 1 ]]; then pass "a three-serial submit confirms THREE before stamping any ('Revoke 3 certificates?')"
    else fail "multi-select confirm: status $status, 'Revoke 3 certificates?' $n"; fi
    n=$(count_all "$MULTI" 'not a record on this host &mdash; it will be reported, not revoked')
    [[ "$n" == "1" ]] && pass "the confirmation calls the unknown serial what it is (reported, not revoked)" \
      || fail "the confirmation hides that one of the three has no record here ($n)"
    # Compared against STEP B's page, not §10's list: STEP B legitimately stamped one record on the way here, so the
    # starting point for THIS submit is the count the operator last saw. MEASURED (6 -> 7 after STEP B): comparing back to
    # $LIST would report a correct app as stamping something it did not stamp.
    n=$(count_all "$MULTI" '<span class="pill revoked">revoked</span>')
    m=$(count_all "$REV" '<span class="pill revoked">revoked</span>')
    [[ "$n" == "$m" ]] && pass "an unconfirmed multi-select stamps nothing ($n revoked pills, unchanged from $m)" \
      || fail "an unconfirmed multi-select moved the revoked count ($m -> $n) before confirmation"
    n=$(count_all "$MULTI" 'already revoked &mdash; its stamp and reason will not change')
    [[ "$n" == "0" ]] && pass "the confirmation lists no already-stamped serial (all three are active here)" \
      || fail "the confirmation calls $n of the three already revoked, which §10 says they are not"

    # STEP D — the same three confirmed. The batch must separate the two real stamps from the one miss, and a miss must not
    # 404 away the two decisions the operator did mean to make.
    status=$(post_form "/issued/revoke" "$WORK/revoke-multi.html" \
      "csrf_token=$TOKEN" "serial_hex=${OTHERS[0]}" "serial_hex=${OTHERS[1]}" "serial_hex=deadbeefcafebabf" "confirm=1")
    BATCH=$(cat "$WORK/revoke-multi.html")
    n=$(count_all "$BATCH" '2 stamped now,')
    if [[ "$status" == "200" && "$n" -ge 1 ]]; then pass "a mixed batch stamps the two records it owns ('2 stamped now,')"
    else fail "mixed batch: status $status, '2 stamped now,' $n"; fi
    n=$(count_all "$BATCH" '0 already revoked before this submit')
    [[ "$n" -ge 1 ]] && pass "the batch counts zero already-revoked (true here, and stated rather than left blank)" \
      || fail "the batch card does not state its already-revoked count"
    n=$(count_all "$BATCH" '1 with no record on this host')
    [[ "$n" -ge 1 ]] && pass "the batch counts the one serial with no record here" || fail "the batch hides the miss it was given"
    # MEASURED byte-for-byte: the apostrophe here is plain ASCII U+0027 (`od` reads `h o s t ' s database`) — Jinja autoescape
    # leaves a typographic apostrophe raw, and this one is not typographic. Asserting '&#8217;' would fail against a correct
    # page. Double-quoted so the apostrophe needs no escaping.
    n=$(count_all "$BATCH" "no record with that serial in this host's database &mdash; nothing was changed")
    [[ "$n" -ge 1 ]] && pass "the batch names the missed serial plainly, with what it did NOT do" \
      || fail "the batch reports a miss without naming it and saying nothing was changed"
    n=$(count_all "$BATCH" 'deadbeefcafebabf')
    [[ "$n" -ge 1 ]] && pass "the missed serial is printed, not hidden behind a count" \
      || fail "the batch counted the miss but never named the serial"

    # STEP E — re-submitting the serial STEP B already stamped. store.revoke refuses to move an existing stamp, so this must
    # read as '0 stamped now' / '1 already revoked', with the original reason still shown back. This is the stale-tab case
    # the three-way card exists for.
    status=$(post_form "/issued/revoke" "$WORK/revoke-again.html" \
      "csrf_token=$TOKEN" "serial_hex=$ROW_SERIAL" "confirm=1" "reason=second submit from a stale tab")
    AGAIN=$(cat "$WORK/revoke-again.html")
    n=$(count_all "$AGAIN" '0 stamped now,')
    m=$(count_all "$AGAIN" '1 already revoked before this submit')
    if [[ "$status" == "200" && "$n" -ge 1 && "$m" -ge 1 ]]; then pass "re-submitting a stamped serial stamps nothing ('0 stamped now,' '1 already revoked')"
    else fail "re-revoke: status $status, '0 stamped now,' $n, '1 already revoked' $m"; fi
    n=$(count_all "$AGAIN" 'smoke harness: retired on purpose')
    [[ "$n" -ge 1 ]] && pass "the original stamp and reason survive a second submit (not overwritten by the new one)" \
      || fail "a re-revoke lost the reason recorded by the first one"
    n=$(count_all "$AGAIN" 'already revoked &mdash; its stamp and reason were left alone')
    [[ "$n" -ge 1 ]] && pass "the card says what it did NOT do to that record" || fail "the card does not say the existing stamp was left alone"
  fi

  # And it survives a plain GET, which is what an operator does next (refresh, bookmark, another browser).
  status=$(get "/issued" "$WORK/issued-after.html")
  AFTER=$(cat "$WORK/issued-after.html")
  n=$(count_all "$AFTER" '<span class="pill revoked">revoked</span>')
  # Three stamps is the precondition this section now guarantees (see §6's seeding block), so `>= 3` is a real
  # expectation rather than a hope that the host happened to hold extra records. The count is printed so a run on a
  # busier host reads as "more records than I stamped", not as an unexplained number.
  [[ "$status" == "200" && "$n" -ge 3 ]] && pass "the revoked state survives a plain GET /issued ($n revoked pills after at least three stamps)" \
    || fail "GET /issued after revoking: status $status, 'revoked' pills $n (expected at least 3 — §6 seeds two extra records so three stamps are reachable)"
  n=$(count_all "$AFTER" "name=\"serial_hex\" value=\"$ROW_SERIAL\"")
  [[ "$n" == "0" ]] && pass "a plain GET still offers no control for a stamped serial" \
    || fail "GET /issued re-offered a control for the stamped serial ($n)"
  # The stamp moved into the Status cell when the Revoked column was deleted: same shape (`class="hint">revoked
  # YYYY-MM-DD…`), one fewer place for a reader to look, and one fewer place for two cells to disagree.
  n=$(count_re "$AFTER" 'class="hint">revoked [0-9]{4}-[0-9]{2}-[0-9]{2}')
  [[ "$n" -ge 3 ]] && pass "the Status cell reads as a dated decision ('revoked YYYY-MM-DD…', $n)" \
    || fail "the Status cell carries no revocation stamp ($n)"
  n=$(count_all "$AFTER" '<th scope="col">Revoked</th>')
  [[ "$n" == "0" ]] && pass "the list has no separate Revoked column any more ($n)" \
    || fail "/issued still renders a Revoked column ($n) while claiming the Status cell carries the stamp"

  # --------------------------------------------------------------------------- STEP F - the CRL and the OCSP answer this walk earned
  #
  # Everything above stamped revocations. From 0.7.0 that means two more artifacts exist and can be checked: a signed CRL
  # on disk (`GET /crl`, `GET /crl.pem`) and a responder that answers for one serial (`POST /ocsp`). Asserted at the END
  # of §11 rather than in §5 because §11 is what creates the revoked rows an entry and an answer are about: against a
  # ledger with nothing stamped, almost any CRL assertion passes vacuously.
  #
  # NO openssl (plan U7: `.github/workflows/ci.yml`'s "NO OpenSSL binary is required anywhere" is a contract, and this
  # harness exists to be run where no toolchain is installed) and NO shell DER parser: `base64 -d` + `od` read bytes,
  # bash's `printf %b` writes them (see the helpers above for why that printer cannot run under dash).
  #
  # THE MARKERS ARE MEASURED, not inferred. Every one was produced twice: once through cryptography/openssl in plan §2,
  # and again against THIS build's responder with a zeroed-hash CertID (see SMOKE_TESTING.md "0.7.0"):
  #   * bytes 4..6 of a successful answer are `0a 01 00` (OCSPResponseStatus SUCCESSFUL) - the one offset this file does
  #     assert, because it is fixed by RFC 6960 §4.2.1's outer SEQUENCE, not by anything mypki chooses;
  #   * CertStatus sits immediately after the response's copy of the request's serial INTEGER: GOOD `80 00`, UNKNOWN
  #     `82 00`, REVOKED `a1 16 … a0 03 0a 01 00` (the revokedReason SEQUENCE holding `unspecified`);
  #   * a refusal is the whole body: `30 03 0a 01 01` MALFORMED_REQUEST, `30 03 0a 01 02` INTERNAL_ERROR, both at HTTP
  #     200. At this endpoint an error is a body, never a status code - which is the one place in mypki where the usual
  #     "every rejection gets an HTML page with a telling status" rule is suspended on purpose.
  # NOTHING below asserts a response LENGTH or an absolute CertStatus offset: MEASURED sizes for this harness's RSA-3072
  # scratch CA are 1704 B (GOOD), 1704 B (UNKNOWN) and 1735 B (REVOKED), while plan §2 measured 1778/1781/1805 for a
  # different 3072-bit CA and 1841/1863 with SHA-256 + nonce. A size assertion would be a measurement of one key.
  # The status search is also SCOPED to the bytes between the serial field and the signature's AlgorithmIdentifier
  # (`30 0d 06 09`): MEASURED over 300 signed REVOKED answers, `8000`/`8200` appear somewhere in the body 7 times out of
  # 300 - inside random signature bytes - and 0 times out of 300 inside that region. Unscoped, this section would flake.
  WALK_STAMPS=1                                   # STEP B stamped one serial on the way here
  [[ -s "$WORK/revoke-multi.html" ]] && WALK_STAMPS=$((WALK_STAMPS + 2))   # STEP D's batch stamped two more
  STAMPED_SERIALS=("$ROW_SERIAL")
  if [[ -s "$WORK/revoke-multi.html" ]]; then STAMPED_SERIALS+=("${OTHERS[0]}" "${OTHERS[1]}"); fi

  status=$(get "/crl" "$WORK/crl.html")
  [[ "$status" == "200" ]] && pass "GET /crl answers 200 (the page, not just the artifact)" \
    || fail "GET /crl answered $status (expected 200)"
  CRL_PAGE=$(cat "$WORK/crl.html")
  n=$(count_all "$CRL_PAGE" '-----BEGIN X509 CRL-----')
  [[ "$n" == "1" ]] && pass "/crl renders exactly one CRL armour block ($n)" \
    || fail "/crl renders $n CRL armour blocks (expected 1: the page shows the artifact it is describing)"
  n=$(count_all "$CRL_PAGE" 'id="pem-crl"')
  [[ "$n" == "1" ]] && pass "/crl's PEM block has its own id, so the copy button can point at it ($n)" \
    || fail "/crl renders no pem-crl block ($n)"
  n=$(count_all "$CRL_PAGE" 'data-mypki-copy="pem-crl"')
  [[ "$n" == "1" ]] && pass "/crl's copy button points at that block ($n)" || fail "/crl has no copy button wired to pem-crl ($n)"
  n=$(count_re "$CRL_PAGE" '<td>[0-9]+ revoked certificate')
  [[ "$n" == "1" ]] && pass "/crl states its entry count once, in words ($n)" \
    || fail "/crl's Entries row is not the one documented row ($n)"
  CRL_ENTRIES=$(printf '%s' "$CRL_PAGE" | grep -oE '<td>[0-9]+ revoked certificate' | head -1 | grep -oE '[0-9]+')
  if [[ -n "$CRL_ENTRIES" && "$CRL_ENTRIES" == "$WALK_STAMPS" ]]; then
    pass "the published CRL lists exactly the $WALK_STAMPS revocation(s) this walk stamped ($CRL_ENTRIES entries)"
  else
    fail "/crl reports ${CRL_ENTRIES:-no number} entries but this walk stamped $WALK_STAMPS — the artifact and the ledger disagree"
  fi
  n=$(count_all "$CRL_PAGE" 'What this CRL does not do')
  [[ "$n" == "1" ]] && pass "/crl carries the honest-limits card (page-map §14's four measured caveats) ($n)" \
    || fail "/crl renders no 'does not do' card ($n): an artifact with unstated limits is a page that overstates itself"
  n=$(count_all "$CRL_PAGE" 'What the OCSP responder does not do')
  [[ "$n" == "1" ]] && pass "/crl carries the OCSP limits card (echoed hashes, the two size caps, no CSRF) ($n)" \
    || fail "/crl renders no OCSP limits card ($n)"

  status=$(get "/crl.pem" "$WORK/crl.pem")
  [[ "$status" == "200" ]] && pass "GET /crl.pem answers 200 (the URL certificates issued from 0.7.0 carry)" \
    || fail "GET /crl.pem answered $status (expected 200)"
  # headers_of(), not `cat $WORK/headers.txt`: get() writes only the body, so reading a header dump here would count the
  # headers of whatever request last wrote that file (in this walk, §9's /ca/certificate download) and every media-type
  # assertion below would pass against the wrong response. headers_of re-Gets the same path and is the only helper that
  # fills headers.txt; it is called here, immediately, before any other headers_of call can overwrite the file.
  PEM_HDRS=$(headers_of "/crl.pem")
  n=$(count_all "$(printf '%s' "$PEM_HDRS" | lower)" 'content-type: application/pkix-crl')
  [[ "$n" == "1" ]] && pass "/crl.pem declares application/pkix-crl, so a client need not guess from the filename ($n)" \
    || fail "/crl.pem's media type is not application/pkix-crl ($n) — page-map §14 names this header as the point of the route"
  n=$(count_all "$(printf '%s' "$PEM_HDRS" | lower)" 'content-disposition: attachment; filename="mypki.crl.pem"')
  [[ "$n" == "1" ]] && pass "/crl.pem is an attachment named mypki.crl.pem ($n)" || fail "/crl.pem's Content-Disposition is wrong ($n)"
  n=$(count_all "$(printf '%s' "$PEM_HDRS" | lower)" 'cache-control: no-store')
  [[ "$n" == "1" ]] && pass "/crl.pem is not cacheable (a proxy replaying a 24 h-old CRL keeps a revoked certificate trusted) ($n)" \
    || fail "/crl.pem is cacheable ($n)"

  n=$(count_all "$(cat "$WORK/crl.pem")" '-----BEGIN X509 CRL-----')
  [[ "$n" == "1" ]] && pass "the download contains exactly one armour block ($n)" \
    || fail "the /crl.pem download contains $n armour blocks (expected 1)"
  CRL_DER_HEX=$(crl_pem_der_hex "$WORK/crl.pem")
  if [[ -z "$CRL_DER_HEX" ]]; then
    fail "/crl.pem's base64 body could not be decoded — nothing below about entries can be checked"
  else
    pass "/crl.pem decodes to $((${#CRL_DER_HEX} / 2)) bytes of DER (read with od + base64, no openssl)"
    # Every serial this walk stamped has to be IN the artifact. This is the assertion that makes the revoke→publish link
    # real: a CRL that says "3 entries" and lists three other serials would pass every count above.
    for serial in "${STAMPED_SERIALS[@]}"; do
      value=$(der_integer_hex "$serial")
      field="02$(printf '%02x' $(( ${#value} / 2 )))${value}"
      n=$(count_all "$CRL_DER_HEX" "$field")
      [[ "$n" == "1" ]] && pass "the CRL lists the stamped serial ${serial:0:12}… as DER INTEGER $field ($n)" \
        || fail "the published CRL does not carry the stamped serial $serial as $field (found $n) — a revoked row with no entry"
    done
    # `170d` is UTCTime's tag+length (`17 0d`, thirteen content bytes: YYYYMMDDHHMMSSZ). MEASURED across CRLs holding 0, 1,
    # 3 and 5 entries: exactly entry_count + 2 (thisUpdate + nextUpdate), which is why it counts entries here. It is a
    # cross-check on the page's number, not a substitute for the serial search above.
    n=$(count_all "$CRL_DER_HEX" '170d')
    [[ "$n" == "$(( CRL_ENTRIES + 2 ))" ]] \
      && pass "the decoded artifact holds $((n - 2)) revocationDate fields plus thisUpdate/nextUpdate ($n UTCTime fields)" \
      || fail "the decoded artifact carries $n UTCTime fields, not entries($CRL_ENTRIES)+2 — the page's count and the bytes disagree"
    # The two extensions crl.py adds, and the two it refuses to add (plan §4's measured `error 44 … different CRL scope`
    # reason). Asserted as OIDs read out of the decoded body: absent IDP/DeltaCRL is a decision with evidence behind it,
    # and an accidental `.add_extension(x509.IssuingDistributionPoint(...))` would break every pre-0.7 certificate this
    # CA ever signed at `openssl verify -crl_check`.
    # The four OID markers, each named by its DOTTED NUMBER and asserted on the DER encoding of that number
    # (`06 03 55 1d XX` = OBJECT IDENTIFIER with 3 content bytes: the first folds arcs {2,5} into 2*40+5 = 85 = 0x55, the
    # second is arc 29 = 0x1d, so any 2.5.29.N OID is `0603551d` followed by N as one hex byte). MEASURED with /tmp/s11/probe_crl4.py against a CRL this build signed for 3
    # entries: `extensions: [('2.5.29.20', 'CRLNumber'), ('2.5.29.35', 'AuthorityKeyIdentifier')]` and the marker census on
    # the decoded body read 0603551d14 = 1, 0603551d23 = 1, 0603551d1b = 0, 0603551d1c = 0. Getting these labels wrong is
    # the trap this comment exists for: 2.5.29.20 is CRLNumber (NOT ...1d23), 2.5.29.35 is AKI (NOT ...1d1c, which is
    # IDP's number at 2.5.29.28), and 2.5.29.27 = ...1d1b is DeltaCRLIndicator.
    n=$(count_all "$CRL_DER_HEX" '0603551d14')
    [[ "$n" == "1" ]] && pass "the CRL carries CRLNumber, OID 2.5.29.20 = \`06 03 55 1d 14\` (RFC 5280 §5.2.1: it counts stamps, so it never decreases) ($n)" \
      || fail "the published CRL has no CRLNumber extension (OID 2.5.29.20 / 0603551d14 found $n times)"
    n=$(count_all "$CRL_DER_HEX" '0603551d23')
    [[ "$n" == "1" ]] && pass "the CRL carries an AuthorityKeyIdentifier, OID 2.5.29.35 = \`06 03 55 1d 23\`, so a client can tell which CA signed it ($n)" \
      || fail "the published CRL has no AKI (OID 2.5.29.35 / 0603551d23 found $n times)"
    n=$(count_all "$CRL_DER_HEX" '0603551d1c')
    [[ "$n" == "0" ]] && pass "the CRL carries no IssuingDistributionPoint, OID 2.5.29.28 = \`06 03 55 1d 1c\` (measured: an IDP-scoped CRL answers error 44 'different CRL scope' for every pre-0.7 leaf) ($n)" \
      || fail "the published CRL grew an IssuingDistributionPoint (OID 2.5.29.28 / 0603551d1c found $n times) — that would make -crl_check unusable on this CA's own history"
    n=$(count_all "$CRL_DER_HEX" '0603551d1b')
    [[ "$n" == "0" ]] && pass "the CRL carries no DeltaCRLIndicator, OID 2.5.29.27 = \`06 03 55 1d 1b\` (no delta CRLs are published, so none may be claimed) ($n)" \
      || fail "the published CRL grew a DeltaCRLIndicator (OID 2.5.29.27 / 0603551d1b found $n times)"
  fi

  # --- POST /ocsp: three answers, all of them HTTP 200 with the status inside the body.
  OCSP_UNUSED="0badc0de0badc0de0badc0de0badc0de"   # fixed, and never signed by any scratch CA: `find()` finds nothing
  der_hex=$(ocsp_request_der_hex "$OCSP_UNUSED")
  der_bytes_from_hex "$der_hex" > "$WORK/ocsp-unknown.der"
  status=$(post_der "/ocsp" "$WORK/ocsp-unknown.resp" "$WORK/ocsp-unknown.der" "application/ocsp-request" "$WORK/ocsp-unknown-hdrs.txt")
  if [[ "$status" == "200" ]]; then pass "POST /ocsp answers 200 for a serial this host never signed (the status is in the body)"
  else fail "POST /ocsp answered $status for an unknown serial (expected 200: a protocol answer is not an HTTP error)"; fi
  HDRS=$(cat "$WORK/ocsp-unknown-hdrs.txt")
  n=$(count_all "$(printf '%s' "$HDRS" | lower)" 'content-type: application/ocsp-response')
  [[ "$n" == "1" ]] && pass "/ocsp answers application/ocsp-response (DER, not mypki's HTML) ($n)" \
    || fail "/ocsp's media type is not application/ocsp-response ($n) — a client that expects DER cannot read HTML"
  n=$(count_all "$(printf '%s' "$HDRS" | lower)" 'cache-control: no-store')
  [[ "$n" == "1" ]] && pass "/ocsp answers are not cacheable ($n)" \
    || fail "/ocsp is cacheable ($n): a replayed GOOD outlives the revocation it used to describe"
  n=$(count_all "$(printf '%s' "$HDRS" | lower)" 'content-disposition')
  [[ "$n" == "0" ]] && pass "/ocsp sends no Content-Disposition (these bytes are consumed by a library, not saved) ($n)" \
    || fail "/ocsp attaches a filename to DER a browser would offer to download ($n)"

  UNKNOWN_HEX=$(der_hex_of "$WORK/ocsp-unknown.resp")
  n=$(count_all "${UNKNOWN_HEX:8:6}" '0a0100')
  [[ "$n" == "1" ]] && pass "the unknown-serial answer reports OCSPResponseStatus SUCCESSFUL at bytes 4..6 ($n)" \
    || fail "the unknown-serial answer's responseStatus is not 0a0100 (got ${UNKNOWN_HEX:8:6}) — RFC 6960 §4.2.1's outer SEQUENCE moved"
  value=$(der_integer_hex "$OCSP_UNUSED")
  region=$(after_serial_hex "$UNKNOWN_HEX" "$value")
  case "$region" in
    8200*) pass "a serial with no record here answers UNKNOWN (\`82 00\` right after the serial) — not GOOD, which would claim knowledge of a certificate this CA never signed" ;;
    *) fail "the unknown serial did not answer UNKNOWN (region starts ${region:0:4}, expected 8200)" ;;
  esac

  der_bytes_from_hex "$(ocsp_request_der_hex "$ROW_SERIAL")" > "$WORK/ocsp-revoked.der"
  status=$(post_der "/ocsp" "$WORK/ocsp-revoked.resp" "$WORK/ocsp-revoked.der" "application/ocsp-request" "$WORK/ocsp-revoked-hdrs.txt")
  if [[ "$status" == "200" ]]; then pass "POST /ocsp answers 200 for the serial §11 revoked"
  else fail "POST /ocsp answered $status for the revoked serial (expected 200)"; fi
  REVOKED_HEX=$(der_hex_of "$WORK/ocsp-revoked.resp")
  [[ "${REVOKED_HEX:8:6}" == "0a0100" ]] && pass "the revoked answer reports SUCCESSFUL at bytes 4..6" \
    || fail "the revoked answer's responseStatus is not 0a0100 (got ${REVOKED_HEX:8:6})"
  value=$(der_integer_hex "$ROW_SERIAL")
  region=$(after_serial_hex "$REVOKED_HEX" "$value")
  # Cut the region at the signature's AlgorithmIdentifier (`30 0d 06 09`): everything after it is random RSA bytes, and
  # MEASURED those bytes carry `8000`/`8200` in 7 of 300 answers. Scoping is what makes the absence below an assertion.
  region="${region%%300d0609*}"
  case "$region" in
    a116*) pass "the revoked serial answers REVOKED (\`a1 16\`, the revocationInfo SEQUENCE, right after the serial)" ;;
    *) fail "the revoked serial did not answer REVOKED (region starts ${region:0:4}, expected a116) — /issued stamped it and this responder does not know" ;;
  esac
  n=$(count_all "$region" 'a0030a0100')
  [[ "$n" == "1" ]] && pass "the REVOKED answer carries revokedReason = unspecified (\`a0 03 0a 01 00\`) — the store's reason is prose, and inventing a code from it would be a lie (plan U6) ($n)" \
    || fail "the REVOKED answer states no revocation reason ($n): RFC 5280 §5.3.1 says an absent code means unspecified, so say it"
  n=$(count_all "$region" '8000'); m=$(count_all "$region" '8200')
  [[ "$n" == "0" && "$m" == "0" ]] && pass "the REVOKED answer says nothing else about this serial (no GOOD \`8000\`, no UNKNOWN \`8200\` in its singleResponse: $n/$m)" \
    || fail "one body claims two statuses for the same serial (GOOD=$n UNKNOWN=$m inside the singleResponse)"

  der_bytes_from_hex '30423040303e303c303a300906052b0e03021a05000414' > "$WORK/ocsp-garbage.der"
  printf 'not-an-ocsp-request' > "$WORK/ocsp-garbage2.der"
  status=$(post_der "/ocsp" "$WORK/ocsp-garbage.resp" "$WORK/ocsp-garbage.der" "application/ocsp-request")
  if [[ "$status" == "200" ]]; then pass "POST /ocsp answers 200 to a truncated request (it refuses inside the body, as RFC 6960 §4.2 requires)"
  else fail "POST /ocsp answered $status for garbage (expected 200 — mypki's HTML 4xx rule is suspended at this route on purpose)"; fi
  n=$(der_hex_of "$WORK/ocsp-garbage.resp")
  if [[ "${#n}" == "10" && "$n" == "30030a0101" ]]; then pass "the refusal is byte-exact MALFORMED_REQUEST: \`30 03 0a 01 01\`, five bytes, unsigned (measured spelling)"
  else fail "the malformed-request answer is $((${#n} / 2)) bytes ($n), not 30030a0101 — a client reads a wrong refusal as a dead responder"; fi
  status=$(post_der "/ocsp" "$WORK/ocsp-garbage2.resp" "$WORK/ocsp-garbage2.der" "application/ocsp-request")
  n=$(der_hex_of "$WORK/ocsp-garbage2.resp")
  if [[ "$status" == "200" && "$n" == "30030a0101" ]]; then pass "text where DER was expected gets the same five-byte refusal (status $status)"
  else fail "non-DER body: status $status, body ${n:-empty} ($(( ${#n} / 2 )) bytes), expected 200 + 30030a0101"; fi
fi

# =========================================================================== §12 About + Settings (page-map §12)
echo "§12 About and Settings (page-map §12)"
status=$(get "/about" "$WORK/about.html")
[[ "$status" == "200" ]] && pass "GET /about answers 200" || fail "GET /about answered $status"
ABOUT=$(cat "$WORK/about.html")
if [[ -n "$EXPECTED_VERSION" ]]; then
  n=$(count_all "$ABOUT" "mypki $EXPECTED_VERSION")
  [[ "$n" -ge 1 ]] && pass "/about names the running version" || fail "/about does not name version $EXPECTED_VERSION"
fi
# Single-quoted pattern on purpose: it contains both a `"` and a `\"`, and inside a double-quoted bash string the first `"`
# closes the string and the rest parses as shell -- which is a syntax error at `bash -n`, not a failed assertion.
n=$(count_re "$ABOUT" '<a href="https://github\.com/[^"]*/mypki"')
[[ "$n" -ge 1 ]] && pass "/about links the source URL, so a problem can be cited against a build" \
  || fail "/about has no source link"
# 0.5.0: the "what this host is running" card moved to the TOP of /about, above the lede and the profile hero. Its rows
# are what a problem report quotes (version + source URL) and what tells you whether this host is on TLS or plain HTTP,
# so they belong before the prose rather than after it. Asserted as offsets for the same reason §12's other assertions
# are not: every one of these needles was already present somewhere on the page, so presence could not see the move.
RUNNING_OFFSET=$(offset_of "$WORK/about.html" "What this host is running")
LEDE_OFFSET=$(offset_of "$WORK/about.html" '<p class="lede">')
HERO_OFFSET=$(offset_of "$WORK/about.html" "What the three profiles mean")
if [[ "$RUNNING_OFFSET" == "-1" ]]; then
  fail "/about no longer renders the 'what this host is running' card"
elif [[ "$LEDE_OFFSET" != "-1" && "$RUNNING_OFFSET" -lt "$LEDE_OFFSET" && "$HERO_OFFSET" != "-1" && "$RUNNING_OFFSET" -lt "$HERO_OFFSET" ]]; then
  pass "/about leads with the running-host card (card $RUNNING_OFFSET < lede $LEDE_OFFSET < profiles $HERO_OFFSET)"
else
  fail "/about does not lead with the running-host card (got card=$RUNNING_OFFSET lede=$LEDE_OFFSET profiles=$HERO_OFFSET)"
fi

# 0.7.0 prose sweep: the old needle `No published CRL or OCSP` is gone from about.html — grep -rn over src/mypki/ finds no
# such phrase. The card is still there and its first row now opens with the sentence that replaced the claim (about.html:58,
# grepped from the template and confirmed live against $WORK/about.html): publishing began, and reaching a client is still
# the client's side of the job.
n=$(count_all "$ABOUT" 'What this CA does not do (yet)')
[[ "$n" -ge 1 ]] && pass "/about still carries the 'does not do (yet)' card" || fail "/about dropped the 'does not do (yet)' card"
n=$(count_joined "$WORK/about.html" 'Revocation reaches only clients that go looking for it.')
[[ "$n" -ge 1 ]] && pass "/about states the 0.7.0 revocation caveat: a CRL and an OCSP answer exist here, and consulting them is the client's side" \
  || fail "/about omits the 0.7.0 revocation caveat ($n) — 'does not do (yet)' must say what HAS changed as well as what has not"
# The three profiles in words, from signing.CERT_PROFILE_HELP. These are the sentences users asked for after 0.1.0 shipped
# the radio buttons with no explanation at all.
for pair in "This is the web-server profile:the server profile says what it IS" "It will NOT make a browser trust a web site:the client profile says what it does NOT do"; do
  needle="${pair%%:*}"
  label="${pair#*:}"
  n=$(count_all "$ABOUT" "$needle")
  [[ "$n" -ge 1 ]] && pass "$label present on /about" || fail "$label missing from /about ($needle)"
done

status=$(get "/settings" "$WORK/settings.html")
[[ "$status" == "200" ]] && pass "GET /settings answers 200" || fail "GET /settings answered $status"
SET_PAGE=$(cat "$WORK/settings.html")
n=$(count_all "$SET_PAGE" "MYPKI_VALIDITY_MAX_DAYS")
[[ "$n" -ge 1 ]] && pass "/settings lists MYPKI_VALIDITY_MAX_DAYS" || fail "/settings does not list the validity ceiling knob"
# Both honest spellings are accepted, because which one a live server shows depends on whether the OPERATOR set a
# secret: app._SECRET_KEY_PRESENT is 'set (value not displayed)' and app._SECRET_KEY_ABSENT is 'unset — mypki generated
# one into the data dir at startup (not displayed)'. A serve that was never given MYPKI_SECRET_KEY shows the second
# (MEASURED on 0.4.0: the first needle failed here on a fresh live run while the value stayed perfectly masked). What
# must hold is exactly ONE of them, so a page cannot hedge by printing both.
PRESENT=$(count_all "$SET_PAGE" "set (value not displayed)")
GENERATED=$(count_all "$SET_PAGE" "generated one into the data dir at startup (not displayed)")
if [[ $((PRESENT + GENERATED)) == 1 ]]; then pass "MYPKI_SECRET_KEY renders as a presence flag, not a value (present=$PRESENT generated-one=$GENERATED)" \
  else fail "/settings states the session secret $PRESENT + $GENERATED time(s); exactly one masked spelling must appear"
fi
n=$(count_all "$SET_PAGE" "indistinguishable here")
[[ "$n" -ge 1 ]] && pass "/settings states that .env vs shell vs CLI flag cannot be told apart" \
  || fail "/settings implies a precision the process cannot have (no 'indistinguishable' statement)"

# ---- 0.3.0: /settings became EDITABLE. What is asserted below is a refusal and its CONSEQUENCE, not just the wording:
# each refused save is checked against a fingerprint of this host's real config file, so "nothing was written" is an
# assertion rather than a hope. A successful save is deliberately NOT exercised here — that would write into the operator's
# own ~/.config/mypki (or %APPDATA%) from a script whose job is only to look. The write path, the 0600 mode, the preserved
# unmanaged lines and the restart wording are covered by tests/test_settings_save.py against a temporary config dir.
n=$(count_all "$SET_PAGE" '<button class="save-settings" type="submit">Save Settings</button>')
[[ "$n" == "1" ]] && pass "/settings renders its Save button ($n)" \
  || fail "/settings has no Save button ($n) — the page is read-only again while claiming to save"

KNOBS=$(count_re "$SET_PAGE" 'name="MYPKI_[A-Z0-9_]+"')
[[ "$KNOBS" -ge 20 ]] && pass "/settings renders one control per editable knob ($KNOBS)" \
  || fail "/settings renders only $KNOBS MYPKI_* controls — a knob lost its input, so a save would post nothing for it"

# Same two-spelling contract as above, now checked on the card specifically: the knob is named as <code> and never as
# a form control, and its state is stated without stating the value.
CARD=$(sed -n '/Not editable here/,/<\/section>/p' "$WORK/settings.html")
CARD_PRESENT=$(count_all "$CARD" "set (value not displayed)")
CARD_GENERATED=$(count_all "$CARD" "generated one into the data dir at startup (not displayed)")
if [[ $((CARD_PRESENT + CARD_GENERATED)) == 1 ]]; then pass "the unmanaged card states the secret's presence once, masked ($((CARD_PRESENT + CARD_GENERATED)))" \
  else fail "the 'Not editable here' card states the secret $CARD_PRESENT + $CARD_GENERATED time(s)"
fi
if [[ "$(count_all "$CARD" 'name="MYPKI_SECRET_KEY"')" == "0" ]]; then pass "the card carries no control for MYPKI_SECRET_KEY" \
  else fail "the 'Not editable here' card grew a form control for the session secret"
fi

CONFIG_FILE=$(sed -n 's/.*saved to <code>\([^<]*\)<\/code>.*/\1/p' "$WORK/settings.html" | head -1)
if [[ -z "$CONFIG_FILE" ]]; then
  fail "/settings never names the file a save writes — the refusal checks below have nothing to compare against"
else
  pass "/settings names the file a save writes ($CONFIG_FILE)"
  FILE_BEFORE=$(file_state "$CONFIG_FILE")

  # The bound in the refusal is read from the SAME control the page renders (min/max), which app.py fills from the same
  # Field(ge=…, le=…) metadata pydantic enforces. So this check cannot drift from config.py: change the knob there and both
  # the input's max= and the expected sentence move together.
  PORT_MIN=$(knob_bound "$WORK/settings.html" MYPKI_PORT min)
  PORT_MAX=$(knob_bound "$WORK/settings.html" MYPKI_PORT max)
  if [[ -z "$PORT_MIN" || -z "$PORT_MAX" ]]; then
    fail "the port input declares no range (got min=$PORT_MIN max=$PORT_MAX) — the form would accept anything a browser typed"
  else
    pass "the port input declares its allowed range ($PORT_MIN to $PORT_MAX, from config.py's Field)"
    BAD_PORT=$((PORT_MAX + 1))
    settings_form_body "$WORK/settings.html" "$WORK/save-badport.txt" "MYPKI_PORT=$BAD_PORT" \
      || fail "could not build the settings form body from the page"
    status=$(post_body "/settings" "$WORK/save-badport.html" "$WORK/save-badport.txt")
    BADSAVE=$(cat "$WORK/save-badport.html")
    n=$(count_all "$BADSAVE" "Not saved &mdash; fix this and submit again")
    if [[ "$status" == "200" && "$n" -ge 1 ]]; then pass "an out-of-range save answers 200 with the amber 'Not saved' block (not a 500)"
    else fail "out-of-range save: status $status, 'Not saved' block $n"; fi
    n=$(count_all "$BADSAVE" "MYPKI_PORT must be $PORT_MIN to $PORT_MAX; you entered an invalid value.")
    [[ "$n" -ge 1 ]] && pass "the refusal names the knob and the bound it failed ($PORT_MIN to $PORT_MAX)" \
      || fail "the refusal does not name MYPKI_PORT's bound — an operator cannot fix a field from a message that omits it"
    n=$(count_all "$BADSAVE" "value=\"$BAD_PORT\"")
    [[ "$n" -ge 1 ]] && pass "the rejected value is still filled in ($BAD_PORT) rather than lost" \
      || fail "a rejected save threw away what the operator typed"
    n=$(count_all "$BADSAVE" "Nothing was written to <code>$CONFIG_FILE</code>")
    [[ "$n" -ge 1 ]] && pass "the refusal states plainly that nothing was written" || fail "the refusal does not say the file was left alone"
    FILE_AFTER=$(file_state "$CONFIG_FILE")
    [[ "$FILE_AFTER" == "$FILE_BEFORE" ]] && pass "a refused save changed nothing on disk (config file state unchanged: $FILE_AFTER)" \
      || fail "a REFUSED save modified $CONFIG_FILE ($FILE_BEFORE -> $FILE_AFTER)"
  fi

  # An unticked checkbox posts NOTHING, and app.py turns that into an explicit `false` for the one bool knob. The interesting
  # part is what happens when a body is missing a knob the page renders: validate_candidate refuses rather than guessing, and
  # MEASURED on a live 0.3.0 server the first refusal it reaches names the FIRST knob whose empty box is not a value —
  # MYPKI_HOST. Asserting the shape (a refusal naming an empty knob, no file change) rather than only that name keeps this
  # honest if config.py reorders its knobs.
  # An EMPTY box, not a missing knob. MEASURED correction that matters here: app.py's `_submitted_settings_fields` fills any
  # knob the body omitted with '' (or 'false' for the one checkbox), so deleting a field from this body would NOT reach
  # validate_candidate's "was not submitted" arm — it would land on `log_to_console=false`, VALIDATE, and WRITE the operator's
  # real config file from a script whose job is only to look. So the empty value is posted explicitly, and the knob chosen is
  # one of `_EMPTY_IS_NOT_A_VALUE` (host/ca_cn/log_level): an empty box there is refused rather than silently reverting to a
  # default behind the operator's back.
  settings_form_body "$WORK/settings.html" "$WORK/save-empty.txt" "MYPKI_HOST=" \
    || fail "could not build the empty-knob body"
  status=$(post_body "/settings" "$WORK/save-empty.html" "$WORK/save-empty.txt")
  EMPTY=$(cat "$WORK/save-empty.html")
  n=$(count_all "$EMPTY" "cannot be empty")
  if [[ "$status" == "200" && "$n" -ge 1 ]]; then pass "an empty box on a knob that has no empty value is refused ($n)"
  else fail "empty-knob save: status $status, 'cannot be empty' refusal $n"; fi
  n=$(count_re "$EMPTY" "<li>MYPKI_[A-Z0-9_]+ cannot be empty")
  [[ "$n" -ge 1 ]] && pass "the refusal names the knob it refused ($n)" \
    || fail "the refusal did not name a MYPKI_* knob — an operator cannot fix what is not named"
  FILE_AFTER=$(file_state "$CONFIG_FILE")
  [[ "$FILE_AFTER" == "$FILE_BEFORE" ]] && pass "the empty-knob refusal wrote nothing either" \
    || fail "a REFUSED empty-knob save modified $CONFIG_FILE ($FILE_BEFORE -> $FILE_AFTER)"

  # A stale tab posting the page's own values with an EMPTY token: mypki's 400, naming the CSRF token, and again no write.
  settings_form_body "$WORK/settings.html" "$WORK/save-nocsrf.txt" "csrf_token=" \
    || fail "could not build the empty-token body"
  status=$(post_body "/settings" "$WORK/save-nocsrf.html" "$WORK/save-nocsrf.txt")
  n=$(count_all "$(cat "$WORK/save-nocsrf.html")" "CSRF token")
  [[ "$status" == "400" && "$n" -ge 1 ]] && pass "a save with an empty CSRF token answers mypki's own 400 naming the token ($n)" \
    || fail "empty-token save: status $status (expected 400), 'CSRF token' named $n time(s)"
  FILE_AFTER=$(file_state "$CONFIG_FILE")
  [[ "$FILE_AFTER" == "$FILE_BEFORE" ]] && pass "a CSRF-rejected save wrote nothing to the config file" \
    || fail "a CSRF-rejected save modified $CONFIG_FILE ($FILE_BEFORE -> $FILE_AFTER)"

  n=$(count_all "$SET_PAGE" "read once at startup")
  [[ "$n" -ge 1 ]] && pass "/settings says which knobs need a restart ('read once at startup', $n)" \
    || fail "/settings no longer states that host/port/session_max_age/data_dir are read once at startup"
  # 0.4.0 shrank the restart list to four knobs and made everything else live, so the page has to say BOTH halves: a
  # page that still tells an operator to reboot for a logging change is a page that asks for an unnecessary outage.
  n=$(count_all "$SET_PAGE" "applied by this process as soon")
  [[ "$n" -ge 1 ]] && pass "/settings states that every other knob is applied without a restart" \
    || fail "/settings does not say that non-startup knobs take effect immediately"

  # ---- 0.5.0 Feature C: the restart-only boxes now show the SAVED value and name what is still running beside it.
  # This harness deliberately performs NO successful save (see the comment at the top of §12: a save would write into this
  # operator's own ~/.config/mypki), so everything assertable here is the NEGATIVE half of the rule plus the wording that
  # promises the positive half. The positive case — box shows 8543 while the sentence names 8443 — is proven in
  # tests/test_settings_save.py::test_a_plain_get_after_a_save_does_not_claim_that_a_save_just_happened against a temporary
  # config dir, and nowhere else on this host. A run that passes here has NOT seen a pending sentence render.
  n=$(count_all "$SET_PAGE" '<p class="pending-saved">')
  [[ "$n" == "0" ]] && pass "/settings shows no pending sentence on a host that has never saved ($n) — the marker is earned, not decorative" \
    || fail "/settings renders $n pending sentence(s) with nothing pending: a rose marker on every startup-only knob trains an operator to ignore the one that means something"
  # count_joined rather than count_all or count_re, both of which read 0 against a page that renders this sentence:
  # settings.html wraps it mid-clause (`… those four boxes show\nwhat the file says …`), and MEASURED on the first live
  # 0.5.0 run a contiguous needle failed here while the sentence was plainly present. count_re could not help even with an
  # escape in it, because grep never matches across a newline.
  n=$(count_joined "$WORK/settings.html" 'those four boxes show what the file says')
  [[ "$n" -ge 1 ]] && pass "/settings states the 0.5.0 rule for the four restart-only boxes ($n)" \
    || fail "/settings no longer says the restart-only boxes show the file's value — an operator reading only this page cannot tell saved from live"
  # Deliberately NO assertion on 'saved for the next start': MEASURED, that phrase already occurs 4x on every /settings render
  # because app._knob_input appends it to each of the four startup-only hints. An assertion counting it would pass forever and
  # prove nothing, which is worse than no assertion.
fi
# The leak question here is about RESOLVED ABSOLUTE paths, which only a live process knows. Bare filenames legitimately appear:
# two `config.py` Field descriptions name `<data>/ca/ca_key.pem` and `<data>/instance/secret_key` to explain what mypki does
# NOT touch, and those descriptions are rendered verbatim in the table's description column. Asserting their absence would fail
# against a correct page -- MEASURED, an earlier draft of `tests/test_no_key_leakage.py` did exactly that. So this reads the
# resolved data dir off the card and asks whether either key path is built under it.
DATA_ROOT=$(grep -A 1 'Data directory (resolved)' "$WORK/settings.html" \
  | sed -n 's/.*<td class="mono">\([^<]*\)<\/td>.*/\1/p' | head -1)
if [[ -z "$DATA_ROOT" ]]; then
  fail "/settings does not show a resolved data directory -- the leak check below cannot run"
else
  pass "/settings shows the resolved data directory ($DATA_ROOT)"
  leaked=0
  for suffix in "/ca/ca_key.pem" "/instance/secret_key"; do
    n=$(count_all "$SET_PAGE" "$DATA_ROOT$suffix")
    if [[ "$n" -ge 1 ]]; then fail "/settings renders the resolved key path $DATA_ROOT$suffix"; leaked=1; fi
  done
  if [[ "$leaked" == "0" ]]; then pass "/settings names no resolved CA-key or secret-key path"; fi
fi

# =========================================================================== §13 an editable confirm page that fails well
echo "§13 Inline form errors on the confirm page (page-map §3)"
# A fresh step A: §6's signing consumed the staged request, so nothing is pending now.
get "/csr/sign" "$WORK/sign-form2.html" >/dev/null
TOKEN=$(csrf_token "$WORK/sign-form2.html")
status=$(post_pem "/csr/sign" "$WORK/confirm2.html" "$WORK/generated.csr" "csrf_token=$TOKEN")
[[ "$status" == "200" ]] && pass "step A again answers 200" || fail "second step A answered $status"
PENDING=$(pending_id "$WORK/confirm2.html")
if [[ -z "$PENDING" ]]; then
  fail "the confirm form carries no ?pending= id — a rejected edit could not survive the round trip"
else
  pass "the confirm form carries the staged request in its action URL"
  TOKEN=$(csrf_token "$WORK/confirm2.html")
  # One bad field (a three-letter country) alongside two deliberate edits. Everything else is left as the request said it.
  status=$(post_form "/csr/sign?pending=$PENDING" "$WORK/badcountry.html" \
    "csrf_token=$TOKEN" "confirm=1" "cert_type=server" "validity_days=30" \
    "common_name=web.internal" "organization=Renamed By Smoke" "organizational_unit=" \
    "country=XXL" "state=" "locality=" "email=ops@example.test" \
    "sans=web.internal, *.lab.local, 10.0.0.7")
  BAD=$(cat "$WORK/badcountry.html")
  if [[ "$status" == "200" ]]; then pass "a bad edited country returns the same page at 200 (not an error page)"
  else fail "bad edited country answered $status (expected 200, inline)"; fi
  n=$(count_all "$BAD" "exactly two letters")
  [[ "$n" -ge 1 ]] && pass "the reason names the field and the offending value" || fail "no inline reason for the bad country"
  n=$(count_all "$BAD" "value=\"Renamed By Smoke\"")
  [[ "$n" -ge 1 ]] && pass "the other edit is preserved in its input" || fail "a rejected field cost the operator their other edit"
  n=$(count_all "$BAD" "Nothing was signed")
  [[ "$n" -ge 1 ]] && pass "the page says plainly that nothing was signed" || fail "no 'nothing was signed' statement on the rejected confirm"
  # The staged request must still be there, under the SAME id — otherwise fixing one character means re-pasting a PEM.
  PENDING2=$(pending_id "$WORK/badcountry.html")
  [[ -n "$PENDING2" && "$PENDING2" == "$PENDING" ]] && pass "the staged request survives with the same ?pending= id" \
    || fail "the rejected page lost the staged request (got ${PENDING2:-none}, expected $PENDING)"
  # And fixing it works: same pending id, valid country, and the diff block must then name what was changed.
  TOKEN=$(csrf_token "$WORK/badcountry.html")
  status=$(post_form "/csr/sign?pending=$PENDING" "$WORK/edited-issue.html" \
    "csrf_token=$TOKEN" "confirm=1" "cert_type=server" "validity_days=30" \
    "common_name=web.internal" "organization=Renamed By Smoke" "organizational_unit=" \
    "country=DE" "state=" "locality=" "email=ops@example.test" \
    "sans=web.internal, *.lab.local, 10.0.0.7")
  [[ "$status" == "200" ]] && pass "the corrected confirm issues at 200" || fail "corrected confirm answered $status"
  EDITED=$(cat "$WORK/edited-issue.html")
  n=$(count_all "$EDITED" "Changed from your request")
  [[ "$n" -ge 1 ]] && pass "the issued page names what the operator changed (page-map §3's diff)" \
    || fail "an edited subject was signed without reporting the change"
  n=$(count_all "$EDITED" "Renamed By Smoke")
  [[ "$n" -ge 1 ]] && pass "the diff carries the edited value, not just a label" || fail "the diff omits the edited value"
fi

# =========================================================================== §14 nothing private in any response
echo "§14 No key material in any response (page-map §0)"
# The assertion is against PEM ARMOUR (`-----BEGIN ... PRIVATE KEY-----`), not against the phrase "PRIVATE KEY". The
# generate page legitimately NAMES the format -- "the key is returned as ENCRYPTED PRIVATE KEY" is documentation an
# operator needs -- and a check that forbids the words would either fail on honest prose or be loosened until it stops
# catching real leaks. What must never appear is armour.
# 0.2.0 added /about and /settings to this sweep: /settings is the page whose whole purpose is printing configuration, which
# is exactly the kind of page that leaks a path if nobody checks it from outside.
# 0.5.0 adds /inspect — but only as a plain GET, and that distinction is load-bearing. `/inspect` PASTED with a key renders
# `-----BEGIN PRIVATE KEY-----` TWICE on purpose (the armour lines stay so the operator can see which block was redacted; only
# the base64 body is replaced). Feeding a key paste to this sweep would fail a correct app, so §15 asserts the key case against
# the base64 lines in its own case and this loop stays a GET-only armour sweep.
for page in "/" "/csr/generate" "/csr/sign" "/ca" "/issued" "/about" "/inspect" "/settings" "/version"; do
  get "$page" "$WORK/probe.html" >/dev/null
  n=$(count_re "$(cat "$WORK/probe.html")" "-----BEGIN [A-Z ]*PRIVATE KEY-----")
  [[ "$n" == "0" ]] && pass "$page contains no private-key armour" || fail "$page contains private-key armour ($n occurrence(s))"
done

# =========================================================================== §15 /inspect reads a paste and refuses nothing
echo "§15 Inspect PEM (page-map §13)"
# The posture this section exists to hold: `/inspect` is a READER. It describes what a PEM says and refuses exactly one thing,
# an oversized body. Every other page in this app refuses input it dislikes; a page that never refuses has no error surface to
# assert on, so §15 asserts the opposite — that facts appear where a refusal used to be, and that the one refusal that does
# exist is mine rather than the framework's.
#
# The PEM pasted here is the harness's own CA download ($WORK/ca.crt, fetched in §9), which makes §15 self-referential in the
# useful direction: the bytes §9 asserted as a download and §9 asserted as an on-screen block are handed back to a THIRD page,
# and the answer has to agree with both. It also means no fixture is hard-coded here — a host whose CA is EC, or RSA-4096, or
# named differently, still passes, because the assertions below are about structure plus the rows §9 already proved.
status=$(get "/inspect" "$WORK/inspect-get.html")
[[ "$status" == "200" ]] && pass "GET /inspect answers 200" || fail "GET /inspect answered $status (expected 200)"
INSPECT_GET=$(cat "$WORK/inspect-get.html")
n=$(count_all "$INSPECT_GET" 'name="pem_paste"')
[[ "$n" == "1" ]] && pass "/inspect posts exactly one field, pem_paste ($n) — the whole page is one textarea" \
  || fail "/inspect's form fields are not the one documented field (pem_paste x$n)"
n=$(count_all "$INSPECT_GET" 'Nothing pasted yet')
[[ "$n" == "1" ]] && pass "/inspect says plainly that nothing has been pasted yet" || fail "/inspect renders no empty-state statement ($n)"
n=$(count_all "$INSPECT_GET" '<th scope="row">')
[[ "$n" == "0" ]] && pass "/inspect inventories no facts on an empty paste (no facts table, $n rows)" \
  || fail "/inspect fabricated $n fact row(s) out of an empty paste"
n=$(count_all "$INSPECT_GET" 'It does not verify a chain.')
[[ "$n" == "1" ]] && pass "/inspect states that it cannot verify a chain" || fail "/inspect no longer says it does not verify a chain ($n)"
n=$(count_all "$INSPECT_GET" 'It does not know about revocation.')
# The NEEDLE is unchanged and still true on 0.7.0 (inspect.html:32 reads exactly this); what was stale is the label, which
# said "no CRL, no OCSP" as if this host published neither. It publishes both now — /inspect just never consults either.
[[ "$n" == "1" ]] && pass "/inspect states that it consults nothing: it reports no CRL or OCSP answer even though this host now publishes both" \
  || fail "/inspect stopped naming the revocation gap ($n): a reader that implies 'valid' is worse than no reader"
n=$(count_all "$INSPECT_GET" 'Its findings are not gates.')
[[ "$n" == "1" ]] && pass "/inspect states that its findings are descriptions, not refusals" || fail "/inspect no longer says findings are not gates ($n)"
n=$(count_all "$INSPECT_GET" 'A private key is named and not opened.')
[[ "$n" == "1" ]] && pass "/inspect promises a pasted key will be named, not opened" || fail "/inspect no longer states the key posture ($n)"
# The nav has to reach this page from pages that existed before it, or the page does not exist in practice. Each page is
# checked separately (rather than /inspect's own render) because a nav that carried the link only on /inspect would pass a
# count taken from /inspect alone.
for pair in "/ $WORK/home.html" "/ca $WORK/ca.html" "/settings $WORK/settings.html"; do
  page=${pair%% *}
  file=${pair#* }
  if [[ -f "$file" ]]; then
    n=$(count_re "$(cat "$file")" 'class="nav-item[^"]*" href="/inspect"')
    [[ "$n" == "1" ]] && pass "$page's nav links to /inspect ($n)" || fail "$page's nav has no /inspect link ($n)"
  else
    warn "$page was not fetched earlier in this run, so its nav could not be checked for the /inspect link"
  fi
done
n=$(count_re "$(cat "$WORK/inspect-get.html")" 'class="nav-item active" href="/inspect"')
[[ "$n" == "1" ]] && pass "/inspect marks its own nav item active ($n)" || fail "/inspect's nav item is not marked active ($n)"

# --- a real certificate: the CA this harness runs on, read back off the download §9 already fetched.
if [[ -s "$WORK/ca.crt" ]]; then
  TOKEN=$(csrf_token "$WORK/inspect-get.html")
  if [[ -z "$TOKEN" ]]; then
    fail "/inspect's form carries no CSRF token — every §15 POST below would be untestable"
  else
    status=$(post_pem_field "/inspect" "$WORK/inspect-ca.html" "pem_paste" "$WORK/ca.crt" "csrf_token=$TOKEN")
    [[ "$status" == "200" ]] && pass "POST /inspect with a real CA certificate answers 200" || fail "POST /inspect answered $status (expected 200)"
    CA_READ=$(cat "$WORK/inspect-ca.html")
    n=$(count_all "$CA_READ" 'CA:TRUE pathLength:0')
    [[ "$n" == "1" ]] && pass "/inspect reads BasicConstraints out of the paste and renders it ($n)" \
      || fail "/inspect did not render the root's BasicConstraints CA:TRUE pathLength:0 ($n)"
    n=$(count_all "$CA_READ" 'self-signed root')
    [[ "$n" -ge 1 ]] && pass "/inspect names a self-signed root as a finding ($n)" \
      || fail "/inspect described a self-signed certificate without saying so ($n)"
    # Scoped on purpose. The lede legitimately contains `not a CA` as an EXAMPLE of what findings look like (MEASURED:
    # page-wide 1, findings block 0). Asserting page-wide absence would fail a correct app; asserting nothing at all would
    # let "not a CA" leak onto the host's own root.
    n=$(findings_count "$WORK/inspect-ca.html" 'not a CA')
    if [[ "$n" == "-1" ]]; then
      fail "/inspect rendered no findings block for a self-signed root, so 'not a CA' could not be scoped"
    elif [[ "$n" == "0" ]]; then
      pass "the host's own root is not called 'not a CA' inside its findings block ($n)"
    else
      fail "/inspect calls the host's root 'not a CA' inside the findings block ($n): the flag rules are wrong, not the wording"
    fi
    n=$(count_all "$CA_READ" 'class="findings"')
    [[ "$n" == "1" ]] && pass "a finding renders as class=\"findings\", not as a form error ($n)" \
      || fail "/inspect rendered findings as $n findings block(s): the amber/not-an-error distinction is gone"
    n=$(count_all "$CA_READ" 'class="form-errors"')
    [[ "$n" == "0" ]] && pass "/inspect reports nothing as a form error ($n) — it refused nothing, so there is nothing to fix" \
      || fail "/inspect wrote a finding into .form-errors ($n): that block promises 'fix this and submit again'"
    n=$(count_all "$CA_READ" 'id="pem-1"')
    [[ "$n" == "1" ]] && pass "/inspect echoes the parsed block as an addressable PEM block ($n)" || fail "/inspect echoed no PEM block with id pem-1 ($n)"
    n=$(count_all "$CA_READ" 'data-mypki-copy="pem-1"')
    [[ "$n" == "1" ]] && pass "/inspect wires the copy button to that block ($n)" || fail "/inspect's PEM block has no copy button wired to it"
    n=$(count_all "$CA_READ" 'SHA-256 of the DER')
    [[ "$n" == "1" ]] && pass "/inspect reports a SHA-256 of the DER it decoded ($n)" || fail "/inspect printed no hash of the bytes it parsed"
    # Byte parity, the same question §9 asks of /ca's block, asked of a THIRD rendering of the same certificate.
    # Scoped to the report block rather than handed straight to extract_pem, because MEASURED on the first live run:
    # /inspect's textarea carries a PLACEHOLDER that spells out `-----BEGIN CERTIFICATE----- … -----END CERTIFICATE-----`,
    # so the FIRST such pair on this page is an example, not the parsed block. Unscoped, this assertion hashed placeholder
    # text and reported a byte mismatch against a correct app — a harness bug, found by running the harness.
    sed -n '/<pre class="pem" id="pem-1">/,/<\/pre>/p' "$WORK/inspect-ca.html" > "$WORK/inspect-block.html"
    if [[ -s "$WORK/inspect-block.html" ]] && extract_pem "$WORK/inspect-block.html" "CERTIFICATE" > "$WORK/inspect-page.pem"; then
      PAGE_SHA=$(pem_sha "$WORK/inspect-page.pem")
      DL_SHA=$(pem_sha "$WORK/ca.crt")
      if [[ -n "$PAGE_SHA" && "$PAGE_SHA" == "$DL_SHA" ]]; then
        pass "the block /inspect echoed is the same bytes as the CA download ($PAGE_SHA)"
      else
        fail "/inspect's echoed block differs from /ca/certificate (page $PAGE_SHA vs download $DL_SHA)"
      fi
    else
      fail "/inspect echoed no extractable CERTIFICATE block to compare against the download"
    fi

    # --- a private key pasted by accident: named, redacted, and asserted against the BASE64, never against armour.
    # The sentinel body is not a key — it is fixed text whose base64 this script can name exactly. Asserting that two long
    # base64 lines are ABSENT is a leak test a real key could not be: with a real key there is no string to search for, so
    # the only honest version of this case uses material the harness wrote itself.
    SENTINEL="MYPKI-SMOKE-SENTINEL-PRIVATE-KEY-BODY-not-a-real-key-0123456789abcdef"
    { echo "-----BEGIN PRIVATE KEY-----"; printf '%s' "$SENTINEL" | base64 | fold -w 64; echo "-----END PRIVATE KEY-----"; } > "$WORK/sentinel.key"
    status=$(post_pem_field "/inspect" "$WORK/inspect-key.html" "pem_paste" "$WORK/sentinel.key" "csrf_token=$TOKEN")
    [[ "$status" == "200" ]] && pass "POST /inspect with a private key answers 200 (it refuses nothing, including this)" \
      || fail "POST /inspect with a key answered $status (expected 200 — this page does not refuse)"
    KEY_READ=$(cat "$WORK/inspect-key.html")
    n=$(count_all "$KEY_READ" 'private-key block(s) were in your paste')
    [[ "$n" == "1" ]] && pass "/inspect says out loud that it redacted a key ($n) — no quiet edit of what was pasted" \
      || fail "/inspect redacted a paste without saying so ($n): the quiet edit this project refuses elsewhere"
    n=$(count_all "$KEY_READ" 'redacted by mypki')
    [[ "$n" == "2" ]] && pass "the marker appears twice: once in the echoed paste, once naming itself ($n)" \
      || fail "/inspect's redaction marker appears $n time(s), expected 2"
    n=$(count_all "$KEY_READ" 'this is a private key. mypki did not open it')
    [[ "$n" == "1" ]] && pass "/inspect names the block as a key and says it was not opened ($n)" \
      || fail "/inspect did not name the pasted block as a private key ($n)"
    # THE leak assertion. Both wrapped base64 lines, searched for by name.
    LEAKED=0
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      [[ "$line" == -----* ]] && continue
      if [[ "$KEY_READ" == *"$line"* ]]; then fail "the pasted key's base64 came back verbatim: $line"; LEAKED=1; fi
    done < "$WORK/sentinel.key"
    n=$(count_re "$KEY_READ" '-----BEGIN [A-Z ]*PRIVATE KEY-----')
    if [[ "$LEAKED" == "0" ]]; then pass "no base64 body from the pasted key survives in the response (armour lines present x$n, by design)"; fi
    n=$(count_all "$KEY_READ" 'SHA-256 of the DER')
    [[ "$n" == "0" ]] && pass "/inspect hashed nothing it refused to read ($n) — no fingerprint for a key it never opened" \
      || fail "/inspect produced a hash for a private key it says it did not open ($n)"

    # --- the one refusal this page makes, and whose sentence it is.
    head -c 40000 /dev/zero | tr '\0' 'y' > "$WORK/big.txt"
    status=$(post_pem_field "/inspect" "$WORK/inspect-big.html" "pem_paste" "$WORK/big.txt" "csrf_token=$TOKEN")
    BIG=$(cat "$WORK/inspect-big.html")
    n=$(count_all "$BIG" 'MYPKI_MAX_CSR_CHARS')
    if [[ "$status" == "413" && "$n" -ge 1 ]]; then pass "an oversized paste answers 413 naming MYPKI_MAX_CSR_CHARS ($n)"; else fail "oversized /inspect paste: status $status (expected 413), knob named $n time(s)"; fi
    n=$(count_all "$BIG" 'Field exceeded maximum size')
    [[ "$n" == "0" ]] && pass "/inspect's size refusal is mypki's page, not starlette's JSON ($n)" \
      || fail "starlette's bare size error surfaced on /inspect instead of mypki's sentence"

    # --- a missing token: refused BEFORE the paste is read, so the paste never reaches the page.
    status=$(curl_base -b "$JAR" -c "$JAR" -o "$WORK/inspect-notoken.html" -w "%{http_code}" -X POST \
      --data-urlencode "pem_paste@$WORK/ca.crt" "$BASE/inspect")
    NOTOKEN=$(cat "$WORK/inspect-notoken.html")
    n=$(count_all "$NOTOKEN" 'CSRF')
    [[ "$status" == "400" && "$n" -ge 1 ]] && pass "/inspect refuses a tokenless POST at 400 naming CSRF ($n)" \
      || fail "/inspect with no token: status $status (expected 400), CSRF named $n time(s)"
    n=$(count_all "$NOTOKEN" '-----BEGIN CERTIFICATE-----')
    [[ "$n" == "0" ]] && pass "the rejected paste is not echoed back ($n) — a refusal is not an echo chamber" \
      || fail "/inspect echoed the pasted PEM on its CSRF refusal ($n)"

    # --- junk: described, not refused. This is the whole point of the page existing.
    printf 'hello world' > "$WORK/junk.txt"
    status=$(post_pem_field "/inspect" "$WORK/inspect-junk.html" "pem_paste" "$WORK/junk.txt" "csrf_token=$TOKEN")
    [[ "$status" == "200" ]] && pass "text with no PEM armour answers 200 rather than a refusal" || fail "junk paste answered $status (expected 200)"
    JUNK=$(cat "$WORK/inspect-junk.html")
    n=$(count_all "$JUNK" 'nothing readable')
    [[ "$n" -ge 1 ]] && pass "/inspect names junk as 'nothing readable' ($n) instead of refusing it" || fail "/inspect refused or ignored a junk paste ($n)"
    n=$(count_all "$JUNK" 'nothing to report')
    [[ "$n" -ge 1 ]] && pass "the finding says what is missing rather than 'invalid input' ($n)" || fail "/inspect's junk case carries no usable finding ($n)"
  fi
else
  warn "§9 left no CA download in $WORK, so /inspect's certificate, key and oversized cases were not exercised"
fi

# =========================================================================== §16 dropped extensions need consent (page-map §3 rule 6)
echo "§16 Dropped extensions need consent (page-map §3 rule 6)"
# The two CSRs below are written by openssl itself, not by this harness: `basicConstraints = CA:FALSE` and
# `keyUsage = digitalSignature, keyEncipherment` are what a distro `[v3_req]` puts into every request `openssl req`
# makes, which is the operator report this section exists for. Minting them here with openssl would need openssl on
# PATH; embedding the PEMs keeps §16 runnable anywhere the other fifteen sections run, and the bytes are a real
# openssl 3.x output rather than a hand-built approximation (their self-signatures verify: `openssl req -verify`).
{
  echo '-----BEGIN CERTIFICATE REQUEST-----'
  cat <<'PEM'
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
PEM
  echo '-----END CERTIFICATE REQUEST-----'
} > "$WORK/consent.csr"
{
  echo '-----BEGIN CERTIFICATE REQUEST-----'
  cat <<'PEM'
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
PEM
  echo '-----END CERTIFICATE REQUEST-----'
} > "$WORK/privileged.csr"

n=$(count_all "$(cat "$WORK/consent.csr")" "-----BEGIN CERTIFICATE REQUEST-----")
[[ "$n" == "1" ]] && pass "§16 wrote a well-formed openssl-default CSR ($(wc -c < "$WORK/consent.csr") bytes)" \
  || fail "the consent fixture is not a single PEM block ($n)"
n=$(count_all "$(cat "$WORK/privileged.csr")" "-----BEGIN CERTIFICATE REQUEST-----")
[[ "$n" == "1" ]] && pass "§16 wrote a well-formed CA-privileged CSR ($(wc -c < "$WORK/privileged.csr") bytes)" \
  || fail "the privileged fixture is not a single PEM block ($n)"

# --- STEP A: a request carrying ignorable extensions now reaches the panel instead of being refused at step 6.
get "/csr/sign" "$WORK/consent-form.html" >/dev/null
TOKEN=$(csrf_token "$WORK/consent-form.html")
status=$(post_pem "/csr/sign" "$WORK/consent-confirm.html" "$WORK/consent.csr" "csrf_token=$TOKEN")
[[ "$status" == "200" ]] \
  && pass "a CA:FALSE + keyUsage CSR reaches the confirmation panel at 200 (rule 6's ignorable half)" \
  || fail "the openssl-default CSR answered $status (expected 200, not a 403 refusal)"
CCONF=$(cat "$WORK/consent-confirm.html")
n=$(count_all "$CCONF" "BasicConstraints CA:FALSE")
[[ "$n" -ge 1 ]] && pass "the panel names BasicConstraints CA:FALSE as something it will not copy" \
  || fail "the confirmation panel omits the extension it is about to drop"
n=$(count_all "$CCONF" "KeyUsage (digitalSignature, keyEncipherment)")
[[ "$n" -ge 1 ]] && pass "the panel names both KeyUsage bits by name, not 'KeyUsage'" \
  || fail "the disclosure does not say which usage bits are being dropped"
n=$(count_re "$CCONF" '<input type="checkbox"[^>]*name="ignore_extensions"')
[[ "$n" == "1" ]] && pass "exactly one consent box is offered ($n)" \
  || fail "the consent control appears $n times (expected exactly 1)"
n=$(count_re "$CCONF" '<input type="checkbox"[^>]*name="ignore_extensions"[^>]*checked')
[[ "$n" == "0" ]] && pass "the consent box arrives UNTICKED — default OFF is markup, not a promise" \
  || fail "the consent box arrived pre-ticked, which would consent before anyone read the list"
n=$(count_all "$CCONF" 'class="checkbox-state state-off">off<')
[[ "$n" == "1" ]] && pass "the word beside the unticked box reads 'off' in the off colour ($n)" \
  || fail "the consent box's state word disagrees with the box next to it ($n)"
# The reverse case, which is what makes "no box" unambiguous: a CSR mypki generated itself (§5's output, carried
# through §6 and §13) has SAN and nothing else, so it must render no list and no box rather than an empty one.
# Asserted on its own step A POST rather than on §6's page, so this section does not depend on what earlier sections
# left in a variable — and staging a request signs nothing, so no ledger count moves here.
if [[ -s "$WORK/generated.csr" ]]; then
  get "/csr/sign" "$WORK/plain-form.html" >/dev/null
  PTOKEN=$(csrf_token "$WORK/plain-form.html")
  status=$(post_pem "/csr/sign" "$WORK/plain-confirm.html" "$WORK/generated.csr" "csrf_token=$PTOKEN")
  PLAIN=$(cat "$WORK/plain-confirm.html")
  n=$(count_all "$PLAIN" 'name="ignore_extensions"')
  [[ "$n" == "0" ]] && pass "a mypki-generated CSR renders no consent box at all (nothing to consent about)" \
    || fail "a request with no non-SAN extensions still offered a consent box ($n)"
  n=$(count_all "$PLAIN" 'class="provenance dropped-extensions"')
  [[ "$n" == "0" ]] && pass "and no empty dropped-extension block either ($n)" \
    || fail "the disclosure block rendered for a request that carried nothing to disclose"
else
  warn "§5 left no generated CSR in $WORK, so the no-consent-box case was not exercised"
fi

# --- STEP B, consent WITHHELD: an input to fix, not a refused request. 200, everything named, nothing signed.
PENDING=$(pending_id "$WORK/consent-confirm.html")
if [[ -z "$PENDING" ]]; then
  fail "step A staged no ?pending= id — the consent checks below cannot run"
else
  TOKEN=$(csrf_token "$WORK/consent-confirm.html")
  status=$(post_form "/csr/sign?pending=$PENDING" "$WORK/consent-unticked.html" \
    "csrf_token=$TOKEN" "confirm=1" "cert_type=server" "validity_days=30")
  [[ "$status" == "200" ]] && pass "confirming without the box answers 200, not 403 (nothing was refused)" \
    || fail "confirming without consent answered $status (expected 200 inline)"
  UNTICKED=$(cat "$WORK/consent-unticked.html")
  n=$(count_all "$UNTICKED" "consent to dropped extensions")
  [[ "$n" -ge 1 ]] && pass "the refusal names the decision that is missing" || fail "no consent reason on the unticked confirm"
  n=$(count_all "$UNTICKED" "KeyUsage (digitalSignature, keyEncipherment)")
  [[ "$n" -ge 1 ]] && pass "the unticked refusal lists every extension at stake" \
    || fail "the consent refusal says 'some extensions' without naming them"
  n=$(count_all "$UNTICKED" "Nothing was signed")
  [[ "$n" -ge 1 ]] && pass "the unticked refusal states plainly that nothing was signed" \
    || fail "an unticked box leaves it unclear whether a certificate was issued"
  n=$(count_re "$UNTICKED" '<h2>Issued:')
  [[ "$n" == "0" ]] && pass "no certificate card was rendered while consent was withheld ($n)" \
    || fail "consent was withheld and a certificate was issued anyway ($n)"
  # The staged request has to survive, under the SAME id: 'tick the box' is only fixable without re-pasting a PEM if
  # this page is still pointing at the request it is talking about.
  PENDING2=$(pending_id "$WORK/consent-unticked.html")
  [[ -n "$PENDING2" && "$PENDING2" == "$PENDING" ]] && pass "the staged request survives the unticked refusal (same ?pending= id)" \
    || fail "the unticked refusal lost the staged request (got ${PENDING2:-none}, expected $PENDING)"
  n=$(count_re "$UNTICKED" '<input type="checkbox"[^>]*name="ignore_extensions"')
  [[ "$n" == "1" ]] && pass "the re-rendered page offers the box again ($n) rather than a dead end" \
    || fail "the unticked refusal no longer offers a way to consent ($n)"

  # --- STEP B, consent GRANTED: issue, and name every dropped extension on the issued page.
  TOKEN=$(csrf_token "$WORK/consent-unticked.html")
  status=$(post_form "/csr/sign?pending=$PENDING" "$WORK/consent-issued.html" \
    "csrf_token=$TOKEN" "confirm=1" "cert_type=server" "validity_days=30" "ignore_extensions=true")
  [[ "$status" == "200" ]] && pass "confirming with the box issues at 200" || fail "confirming with consent answered $status"
  CISSUED=$(cat "$WORK/consent-issued.html")
  n=$(count_all "$CISSUED" "Issued: consent.lab.local")
  [[ "$n" -ge 1 ]] && pass "the certificate the operator consented to is the one that was issued" \
    || fail "no 'Issued: consent.lab.local' card after consent was granted"
  n=$(count_all "$CISSUED" "Changed from your request")
  [[ "$n" -ge 1 ]] && pass "a dropped extension lands in the same diff block as an edited name (page-map §3)" \
    || fail "the issued page signed a request with dropped extensions without reporting them"
  n=$(count_all "$CISSUED" "Extension not copied: BasicConstraints CA:FALSE")
  [[ "$n" == "1" ]] && pass "the diff names the dropped BasicConstraints ($n)" \
    || fail "the issued page does not name the dropped BasicConstraints ($n)"
  n=$(count_all "$CISSUED" "Extension not copied: KeyUsage (digitalSignature, keyEncipherment)")
  [[ "$n" == "1" ]] && pass "the diff names the dropped KeyUsage with its bits ($n)" \
    || fail "the issued page does not name the dropped KeyUsage ($n)"
  n=$(count_all "$CISSUED" "The public key and every extension still came from mypki")
  [[ "$n" -ge 1 ]] && pass "the diff closes by stating where the extensions actually came from" \
    || fail "the issued page omits where a dropped extension's replacement came from"
  # Consent changes what is *copied*, never what is *signed*: the staged PEM keeps its extensions (a CSR signature
  # covers them), so the only visible trace of the request's own BasicConstraints is on this diff block — and the
  # certificate itself has to read as mypki's profile. §10 already proved the artifact round trip; here the serial is
  # what proves a real leaf exists behind the card.
  CISSUED_SERIAL=$(issued_serial "$WORK/consent-issued.html")
  if [[ -z "$CISSUED_SERIAL" ]]; then
    fail "the consented signing rendered no leaf serial"
  else
    pass "the consented signing reports its own leaf serial (${CISSUED_SERIAL:0:12}…)"
  fi
fi

# --- A privilege claim is not a consent question, and ticking the box does not make it one.
get "/csr/sign" "$WORK/priv-form.html" >/dev/null
TOKEN=$(csrf_token "$WORK/priv-form.html")
status=$(post_pem "/csr/sign" "$WORK/priv-refused.html" "$WORK/privileged.csr" "csrf_token=$TOKEN" "ignore_extensions=true")
PRIV=$(cat "$WORK/priv-refused.html")
if [[ "$status" == "403" ]]; then pass "CA:TRUE is refused at 403 even with the consent field posted" \
  else fail "a CA-privileged CSR answered $status while carrying ignore_extensions=true (expected 403)"; fi
n=$(count_all "$PRIV" "BasicConstraints CA:TRUE")
[[ "$n" -ge 1 ]] && pass "the refusal names BasicConstraints CA:TRUE" || fail "the 403 omits the extension it refused"
n=$(count_all "$PRIV" "keyCertSign")
[[ "$n" -ge 1 ]] && pass "the refusal names keyCertSign" || fail "the 403 omits keyCertSign"
n=$(count_all "$PRIV" "crlSign")
[[ "$n" -ge 1 ]] && pass "the refusal names crlSign" || fail "the 403 omits crlSign"
# MEASURED wording: app.py's hint closes "… and dropped only when you tick the box there." An earlier draft of this needle
# read "only if you tick the box", which no build ever printed — it failed here against a correct 403 page, so the NEEDLE was
# the bug, not the page.
n=$(count_all "$PRIV" "you tick the box")
[[ "$n" -ge 1 ]] && pass "the hint now points at the consent box for the extensions that are ignorable" \
  || fail "the 403 gives no route to the half of rule 6 that is signable"
n=$(count_re "$PRIV" '<h2>Issued:')
[[ "$n" == "0" ]] && pass "refusing signed nothing ($n)" || fail "a refused privilege claim still produced a certificate card"

# =========================================================================== report

echo
echo "== summary: $PASS pass, $FAIL fail, $WARN warn =="
if (( ${#FAILURES[@]} > 0 )); then echo "FAILURES:"; for f in "${FAILURES[@]}"; do echo "  - $f"; done; fi
if (( ${#WARNINGS[@]} > 0 )); then echo "WARNINGS:"; for w in "${WARNINGS[@]}"; do echo "  - $w"; done; fi

if [[ -n "$REPORT" ]]; then
  {
    printf '# mypki smoke report\n\n'
    # 'base resolved from' is the answer an operator needs when a run reports NOTHING WAS CHECKED: it says which layer this
    # harness believed it was reading, so a wrong base is traceable to a file rather than to a guess. It lives here and not on
    # stdout because both logs start at line 1 with '§1 Home page' and SMOKE_TESTING.md records heading line numbers for them.
    printf 'base: %s\nbase resolved from: %s\nwork: %s\nexpected version: %s\nrun at: %s\n\n' \
      "$BASE" "$BASE_RESOLVED_FROM" "$WORK" "${EXPECTED_VERSION:-not determined}" "$(date -u +%FT%TZ)"
    printf 'summary: %d pass, %d fail, %d warn\n\n' "$PASS" "$FAIL" "$WARN"
    printf '%s' "$REPORT_BODY"
  } > "$REPORT"
  echo "report written to $REPORT"
fi

if (( FAIL > 0 )); then exit 1; fi
exit 0
