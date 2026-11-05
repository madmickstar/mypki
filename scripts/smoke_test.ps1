<#
.SYNOPSIS
  smoke_test.ps1 - automated walk of SMOKE_TESTING.md sections 1-16, with expectations asserted by the script
  instead of by eye.

.DESCRIPTION
  WHAT THIS IS
    Every manual step in SMOKE_TESTING.md, run in order against a live `mypki serve`, then reported (console + optional
    markdown file). It is the Windows counterpart of scripts/smoke_test.sh; both walk the same numbered document and both
    execute the same numbered checks in the same order, so a failure on either OS names the same step. No check COUNT is
    written into this file: both harnesses print their own from the summary line at the end of a run.

  WHY THE ASSERTIONS ARE NOT LINE COUNTS
    Select-String counts LINES. mypki's pages put several facts on one line and repeat others across lines, so "1" is the
    answer for a full table and for an empty <pre> alike depending on where the pattern sits - it never answers the real
    question, which is HOW MANY OCCURRENCES. Every count here is an occurrence count (Measure-Occurrence / Measure-Regex),
    and 0 is a FAIL wherever the honest expectation is at least one.

  WHY THE HTTP LAYER IS curl.exe AND NOT A CMDLET
    Header-level assertions (Content-Disposition, Cache-Control, CSP) are the point of sections 2 and 8, and they have to be
    read from the same client a browser would use. Invoke-WebRequest and Invoke-RestMethod normalise headers into a parsed
    dictionary, follow redirects, decode bodies, and add their own User-Agent - so the header this script exists to check is
    no longer the header the server sent (STYLE section 12). Every request here goes through real curl.exe with an argument
    ARRAY (`& curl.exe @args` -- the sigil takes the name WITHOUT `$`): no shell string is ever re-parsed, so a SAN
    containing `*` or a PEM containing newlines
    cannot be re-tokenised on the way to the wire.

  WHY ONE PART OF THIS USES .NET INSTEAD OF A REGEX CHAIN
    Extracting the generated CSR from the confirmation page means un-escaping HTML entities (`&lt;` -> `<`) that Jinja's
    autoescape deliberately added. Doing that with `-replace` is a chain of substitutions that silently mis-orders `&amp;` and
    produces a PEM that fails validation - which would read as "the sign page is broken" rather than "the harness is broken".
    [System.Net.WebUtility]::HtmlDecode is the framework's own decoder and gets the ordering right. Everything else stays
    PowerShell + curl.

  WHY THE SECTION MARK IS BUILT FROM A CODE POINT INSTEAD OF TYPED
    The section sign in every printed label comes from `[char]0x00A7`, not from a literal character in this file, so the
    source is pure ASCII. Windows PowerShell 5.1 decodes a .ps1 that has no byte-order mark using the system ANSI codepage,
    and a literal section sign would then arrive at the parser mangled: the headings would stop matching SMOKE_TESTING.md and
    smoke_test.sh, and "my harness prints garbage" versus "my harness works" would come down to three bytes at the start of
    the file that any editor can silently strip. A code point cannot be mangled by a codepage. pwsh 7 is unaffected either
    way; 5.1 is what a Windows operator who has installed nothing actually has.

  WHERE THIS LIVES, AND WHY THAT MATTERS
    scripts/smoke_test.ps1, tracked in git and deliberately NOT shipped in the sdist or wheel (pyproject's sdist `exclude`
    names `scripts`). An installed CA has no business carrying a curl harness; a source checkout does.

.PARAMETER Base
  Root URL of the running app. When it is omitted the server is FOUND rather than assumed, in mypki's own order:
  -Base > $env:BASE > MYPKI_HOST/MYPKI_PORT in the real environment > <config-dir>\mypki.env > .\.env >
  http://127.0.0.1:8443 (the last arm is mypki's own default, ASSIGNED on exactly one line - $defaultPort - and every other 8443 in
  this file is prose or an example). Layer precedence follows
  settingsfile.env_file_layers(), which returns ('.env', <config>/mypki.env) with the LATER entry winning, and
  paths.resolve_config_dir, which prefers MYPKI_CONFIG_DIR, then %APPDATA%\mypki, then $XDG_CONFIG_HOME/mypki, then ~/.config/mypki.
  Host and port resolve independently, because config.py's Settings.host and Settings.port are two fields with two defaults: a saved
  host with no saved port binds the default port, exactly as mypki would. A value config.py would reject (MYPKI_PORT=abc, MYPKI_PORT=0)
  is not used here either - it falls back to the default and the report header says which layer refused to answer.
  Before 0.5.2 this harness read only -Base and the literal, so an operator who saved a new port on /settings got "NOTHING WAS CHECKED:
  http://127.0.0.1:8443 is not answering" from a healthy server. The resolved base and the layer that won are written in the markdown
  report header, never on stdout before section 1.
  A WILDCARD HOST IS DIALLED AS LOOPBACK: MYPKI_HOST=0.0.0.0 (or ::) is a BIND address - it says "listen on every interface of this box",
  which is why config.py accepts it - and it is not an address anyone can connect to. MEASURED on Linux, curl happens to accept
  http://0.0.0.0:8591/ and reaches the server, so the defect is invisible there; on Windows it resolves through the route table and this
  harness's own reachability gate answers "NOTHING WAS CHECKED" from a healthy server, which is the exact failure this resolver exists to
  prevent. So the report header keeps spelling what the operator's file says, while the host this harness dials becomes 127.0.0.1 ([::1] for
  ::). An explicit -Base or $env:BASE is never rewritten: if you name an address, you mean that address.
  WHY THIS HALF IS PURE PowerShell WHILE THE .sh HALF USES ITS python3 HELPER: smoke_test.sh already shells out to python3 seven times
  for HTML entity decoding, so a dotenv reader costs it nothing; this file's own header promises "everything else stays PowerShell +
  curl", so the same chain is written in PowerShell instead. One rule expressed twice, deliberately - the two chains are mirrors of each
  other and must be edited together or they drift.

.PARAMETER Insecure
  Pass `-k` to curl for a TLS run whose certificate this machine does not trust yet. Without it a TLS smoke run reports
  "nothing was checked" (exit 2) rather than pretending every page failed.

.PARAMETER Work
  Directory for the downloaded pages, the cookie jar and the scratch CSRs. Default: a new directory under the temp path.

.PARAMETER Report
  Optional markdown file to write the full transcript to.

.PARAMETER Version
  Override the expected version string. Explicit wins, always. Otherwise it is read from src/mypki/__init__.py next to this
  script - the same anchored line hatchling reads. A literal in this file would be a second copy of a fact that has exactly
  one source, and it rots on the first release.

.EXAMPLE
  pwsh scripts\smoke_test.ps1                              # finds the server the way mypki would
  pwsh scripts\smoke_test.ps1 -Base https://localhost:8443 -Insecure
  $env:MYPKI_PORT = 8543; pwsh scripts\smoke_test.ps1      # a saved or exported port is FOUND, not guessed
  pwsh scripts\smoke_test.ps1 -Work C:\tmp\mypki-smoke -Report C:\tmp\report.md
  pwsh scripts\smoke_test.ps1 -Version 0.1.0

.OUTPUTS
  Exit codes (the repo's convention: "not checked" is NOT "checked and clean")
    0  every check passed (warnings allowed, and listed in the report)
    1  at least one FAIL - a real defect in what you are testing
    2  NOTHING WAS CHECKED: server unreachable, curl.exe missing, or bad usage. Never read this as a pass.
#>

[CmdletBinding()]
param(
    [string]$Base = '',
    [switch]$Insecure,
    [string]$Work = '',
    [string]$Report = '',
    [string]$Version = '',
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Rest
)

# --------------------------------------------------------------------------- which server to talk to (mypki's own precedence)

# The PowerShell mirror of smoke_test.sh's python3 resolver. It is deliberately a second implementation rather than a call into
# python: this file's header promises PowerShell + curl, and a harness that needs a second runtime to answer "where is my server"
# is a harness that cannot run on the machine an operator actually has (Windows PowerShell 5.1 with nothing installed).
function Resolve-MypkiBase {
    # mypki's own defaults - the ONLY place this file spells a port, matching config.py's Field defaults.
    $defaultHost = '127.0.0.1'
    $defaultPort = '8443'

    # The same shape settingsfile.read_saved_values parses: comments and blanks skipped, an `export ` prefix tolerated, a matching
    # pair of surrounding quotes dropped, a later line beating an earlier one. Keys are uppercased because pydantic-settings matches
    # env names case-insensitively and preserve_unmanaged compares them the same way.
    function Read-DotenvLayer([string]$path) {
        $values = @{}
        if (-not (Test-Path -LiteralPath $path)) { return $values }
        foreach ($line in @(Get-Content -LiteralPath $path -ErrorAction SilentlyContinue)) {
            $text = $line.Trim()
            if ($text -eq '' -or $text.StartsWith('#')) { continue }
            $match = [regex]::Match($text, '^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$')
            if (-not $match.Success) { continue }
            $name = $match.Groups[1].Value.ToUpperInvariant()
            $value = $match.Groups[2].Value.Trim()
            if ($value.Length -ge 2 -and $value.Substring(0, 1) -eq $value.Substring($value.Length - 1, 1) -and
                ($value.Substring(0, 1) -eq '"' -or $value.Substring(0, 1) -eq "'")) {
                $value = $value.Substring(1, $value.Length - 2)
            }
            $values[$name] = $value
        }
        return $values
    }

    # paths.resolve_config_dir from the outside: MYPKI_CONFIG_DIR, then %APPDATA%\mypki, then $XDG_CONFIG_HOME/mypki,
    # then ~/.config/mypki. PowerShell 5.1 has no $IsWindows, hence the same version test used for $Discard above.
    function Get-MypkiConfigDir {
        if ($env:MYPKI_CONFIG_DIR -and $env:MYPKI_CONFIG_DIR.Trim() -ne '') {
            # ExpandEnvironmentVariables handles a `%USERPROFILE%`-style value an operator may have typed into the shell;
            # Join-Path then appends one segment at a time so the result is correct on both platforms.
            return Join-Path ([System.Environment]::ExpandEnvironmentVariables($env:MYPKI_CONFIG_DIR.Trim())) ''
        }
        $onWindows = ($PSVersionTable.PSVersion.Major -lt 6) -or ($IsWindows)
        if ($onWindows -and $env:APPDATA -and $env:APPDATA.Trim() -ne '') {
            return Join-Path $env:APPDATA.Trim() 'mypki'
        }
        if (-not $onWindows -and $env:XDG_CONFIG_HOME -and $env:XDG_CONFIG_HOME.Trim() -ne '') {
            return Join-Path $env:XDG_CONFIG_HOME.Trim() 'mypki'
        }
        return Join-Path ([System.Environment]::GetFolderPath('UserProfile')) '.config\mypki'
    }

    function Test-MypkiHost([string]$value) { return (-not [string]::IsNullOrWhiteSpace($value)) -and ($value -notmatch '\s') }
    function Test-MypkiPort([string]$value) {
        if ([string]::IsNullOrWhiteSpace($value) -or $value -notmatch '^\d+$') { return $false }
        $number = [int]$value
        return ($number -ge 1) -and ($number -le 65535)
    }

    $configFile = Join-Path (Get-MypkiConfigDir) 'mypki.env'
    $layers = @(
        @('defaults', @{ MYPKI_HOST = $defaultHost; MYPKI_PORT = $defaultPort }),
        @('./.env', (Read-DotenvLayer './.env')),
        @($configFile, (Read-DotenvLayer $configFile)),
        @('the environment', @{
            MYPKI_HOST = if ($env:MYPKI_HOST) { $env:MYPKI_HOST.Trim() } else { '' }
            MYPKI_PORT = if ($env:MYPKI_PORT) { $env:MYPKI_PORT.Trim() } else { '' }
        })
    )

    # Weakest first, each layer beating the last - settingsfile.env_file_layers() is ('.env', <config>/mypki.env) with the LATER
    # entry winning, and a real environment variable measured to beat both files. Host and port are resolved in separate passes
    # because config.py resolves two independent fields.
    $winnerHost = @($defaultHost, 'defaults')
    $winnerPort = @($defaultPort, 'defaults')
    foreach ($layer in $layers) {
        $name = $layer[0]
        $values = $layer[1]
        $hostValue = ''
        $portValue = ''
        if ($values.ContainsKey('MYPKI_HOST')) { $hostValue = [string]$values['MYPKI_HOST'] }
        if ($values.ContainsKey('MYPKI_PORT')) { $portValue = [string]$values['MYPKI_PORT'] }
        if (Test-MypkiHost $hostValue) {
            $winnerHost = @($hostValue, $name)
        } elseif (-not [string]::IsNullOrWhiteSpace($hostValue)) {
            $winnerHost = @($defaultHost, "$name (MYPKI_HOST='$hostValue' does not validate)")
        }
        if (Test-MypkiPort $portValue) {
            $winnerPort = @($portValue, $name)
        } elseif (-not [string]::IsNullOrWhiteSpace($portValue)) {
            $winnerPort = @($defaultPort, "$name (MYPKI_PORT='$portValue' does not validate)")
        }
    }

    # A wildcard is a bind address, not a reachable one. `MYPKI_HOST=0.0.0.0` is how an operator says "answer on every interface of
    # this box", and config.py accepts it for exactly that reason - but nothing can dial it. MEASURED on Linux: curl accepts
    # http://0.0.0.0:8591/ and connects, so the failure is invisible here; on Windows the same base resolves through the route table and
    # the reachability gate below reports "NOTHING WAS CHECKED" from a healthy server (and a client that prefers IPv6 dials ::1 against an
    # IPv4-only bind). The layer note therefore keeps spelling what the operator's file says, and only the host THIS harness dials becomes
    # loopback - the same process, on the machine running this script.
    $wildcardToLoopback = @{ '0.0.0.0' = '127.0.0.1'; '::' = '[::1]'; '[::]' = '[::1]' }
    $probeHost = $winnerHost[0]
    $dialNote = ''
    if ($wildcardToLoopback.ContainsKey($winnerHost[0])) {
        $probeHost = $wildcardToLoopback[$winnerHost[0]]
        $dialNote = " (host '$($winnerHost[0])' is what mypki binds, not an address to dial: probing '$probeHost')"
    }

    $layerNote = $winnerHost[1]
    if ($winnerHost[1] -ne $winnerPort[1]) {
        $layerNote = "host from $($winnerHost[1]); port from $($winnerPort[1])"
    }
    return @{ url = "http://$($probeHost):$($winnerPort[0])"; layer = "$layerNote$dialNote" }
}

# --------------------------------------------------------------------------- options

# `$Base` starts empty rather than carrying the default in the signature, so the precedence order is visible as code:
# parameter > $env:BASE > the dotenv layers mypki itself reads > literal. A default written in the param block would outrank every
# layer below it and make `set BASE=...` - or a port saved on /settings - silently do nothing.
$BaseResolvedFrom = ''
if ([string]::IsNullOrWhiteSpace($Base)) {
    if ($env:BASE) {
        $Base = $env:BASE
        $BaseResolvedFrom = '-Base/$env:BASE (explicit)'
    } else {
        $resolved = Resolve-MypkiBase
        $Base = $resolved['url']
        $BaseResolvedFrom = $resolved['layer']
    }
} else {
    $BaseResolvedFrom = '-Base (explicit)'
}
if ([string]::IsNullOrWhiteSpace($Work)) { $Work = if ($env:WORK) { $env:WORK } else { '' } }
if ([string]::IsNullOrWhiteSpace($Version)) { $Version = if ($env:MYPKI_EXPECTED_VERSION) { $env:MYPKI_EXPECTED_VERSION } else { '' } }

$BaseExtra = @()
if ($Insecure) { $BaseExtra = @('-k') }

# Leftover tokens are collected explicitly so an unknown switch is reported by THIS script with usage and exit 2, rather
# than by PowerShell's binder with a ParameterArgumentError and exit 1 - which would look to a reader like "a check failed".
if ($Rest -and $Rest.Count -gt 0) {
    Write-Host "unknown argument: $($Rest -join ' ')"
    Write-Host 'usage: smoke_test.ps1 [-Base URL] [-Insecure] [-Work DIR] [-Report FILE] [-Version X.Y.Z]'
    exit 2
}

# --------------------------------------------------------------------------- reachability gate: exit 2, never 0

# Resolved by name rather than hard-coded, and `curl.exe` first because that is the binary Windows ships. pwsh 7 runs on
# Linux and macOS as well, where the same program is spelled `curl`; a hard-coded `.exe` made this harness report "nothing was
# checked" (exit 2) on a machine that has curl installed and a healthy server running -- which is the one answer this script
# exists never to give. The chosen path is printed below so a reader can see which binary every assertion went through.
$curl = Get-Command curl.exe -ErrorAction SilentlyContinue
if (-not $curl) { $curl = Get-Command curl -ErrorAction SilentlyContinue }
if (-not $curl) {
    Write-Host 'NOTHING WAS CHECKED: neither curl.exe nor curl is installed (Windows 10 1803+ ships curl.exe).'
    exit 2
}
$script:CurlBin = $curl.Source

if ([string]::IsNullOrWhiteSpace($Work)) {
    $guid = [System.Guid]::NewGuid().ToString('N').Substring(0, 8)
    $Work = Join-Path ([System.IO.Path]::GetTempPath()) "mypki-smoke.$guid"
}
try {
    if (-not (Test-Path -LiteralPath $Work)) { New-Item -ItemType Directory -Path $Work -Force | Out-Null }
} catch {
    Write-Host "NOTHING WAS CHECKED: cannot create $Work."
    exit 2
}

$Jar = Join-Path $Work 'cookies.txt'
if (Test-Path -LiteralPath $Jar) { Remove-Item -LiteralPath $Jar -Force }

# Where curl sends a body when only the headers are wanted. `NUL` is the Windows discard target; on a non-Windows pwsh 7 run
# it would become a file literally named NUL, which is why this is chosen per platform rather than hard-coded. (Windows
# PowerShell 5.1 has no $IsWindows automatic variable, hence the version test - 5.1 only ever runs on Windows.)
$Discard = '/dev/null'
if ($PSVersionTable.PSVersion.Major -lt 6 -or $IsWindows) { $Discard = 'NUL' }

# --------------------------------------------------------------------------- version from the single source of truth

$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
# Joined one segment at a time so it resolves on both platforms. A single literal `'src\mypki\__init__.py'` is fine on Windows
# and stays a backslash-riddled string on Linux/macOS, where `Test-Path` then fails and the harness silently loses its expected
# version (which sections 3 and 12 skip rather than fail on).
$VersionFile = Join-Path (Join-Path (Join-Path (Split-Path -Parent $ScriptDir) 'src') 'mypki') '__init__.py'
if ([string]::IsNullOrWhiteSpace($Version) -and (Test-Path -LiteralPath $VersionFile)) {
    # The same anchored pattern check_version.py and hatchling use. Anchored, so a commented-out or single-quoted line
    # cannot be read as the version and then reported against a server that is honestly reporting something else.
    $found = Select-String -LiteralPath $VersionFile -Pattern '^__version__ = "([^"]+)"$' | Select-Object -First 1
    if ($found) { $Version = $found.Matches[0].Groups[1].Value }
}

try {
    # The argument array is built into a variable before it is splatted, and the splat sigil takes the variable NAME
    # without its `$`: `@probeArgs`, never `@$probeArgs`. **MEASURED on a real Windows 10 host:** with the `$` spelled in,
    # PowerShell did not splat at all - it passed curl ONE argument, `@-fsS -o NUL http://127.0.0.1:8443/`, and curl read
    # the leading `@` as "read options from this file": `curl: option @-fsS ...: error encountered when reading a file`
    # (reproduced verbatim with curl 8 on Linux). The script then reported a live, browser-reachable server as
    # "not answering". A wrong splat is therefore indistinguishable from a dead server unless the exit code separates them.
    $probeArgs = @('-fsS') + $BaseExtra + @('-o', $Discard, "$Base/")
    & $script:CurlBin @probeArgs | Out-Null
} catch {
    Write-Host "NOTHING WAS CHECKED: cannot run $script:CurlBin ($($_.Exception.Message))."
    exit 2
}
if ($LASTEXITCODE -ne 0) {
    # curl's own exit codes say WHY the probe failed, and the two answers are opposite: 7 (and 28) mean the server did
    # not answer; 2 means curl could not parse what THIS script handed it. Collapsing both into "the server is not
    # answering" sends an operator to check a healthy server - which is exactly what happened on the first real Windows
    # run, where the browser reached the page while this harness blamed the server for its own bad arguments.
    if ($LASTEXITCODE -eq 2) {
        Write-Host "HARNESS BUG: $script:CurlBin rejected this script's own arguments (curl exit 2), not a server failure."
        Write-Host "  The probe argv was: $($probeArgs -join ' ')"
    } else {
        Write-Host "NOTHING WAS CHECKED: $Base is not answering (curl exit $LASTEXITCODE). Start it with:"
        Write-Host '    mypki serve            # then re-run this script'
    }
    Write-Host 'Exit 2 means "no assertions ran", not "everything passed".'
    exit 2
}

# --------------------------------------------------------------------------- report plumbing

$script:Pass = 0
$script:Fail = 0
$script:Warn = 0
$script:Failures = New-Object 'System.Collections.Generic.List[string]'
$script:Warnings = New-Object 'System.Collections.Generic.List[string]'
$script:ReportBody = New-Object System.Text.StringBuilder

# The section sign, built from its code point so this file stays pure ASCII (see the .DESCRIPTION note above). Every label
# below is printed as `SectionMark + '1 Home page ...'`, which renders identically to scripts/smoke_test.sh's headings.
$script:SectionMark = [string][char]0x00A7

function Emit([string]$line) {
    [void]$script:ReportBody.AppendLine($line)
    Write-Host $line
}
function Add-Pass([string]$message) { $script:Pass++; Emit "  PASS  $message" }
function Add-Warn([string]$message) {
    $script:Warn++
    $script:Warnings.Add($message)
    Emit "  WARN  $message"
}
function Add-Fail([string]$message) {
    $script:Fail++
    $script:Failures.Add($message)
    Emit "  FAIL  $message"
}

# Occurrence counting, never line counting. IndexOf stepping is the honest form for a literal needle; [regex]::Matches is used
# where the needle is a pattern. Both return 0 rather than throwing on an empty haystack, because a harness that dies mid-
# count reports "no matches" through the exception path and a leak then reads as clean.
function Measure-Occurrence {
    param([string]$Haystack, [string]$Needle)
    if ([string]::IsNullOrEmpty($Haystack) -or [string]::IsNullOrEmpty($Needle)) { return 0 }
    $count = 0
    $index = 0
    while ($true) {
        $index = $Haystack.IndexOf($Needle, $index, [System.StringComparison]::Ordinal)
        if ($index -lt 0) { break }
        $count++
        $index += $Needle.Length
    }
    return $count
}

function Measure-Regex {
    param([string]$Haystack, [string]$Pattern)
    if ([string]::IsNullOrEmpty($Haystack)) { return 0 }
    try {
        return ([regex]::Matches($Haystack, $Pattern)).Count
    } catch {
        # A bad pattern is a bug in THIS file. Returning 0 would report every assertion that uses it as "no matches", i.e. a
        # leak reported as clean - so the harness says so out loud and fails the count instead.
        Add-Fail "measure-regex: unusable pattern $Pattern ($($_.Exception.Message))"
        return -1
    }
}

# --------------------------------------------------------------------------- request helpers

# The array is the whole point of this helper: it exists to inject $BaseExtra into every call, and a body that names only
# $BaseExtra silently discards the caller's arguments - curl then reports "no URL specified", every request fails, and a
# healthy server is reported as 40 failures. Mutation check: delete $CurlArgs from the concatenation and this script fails
# everywhere at once.
function Invoke-Curl {
    param([string[]]$CurlArgs)
    $all = @('-sS') + $script:BaseExtra + $CurlArgs
    # `$script:CurlBin`, not a literal `curl.exe`: the reachability gate resolved which binary this host actually has, and
    # calling a hard-coded name here would re-introduce the exact failure that gate exists to prevent.
    return (& $script:CurlBin @all)
}

# curl writes the `-w` text to stdout, and when a body leaks through it arrives as an ARRAY of lines. Comparing an array
# against '200' is always False, which reports a working server as broken; joining first removes that whole class of bug.
function Get-Page {
    param([string]$Path, [string]$OutFile)
    $all = @('-b', $script:Jar, '-c', $script:Jar, '-o', $OutFile, '-w', '%{http_code}', "$($script:Base)$Path")
    $raw = Invoke-Curl -CurlArgs $all
    return (($raw | ForEach-Object { [string]$_ }) -join '').Trim()
}

function Read-Body {
    param([string]$OutFile)
    if (-not (Test-Path -LiteralPath $OutFile)) { return '' }
    # -Raw is required: without it Get-Content returns an ARRAY of lines, and every occurrence count below would be a count
    # of line objects rather than a count of occurrences in the document.
    return Get-Content -LiteralPath $OutFile -Raw -Encoding UTF8
}

# `-Form` (multipart) is used for ordinary single-line fields and urlencoded for anything multi-line. The reason is a trap in
# curl itself: `--form 'name=<text containing newlines>'` submits only the FIRST line of that text. A PEM CSR posted with
# -Form therefore arrives truncated to its BEGIN line, mypki correctly answers "not valid base64", and the failure reads as a
# bug in the sign page when it is a bug in the harness. (The `sans` field below does carry a newline on purpose: it is what
# proves mypki splits a multi-line textarea rather than reading only its first line.)
function Send-Form {
    param([string]$Path, [string]$OutFile, [string[]]$Fields)
    $all = @('-b', $script:Jar, '-c', $script:Jar, '-o', $OutFile, '-w', '%{http_code}', '-X', 'POST')
    foreach ($field in $Fields) { $all += @('-F', $field) }
    $all += "$($script:Base)$Path"
    $raw = Invoke-Curl -CurlArgs $all
    return (($raw | ForEach-Object { [string]$_ }) -join '').Trim()
}

function Send-Pem {
    param([string]$Path, [string]$OutFile, [string]$CsrFile, [string[]]$Fields)
    $all = @('-b', $script:Jar, '-c', $script:Jar, '-o', $OutFile, '-w', '%{http_code}', '-X', 'POST')
    foreach ($field in $Fields) { $all += @('--data-urlencode', $field) }
    # `@file` is curl's own "read this field from a file" form: the bytes never pass through PowerShell's parser at all, so
    # no quoting rule can corrupt a PEM on the way out.
    $all += @('--data-urlencode', "csr_pem@$CsrFile")
    $all += "$($script:Base)$Path"
    $raw = Invoke-Curl -CurlArgs $all
    return (($raw | ForEach-Object { [string]$_ }) -join '').Trim()
}

# 0.5.0 (section 15): the same request shape as Send-Pem with the FIELD NAME spelled out, because `/inspect` posts
# `pem_paste` while Send-Pem hard-codes `csr_pem@$CsrFile`. `--data-urlencode name@file` is what keeps a multi-line PEM
# intact; Send-Form's -F truncates it at the first newline (see the comment above Send-Form), so a section 15 written with
# Send-Form would test "does curl mangle a PEM" rather than "does /inspect read one".
function Send-PemField {
    param([string]$Path, [string]$OutFile, [string]$FieldName, [string]$PemFile, [string[]]$Fields)
    $all = @('-b', $script:Jar, '-c', $script:Jar, '-o', $OutFile, '-w', '%{http_code}', '-X', 'POST')
    foreach ($field in $Fields) { $all += @('--data-urlencode', $field) }
    $all += @('--data-urlencode', ($FieldName + '@' + $PemFile))
    $all += "$($script:Base)$Path"
    $raw = Invoke-Curl -CurlArgs $all
    return (($raw | ForEach-Object { [string]$_ }) -join '').Trim()
}

function Get-CsrfToken {
    param([string]$PageFile)
    $page = Read-Body $PageFile
    $match = [regex]::Match($page, 'name="csrf_token" value="([^"]*)"')
    if (-not $match.Success) { return '' }
    return $match.Groups[1].Value
}

# The leaf serial from the issued card, scoped to that card on purpose (the counterpart of scripts/smoke_test.sh's
# `issued_serial`). `/csr/sign` and `/` also render the CA facts strip, whose serial cell is spelled IDENTICALLY
# (`<td class="mono">...`), so a page-wide search returns the **CA's** serial and every later assertion silently compares the
# store against the wrong certificate. MEASURED: it did exactly that in tests/test_views.py ('3432f851...' != '21adb4d3...').
# Anchoring on `<h2>Issued:` is what scopes it; Singleline `.*?` covers the 0.2.0 "Changed from your request" block that can
# sit between the heading and the serial row.
function Get-IssuedSerial {
    param([string]$PageFile)
    $match = [regex]::Match((Read-Body $PageFile), '<h2>Issued:.*?<td class="mono">([0-9a-f]{8,})<', [System.Text.RegularExpressions.RegexOptions]::Singleline)
    if (-not $match.Success) { return '' }
    return $match.Groups[1].Value
}

# The serial a row's Revoke control carries. Read from the hidden input rather than from the visible cell, because the input is
# what the POST actually submits: asserting against the displayed value would pass even if the form dropped it.
function Get-RowSerial {
    param([string]$PageFile)
    $match = [regex]::Match((Read-Body $PageFile), 'name="serial_hex" value="([0-9a-f]+)"')
    if (-not $match.Success) { return '' }
    return $match.Groups[1].Value
}

# The staged request's opaque id, from the confirm form's action URL. It is BASE64URL (`secrets.token_urlsafe(32)`), not hex --
# a `[0-9a-f]+` class here fails against a perfectly correct page, which is how tests/test_views.py first mis-read it (MEASURED
# id: 'Rbsz2sme4d-8tBnoF3Eih4-sA-aXrHNN4y5kzvdkCX0', 43 characters).
function Get-PendingId {
    param([string]$PageFile)
    $match = [regex]::Match((Read-Body $PageFile), 'action="/csr/sign\?pending=([^"]+)"')
    if (-not $match.Success) { return '' }
    return $match.Groups[1].Value
}

function Get-HeadersOf {
    param([string]$Path)
    # Two deliberate choices. (1) GET, not `curl -I` / `-X HEAD`: mypki declares GET-only routes, so HEAD answers 405 with
    # FastAPI's JSON body and the headers asserted would be the 405 response's - present, but describing a request that never
    # happened. (2) `-D <file>`, not `-D -`: curl styles a header dump differently depending on whether stdout is a console,
    # and those styling bytes land inside the strings counted below, so a header that IS present can be reported missing.
    $headerFile = Join-Path $script:Work 'headers.txt'
    $all = @('-b', $script:Jar, '-o', $Discard, '-D', $headerFile, "$($script:Base)$Path")
    Invoke-Curl -CurlArgs $all | Out-Null
    return Read-Body $headerFile
}

# --------------------------------------------------------------------------- 0.7.0 helpers (section 11): DER read and written
# without a DER parser - the mirror of scripts/smoke_test.sh's block of the same name. They are edited together on purpose:
# one rule, expressed twice, so neither harness can drift into asserting something the other no longer does.
#
# [Convert]::FromBase64String turns the CRL's armour into bytes, [System.IO.File]::ReadAllBytes turns bytes into the lowercase
# hex every assertion below searches, and WriteAllBytes writes a request back out. That is the whole toolkit: no openssl (plan
# U7 makes openssl a permanent outsider in this harness, which exists to run where no toolchain is installed) and no ASN.1
# code in a shell script, which would be a second, worse DER parser to maintain. The .sh half carries a dash caveat for its
# byte printer; PowerShell has no equivalent trap - ReadAllBytes/WriteAllBytes are bytes on every OS.
function Get-DerHexFromFile {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return '' }
    (([System.IO.File]::ReadAllBytes($Path) | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Get-CrlPemDerHex {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return '' }
    $match = [regex]::Match((Read-Body $Path), '-----BEGIN X509 CRL-----(.*?)-----END X509 CRL-----', [System.Text.RegularExpressions.RegexOptions]::Singleline)
    if (-not $match.Success) { return '' }
    try {
        (([Convert]::FromBase64String(($match.Groups[1].Value -replace '\s', '')) | ForEach-Object { $_.ToString('x2') }) -join '')
    } catch {
        Add-Fail "Get-CrlPemDerHex: cannot base64-decode the CRL in $Path ($($_.Exception.Message))"
        return ''
    }
}

# The DER INTEGER content of a serial, exactly as `cryptography` writes it: leading zeros stripped, even length restored, and a
# 0x00 prepended when the top bit of the leading byte is set (otherwise an INTEGER reads as negative). MEASURED with
# cryptography's own OCSPRequestBuilder: serial 0xff -> '02 02 00 ff', 0x8000 -> '02 03 00 80 00', and a real 159-bit random
# serial -> '02 21 00 ...'. Getting this wrong answers UNKNOWN for a certificate that exists, which is the worst way for an
# OCSP check to be wrong. Byte-identical to scripts/smoke_test.sh's der_integer_hex by construction.
function Get-DerIntegerHex {
    param([string]$SerialHex)
    $digits = ([string]$SerialHex).ToLower() -replace '^0+', ''
    if ($digits -eq '') { $digits = '0' }
    if (($digits.Length % 2) -ne 0) { $digits = '0' + $digits }
    if ('89abcdef'.IndexOf($digits.Substring(0, 1)) -ge 0) { $digits = '00' + $digits }
    return $digits
}

# One complete OCSP request as hex, spelled the way both `cryptography`'s OCSPRequestBuilder and `openssl ocsp -reqout` spell
# it: five nested SEQUENCE wrappers with content lengths L5+8, L5+6, L5+4, L5+2, L5 (where L5 is the CertID itself: 11 for
# AlgorithmID+Parameters, 22+22 for the two OCTET STRING hashes, 2+len for the serial INTEGER), then the SHA-1 AlgorithmID
# '30 09 06 05 2b 0e 03 02 1a 05 00', two 20-byte hashes, and the serial.
# THE HASHES ARE ZEROED ON PURPOSE. This responder echoes them without verifying them (risk R-OCSP-1: it stores no certificate
# bytes and cannot recompute a SHA-256 issuerKeyHash), so the answer depends only on the SERIAL - which is exactly what these
# assertions are about, and it keeps this harness free of any need to hash the scratch CA. MEASURED in plan 2: every explicit
# [1]/[2]/[3]-tagged CertID spelling FAILS to parse; do not "improve" this shape by hand-tagging anything. A request built this
# way is byte-identical to what a real client sends apart from the hash bytes.
function Get-OcspRequestDerHex {
    param([string]$SerialHex)
    $value = Get-DerIntegerHex $SerialHex
    $len = [int]($value.Length / 2)
    $l5 = 11 + 22 + 22 + 2 + $len
    $zeros = '00' * 20
    $out = ''
    foreach ($content in @(($l5 + 8), ($l5 + 6), ($l5 + 4), ($l5 + 2), $l5)) { $out += '30' + $content.ToString('x2') }
    $out += '300906052b0e03021a0500'
    $out += '0414' + $zeros + '0414' + $zeros
    $out += '02' + $len.ToString('x2') + $value
    return $out
}

function Write-DerBytesFromHex {
    param([string]$Hex, [string]$OutFile)
    $bytes = New-Object byte[] ([int]($Hex.Length / 2))
    for ($i = 0; $i -lt $Hex.Length; $i += 2) { $bytes[[int]($i / 2)] = [Convert]::ToInt32($Hex.Substring($i, 2), 16) }
    [System.IO.File]::WriteAllBytes($OutFile, $bytes)
}

# Raw-DER POST - the shape a protocol client posts. The optional header dump is what section 11's two ANSWER checks read; the
# three refusal posts never ask for one and must not touch $Work/headers.txt, which Get-HeadersOf owns. '-D <file>' rather than
# '-D -' for the reason Get-HeadersOf spells out (a styled header dump injects escape bytes into the strings being counted).
function Send-Der {
    param([string]$Path, [string]$OutFile, [string]$BodyFile, [string]$MediaType, [string]$HeaderDumpFile)
    $all = @('-b', $script:Jar, '-c', $script:Jar, '-o', $OutFile, '-w', '%{http_code}', '-X', 'POST')
    if (-not [string]::IsNullOrWhiteSpace($HeaderDumpFile)) { $all += @('-D', $HeaderDumpFile) }
    $all += @('--data-binary', ('@' + $BodyFile))
    $all += @('-H', ('Content-Type: ' + $MediaType))
    $all += "$($script:Base)$Path"
    $raw = Invoke-Curl -CurlArgs $all
    return (($raw | ForEach-Object { [string]$_ }) -join '').Trim()
}

# What follows the request's own serial INTEGER inside a response body. This is where CertStatus lives, and its POSITION moves
# with the CA key size (MEASURED with a 3072-bit harness CA: 84 -> 1778 bytes for UNKNOWN, 87 -> 1781 GOOD, 87 -> 1805 REVOKED,
# 146 -> 1841/1863 with SHA-256 + nonce), so an absolute offset would be a measurement of one CA key pretending to be a protocol
# rule. Anchoring on the serial field is what makes this portable. Empty string when the serial is not in the body at all, which
# the caller turns into a FAIL naming that fact rather than a status mismatch.
function Get-AfterSerialHex {
    param([string]$Hex, [string]$ValueHex, [int]$Window)
    $field = '02' + ([int]($ValueHex.Length / 2)).ToString('x2') + $ValueHex
    $at = $Hex.IndexOf($field, [System.StringComparison]::Ordinal)
    if ($at -lt 0) { return '' }
    $rest = $Hex.Substring($at + $field.Length)
    if ($Window -gt 0 -and $rest.Length -gt $Window) { return $rest.Substring(0, $Window) }
    return $rest
}

# Occurrence counting ACROSS a wrapped line, the mirror of scripts/smoke_test.sh's count_joined: a template that re-wraps a
# sentence changes the exact bytes a literal needle needs without changing the sentence. Measure-Regex with '\s+' would work
# for one sentence and silently stop working on the next; joining newlines first is the same normalisation
# Write-SettingsFormBody already applies to tags for the same reason.
function Measure-Joined {
    param([string]$PageFile, [string]$Needle)
    if (-not (Test-Path -LiteralPath $PageFile -PathType Leaf)) { return 0 }
    $text = ((Read-Body $PageFile) -replace '\r?\n\s*', ' ')
    return (Measure-Occurrence $text $Needle)
}


# --------------------------------------------------------------------------- section 5 helper: HTML <pre> back to PEM

function Extract-Pem {
    param([string]$PageFile, [string]$Marker)
    # HtmlDecode before slicing, not after: unescaping the whole page first is what keeps `&amp;lt;` from being decoded twice
    # into a character that was never there (the same ordering trap the bash counterpart avoids with Python's html module).
    $text = [System.Net.WebUtility]::HtmlDecode((Read-Body $PageFile))
    $pattern = '-----BEGIN ' + $Marker + '-----.*?-----END ' + $Marker + '-----'
    $match = [regex]::Match($text, $pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
    if (-not $match.Success) { return $null }
    return $match.Value
}
# --------------------------------------------------------------------------- 0.5.0 helper: a PEM file's certificate bytes hashed
#
# Hashes the DER inside a PEM file rather than the text of the file, for the same reason scripts/smoke_test.sh's pem_sha
# exists: the page copy arrives through an HTML decoder and the download through curl, their trailing-newline handling
# differs, and a text comparison would report a difference that is only a newline. This asks "is this the same
# certificate?" and answers it the same way on both sides.
function Get-PemDerSha {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return '' }
    $body = Read-Body $Path
    $match = [regex]::Match($body, '-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----', [System.Text.RegularExpressions.RegexOptions]::Singleline)
    if (-not $match.Success) { return '' }
    try {
        $der = [Convert]::FromBase64String(($match.Groups[1].Value -replace '\s', ''))
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            ((($sha.ComputeHash($der)) | ForEach-Object { $_.ToString('x2') }) -join '')
        } finally {
            $sha.Dispose()
        }
    } catch {
        Add-Fail "Get-PemDerSha: cannot decode the certificate in $Path ($($_.Exception.Message))"
        return ''
    }
}

# --------------------------------------------------------------------------- 0.5.0 helper: where a string first appears
#
# Position, not presence -- the mirror of scripts/smoke_test.sh's offset_of, for the same reason: every needle in the
# "what this host is running" card was already on /about, so a presence check could not see the card being moved.
# -1 means absent and the CALLER has to handle it; comparing -1 with a real offset would otherwise pass an assertion
# about a heading that disappeared. Ordinal matching, like Measure-Occurrence, so no culture rules shift an index.
function Get-OffsetOf {
    param([string]$Haystack, [string]$Needle)
    if ([string]::IsNullOrEmpty($Haystack) -or [string]::IsNullOrEmpty($Needle)) { return -1 }
    return $Haystack.IndexOf($Needle, [System.StringComparison]::Ordinal)
}

# --------------------------------------------------------------------------- 0.3.0 helpers: the settings-save checks

# The state of the file a save writes, fingerprinted so "nothing was written" is an assertion rather than a hope. 'absent' is a
# real state (a host that has never saved anything), and comparing two fingerprints catches both a change and a creation. Hash is
# lowercased so this helper's output is comparable with scripts/smoke_test.sh's `sha256sum`.
function Get-FileState {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return 'absent' }
    try {
        return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLower()
    } catch {
        # A file that exists but cannot be hashed is NOT the same as a file that is absent. Returning 'absent' here would let a
        # refusal that DID write the file pass the "nothing changed" comparison.
        Add-Fail "Get-FileState: cannot hash $Path ($($_.Exception.Message))"
        return 'unreadable'
    }
}

# Percent-encoder for building the urlencoded body by hand. [System.Web.HttpUtility] is not available in pwsh 7 (no System.Web),
# and curl's --data-urlencode would re-encode on its own rather than let this script prove what the page rendered. Unreserved set
# per RFC 3986; everything else becomes %XX over UTF-8 bytes.
function Convert-ToUrlEncoded {
    param([string]$Text)
    $out = New-Object System.Text.StringBuilder
    foreach ($ch in $Text.ToCharArray()) {
        if ($ch -match '^[A-Za-z0-9.~-]$') {
            [void]$out.Append($ch)
        } else {
            foreach ($byte in [System.Text.Encoding]::UTF8.GetBytes([string]$ch)) {
                [void]$out.Append('%' + $byte.ToString('X2'))
            }
        }
    }
    return $out.ToString()
}

# The /settings form posts ONE control per editable knob (MEASURED: 22 on 0.3.0) and several of them are legitimately EMPTY -
# log_file, public_base_url and the six subject defaults all render value="". That is why this body is scraped from the page
# rather than typed out here: a hand-written list reports a product bug every time config.py gains a knob. Overrides are applied
# after scraping, which is how the harness posts an out-of-range port while leaving every other field exactly as the page rendered
# it. Returns $false when the page carried too few controls, so the caller fails with a reason rather than posting a stub body.
function Write-SettingsFormBody {
    param([string]$PageFile, [string]$OutFile, [string[]]$Overrides)
    $page = Read-Body $PageFile
    # settings.html renders each <input> across five lines (name, type, min, max, value). Joining newlines first is what makes the
    # tags match at all: without it only the name line is seen, most knobs vanish from the body, and the app correctly answers
    # 'was not submitted' for a page that did render them.
    $joined = ($page -replace '\r?\n\s*', ' ')
    $fields = [ordered]@{}
    foreach ($tag in [regex]::Matches($joined, '<input\b[^>]*>')) {
        $nameMatch = [regex]::Match($tag.Value, 'name="(MYPKI_[A-Za-z0-9_]+|csrf_token)"')
        if (-not $nameMatch.Success) { continue }
        $valueMatch = [regex]::Match($tag.Value, 'value="([^"]*)"')
        $fields[$nameMatch.Groups[1].Value] = if ($valueMatch.Success) { $valueMatch.Groups[1].Value } else { '' }
    }
    if ($fields.Count -lt 20) {
        Add-Fail "settings page carried only $($fields.Count) MYPKI_* controls plus the token"
        return $false
    }
    foreach ($pair in $Overrides) {
        $idx = $pair.IndexOf('=')
        if ($idx -lt 0) { continue }
        $fields[$pair.Substring(0, $idx)] = $pair.Substring($idx + 1)
    }
    $pairs = @()
    foreach ($key in $fields.Keys) { $pairs += (Convert-ToUrlEncoded $key) + '=' + (Convert-ToUrlEncoded ([string]$fields[$key])) }
    # WriteAllText, not Out-File: no trailing newline and no BOM, so the body is byte-for-byte what a browser would post.
    [System.IO.File]::WriteAllText($OutFile, ($pairs -join '&'))
    return $true
}

# A bound read off the control the page itself renders (min= / max=), which app.py fills from the same Field(ge=..., le=...)
# metadata pydantic enforces. Asserting a refusal against THIS number rather than a literal keeps the harness and config.py on one
# fact: move the knob in config.py and both the input's max= and the expected sentence move with it.
function Get-KnobBound {
    param([string]$PageFile, [string]$Knob, [string]$Which)
    $joined = ((Read-Body $PageFile) -replace '\r?\n\s*', ' ')
    foreach ($tag in [regex]::Matches($joined, '<input\b[^>]*>')) {
        if ([regex]::IsMatch($tag.Value, ('name="' + [regex]::Escape($Knob) + '"'))) {
            $match = [regex]::Match($tag.Value, ($Which + '="([0-9]+)"'))
            if ($match.Success) { return $match.Groups[1].Value }
            return ''
        }
    }
    return ''
}

# urlencoded POST - the shape a browser's form actually posts. `@file` again so no quoting rule can corrupt the body on the way
# out, exactly as Send-Pem does for a PEM.
function Send-Body {
    param([string]$Path, [string]$OutFile, [string]$BodyFile)
    $all = @('-b', $script:Jar, '-c', $script:Jar, '-o', $OutFile, '-w', '%{http_code}', '-X', 'POST',
        '--data-binary', ('@' + $BodyFile), '-H', 'Content-Type: application/x-www-form-urlencoded')
    $all += "$($script:Base)$Path"
    $raw = Invoke-Curl -CurlArgs $all
    return (($raw | ForEach-Object { [string]$_ }) -join '').Trim()
}

# Every checkbox the bulk form offers, in page order. Section 11 needs a SECOND and THIRD one to prove multi-select is real
# rather than a single-row form wearing a checkbox.
function Get-AllRowSerials {
    param([string]$PageFile)
    $serials = @()
    foreach ($match in [regex]::Matches((Read-Body $PageFile), 'type="checkbox" name="serial_hex" value="([0-9a-f]+)"')) {
        $serials += $match.Groups[1].Value
    }
    return $serials
}


# =========================================================================== 1 home page
Write-Host ($script:SectionMark + '1 Home page (page-map ' + $script:SectionMark + '1)')
$status = Get-Page '/' (Join-Path $Work 'home.html')
if ($status -eq '200') { Add-Pass 'GET / answers 200' } else { Add-Fail "GET / answered $status (expected 200)" }

$homeBody = Read-Body (Join-Path $Work 'home.html')
# 0.3.0 moved every CA fact to /ca (page-map 1 vs 4): '/' is the signing form and nothing else. These are the same four needles
# section 9 asks for on /ca, asked here as ABSENT - a home page that grew the CA card back would still answer 200 and every other
# section 1 check would still pass, so absence is the only way to catch the drift. MEASURED against a live 0.3.0 server: all four
# read 0 on '/'. 'BasicConstraints' replaces the old 'CA:TRUE pathLength:0' needle because csr_sign.html renders 'BasicConstraints
# CA:FALSE' for a STAGED request, and that one is legitimately on this address after a paste (page-map 3) - what must be absent is
# any BasicConstraints line with nothing staged.
$n = Measure-Occurrence $homeBody 'mypki Root CA'
if ($n -eq 0) { Add-Pass 'home no longer prints the CA subject (page-map 1: /ca carries the CA facts alone)' }
else { Add-Fail "home still renders a CA card ($n occurrence(s) of the CA subject)" }

$n = Measure-Regex $homeBody '([0-9A-F]{2}:){31}[0-9A-F]{2}'
if ($n -eq 0) { Add-Pass "home shows no fingerprint (a leaf's own appears on /csr/sign after a signing, section 6 asserts it)" }
else { Add-Fail "home carries a colon-grouped fingerprint ($n) where page-map 1 says none belongs" }

$n = Measure-Occurrence $homeBody 'BasicConstraints'
if ($n -eq 0) { Add-Pass 'home prints no BasicConstraints line with nothing staged' }
else { Add-Fail "home renders BasicConstraints ($n) on a fresh page" }

$n = Measure-Occurrence $homeBody 'private key on this host'
if ($n -eq 0) { Add-Pass 'home does not report CA key presence (that boolean lives on /ca, section 9)' }
else { Add-Fail "home still reports CA key presence ($n)" }

# 0.2.0: `/` IS the sign form rather than a prose page (page-map 1). Asserted because the two addresses must render
# the same template, and a home.html that survived would still answer 200 while being a second document that drifts.
$n = Measure-Occurrence $homeBody '<h1>Sign a certificate</h1>'
if ($n -ge 1) { Add-Pass "home is the sign form, not prose (page-map 1; heading renamed from 'Sign a certificate signing request')" } else { Add-Fail "home is not rendering the sign form with this build's renamed heading ($n)" }
$n = Measure-Occurrence $homeBody 'CSR requesting CA powers will be refused.'
if ($n -ge 1) { Add-Pass 'the sign page states the CA-power refusal in one line under the heading' } else { Add-Fail "the sign page carries no CA-power refusal sentence ($n)" }
$n = Measure-Occurrence $homeBody 'Paste a CSR (PEM)'
if ($n -ge 1) { Add-Pass 'home offers the paste form directly' } else { Add-Fail 'home has no paste form' }

# =========================================================================== 2 headers on every page
Write-Host ($script:SectionMark + '2 Security headers (page-map ' + $script:SectionMark + '0)')
$hdrs = (Get-HeadersOf '/').ToLower()
# Every needle here is already lower-case because the haystack went through ToLower(). Comparing against 'DENY' after
# ToLower() guarantees a miss for every value, not just this one - which reports a correctly configured response as missing
# the header.
foreach ($header in @('x-content-type-options: nosniff', 'x-frame-options: deny', 'referrer-policy: same-origin')) {
    $n = Measure-Occurrence $hdrs $header
    if ($n -ge 1) { Add-Pass "response carries $header" } else { Add-Fail "response is missing $header" }
}
$n = Measure-Occurrence $hdrs "content-security-policy: default-src 'self'"
if ($n -ge 1) { Add-Pass "CSP starts with default-src 'self'" } else { Add-Fail "CSP missing, or does not start with default-src 'self'" }
$n = Measure-Occurrence $hdrs 'unsafe-inline'
if ($n -eq 0) { Add-Pass 'CSP contains no unsafe-inline' } else { Add-Fail 'CSP contains unsafe-inline (page-map 0 forbids it)' }

# 0.3.0 ships exactly ONE script, same-origin, linked with <script src>. Both halves are asserted because they are two different
# promises: default-src 'self' with no unsafe-inline only holds if nothing is inlined, and a page that lost its link would lose
# the copy buttons silently while every flow in this harness kept passing. The script is asserted as an ASSET and never as a
# requirement - everything here ran without executing it, which is what page-map 0 promises.
$n = Measure-Occurrence $homeBody '<script>'
if ($n -eq 0) { Add-Pass 'no inline <script> on the home page (its own CSP forbids unsafe-inline)' }
else { Add-Fail "the home page inlines $n <script> block(s) while its CSP says no unsafe-inline" }
$n = Measure-Occurrence $homeBody '<script src='
if ($n -ge 1) { Add-Pass "the home page links its script with <script src> ($n)" } else { Add-Fail 'the home page links no script at all' }

$status = Get-Page '/static/app.js' (Join-Path $Work 'app.js')
if ($status -eq '200') { Add-Pass 'GET /static/app.js answers 200' } else { Add-Fail "GET /static/app.js answered $status" }
$jsHeaders = (Get-HeadersOf '/static/app.js').ToLower()
$n = Measure-Occurrence $jsHeaders 'content-type: text/javascript'
if ($n -eq 1) { Add-Pass 'app.js is served as text/javascript (a browser refuses a script served as text/plain)' }
else { Add-Fail "app.js has the wrong content type for a script" }
$n = Measure-Occurrence $jsHeaders "content-security-policy: default-src 'self'"
if ($n -eq 1) { Add-Pass 'the static response carries the same CSP as the pages' } else { Add-Fail '/static/app.js bypasses the CSP' }

# 0.5.0: /settings gained .pending-saved, the rose sentence beside a restart-only box whose saved value and live value disagree.
# It is CSS, so it lives in the stylesheet and not in the page - and this harness never renders a page in a browser, so the only
# honest assertion available is that the served asset carries the rule (MEASURED: /static/style.css answers 200 as text/css with
# the same CSP as the pages). What CANNOT be asserted from here is what the sentence looks like on screen; no browser on this host
# has ever rendered it, and this script says so out loud rather than implying otherwise.
$cssStatus = Get-Page '/static/style.css' (Join-Path $Work 'style.css')
if ($cssStatus -eq '200') { Add-Pass 'GET /static/style.css answers 200' } else { Add-Fail "GET /static/style.css answered $cssStatus" }
$cssHeaders = (Get-HeadersOf '/static/style.css').ToLower()
$n = Measure-Occurrence $cssHeaders 'content-type: text/css'
if ($n -eq 1) { Add-Pass 'style.css is served as text/css (a browser refuses a stylesheet served as text/plain)' }
else { Add-Fail 'style.css has the wrong content type for a stylesheet' }
$n = Measure-Occurrence $cssHeaders "content-security-policy: default-src 'self'"
if ($n -eq 1) { Add-Pass 'the stylesheet response carries the same CSP as the pages' } else { Add-Fail '/static/style.css bypasses the CSP' }
$cssBody = Read-Body (Join-Path $Work 'style.css')
$n = Measure-Occurrence $cssBody '.pending-saved {'
if ($n -eq 1) { Add-Pass 'the served stylesheet defines .pending-saved (1) - the 0.5.0 pending sentence is styled' }
else { Add-Fail ".pending-saved is not defined in the served stylesheet ($n): settings.html renders a class nothing styles" }
$n = Measure-Occurrence $cssBody 'var(--rose)'
if ($n -ge 1) { Add-Pass ".pending-saved reuses the existing --rose colour rather than adding one ($n rose uses)" }
else { Add-Fail 'the stylesheet no longer uses --rose anywhere - the restart language lost its one colour' }

# 0.5.2: the same posture for the /inspect width fix (page-map 13). An operator reported that the PEM paste box rendered narrower than
# every other section on its own page; the fix is three CSS rules plus one class in the template, and this harness renders no page in a
# browser, so what can honestly be asserted is that the served asset carries each rule - including the SCOPING selector, because a rule
# that widened .settings-form instead would 'fix' /inspect by widening every field on /settings. Invisible without a browser, plainly
# visible in the text of the file, which is exactly why it is asserted here.
$n = Measure-Occurrence $cssBody 'form.stacked.inspect-form { max-width: none; }'
if ($n -eq 1) { Add-Pass 'the served stylesheet lifts the 46rem cap for /inspect form only (1) - scoped by .inspect-form, not by .settings-form' }
else { Add-Fail "form.stacked.inspect-form is not defined in the served stylesheet ($n): /inspect paste box is still clipped at 46rem" }
$n = Measure-Occurrence $cssBody 'form.inspect-form #pem_paste { width: 100%; max-width: none; }'
if ($n -eq 1) { Add-Pass 'the served stylesheet widens #pem_paste to its section (1) - the box an operator saw at ~21rem' }
else { Add-Fail "#pem_paste has no width rule in the served stylesheet ($n): the textarea falls back to the browser default again" }
$n = Measure-Occurrence $cssBody 'form.inspect-form button.save-settings { max-width: none; }'
if ($n -eq 1) { Add-Pass 'the Inspect button follows its field instead of sitting half-width under it (1)' }
else { Add-Fail "/inspect submit button is not widened with its form ($n): a full-width box over a 46rem button is the same mismatch, moved" }
$n = Measure-Occurrence $cssBody '.settings-form .field textarea'
if ($n -eq 0) { Add-Pass 'no rule widens .settings-form textareas globally (0) - /settings keeps its fields as they are' }
else { Add-Fail ".settings-form grew $n global textarea rule(s): a fix scoped to /inspect leaked into /settings" }

# And the template half, fetched here rather than borrowed from section 15: a CSS rule whose class is missing from the markup styles
# nothing, and the two halves of this fix live in different files. The GET is not an assertion - only its class count is.
$inspectFormStatus = Get-Page '/inspect' (Join-Path $Work 'inspect-form.html')
if ($inspectFormStatus -ne '200') {
    Add-Fail "GET /inspect answered $inspectFormStatus while checking the stylesheet's scoping target"
} else {
    $n = Measure-Occurrence (Read-Body (Join-Path $Work 'inspect-form.html')) 'class="settings-form stacked inspect-form"'
    if ($n -eq 1) { Add-Pass "/inspect form carries the class those three rules are scoped to ($n)" }
    else { Add-Fail "/inspect form does not carry inspect-form ($n): the width rules above would style nothing" }
}


# =========================================================================== 3 the version chain, read from the running app
Write-Host ($script:SectionMark + '3 Version (read from __init__.py, never hard-coded here)')
if ([string]::IsNullOrWhiteSpace($Version)) {
    Add-Warn 'no expected version available: pass -Version or run from a checkout'
} else {
    Get-Page '/version' (Join-Path $Work 'version.html') | Out-Null
    $n = Measure-Occurrence (Read-Body (Join-Path $Work 'version.html')) "mypki $Version"
    if ($n -ge 1) { Add-Pass "the running app reports version $Version" }
    else { Add-Fail "the running app does not report $Version - you are testing a different build than this checkout" }
}

# =========================================================================== 4 no API surface advertised
Write-Host ($script:SectionMark + '4 No API surface (docs_url/redoc_url/openapi_url are None)')
foreach ($path in @('/docs', '/redoc', '/openapi.json')) {
    $status = Get-Page $path (Join-Path $Work 'api-probe.html')
    if ($status -eq '404' -or $status -eq '405') { Add-Pass "$path is not served ($status)" }
    else { Add-Fail "$path answered $status - an API surface exists where page-map 0 says none may" }
# (The reference to page-map section 0 is spelled without the mark on purpose here: it is prose in a failure message, not a
# heading another harness has to match.)
}

# =========================================================================== 5 generate a key + CSR
Write-Host ($script:SectionMark + '5 Generate CSR (page-map ' + $script:SectionMark + '2)')
Get-Page '/csr/generate' (Join-Path $Work 'gen-form.html') | Out-Null
$token = Get-CsrfToken (Join-Path $Work 'gen-form.html')
if ([string]::IsNullOrWhiteSpace($token)) { Add-Fail 'the generate form carries no CSRF token'; $token = 'absent' }

$status = Send-Form '/csr/generate' (Join-Path $Work 'gen-no-csrf.html') @('common_name=nocsrf.internal', 'key_type=rsa-2048')
if ($status -eq '400') { Add-Pass 'POST without a CSRF token answers 400' }
else { Add-Fail "POST without a CSRF token answered $status (expected 400)" }
# This one assertion is about the phrase rather than the armour, and only on the page that renders no prose at all: a
# CSRF-rejected POST has no legitimate reason to mention keys, so any occurrence means something was generated anyway.
$n = Measure-Occurrence (Read-Body (Join-Path $Work 'gen-no-csrf.html')) 'PRIVATE KEY'
if ($n -eq 0) { Add-Pass 'the CSRF-rejected POST returned no key material' } else { Add-Fail 'a CSRF-rejected POST contained key material' }

# The embedded newline in `sans` is a backtick-n, not "\n": PowerShell does not interpret \n inside a double-quoted string,
# so a literal \n would be sent as two characters and the IP SAN would fail validation for a reason that has nothing to do
# with mypki.
$sans = "web.internal, *.lab.local`n10.0.0.7"
$status = Send-Form '/csr/generate' (Join-Path $Work 'gen.html') @(
    "csrf_token=$token",
    'common_name=web.internal',
    "sans=$sans",
    'organization=Acme',
    'country=DE',
    'key_type=rsa-2048'
)
if ($status -eq '200') { Add-Pass 'POST /csr/generate answers 200' } else { Add-Fail "POST /csr/generate answered $status" }

$gen = Read-Body (Join-Path $Work 'gen.html')
$n = Measure-Occurrence $gen '-----BEGIN CERTIFICATE REQUEST-----'
if ($n -eq 1) { Add-Pass 'exactly one CSR PEM block shown' } else { Add-Fail "expected exactly 1 CSR block, found $n" }
$n = Measure-Occurrence $gen '-----BEGIN PRIVATE KEY-----'
if ($n -eq 1) { Add-Pass 'exactly one private key block shown' } else { Add-Fail "expected exactly 1 key block, found $n" }
$n = Measure-Occurrence $gen 'stored nowhere'
if ($n -lt 1) { $n = Measure-Occurrence $gen 'not stored anywhere' }
if ($n -ge 1) { Add-Pass 'the page states the output is stored nowhere' } else { Add-Warn "the page lacks the 'stored nowhere' warning" }
$n = Measure-Occurrence $gen 'Download private key'
if ($n -eq 1) { Add-Pass 'a private-key download link is offered' } else { Add-Fail 'no private-key download link' }
$n = Measure-Occurrence $gen '10.0.0.7'
if ($n -ge 1) { Add-Pass 'the IP SAN survived generation as an IP general name' } else { Add-Fail 'the IP SAN did not survive generation' }

$csrText = Extract-Pem (Join-Path $Work 'gen.html') 'CERTIFICATE REQUEST'
if (-not $csrText) {
    Add-Fail 'could not extract the generated CSR from the page'
    $generatedCsr = ''
} else {
    $generatedCsr = Join-Path $Work 'generated.csr'
    # WriteAllText rather than Set-Content: on Windows PowerShell 5.1 `Set-Content -Encoding UTF8` writes a UTF-8 BOM, and a
    # BOM ahead of `-----BEGIN CERTIFICATE REQUEST-----` makes the next step answer "No PEM block found" - a harness defect
    # that reads as a broken sign page. WriteAllText emits no BOM on any version.
    [System.IO.File]::WriteAllText($generatedCsr, $csrText)
    $n = Measure-Occurrence (Read-Body $generatedCsr) '-----BEGIN CERTIFICATE REQUEST-----'
    $bytes = (Get-Item -LiteralPath $generatedCsr).Length
    if ($n -eq 1) { Add-Pass "the extracted CSR is a single well-formed block ($bytes bytes)" } else { Add-Fail 'extracted CSR is malformed' }
}

# =========================================================================== 6 sign the generated CSR, two steps
Write-Host ($script:SectionMark + '6 Sign CSR (page-map ' + $script:SectionMark + '3)')
Get-Page '/csr/sign' (Join-Path $Work 'sign-form.html') | Out-Null
$token = Get-CsrfToken (Join-Path $Work 'sign-form.html')

# SEED, before anything is asserted about the ledger. Section 11 needs THREE active records on this host: one for its
# own round trip and two more for multi-select. On a FRESH data dir exactly one record exists by this point, so STEPS
# C-E WARN-skip and the `>= 3` needles below them fail against a correct app. Signing is idempotent per request
# (MEASURED: re-signing this same CSR twice yields two DISTINCT serials), and this runs BEFORE section 6's own signing
# because /issued is newest-first - seeding afterwards would push section 6's record off the first row and break
# RowSerial == IssuedSerial. Not runtime-verified: this script has never been executed on this host.
$seeded = 0
foreach ($seed in 1, 2) {
    $status = Send-Pem '/csr/sign' (Join-Path $Work ("seed-confirm-{0}.html" -f $seed)) $generatedCsr @("csrf_token=$token")
    if ($status -ne '200') { Add-Fail "seed $seed step A answered $status - the multi-select checks will WARN-skip"; continue }
    $seedPending = Get-PendingId (Join-Path $Work ("seed-confirm-{0}.html" -f $seed))
    if ([string]::IsNullOrWhiteSpace($seedPending)) { Add-Fail "seed $seed step A staged no pending id"; continue }
    $status = Send-Form ("/csr/sign?pending={0}" -f $seedPending) (Join-Path $Work ("seed-issue-{0}.html" -f $seed)) @(
        "csrf_token=$token", 'confirm=1', 'cert_type=server', 'validity_days=30'
    )
    if ($status -eq '200') { $seeded++ } else { Add-Fail "seed $seed step B answered $status" }
}
if ($seeded -eq 2) { Add-Pass "two extra certificates seeded so section 11 has a real multi-select ledger ($seeded)" }
else { Add-Warn "seeded only $seeded extra certificate(s); the multi-select checks may WARN-skip instead of asserting" }

$status = Send-Pem '/csr/sign' (Join-Path $Work 'confirm.html') $generatedCsr @("csrf_token=$token")
if ($status -eq '200') { Add-Pass 'step A (validate + show details) answers 200' } else { Add-Fail "step A answered $status" }

$confirm = Read-Body (Join-Path $Work 'confirm.html')
$n = Measure-Occurrence $confirm 'web.internal'
if ($n -ge 1) { Add-Pass 'the confirmation panel shows the parsed CN/SAN' } else { Add-Fail 'confirmation panel omits the parsed subject' }
$n = Measure-Occurrence $confirm '*.lab.local'
if ($n -ge 1) { Add-Pass 'the wildcard SAN is shown as validated, not rejected' } else { Add-Fail 'the wildcard SAN was not accepted' }
$n = Measure-Occurrence $confirm 'RSA 2048'
if ($n -ge 1) { Add-Pass 'the confirmation panel reports the key spec (RSA 2048)' } else { Add-Fail 'confirmation panel omits the key spec' }

$status = Send-Form '/csr/sign' (Join-Path $Work 'issued.html') @("csrf_token=$token", 'confirm=1', 'cert_type=server', 'validity_days=30')
if ($status -eq '200') { Add-Pass 'step B (confirm + issue) answers 200' } else { Add-Fail "step B answered $status" }

$iss = Read-Body (Join-Path $Work 'issued.html')
$n = Measure-Occurrence $iss '-----BEGIN CERTIFICATE-----'
if ($n -ge 1) { Add-Pass "a signed certificate is rendered ($n block(s))" } else { Add-Fail 'no certificate was rendered' }
$n = Measure-Occurrence $iss 'Download chain'
if ($n -eq 1) { Add-Pass 'a chain download is offered' } else { Add-Fail 'no chain download link' }
$n = Measure-Regex $iss '([0-9A-F]{2}:){31}[0-9A-F]{2}'
if ($n -ge 1) { Add-Pass "the issued certificate's fingerprint is displayed" } else { Add-Fail 'the issued certificate shows no fingerprint' }

# Scoped by Get-IssuedSerial (see its comment): this page also carries the CA's serial in an identical cell.
$IssuedSerial = Get-IssuedSerial (Join-Path $Work 'issued.html')
if ([string]::IsNullOrWhiteSpace($IssuedSerial)) {
    Add-Fail ("the issued card shows no hex serial - " + $script:SectionMark + "10 and " + $script:SectionMark + "11 cannot address a certificate")
} else {
    $shown = if ($IssuedSerial.Length -gt 12) { $IssuedSerial.Substring(0, 12) } else { $IssuedSerial }
    Add-Pass "the issued card reports a leaf serial ($shown...)"
}
# The 0.2.0 provenance split replaces 0.1.0's inaccurate "Only the SANs above are copied from your request": CN/O/OU/C/ST/L and
# email DO come from the request (and now from the operator's edits); only the extensions never do (page-map 7). Asserted against
# step A's confirm page, NOT against the issued card: the provenance block sits inside the confirm form, and step B re-renders
# /csr/sign with only the issued card (MEASURED - 1 occurrence in confirm.html, 0 in issued.html). Asserting it on the issued
# card fails against a correct app.
$n = Measure-Occurrence $confirm 'Set by mypki, never from the request'
if ($n -ge 1) { Add-Pass 'the confirm form states which parts never come from the request' } else { Add-Fail 'the confirm form omits the provenance split' }
$n = Measure-Occurrence $confirm 'Only the SANs above are copied'
if ($n -eq 0) { Add-Pass "the inaccurate 'only the SANs' wording is gone from the confirm form" } else { Add-Fail "the inaccurate 'only the SANs' wording is still on the page" }

# =========================================================================== 7 rejections name a specific reason
# The quotes inside this label are single quotes because that is what scripts/smoke_test.sh prints; the two harnesses are
# compared line by line against SMOKE_TESTING.md, and a label that differs only in quote style is a diff nobody can act on.
Write-Host ($script:SectionMark + "7 Rejections name their reason (never 'invalid CSR')")
$status = Send-Form '/csr/sign' (Join-Path $Work 'bad1.html') @("csrf_token=$token", 'csr_pem=not a csr at all')
$n = Measure-Occurrence (Read-Body (Join-Path $Work 'bad1.html')) 'No PEM block found'
if ($status -eq '400' -and $n -ge 1) { Add-Pass 'garbage input is refused naming the reason' }
else { Add-Fail "garbage input: status $status (expected 400), reason occurrences $n" }

# Written with a LF terminator on purpose. curl reads the file byte-for-byte and mypki's parser accepts either line ending,
# but a CRLF here would make this harness's bogus-CSR case differ from the bash harness's for a reason nobody is testing.
$bogus = @(
    '-----BEGIN CERTIFICATE REQUEST-----'
    'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY='
    '-----END CERTIFICATE REQUEST-----'
) -join "`n"
$bogusFile = Join-Path $Work 'bogus.csr'
[System.IO.File]::WriteAllText($bogusFile, ($bogus + "`n"))
$status = Send-Pem '/csr/sign' (Join-Path $Work 'bad2.html') $bogusFile @("csrf_token=$token")
$n = Measure-Occurrence (Read-Body (Join-Path $Work 'bad2.html')) 'not a DER certificate request'
if ($status -eq '400' -and $n -ge 1) { Add-Pass 'valid base64 that is not a CSR is refused naming it' }
else { Add-Fail "bogus-CSR case: status $status (expected 400), reason occurrences $n" }

# --- Unreleased (this build): a refused paste is named ON the sign page, above the box it belongs to, and the status did not move.
# Asserted as an ORDER via IndexOf: 'the reason appears somewhere in the body' is also true of a page that mentions it in
# a nav link while showing nothing else. MEASURED on 0.7.0 and earlier: these two POSTs rendered templates/error.html,
# which contains no form at all - the operator had to click back and re-paste.
$bad1 = Read-Body (Join-Path $Work 'bad1.html')
$n = Measure-Occurrence $bad1 'class="form-errors refused"'
if ($n -ge 1) { Add-Pass "the refusal is rendered on the sign page itself ($n block(s), not a separate error document)" }
else { Add-Fail 'the refusal left the sign page: no .form-errors.refused block in the 400 body' }
$refusalAt = $bad1.IndexOf('class="form-errors refused"', 0, [System.StringComparison]::Ordinal)
$labelAt = $bad1.IndexOf('<label for="csr_pem">Paste a CSR (PEM)</label>', 0, [System.StringComparison]::Ordinal)
if ($refusalAt -ge 0 -and $labelAt -gt $refusalAt) { Add-Pass "the refusal sits above 'Paste a CSR (PEM)' (offset $refusalAt vs $labelAt)" }
else { Add-Fail "the refusal is not above the paste box (refusal offset $refusalAt, label offset $labelAt)" }
$n = Measure-Occurrence $bad1 'not a csr at all'
if ($n -ge 1) { Add-Pass "the rejected paste is echoed back into its own textarea, so the fix is typed in place ($n)" }
else { Add-Fail 'the rejected paste was thrown away: it is not in the re-rendered form' }
$n = Measure-Occurrence $bad1 'This is what the request says'
if ($n -eq 0) { Add-Pass 'a refused paste staged nothing (no confirmation panel, $n)' }
else { Add-Fail "a refused paste rendered a confirmation panel ($n)" }
# The oversized case is the one refusal that stays on error.html: SizeGuardMiddleware answers it before any route runs,
# so there is no form to put the reason on (section 8 asserts the 413 and the knob).

# =========================================================================== 8 oversized input gets mypki's own page
Write-Host ($script:SectionMark + '8 Oversized input (page-map ' + $script:SectionMark + '0)')
$padding = 'A' * 40000
$hugeFile = Join-Path $Work 'huge.csr'
$hugeBody = '-----BEGIN CERTIFICATE REQUEST-----' + "`n" + $padding + "`n" + '-----END CERTIFICATE REQUEST-----' + "`n"
[System.IO.File]::WriteAllText($hugeFile, $hugeBody)
$status = Send-Pem '/csr/sign' (Join-Path $Work 'huge.html') $hugeFile @("csrf_token=$token")
$body = Read-Body (Join-Path $Work 'huge.html')
$n = Measure-Occurrence $body 'the limit is 32,000'
if ($status -eq '413' -and $n -ge 1) { Add-Pass "oversized paste answers 413 with mypki's own page naming the limit" }
else { Add-Fail "oversized paste: status $status (expected 413), limit named $n time(s)" }
$n = Measure-Occurrence $body 'Field exceeded maximum size'
if ($n -eq 0) { Add-Pass "starlette's bare JSON size error did not surface" }
else { Add-Fail "the framework's own size message surfaced instead of mine" }

# =========================================================================== 9 CA certificate download
Write-Host ($script:SectionMark + '9 CA certificate (page-map ' + $script:SectionMark + '4)')
$status = Get-Page '/ca' (Join-Path $Work 'ca.html')
if ($status -eq '200') { Add-Pass 'GET /ca answers 200' } else { Add-Fail "GET /ca answered $status" }
$caPage = Read-Body (Join-Path $Work 'ca.html')
# The four CA facts 0.2.0 printed on '/' live here and only here (page-map 1 vs 4). Written against what the RENDERED page says
# rather than the template source: 'CA:TRUE pathLength:0' also sits inside a Jinja COMMENT in ca_download.html, so a grep of the
# file would pass against a page that never renders it. MEASURED spellings on a live 0.3.0 server: <td class="mono"> for
# CA:TRUE pathLength:0, and 'CA private key on this host' / 'present - this host can sign'.
$n = Measure-Occurrence $caPage 'mypki Root CA'
if ($n -ge 1) { Add-Pass "/ca shows the CA subject ($n occurrence(s))" }
else { Add-Fail '/ca does not show the CA subject - no CA loaded, or the card is broken' }

$n = Measure-Regex $caPage '([0-9A-F]{2}:){31}[0-9A-F]{2}'
if ($n -ge 1) { Add-Pass "/ca shows a colon-grouped SHA-256 fingerprint ($n)" }
else { Add-Fail '/ca shows no 32-byte colon-grouped fingerprint' }

$n = Measure-Occurrence $caPage 'CA:TRUE pathLength:0'
if ($n -ge 1) { Add-Pass "/ca reports BasicConstraints CA:TRUE pathLength:0" } else { Add-Fail "/ca omits the root's BasicConstraints" }

$n = Measure-Occurrence $caPage 'private key on this host'
if ($n -ge 1) { Add-Pass '/ca reports whether the CA private key is present (boolean only)' } else { Add-Fail '/ca does not report key presence' }

foreach ($pair in @(
    @('Trusted Root Certification Authorities', 'Windows instructions'),
    @('update-ca-certificates', 'Linux instructions'),
    @('Always Trust', 'macOS instructions'),
    @('keytool -importcert', 'Java instructions')
)) {
    $n = Measure-Occurrence $caPage $pair[0]
    if ($n -ge 1) { Add-Pass "$($pair[1]) present" } else { Add-Fail "$($pair[1]) missing" }
}

$status = Get-Page '/ca/certificate' (Join-Path $Work 'ca.crt')
if ($status -eq '200') { Add-Pass 'GET /ca/certificate answers 200' } else { Add-Fail "CA download answered $status" }
$dlHeaders = (Get-HeadersOf '/ca/certificate').ToLower()
$n = Measure-Occurrence $dlHeaders 'content-disposition: attachment; filename="mypki-root-ca.crt"'
if ($n -eq 1) { Add-Pass 'CA download is an attachment named mypki-root-ca.crt' }
else { Add-Fail 'CA download Content-Disposition is wrong (Windows double-click depends on it)' }
$n = Measure-Occurrence $dlHeaders 'cache-control: no-store'
if ($n -eq 1) { Add-Pass 'PEM response sets Cache-Control: no-store' } else { Add-Fail 'PEM response is cacheable (page-map 0 forbids it)' }
# The page-map reference in prose stays plain text; only the fourteen section HEADINGS carry the mark, because those are the
# strings scripts/smoke_test.sh prints and a human compares between the two harnesses. There were eleven until 0.2.0 added
# revocation, About/Settings and the inline-error walk, which pushed this armour sweep from 11 to 14.
$n = Measure-Occurrence (Read-Body (Join-Path $Work 'ca.crt')) '-----BEGIN CERTIFICATE-----'
if ($n -eq 1) { Add-Pass 'the CA download contains exactly one certificate' } else { Add-Fail "CA download contains $n certificates (expected 1)" }

# 0.5.0: /ca now shows the certificate itself with a copy button (page-map 4). Three separate assertions, because there
# are three ways this feature could rot without any of them turning red today: the block vanishes, the button stops
# pointing at it, or the page's copy drifts from the download's. The third is the one that matters -- 0.3.0 deleted the
# home-page CA card for exactly that reason ("a fact shown in two places is two facts that can disagree"), and 0.5.0
# puts a second copy of the root back on screen, so the parity check is what makes that safe.
$n = Measure-Occurrence $caPage 'id="pem-ca"'
if ($n -eq 1) { Add-Pass '/ca renders the CA PEM block (pre id=pem-ca)' } else { Add-Fail '/ca renders no PEM block with id pem-ca' }

$n = Measure-Occurrence $caPage 'data-mypki-copy="pem-ca"'
if ($n -eq 1) { Add-Pass "/ca's copy button points at that block" } else { Add-Fail "/ca has no copy button wired to pem-ca" }

$pagePem = Extract-Pem (Join-Path $Work 'ca.html') 'CERTIFICATE'
if ([string]::IsNullOrEmpty($pagePem)) {
    Add-Fail '/ca renders no extractable CERTIFICATE block to compare'
} else {
    $n = Measure-Occurrence $pagePem '-----BEGIN CERTIFICATE-----'
    if ($n -eq 1) { Add-Pass "/ca's PEM block holds exactly one certificate" } else { Add-Fail "/ca's PEM block holds $n certificates (expected 1)" }

    Set-Content -LiteralPath (Join-Path $Work 'ca-page.pem') -Value $pagePem -Encoding UTF8 -NoNewline
    $pageSha = Get-PemDerSha (Join-Path $Work 'ca-page.pem')
    $dlSha = Get-PemDerSha (Join-Path $Work 'ca.crt')
    if (-not [string]::IsNullOrEmpty($pageSha) -and $pageSha -eq $dlSha) {
        Add-Pass "the certificate shown on /ca is the same bytes as the download ($pageSha)"
    } else {
        Add-Fail "/ca's certificate differs from /ca/certificate (page $pageSha vs download $dlSha)"
    }
}

# =========================================================================== 10 issued list
Write-Host ($script:SectionMark + '10 Issued list (page-map ' + $script:SectionMark + '5)')
$status = Get-Page '/issued' (Join-Path $Work 'issued-list.html')
if ($status -eq '200') { Add-Pass 'GET /issued answers 200' } else { Add-Fail "GET /issued answered $status" }
$list = Read-Body (Join-Path $Work 'issued-list.html')
$n = Measure-Regex $list '<tr>'
if ($n -ge 2) { Add-Pass "the issued table has at least one data row ($n <tr> including the header)" }
else { Add-Fail 'the issued table has no data rows after a successful signing' }
$n = Measure-Occurrence $list 'web.internal'
if ($n -ge 1) { Add-Pass ("the certificate signed in " + $script:SectionMark + "6 appears in the list") }
else { Add-Fail ("the " + $script:SectionMark + "6 certificate is missing from /issued") }
$n = Measure-Occurrence $list '<span class="pill active">active</span>'
if ($n -ge 1) { Add-Pass "a fresh record reports Status 'active'" } else { Add-Fail "no 'active' status pill on a freshly issued record" }
$n = Measure-Occurrence $list 'action="/issued/revoke"'
if ($n -ge 1) { Add-Pass "the row carries a revoke control ($n)" } else { Add-Fail '/issued offers no revoke control for an active record (page-map 5)' }
# Two states, not three: the list reports `active`/`revoked` and leaves expiry to the date cell, because printing "expired"
# beside "revoked" would imply this host knows what every client currently accepts.
$n = Measure-Occurrence $list '>expired<'
if ($n -eq 0) { Add-Pass "the Status column does not claim an 'expired' state" } else { Add-Fail "the Status column renders an 'expired' state (page-map 5 says two states)" }
# 0.3.0 replaced one hidden input per row with CHECKBOXES inside ONE bulk form. Counted against
# type="checkbox" name="serial_hex" deliberately: a build that kept the old per-row forms would still answer 200, still carry
# the right serials, and every section 11 assertion would then run against a shape no browser posts any more. The checkbox count
# matching the ACTIVE-row count is the same contract seen from the other side - a stamped row carries no box.
$boxes = Measure-Occurrence $list 'type="checkbox" name="serial_hex"'
$active = Measure-Occurrence $list '<span class="pill active">active</span>'
if ($boxes -eq $active -and $boxes -ge 1) { Add-Pass "one checkbox per active row and none on a revoked row ($boxes boxes, $active active)" }
else { Add-Fail "/issued offers $boxes checkboxes for $active active records (they must match exactly)" }
$n = Measure-Regex $list '<form method="post" action="/issued/revoke"'
if ($n -eq 1) { Add-Pass "/issued posts ONE bulk revoke form ($n) - the 0.2.0 per-row forms are gone" }
else { Add-Fail "/issued carries $n revoke form(s); 0.3.0 has one bulk form around the table" }
$n = Measure-Occurrence $list 'data-mypki-select-all'
if ($n -eq 1) { Add-Pass "the Select column offers the All box ($n)" } else { Add-Fail "no select-all control on /issued ($n)" }
$n = Measure-Occurrence $list '> All<'
if ($n -ge 1) { Add-Pass "the select-all control is labelled 'All'" } else { Add-Fail "the select-all box carries no label" }
# Counted on the BUTTON TAG, not on the phrase: MEASURED against a live server the bare phrase occurs 3 times on
# /issued (1 button + 2 <strong> mentions in the no-JavaScript hint), so 'exactly once' on the phrase fails against a
# correct page. The CONTROL and the BAR are what have to be singular, and the prose count is reported rather than guessed.
$btn = Measure-Occurrence $list '<button class="danger solid" type="submit">Revoke Selected</button>'
$bars = Measure-Occurrence $list 'class="select-bar"'
$phrase = Measure-Occurrence $list 'Revoke Selected'
$prose = Measure-Occurrence $list '<strong>Revoke Selected</strong>'
if ($btn -eq 1) { Add-Pass "'Revoke Selected' is offered exactly once, as one control ($btn button)" }
else { Add-Fail "'Revoke Selected' rendered $btn submit button(s); 0.4.0 has exactly one bulk control" }
if ($bars -eq 1) { Add-Pass "exactly one select bar survives above the table ($bars) - 0.3.0's bottom bar is gone" }
else { Add-Fail "/issued renders $bars select bars; 0.4.0 keeps only the one above the rows" }
if ($phrase -eq ($btn + $prose) -and $prose -ge 1) { Add-Pass "every other 'Revoke Selected' is prose, inside <strong> ($phrase mentions = $btn control + $prose prose)" }
else { Add-Fail "'Revoke Selected' appears $phrase time(s) but only $btn in a button and $prose in <strong>: an unexplained mention is a second control wearing prose's clothes" }
$n = Measure-Occurrence $list 'data-mypki-count>0 selected'
if ($n -eq 1) { Add-Pass "the selection counter starts at '0 selected' and is live from the first paint ($n)" }
else { Add-Fail "the counter above the table does not start at '0 selected' ($n) - a page that cannot count itself is guessing" }
$n = Measure-Occurrence $list 'name="csrf_token"'
if ($n -eq 1) { Add-Pass "the bulk form carries the CSRF token inside itself ($n)" }
else { Add-Fail "the revoke form's token count is ${n}: with one bulk form the token has to live inside it" }
$n = Measure-Occurrence $list 'tick rows one at a time'
if ($n -ge 1) { Add-Pass '/issued says what still works with JavaScript off (tick rows one at a time)' }
else { Add-Fail '/issued no longer states that revoking works without JavaScript' }


# =========================================================================== 11 revocation round trip (page-map 11 -> 5)
Write-Host ($script:SectionMark + '11 Revocation round trip (page-map ' + $script:SectionMark + '5)')
$RowSerial = Get-RowSerial (Join-Path $Work 'issued-list.html')
if ([string]::IsNullOrWhiteSpace($RowSerial)) {
    Add-Fail 'no revoke control carried a serial - cannot run the revocation checks'
} else {
    if ($RowSerial -eq $IssuedSerial) { Add-Pass ('the checkbox carries the ' + $script:SectionMark + "6 leaf serial, not a row position") }
    else { Add-Fail ('the revoke control carries ' + $RowSerial + ' but ' + $script:SectionMark + '6 issued ' + $IssuedSerial) }

    $token = Get-CsrfToken (Join-Path $Work 'issued-list.html')

    # STEP A - the unconfirmed POST. As of 0.3.0 this stamps NOTHING: it re-renders /issued with the confirmation block at the
    # top (page-map 5). The 0.2.0 harness asserted a revoked pill here, and that assertion is now wrong by construction: against
    # a correct 0.3.0 app it fails. Both halves are asserted - what the block says, and that the ledger is untouched.
    $status = Send-Form '/issued/revoke' (Join-Path $Work 'revoke-confirm.html') @(
        "csrf_token=$token",
        "serial_hex=$RowSerial",
        'reason=smoke harness: retired on purpose'
    )
    if ($status -eq '200') { Add-Pass 'POST /issued/revoke without confirm answers 200 (the confirmation step, not an error)' }
    else { Add-Fail "POST /issued/revoke without confirm answered $status (expected 200)" }

    $confirm = Read-Body (Join-Path $Work 'revoke-confirm.html')
    $n = Measure-Occurrence $confirm '<section class="confirm-revoke">'
    if ($n -eq 1) { Add-Pass "the unconfirmed POST renders the confirmation block ($n)" }
    else { Add-Fail "no confirm-revoke section after an unconfirmed POST ($n)" }
    $n = Measure-Occurrence $confirm 'Revoke 1 certificate?'
    if ($n -ge 1) { Add-Pass "the block counts what is at stake ('Revoke 1 certificate?')" }
    else { Add-Fail 'the confirmation block does not name how many records it is about to change' }
    $n = Measure-Occurrence $confirm 'Nothing has been changed yet.'
    if ($n -ge 1) { Add-Pass 'the block states that nothing has been changed yet' }
    else { Add-Fail 'an unconfirmed POST reads as though it had already revoked' }
    # Nothing NEW was stamped: the confirm page shows the SAME revoked pills the list page already showed (records this host
    # revoked in an earlier run legitimately keep their pills). MEASURED, and it is why a naive 'zero revoked pills' check is
    # wrong - against a ledger that already holds revoked records it fails on a correct app. What must not move is the COUNT.
    $n = Measure-Occurrence $confirm '<span class="pill revoked">revoked</span>'
    $m = Measure-Occurrence $list '<span class="pill revoked">revoked</span>'
    if ($n -eq $m) { Add-Pass "nothing was stamped before confirmation ($n revoked pills, same as the list page's $m)" }
    else { Add-Fail "an unconfirmed POST changed the revoked count ($m -> $n) - the confirmation step would be decorative" }
    $n = Measure-Occurrence $confirm '<h2>Revocation batch</h2>'
    if ($n -eq 0) { Add-Pass 'the unconfirmed POST reports no batch (nothing has been revoked yet)' }
    else { Add-Fail "an unconfirmed POST already rendered the batch card ($n)" }
    $n = Measure-Occurrence $confirm ('name="serial_hex" value="' + $RowSerial + '"')
    if ($n -ge 1) { Add-Pass "the selection is carried forward into the confirm form ($n)" }
    else { Add-Fail 'the confirmation page lost the serial it was confirming' }
    $n = Measure-Occurrence $confirm '<input type="hidden" name="confirm" value="1">'
    if ($n -eq 1) { Add-Pass "the confirm form carries confirm=1 ($n)" } else { Add-Fail "no confirm=1 control on the confirmation form ($n)" }
    $n = Measure-Occurrence $confirm 'active now'
    if ($n -ge 1) { Add-Pass "the block states what that certificate is right now ('active now')" }
    else { Add-Fail 'the confirmation names no current state for the serial it lists' }
    # 0.7.0 prose sweep, mirroring scripts/smoke_test.sh: the needle 'no CRL is published' is in NO template any more (grep
    # -rn over src/mypki/ returns zero hits). The sentence this page actually renders is issued.html:35 - grepped out of the
    # template, then confirmed live against $Work/revoke-confirm.html. Measure-Joined because the template wraps it across a
    # line break in the rendered page.
    $n = Measure-Joined (Join-Path $Work 'revoke-confirm.html') 'Revoking a record cannot be undone from this page: there is no un-revoke and no delete.'
    if ($n -ge 1) { Add-Pass "the confirmation page states what it cannot undo before asking for consent ($n)" }
    else { Add-Fail "the confirmation page asks to revoke without stating that revoking cannot be undone ($n)" }

    # STEP B - the confirmed POST, mirroring tests/test_bulk_revoke.py: the same serial plus confirm=1. This is what actually
    # stamps, and it is also the shape static/app.js's modal submits, so both paths are proven against one handler.
    $status = Send-Form '/issued/revoke' (Join-Path $Work 'revoke.html') @(
        "csrf_token=$token",
        "serial_hex=$RowSerial",
        'confirm=1',
        'reason=smoke harness: retired on purpose'
    )
    if ($status -eq '200') { Add-Pass 'POST /issued/revoke with confirm=1 answers 200' }
    else { Add-Fail "POST /issued/revoke with confirm=1 answered $status (expected 200)" }

    $revoked = Read-Body (Join-Path $Work 'revoke.html')
    $n = Measure-Occurrence $revoked '<h2>Revocation batch</h2>'
    if ($n -eq 1) { Add-Pass "the confirmed submit answers with the three-way batch card ($n)" }
    else { Add-Fail "no 'Revocation batch' card after a confirmed revoke ($n)" }
    $n = Measure-Occurrence $revoked 'stamped now,'
    if ($n -ge 1) { Add-Pass 'the batch card counts what it stamped now' } else { Add-Fail "the batch card reports no 'stamped now' count" }
    $n = Measure-Occurrence $revoked 'already revoked before this submit'
    if ($n -ge 1) { Add-Pass 'the batch card counts records already revoked before this submit' }
    else { Add-Fail "the batch card omits the 'already revoked' count - a stale tab would look like fresh revocations" }
    $n = Measure-Occurrence $revoked 'with no record on this host'
    if ($n -ge 1) { Add-Pass 'the batch card counts serials with no record here' }
    else { Add-Fail "the batch card omits the 'no record on this host' count" }
    $n = Measure-Occurrence $revoked '<span class="pill revoked">revoked</span>'
    if ($n -ge 1) { Add-Pass "the row now reports Status 'revoked'" } else { Add-Fail "no 'revoked' status pill after a confirmed revoke" }
    $n = Measure-Occurrence $revoked 'is marked revoked as of'
    if ($n -ge 1) { Add-Pass 'the card confirms the stamp with a UTC timestamp' } else { Add-Fail 'no confirmation naming the stamp' }
    $n = Measure-Occurrence $revoked 'smoke harness: retired on purpose'
    if ($n -ge 1) { Add-Pass 'the reason is stored and shown back' } else { Add-Fail 'the revoke reason did not survive the round trip' }

    # THE load-bearing assertion of this section, re-worded for 0.7.0 (mirror of the .sh half). Revoking now also re-signs a
    # CRL this host publishes (STEP F proves it), so the old framing - 'mypki publishes no CRL and no OCSP' - is false as
    # written, and its two needles ('no CRL is published') are dead: grep -rn over src/mypki/ finds neither phrase in any
    # template. What is still true, and what the page still has to say, is the client half: issued.html:230 keeps 'a revoked
    # certificate stays trusted by clients until it expires', because consulting a CRL or asking an OCSP responder is the
    # client's side of the job. Asserted on BOTH steps now: the step that asks and the step that acts.
    $n = Measure-Occurrence $revoked 'stays trusted by clients until it expires'
    if ($n -ge 1) { Add-Pass 'the page still states the client-side caveat - a revoked certificate stays trusted by clients until it expires (issued.html:230)' }
    else { Add-Fail '/issued revokes without stating the client-side caveat (this sentence is the feature honest half)' }
    # And the replacement for the dead needle, measured on the live page rather than invented: issued.html:107 names what this
    # host DOES publish now. A page that promises a CRL it does not sign would be as dishonest as one that hid the caveat.
    $n = Measure-Joined (Join-Path $Work 'revoke.html') 'From 0.7.0 this host also signs a CRL and answers OCSP'
    if ($n -ge 1) { Add-Pass "the page names the CRL/OCSP it now publishes instead of claiming revocation reaches clients ($n)" }
    else { Add-Fail "/issued does not say what 0.7.0 publishes ($n): STEP F checks the artifact, but the page has to name it too" }

    # A stamped row offers no checkbox: it cannot be re-revoked (store.revoke preserves the stamp on purpose) and there is no
    # delete. Rewritten for 0.3.0 because the assertion this replaces was false by construction - with ONE bulk form the old
    # action="/issued/revoke" count is 1 before and 1 after, so 'fell by exactly one' could never hold (MEASURED: it failed
    # against a correct app, 1 -> 2). The real contract is about the SERIAL and about CHECKBOXES.
    $n = Measure-Occurrence $revoked ('name="serial_hex" value="' + $RowSerial + '"')
    if ($n -eq 0) { Add-Pass 'no control carries the stamped serial (it cannot be re-revoked, and there is no delete)' }
    else { Add-Fail "a revoked record still offers a control for $RowSerial ($n)" }
    $before = Measure-Occurrence $list 'type="checkbox" name="serial_hex"'
    $afterBoxes = Measure-Occurrence $revoked 'type="checkbox" name="serial_hex"'
    if ($afterBoxes -eq ($before - 1)) { Add-Pass "the checkbox count fell by exactly one ($before -> $afterBoxes): the stamped row lost its box, no other row did" }
    else { Add-Fail "revoking changed the checkbox count by $($before - $afterBoxes) instead of 1 ($before -> $afterBoxes)" }
    $forms = Measure-Regex $revoked '<form method="post" action="/issued/revoke"'
    if ($forms -le 2) { Add-Pass "the confirmed page posts at most one bulk form plus the confirmation form ($forms forms)" }
    else { Add-Fail "/issued rendered $forms revoke forms - 0.3.0 has one bulk form, not a form per row" }

    # STEP C - multi-select, which is what 0.3.0 added: two real active rows plus one serial this host never signed, all in ONE
    # submit. Unconfirmed first, because the confirmation must name all three (including the unknown one) before any changes.
    $allSerials = @(Get-AllRowSerials (Join-Path $Work 'issued-list.html'))
    $others = @($allSerials | Where-Object { $_ -ne $RowSerial } | Select-Object -First 2)
    if ($others.Count -lt 2) {
        Add-Warn "only $($others.Count) other active record(s) on this host - the multi-select checks cannot run"
    } else {
        $status = Send-Form '/issued/revoke' (Join-Path $Work 'revoke-multi-confirm.html') @(
            "csrf_token=$token",
            "serial_hex=$($others[0])",
            "serial_hex=$($others[1])",
            'serial_hex=deadbeefcafebabf'
        )
        $multi = Read-Body (Join-Path $Work 'revoke-multi-confirm.html')
        $n = Measure-Occurrence $multi 'Revoke 3 certificates?'
        if ($status -eq '200' -and $n -ge 1) { Add-Pass "a three-serial submit confirms THREE before stamping any ('Revoke 3 certificates?')" }
        else { Add-Fail "multi-select confirm: status $status, 'Revoke 3 certificates?' $n" }
        $n = Measure-Occurrence $multi 'not a record on this host &mdash; it will be reported, not revoked'
        if ($n -eq 1) { Add-Pass 'the confirmation calls the unknown serial what it is (reported, not revoked)' }
        else { Add-Fail "the confirmation hides that one of the three has no record here ($n)" }
        # Compared against STEP B's page, not section 10's list: STEP B legitimately stamped one record on the way here, so the
        # starting point for THIS submit is the count the operator last saw. MEASURED (6 -> 7 after STEP B): comparing back to
        # the list page would report a correct app as stamping something it did not stamp.
        $n = Measure-Occurrence $multi '<span class="pill revoked">revoked</span>'
        $m = Measure-Occurrence $revoked '<span class="pill revoked">revoked</span>'
        if ($n -eq $m) { Add-Pass "an unconfirmed multi-select stamps nothing ($n revoked pills, unchanged from $m)" }
        else { Add-Fail "an unconfirmed multi-select moved the revoked count ($m -> $n) before confirmation" }
        $n = Measure-Occurrence $multi 'already revoked &mdash; its stamp and reason will not change'
        if ($n -eq 0) { Add-Pass 'the confirmation lists no already-stamped serial (all three are active here)' }
        else { Add-Fail "the confirmation calls $n of the three already revoked, which section 10 says they are not" }

        # STEP D - the same three confirmed. The batch must separate the two real stamps from the one miss, and a miss must not
        # 404 away the two decisions the operator did mean to make.
        $status = Send-Form '/issued/revoke' (Join-Path $Work 'revoke-multi.html') @(
            "csrf_token=$token",
            "serial_hex=$($others[0])",
            "serial_hex=$($others[1])",
            'serial_hex=deadbeefcafebabf',
            'confirm=1'
        )
        $batch = Read-Body (Join-Path $Work 'revoke-multi.html')
        $n = Measure-Occurrence $batch '2 stamped now,'
        if ($status -eq '200' -and $n -ge 1) { Add-Pass "a mixed batch stamps the two records it owns ('2 stamped now,')" }
        else { Add-Fail "mixed batch: status $status, '2 stamped now,' $n" }
        $n = Measure-Occurrence $batch '0 already revoked before this submit'
        if ($n -ge 1) { Add-Pass 'the batch counts zero already-revoked (true here, and stated rather than left blank)' }
        else { Add-Fail 'the batch card does not state its already-revoked count' }
        $n = Measure-Occurrence $batch '1 with no record on this host'
        if ($n -ge 1) { Add-Pass 'the batch counts the one serial with no record here' } else { Add-Fail 'the batch hides the miss it was given' }
        # MEASURED byte-for-byte: the apostrophe here is plain ASCII (od reads h o s t ' s database) - Jinja autoescape leaves a
        # typographic apostrophe raw, and this one is not typographic. Asserting the numeric entity would fail against a correct
        # page. Single-quoted so the apostrophe needs no escaping.
        $n = Measure-Occurrence $batch "no record with that serial in this host's database &mdash; nothing was changed"
        if ($n -ge 1) { Add-Pass 'the batch names the missed serial plainly, with what it did NOT do' }
        else { Add-Fail 'the batch reports a miss without naming it and saying nothing was changed' }
        $n = Measure-Occurrence $batch 'deadbeefcafebabf'
        if ($n -ge 1) { Add-Pass 'the missed serial is printed, not hidden behind a count' } else { Add-Fail 'the batch counted the miss but never named the serial' }

        # STEP E - re-submitting the serial STEP B already stamped. store.revoke refuses to move an existing stamp, so this must
        # read as '0 stamped now' / '1 already revoked', with the original reason still shown back. This is the stale-tab case
        # the three-way card exists for.
        $status = Send-Form '/issued/revoke' (Join-Path $Work 'revoke-again.html') @(
            "csrf_token=$token",
            "serial_hex=$RowSerial",
            'confirm=1',
            'reason=second submit from a stale tab'
        )
        $again = Read-Body (Join-Path $Work 'revoke-again.html')
        $n = Measure-Occurrence $again '0 stamped now,'
        $k = Measure-Occurrence $again '1 already revoked before this submit'
        if ($status -eq '200' -and $n -ge 1 -and $k -ge 1) { Add-Pass "re-submitting a stamped serial stamps nothing ('0 stamped now,' '1 already revoked')" }
        else { Add-Fail "re-revoke: status $status, '0 stamped now,' $n, '1 already revoked' $k" }
        $n = Measure-Occurrence $again 'smoke harness: retired on purpose'
        if ($n -ge 1) { Add-Pass 'the original stamp and reason survive a second submit (not overwritten by the new one)' }
        else { Add-Fail 'a re-revoke lost the reason recorded by the first one' }
        $n = Measure-Occurrence $again 'already revoked &mdash; its stamp and reason were left alone'
        if ($n -ge 1) { Add-Pass 'the card says what it did NOT do to that record' } else { Add-Fail 'the card does not say the existing stamp was left alone' }
    }

    # And it survives a plain GET, which is what an operator does next (refresh, bookmark, another browser).
    $status = Get-Page '/issued' (Join-Path $Work 'issued-after.html')
    $after = Read-Body (Join-Path $Work 'issued-after.html')
    $n = Measure-Occurrence $after '<span class="pill revoked">revoked</span>'
    # Three stamps is the precondition section 6's seeding block now guarantees, so `>= 3` is a real expectation rather
    # than a hope that the host happened to hold extra records.
    if ($status -eq '200' -and $n -ge 3) { Add-Pass "the revoked state survives a plain GET /issued ($n revoked pills after at least three stamps)" }
    else { Add-Fail "GET /issued after revoking: status $status, 'revoked' pills $n (expected at least 3 - section 6 seeds two extra records so three stamps are reachable)" }
    $n = Measure-Occurrence $after ('name="serial_hex" value="' + $RowSerial + '"')
    if ($n -eq 0) { Add-Pass 'a plain GET still offers no control for a stamped serial' }
    else { Add-Fail "GET /issued re-offered a control for the stamped serial ($n)" }
    # The stamp moved into the Status cell when the Revoked column was deleted: same shape (`class="hint">revoked
    # YYYY-MM-DD...`), one fewer place for a reader to look, and one fewer place for two cells to disagree.
    $n = Measure-Regex $after 'class="hint">revoked [0-9]{4}-[0-9]{2}-[0-9]{2}'
    if ($n -ge 3) { Add-Pass "the Status cell reads as a dated decision ('revoked YYYY-MM-DD...', $n)" }
    else { Add-Fail "the Status cell carries no revocation stamp ($n)" }
    $n = Measure-Occurrence $after '<th scope="col">Revoked</th>'
    if ($n -eq 0) { Add-Pass "the list has no separate Revoked column any more ($n)" }
    else { Add-Fail "/issued still renders a Revoked column ($n) while claiming the Status cell carries the stamp" }

    # ------------------------------------------------------------------- STEP F - the CRL and the OCSP answer this walk earned
    #
    # Everything above stamped revocations. From 0.7.0 that means two more artifacts exist and can be checked: a signed CRL
    # on disk (GET /crl, GET /crl.pem) and a responder that answers for one serial (POST /ocsp). Asserted at the END of
    # section 11 rather than in section 5 because section 11 is what creates the revoked rows an entry and an answer are about:
    # against a ledger with nothing stamped, almost any CRL assertion passes vacuously. This block is the mirror of
    # scripts/smoke_test.sh's STEP F and is edited together with it.
    #
    # NO openssl (plan U7: ci.yml's "NO OpenSSL binary is required anywhere" is a contract, and this harness exists to be run
    # where no toolchain is installed) and NO DER parser in PowerShell: [Convert]::FromBase64String + ReadAllBytes read bytes and
    # WriteAllBytes writes them (see the 0.7.0 helpers above).
    #
    # THE MARKERS ARE MEASURED, not inferred - every one produced twice, once through cryptography/openssl in plan 2 and again
    # against THIS build's responder with a zeroed-hash CertID (see SMOKE_TESTING.md "0.7.0"):
    #   * bytes 4..6 of a successful answer are '0a 01 00' (OCSPResponseStatus SUCCESSFUL) - the one offset this file does
    #     assert, because it is fixed by RFC 6960 4.2.1's outer SEQUENCE, not by anything mypki chooses;
    #   * CertStatus sits immediately after the response's copy of the request's serial INTEGER: GOOD '80 00', UNKNOWN '82 00',
    #     REVOKED 'a1 16 ... a0 03 0a 01 00' (the revokedReason SEQUENCE holding 'unspecified');
    #   * a refusal is the whole body: '30 03 0a 01 01' MALFORMED_REQUEST and '30 03 0a 01 02' INTERNAL_ERROR, both at HTTP 200.
    #     At this endpoint an error is a body, never a status code - the one place in mypki where the usual "every rejection gets
    #     an HTML page with a telling status" rule is suspended on purpose.
    # NOTHING below asserts a response LENGTH or an absolute CertStatus offset: MEASURED sizes for this harness's RSA-3072 scratch
    # CA are 1704 B (GOOD), 1704 B (UNKNOWN) and 1735 B (REVOKED), while plan 2 measured 1778/1781/1805 for a different 3072-bit
    # CA and 1841/1863 with SHA-256 + nonce. A size assertion would be a measurement of one key. The status search is also SCOPED
    # to the bytes between the serial field and the signature's AlgorithmIdentifier ('30 0d 06 09'): MEASURED over 300 signed
    # REVOKED answers, '8000'/'8200' appear somewhere in the body 7 times out of 300 - inside random signature bytes - and 0 times
    # out of 300 inside that region. Unscoped, this section would flake.
    $walkStamps = 1                                   # STEP B stamped one serial on the way here
    $multiFile = Join-Path $Work 'revoke-multi.html'
    $stampedSerials = @($RowSerial)
    if ((Test-Path -LiteralPath $multiFile -PathType Leaf) -and ((Get-Item -LiteralPath $multiFile).Length -gt 0)) {
        $walkStamps += 2                              # STEP D's batch stamped two more
        $stampedSerials += @($others[0], $others[1])
    }

    $status = Get-Page '/crl' (Join-Path $Work 'crl.html')
    if ($status -eq '200') { Add-Pass 'GET /crl answers 200 (the page, not just the artifact)' }
    else { Add-Fail "GET /crl answered $status (expected 200)" }
    $crlPage = Read-Body (Join-Path $Work 'crl.html')
    $n = Measure-Occurrence $crlPage '-----BEGIN X509 CRL-----'
    if ($n -eq 1) { Add-Pass "/crl renders exactly one CRL armour block ($n)" }
    else { Add-Fail "/crl renders $n CRL armour blocks (expected 1: the page shows the artifact it is describing)" }
    $n = Measure-Occurrence $crlPage 'id="pem-crl"'
    if ($n -eq 1) { Add-Pass "/crl's PEM block has its own id, so the copy button can point at it ($n)" }
    else { Add-Fail "/crl renders no pem-crl block ($n)" }
    $n = Measure-Occurrence $crlPage 'data-mypki-copy="pem-crl"'
    if ($n -eq 1) { Add-Pass "/crl's copy button points at that block ($n)" } else { Add-Fail "/crl has no copy button wired to pem-crl ($n)" }
    $n = Measure-Regex $crlPage '<td>[0-9]+ revoked certificate'
    if ($n -eq 1) { Add-Pass "/crl states its entry count once, in words ($n)" }
    else { Add-Fail "/crl's Entries row is not the one documented row ($n)" }
    $crlEntriesMatch = [regex]::Match($crlPage, '<td>([0-9]+) revoked certificate')
    $crlEntries = if ($crlEntriesMatch.Success) { [int]$crlEntriesMatch.Groups[1].Value } else { -1 }
    if ($crlEntries -eq $walkStamps) {
        Add-Pass "the published CRL lists exactly the $walkStamps revocation(s) this walk stamped ($crlEntries entries)"
    } else {
        Add-Fail "/crl reports $crlEntries entries but this walk stamped $walkStamps - the artifact and the ledger disagree"
    }
    $n = Measure-Occurrence $crlPage 'What this CRL does not do'
    if ($n -eq 1) { Add-Pass "/crl carries the honest-limits card (page-map $($script:SectionMark)14's four measured caveats) ($n)" }
    else { Add-Fail "/crl renders no 'does not do' card ($n): an artifact with unstated limits is a page that overstates itself" }
    $n = Measure-Occurrence $crlPage 'What the OCSP responder does not do'
    if ($n -eq 1) { Add-Pass "/crl carries the OCSP limits card (echoed hashes, the two size caps, no CSRF) ($n)" }
    else { Add-Fail "/crl renders no OCSP limits card ($n)" }

    $status = Get-Page '/crl.pem' (Join-Path $Work 'crl.pem')
    if ($status -eq '200') { Add-Pass 'GET /crl.pem answers 200 (the URL certificates issued from 0.7.0 carry)' }
    else { Add-Fail "GET /crl.pem answered $status (expected 200)" }
    # Get-HeadersOf, not a stale headers.txt: Get-Page writes only the BODY, so reading a header dump here would count the headers
    # of whatever request last wrote that file and every media-type assertion below would pass against the wrong response.
    # Get-HeadersOf re-Gets the same path (that is what fills headers.txt) and is called HERE, immediately, before any other
    # Get-HeadersOf call can overwrite the file - the one ordering rule this block has to keep.
    $pemHeaders = (Get-HeadersOf '/crl.pem').ToLower()
    $n = Measure-Occurrence $pemHeaders 'content-type: application/pkix-crl'
    if ($n -eq 1) { Add-Pass "/crl.pem declares application/pkix-crl, so a client need not guess from the filename ($n)" }
    else { Add-Fail "/crl.pem's media type is not application/pkix-crl ($n) - page-map $($script:SectionMark)14 names this header as the point of the route" }
    $n = Measure-Occurrence $pemHeaders 'content-disposition: attachment; filename="mypki.crl.pem"'
    if ($n -eq 1) { Add-Pass "/crl.pem is an attachment named mypki.crl.pem ($n)" } else { Add-Fail "/crl.pem's Content-Disposition is wrong ($n)" }
    $n = Measure-Occurrence $pemHeaders 'cache-control: no-store'
    if ($n -eq 1) { Add-Pass "/crl.pem is not cacheable (a proxy replaying a 24 h-old CRL keeps a revoked certificate trusted) ($n)" }
    else { Add-Fail "/crl.pem is cacheable ($n)" }

    $n = Measure-Occurrence (Read-Body (Join-Path $Work 'crl.pem')) '-----BEGIN X509 CRL-----'
    if ($n -eq 1) { Add-Pass "the download contains exactly one armour block ($n)" }
    else { Add-Fail "the /crl.pem download contains $n armour blocks (expected 1)" }
    $crlDerHex = Get-CrlPemDerHex (Join-Path $Work 'crl.pem')
    if ([string]::IsNullOrEmpty($crlDerHex)) {
        Add-Fail "/crl.pem's base64 body could not be decoded - nothing below about entries can be checked"
    } else {
        Add-Pass "/crl.pem decodes to $($crlDerHex.Length / 2) bytes of DER (read with FromBase64String + ReadAllBytes, no openssl)"
        # Every serial this walk stamped has to be IN the artifact. This is the assertion that makes the revoke->publish link
        # real: a CRL that says "3 entries" and lists three other serials would pass every count above.
        foreach ($serial in $stampedSerials) {
            $value = Get-DerIntegerHex $serial
            $field = '02' + ([int]($value.Length / 2)).ToString('x2') + $value
            $n = Measure-Occurrence $crlDerHex $field
            if ($n -eq 1) { Add-Pass "the CRL lists the stamped serial $($serial.Substring(0, 12))... as DER INTEGER $field ($n)" }
            else { Add-Fail "the published CRL does not carry the stamped serial $serial as $field (found $n) - a revoked row with no entry" }
        }
        # '170d' is UTCTime's tag+length ('17 0d', thirteen content bytes: YYYYMMDDHHMMSSZ). MEASURED across CRLs holding 0, 1,
        # 3 and 5 entries: exactly entry_count + 2 (thisUpdate + nextUpdate), which is why it counts entries here. It is a
        # cross-check on the page's number, not a substitute for the serial search above.
        $n = Measure-Occurrence $crlDerHex '170d'
        if ($n -eq ($crlEntries + 2)) { Add-Pass "the decoded artifact holds $($n - 2) revocationDate fields plus thisUpdate/nextUpdate ($n UTCTime fields)" }
        else { Add-Fail "the decoded artifact carries $n UTCTime fields, not entries($crlEntries)+2 - the page's count and the bytes disagree" }
        # The four extension markers, each named by its DOTTED OID NUMBER and asserted on the DER encoding of that number
        # ('06 03 55 1d XX' = OBJECT IDENTIFIER with 3 content bytes: the first folds arcs {2,5} into 2*40+5 = 85 = 0x55, the
        # second is arc 29 = 0x1d, so any 2.5.29.NN OID is '0603551d' followed by NN as one hex byte). MEASURED with
        # /tmp/s11/probe_crl4.py against a CRL this build signed for 3 entries: extensions read [('2.5.29.20', 'CRLNumber'),
        # ('2.5.29.35', 'AuthorityKeyIdentifier')] and the marker census on the decoded body was 0603551d14 = 1, 0603551d23 = 1,
        # 0603551d1c = 0, 0603551d1b = 0. Labeling these is the trap this comment exists for: CRLNumber is 2.5.29.20
        # ('...1d14', NOT '...1d23'), AKI is 2.5.29.35 ('...1d23', NOT '...1d1c', which is IDP's number at 2.5.29.28), and
        # DeltaCRLIndicator is 2.5.29.27 ('...1d1b'). A marker asserted against the wrong name would pass while proving nothing
        # about the extension it claims to name.
        $n = Measure-Occurrence $crlDerHex '0603551d14'
        if ($n -eq 1) { Add-Pass "the CRL carries CRLNumber, OID 2.5.29.20 = '06 03 55 1d 14' (RFC 5280 5.2.1: it counts stamps, so it never decreases) ($n)" }
        else { Add-Fail "the published CRL has no CRLNumber extension (OID 2.5.29.20 / 0603551d14 found $n time(s))" }
        $n = Measure-Occurrence $crlDerHex '0603551d23'
        if ($n -eq 1) { Add-Pass "the CRL carries an AuthorityKeyIdentifier, OID 2.5.29.35 = '06 03 55 1d 23', so a client can tell which CA signed it ($n)" }
        else { Add-Fail "the published CRL has no AKI (OID 2.5.29.35 / 0603551d23 found $n time(s))" }
        $n = Measure-Occurrence $crlDerHex '0603551d1c'
        if ($n -eq 0) { Add-Pass "the CRL carries no IssuingDistributionPoint, OID 2.5.29.28 = '06 03 55 1d 1c' (plan 4 measured why: an IDP-scoped CRL answers error 44 'different CRL scope' for every pre-0.7 leaf) ($n)" }
        else { Add-Fail "the published CRL grew an IssuingDistributionPoint (OID 2.5.29.28 / 0603551d1c found $n time(s)) - that would make -crl_check unusable on this CA's own history" }
        $n = Measure-Occurrence $crlDerHex '0603551d1b'
        if ($n -eq 0) { Add-Pass "the CRL carries no DeltaCRLIndicator, OID 2.5.29.27 = '06 03 55 1d 1b' (no delta CRL is published, so none may be claimed) ($n)" }
        else { Add-Fail "the published CRL grew a DeltaCRLIndicator (OID 2.5.29.27 / 0603551d1b found $n time(s))" }
    }

    # --- POST /ocsp: three answers, all of them HTTP 200 with the status inside the body.
    $ocspUnused = '0badc0de0badc0de0badc0de0badc0de'   # fixed, and never signed by any scratch CA: find() finds nothing
    Write-DerBytesFromHex (Get-OcspRequestDerHex $ocspUnused) (Join-Path $Work 'ocsp-unknown.der')
    $status = Send-Der '/ocsp' (Join-Path $Work 'ocsp-unknown.resp') (Join-Path $Work 'ocsp-unknown.der') 'application/ocsp-request' (Join-Path $Work 'ocsp-unknown-hdrs.txt')
    if ($status -eq '200') { Add-Pass 'POST /ocsp answers 200 for a serial this host never signed (the status is in the body)' }
    else { Add-Fail "POST /ocsp answered $status for an unknown serial (expected 200: a protocol answer is not an HTTP error)" }
    $ocspHdrs = (Read-Body (Join-Path $Work 'ocsp-unknown-hdrs.txt')).ToLower()
    $n = Measure-Occurrence $ocspHdrs 'content-type: application/ocsp-response'
    # Double-quoted because the message contains an apostrophe: PowerShell has no bash-style '\"'\"' splice, and writing one
    # here is a parse error at load time rather than a failed assertion.
    if ($n -eq 1) { Add-Pass "/ocsp answers application/ocsp-response (DER, not mypki's HTML) ($n)" }
    else { Add-Fail "/ocsp's media type is not application/ocsp-response ($n) - a client that expects DER cannot read HTML" }
    $n = Measure-Occurrence $ocspHdrs 'cache-control: no-store'
    if ($n -eq 1) { Add-Pass "/ocsp answers are not cacheable ($n)" } else { Add-Fail "/ocsp is cacheable ($n): a replayed GOOD outlives the revocation it used to describe" }
    $n = Measure-Occurrence $ocspHdrs 'content-disposition'
    if ($n -eq 0) { Add-Pass '/ocsp sends no Content-Disposition (these bytes are consumed by a library, not saved) ($n)' }
    else { Add-Fail "/ocsp attaches a filename to DER a browser would offer to download ($n)" }

    $unknownHex = Get-DerHexFromFile (Join-Path $Work 'ocsp-unknown.resp')
    $statusBytes = if ($unknownHex.Length -ge 14) { $unknownHex.Substring(8, 6) } else { '' }
    if ($statusBytes -eq '0a0100') { Add-Pass "the unknown-serial answer reports OCSPResponseStatus SUCCESSFUL at bytes 4..6 ($statusBytes)" }
    else { Add-Fail "the unknown-serial answer's responseStatus is not 0a0100 (got $statusBytes) - RFC 6960 4.2.1's outer SEQUENCE moved" }
    $value = Get-DerIntegerHex $ocspUnused
    $region = Get-AfterSerialHex $unknownHex $value 0
    if ($region.StartsWith('8200')) {
        Add-Pass "a serial with no record here answers UNKNOWN ('82 00' right after the serial) - not GOOD, which would claim knowledge of a certificate this CA never signed"
    } else {
        $head = if ($region.Length -ge 4) { $region.Substring(0, 4) } else { $region }
        Add-Fail "the unknown serial did not answer UNKNOWN (region starts $head, expected 8200)"
    }

    Write-DerBytesFromHex (Get-OcspRequestDerHex $RowSerial) (Join-Path $Work 'ocsp-revoked.der')
    $status = Send-Der '/ocsp' (Join-Path $Work 'ocsp-revoked.resp') (Join-Path $Work 'ocsp-revoked.der') 'application/ocsp-request' (Join-Path $Work 'ocsp-revoked-hdrs.txt')
    if ($status -eq '200') { Add-Pass 'POST /ocsp answers 200 for the serial section 11 revoked' }
    else { Add-Fail "POST /ocsp answered $status for the revoked serial (expected 200)" }
    $revokedHex = Get-DerHexFromFile (Join-Path $Work 'ocsp-revoked.resp')
    $statusBytes = if ($revokedHex.Length -ge 14) { $revokedHex.Substring(8, 6) } else { '' }
    if ($statusBytes -eq '0a0100') { Add-Pass 'the revoked answer reports SUCCESSFUL at bytes 4..6' }
    else { Add-Fail "the revoked answer's responseStatus is not 0a0100 (got $statusBytes)" }
    $value = Get-DerIntegerHex $RowSerial
    $region = Get-AfterSerialHex $revokedHex $value 0
    # Cut the region at the signature's AlgorithmIdentifier ('30 0d 06 09'): everything after it is random RSA bytes, and
    # MEASURED those bytes carry '8000'/'8200' in 7 of 300 answers. Scoping is what makes the absence below an assertion.
    $cut = $region.IndexOf('300d0609', [System.StringComparison]::Ordinal)
    if ($cut -ge 0) { $region = $region.Substring(0, $cut) }
    if ($region.StartsWith('a116')) {
        Add-Pass "the revoked serial answers REVOKED ('a1 16', the revocationInfo SEQUENCE, right after the serial)"
    } else {
        $head = if ($region.Length -ge 4) { $region.Substring(0, 4) } else { $region }
        Add-Fail "the revoked serial did not answer REVOKED (region starts $head, expected a116) - /issued stamped it and this responder does not know"
    }
    $n = Measure-Occurrence $region 'a0030a0100'
    if ($n -eq 1) { Add-Pass "the REVOKED answer carries revokedReason = unspecified ('a0 03 0a 01 00') - the store's reason is prose, and inventing a code from it would be a lie (plan U6) ($n)" }
    else { Add-Fail "the REVOKED answer states no revocation reason ($n): RFC 5280 5.3.1 says an absent code means unspecified, so say it" }
    $good = Measure-Occurrence $region '8000'
    $unknownCount = Measure-Occurrence $region '8200'
    if ($good -eq 0 -and $unknownCount -eq 0) { Add-Pass "the REVOKED answer says nothing else about this serial (no GOOD '8000', no UNKNOWN '8200' in its singleResponse: $good/$unknownCount)" }
    else { Add-Fail "one body claims two statuses for the same serial (GOOD=$good UNKNOWN=$unknownCount inside the singleResponse)" }

    Write-DerBytesFromHex '30423040303e303c303a300906052b0e03021a05000414' (Join-Path $Work 'ocsp-garbage.der')
    [System.IO.File]::WriteAllBytes((Join-Path $Work 'ocsp-garbage2.der'), [System.Text.Encoding]::UTF8.GetBytes('not-an-ocsp-request'))
    $status = Send-Der '/ocsp' (Join-Path $Work 'ocsp-garbage.resp') (Join-Path $Work 'ocsp-garbage.der') 'application/ocsp-request' ''
    if ($status -eq '200') { Add-Pass 'POST /ocsp answers 200 to a truncated request (it refuses inside the body, as RFC 6960 4.2 requires)' }
    else { Add-Fail "POST /ocsp answered $status for garbage (expected 200 - mypki's HTML 4xx rule is suspended at this route on purpose)" }
    $garbageHex = Get-DerHexFromFile (Join-Path $Work 'ocsp-garbage.resp')
    if (($garbageHex.Length -eq 10) -and ($garbageHex -eq '30030a0101')) { Add-Pass "the refusal is byte-exact MALFORMED_REQUEST: '30 03 0a 01 01', five bytes, unsigned (measured spelling)" }
    else { Add-Fail "the malformed-request answer is $($garbageHex.Length / 2) bytes ($garbageHex), not 30030a0101 - a client reads a wrong refusal as a dead responder" }
    $status = Send-Der '/ocsp' (Join-Path $Work 'ocsp-garbage2.resp') (Join-Path $Work 'ocsp-garbage2.der') 'application/ocsp-request' ''
    $garbage2Hex = Get-DerHexFromFile (Join-Path $Work 'ocsp-garbage2.resp')
    if (($status -eq '200') -and ($garbage2Hex -eq '30030a0101')) { Add-Pass "text where DER was expected gets the same five-byte refusal (status $status)" }
    else { Add-Fail "non-DER body: status $status, body $garbage2Hex ($($garbage2Hex.Length / 2) bytes), expected 200 + 30030a0101" }
}


# =========================================================================== 12 About + Settings (page-map 12)
Write-Host ($script:SectionMark + '12 About and Settings (page-map ' + $script:SectionMark + '12)')
$status = Get-Page '/about' (Join-Path $Work 'about.html')
if ($status -eq '200') { Add-Pass 'GET /about answers 200' } else { Add-Fail "GET /about answered $status" }
$about = Read-Body (Join-Path $Work 'about.html')
if (-not [string]::IsNullOrWhiteSpace($Version)) {
    $n = Measure-Occurrence $about "mypki $Version"
    if ($n -ge 1) { Add-Pass '/about names the running version' } else { Add-Fail "/about does not name version $Version" }
}
# Single-quoted pattern on purpose: it contains `"` characters, and this is the trap scripts/smoke_test.sh hit when the
# equivalent needle was spelled inside double quotes (a syntax error at parse time, not a failed assertion).
$n = Measure-Regex $about '<a href="https://github\.com/[^"]*/mypki"'
if ($n -ge 1) { Add-Pass '/about links the source URL, so a problem can be cited against a build' }
else { Add-Fail '/about has no source link' }
# 0.5.0: the 'what this host is running' card moved to the TOP of /about, above the lede and the profile hero. Its rows
# are what a problem report quotes (version + source URL) and what tells you whether this host is on TLS or plain HTTP,
# so they belong before the prose rather than after it. Asserted as offsets for the same reason the other /about checks
# are not: every one of these needles was already present somewhere on the page, so presence could not see the move.
$runningOffset = Get-OffsetOf $about 'What this host is running'
$ledeOffset = Get-OffsetOf $about '<p class="lede">'
$profilesOffset = Get-OffsetOf $about 'What the three profiles mean'
if ($runningOffset -eq -1) {
    Add-Fail "/about no longer renders the 'what this host is running' card"
} elseif ($ledeOffset -ne -1 -and $runningOffset -lt $ledeOffset -and $profilesOffset -ne -1 -and $runningOffset -lt $profilesOffset) {
    Add-Pass "/about leads with the running-host card (card $runningOffset < lede $ledeOffset < profiles $profilesOffset)"
} else {
    Add-Fail "/about does not lead with the running-host card (got card=$runningOffset lede=$ledeOffset profiles=$profilesOffset)"
}

# 0.7.0 prose sweep, mirroring scripts/smoke_test.sh: the old needle 'No published CRL or OCSP' is gone from about.html -
# grep -rn over src/mypki/ finds no such phrase. The card is still there and its first row now opens with the sentence that
# replaced the claim (about.html:58, grepped from the template and confirmed live against $Work/about.html): publishing began,
# and reaching a client is still the client's side of the job.
$n = Measure-Occurrence $about 'What this CA does not do (yet)'
if ($n -ge 1) { Add-Pass "/about still carries the 'does not do (yet)' card" } else { Add-Fail "/about dropped the 'does not do (yet)' card" }
$n = Measure-Joined (Join-Path $Work 'about.html') 'Revocation reaches only clients that go looking for it.'
if ($n -ge 1) { Add-Pass "/about states the 0.7.0 revocation caveat: a CRL and an OCSP answer exist here, and consulting them is the client's side" }
else { Add-Fail "/about omits the 0.7.0 revocation caveat ($n) - 'does not do (yet)' must say what HAS changed as well as what has not" }
# The profiles in words, from signing.CERT_PROFILE_HELP. These are the sentences users asked for after 0.1.0 shipped the
# radio buttons with no explanation at all.
foreach ($pair in @(
    @('This is the web-server profile', 'the server profile says what it IS'),
    @('It will NOT make a browser trust a web site', 'the client profile says what it does NOT do')
)) {
    $n = Measure-Occurrence $about $pair[0]
    if ($n -ge 1) { Add-Pass "$($pair[1]) present on /about" } else { Add-Fail "$($pair[1]) missing from /about ($($pair[0]))" }
}

$status = Get-Page '/settings' (Join-Path $Work 'settings.html')
if ($status -eq '200') { Add-Pass 'GET /settings answers 200' } else { Add-Fail "GET /settings answered $status" }
$settingsPage = Read-Body (Join-Path $Work 'settings.html')
$n = Measure-Occurrence $settingsPage 'MYPKI_VALIDITY_MAX_DAYS'
if ($n -ge 1) { Add-Pass '/settings lists MYPKI_VALIDITY_MAX_DAYS' } else { Add-Fail '/settings does not list the validity ceiling knob' }
# Both honest spellings are accepted: _SECRET_KEY_PRESENT is 'set (value not displayed)' and _SECRET_KEY_ABSENT is
# 'unset - mypki generated one into the data dir at startup (not displayed)'. A serve never given MYPKI_SECRET_KEY shows
# the second. Exactly ONE must appear, so the page cannot hedge by printing both.
$present = Measure-Occurrence $settingsPage 'set (value not displayed)'
$generatedOne = Measure-Occurrence $settingsPage 'generated one into the data dir at startup (not displayed)'
if (($present + $generatedOne) -eq 1) { Add-Pass "MYPKI_SECRET_KEY renders as a presence flag, not a value (present=$present generated-one=$generatedOne)" }
else { Add-Fail "/settings states the session secret $($present + $generatedOne) time(s); exactly one masked spelling must appear" }
$n = Measure-Occurrence $settingsPage 'indistinguishable here'
if ($n -ge 1) { Add-Pass '/settings states that .env vs shell vs CLI flag cannot be told apart' }
else { Add-Fail '/settings implies a precision the process cannot have (no indistinguishable statement)' }

# 0.3.0 made /settings EDITABLE. What is asserted below is a refusal and its CONSEQUENCE, not just the wording: each refused
# save is checked against a fingerprint of this host's real config file, so "nothing was written" is an assertion rather than a
# hope. A successful save is deliberately NOT exercised here - that would write into the operator's own %APPDATA%\mypki\ (or
# $XDG_CONFIG_HOME/mypki/) from a script whose job is only to look. The write path, the 0600 mode, the preserved unmanaged
# lines and the restart wording are covered by tests/test_settings_save.py against a temporary config dir.
$n = Measure-Occurrence $settingsPage '<button class="save-settings" type="submit">Save Settings</button>'
if ($n -eq 1) { Add-Pass "/settings renders its Save button ($n)" }
else { Add-Fail "/settings has no Save button ($n) - the page is read-only again while claiming to save" }

$knobs = Measure-Regex $settingsPage 'name="MYPKI_[A-Z0-9_]+"'
if ($knobs -ge 20) { Add-Pass "/settings renders one control per editable knob ($knobs)" }
else { Add-Fail "/settings renders only $knobs MYPKI_* controls - a knob lost its input, so a save would post nothing for it" }

# Same two-spelling contract, checked on the card specifically: the knob is named as <code> and never as a control.
$cardMark = $settingsPage.IndexOf('Not editable here')
$cardEnd = if ($cardMark -ge 0) { $settingsPage.IndexOf('</section>', $cardMark) } else { -1 }
$card = if ($cardMark -ge 0 -and $cardEnd -gt $cardMark) { $settingsPage.Substring($cardMark, $cardEnd - $cardMark) } else { '' }
$cardPresent = Measure-Occurrence $card 'set (value not displayed)'
$cardGenerated = Measure-Occurrence $card 'generated one into the data dir at startup (not displayed)'
if (($cardPresent + $cardGenerated) -eq 1) { Add-Pass "the unmanaged card states the secret's presence once, masked ($($cardPresent + $cardGenerated))" }
else { Add-Fail "the 'Not editable here' card states the secret $cardPresent + $cardGenerated time(s)" }
if ((Measure-Occurrence $card 'name="MYPKI_SECRET_KEY"') -eq 0) { Add-Pass 'the card carries no control for MYPKI_SECRET_KEY' }
else { Add-Fail "the 'Not editable here' card grew a form control for the session secret" }

$configMatch = [regex]::Match($settingsPage, 'saved to <code>([^<]*)</code>')
if (-not $configMatch.Success) {
    Add-Fail '/settings never names the file a save writes - the refusal checks below have nothing to compare against'
} else {
    $configFile = $configMatch.Groups[1].Value
    Add-Pass "/settings names the file a save writes ($configFile)"
    $fileBefore = Get-FileState $configFile

    # The bound in the refusal is read from the SAME control the page renders (min= / max=), which app.py fills from the same
    # Field(ge=..., le=...) metadata pydantic enforces. Asserting against THIS number rather than a literal keeps the harness
    # and config.py on one fact: move the knob in config.py and both the input's max= and the expected sentence move with it.
    $portMin = Get-KnobBound (Join-Path $Work 'settings.html') 'MYPKI_PORT' 'min'
    $portMax = Get-KnobBound (Join-Path $Work 'settings.html') 'MYPKI_PORT' 'max'
    if ([string]::IsNullOrWhiteSpace($portMin) -or [string]::IsNullOrWhiteSpace($portMax)) {
        Add-Fail "the port input declares no range (got min=$portMin max=$portMax) - the form would accept anything a browser typed"
    } else {
        Add-Pass "the port input declares its allowed range ($portMin to $portMax, from config.py's Field)"
        $badPort = [int]$portMax + 1
        if (-not (Write-SettingsFormBody (Join-Path $Work 'settings.html') (Join-Path $Work 'save-badport.txt') @("MYPKI_PORT=$badPort"))) {
            Add-Fail 'could not build the settings form body from the page'
        } else {
            $status = Send-Body '/settings' (Join-Path $Work 'save-badport.html') (Join-Path $Work 'save-badport.txt')
            $badSave = Read-Body (Join-Path $Work 'save-badport.html')
            $n = Measure-Occurrence $badSave 'Not saved &mdash; fix this and submit again'
            if ($status -eq '200' -and $n -ge 1) { Add-Pass "an out-of-range save answers 200 with the amber 'Not saved' block (not a 500)" }
            else { Add-Fail "out-of-range save: status $status, 'Not saved' block $n" }
            $n = Measure-Occurrence $badSave ('MYPKI_PORT must be ' + $portMin + ' to ' + $portMax + '; you entered an invalid value.')
            if ($n -ge 1) { Add-Pass "the refusal names the knob and the bound it failed ($portMin to $portMax)" }
            else { Add-Fail "the refusal does not name MYPKI_PORT's bound - an operator cannot fix a field from a message that omits it" }
            $n = Measure-Occurrence $badSave ('value="' + $badPort + '"')
            if ($n -ge 1) { Add-Pass "the rejected value is still filled in ($badPort) rather than lost" }
            else { Add-Fail 'a rejected save threw away what the operator typed' }
            $n = Measure-Occurrence $badSave ('Nothing was written to <code>' + $configFile + '</code>')
            if ($n -ge 1) { Add-Pass 'the refusal states plainly that nothing was written' }
            else { Add-Fail 'the refusal does not say the file was left alone' }
            $fileAfter = Get-FileState $configFile
            if ($fileAfter -eq $fileBefore) { Add-Pass "a refused save changed nothing on disk (config file state unchanged: $fileAfter)" }
            else { Add-Fail "a REFUSED save modified $configFile ($fileBefore -> $fileAfter)" }
        }

        # An EMPTY box, not a missing knob. MEASURED correction that matters here: app.py's _submitted_settings_fields fills any
        # knob the body omitted with '' (or 'false' for the one checkbox), so DELETING a field from this body would NOT reach
        # validate_candidate's "was not submitted" arm - it would land on log_to_console=false, VALIDATE, and WRITE the
        # operator's real config file from a script whose job is only to look. So the empty value is posted explicitly, and the
        # knob chosen is one of _EMPTY_IS_NOT_A_VALUE (host/ca_cn/log_level): an empty box there is refused rather than silently
        # reverting to a default behind the operator's back.
        if (-not (Write-SettingsFormBody (Join-Path $Work 'settings.html') (Join-Path $Work 'save-empty.txt') @('MYPKI_HOST='))) {
            Add-Fail 'could not build the empty-knob body'
        } else {
            $status = Send-Body '/settings' (Join-Path $Work 'save-empty.html') (Join-Path $Work 'save-empty.txt')
            $emptySave = Read-Body (Join-Path $Work 'save-empty.html')
            $n = Measure-Occurrence $emptySave 'cannot be empty'
            if ($status -eq '200' -and $n -ge 1) { Add-Pass "an empty box on a knob that has no empty value is refused ($n)" }
            else { Add-Fail "empty-knob save: status $status, 'cannot be empty' refusal $n" }
            $n = Measure-Regex $emptySave '<li>MYPKI_[A-Z0-9_]+ cannot be empty'
            if ($n -ge 1) { Add-Pass "the refusal names the knob it refused ($n)" }
            else { Add-Fail 'the refusal did not name a MYPKI_* knob - an operator cannot fix what is not named' }
            $fileAfter = Get-FileState $configFile
            if ($fileAfter -eq $fileBefore) { Add-Pass 'the empty-knob refusal wrote nothing either' }
            else { Add-Fail "a REFUSED empty-knob save modified $configFile ($fileBefore -> $fileAfter)" }
        }

        # A stale tab posting the page's own values with an EMPTY token: mypki's 400, naming the CSRF token, and again no write.
        if (-not (Write-SettingsFormBody (Join-Path $Work 'settings.html') (Join-Path $Work 'save-nocsrf.txt') @('csrf_token='))) {
            Add-Fail 'could not build the empty-token body'
        } else {
            $status = Send-Body '/settings' (Join-Path $Work 'save-nocsrf.html') (Join-Path $Work 'save-nocsrf.txt')
            $n = Measure-Occurrence (Read-Body (Join-Path $Work 'save-nocsrf.html')) 'CSRF token'
            if ($status -eq '400' -and $n -ge 1) { Add-Pass "a save with an empty CSRF token answers mypki's own 400 naming the token ($n)" }
            else { Add-Fail "empty-token save: status $status (expected 400), 'CSRF token' named $n time(s)" }
            $fileAfter = Get-FileState $configFile
            if ($fileAfter -eq $fileBefore) { Add-Pass 'a CSRF-rejected save wrote nothing to the config file' }
            else { Add-Fail "a CSRF-rejected save modified $configFile ($fileBefore -> $fileAfter)" }
        }

        $n = Measure-Occurrence $settingsPage 'read once at startup'
        if ($n -ge 1) { Add-Pass "/settings says which knobs need a restart ('read once at startup', $n)" }
        else { Add-Fail '/settings no longer states that host/port/session_max_age/data_dir are read once at startup' }
        # 0.4.0 shrank the restart list to four knobs and made everything else live, so the page has to say BOTH halves:
        # a page that still tells an operator to reboot for a logging change asks for an unnecessary outage.
        $n = Measure-Occurrence $settingsPage 'applied by this process as soon'
        if ($n -ge 1) { Add-Pass '/settings states that every other knob is applied without a restart' }
        else { Add-Fail '/settings does not say that non-startup knobs take effect immediately' }

        # ---- 0.5.0 Feature C: the restart-only boxes now show the SAVED value and name what is still running beside it.
        # This harness deliberately performs NO successful save (see the comment above: a save would write into this operator's own
        # %APPDATA%\mypki\ or $XDG_CONFIG_HOME/mypki/), so everything assertable here is the NEGATIVE half of the rule plus the
        # wording that promises the positive half. The positive case - box shows 8543 while the sentence names 8443 - is proven in
        # tests/test_settings_save.py::test_a_plain_get_after_a_save_does_not_claim_that_a_save_just_happened against a temporary
        # config dir, and nowhere else on this host. A run that passes here has NOT seen a pending sentence render.
        $n = Measure-Occurrence $settingsPage '<p class="pending-saved">'
        if ($n -eq 0) { Add-Pass '/settings shows no pending sentence on a host that has never saved (0) - the marker is earned, not decorative' }
        else { Add-Fail "/settings renders $n pending sentence(s) with nothing pending: a rose marker on every startup-only knob trains an operator to ignore the one that means something" }
        # \s+ between the two halves on purpose: settings.html wraps this sentence mid-clause, so a contiguous needle reads 0
        # against a page that renders it (MEASURED on the first live 0.5.0 run, where scripts/smoke_test.sh failed exactly here).
        $n = Measure-Regex $settingsPage 'those four boxes show\s+what the file says'
        if ($n -ge 1) { Add-Pass "/settings states the 0.5.0 rule for the four restart-only boxes ($n)" }
        else { Add-Fail '/settings no longer says the restart-only boxes show the file value - an operator reading only this page cannot tell saved from live' }
        # Deliberately NO assertion on 'saved for the next start': MEASURED, that phrase already occurs 4x on every /settings render
        # because app._knob_input appends it to each of the four startup-only hints. An assertion counting it would pass forever and
        # prove nothing, which is worse than no assertion.
    }
}

# The leak question here is about RESOLVED ABSOLUTE paths, which only a live process knows. Bare filenames legitimately appear:
# two config.py Field descriptions name `<data>/ca/ca_key.pem` and `<data>/instance/secret_key` to explain what mypki does NOT
# touch, and those descriptions are rendered verbatim in the table's description column. Asserting their absence would fail
# against a correct page -- MEASURED, an earlier draft of tests/test_no_key_leakage.py did exactly that. So this reads the
# resolved data dir off the card and asks whether either key path is built under it.
$dataRootMatch = [regex]::Match($settingsPage, '<th scope="row">Data directory \(resolved\)</th>\s*<td class="mono">([^<]*)</td>')
if (-not $dataRootMatch.Success) {
    Add-Fail '/settings does not show a resolved data directory - the leak check below cannot run'
} else {
    $dataRoot = $dataRootMatch.Groups[1].Value
    Add-Pass "/settings shows the resolved data directory ($dataRoot)"
    $leaked = 0
    foreach ($suffix in @('/ca/ca_key.pem', '/instance/secret_key')) {
        $n = Measure-Occurrence $settingsPage ($dataRoot + $suffix)
        if ($n -ge 1) { Add-Fail "/settings renders the resolved key path $dataRoot$suffix"; $leaked = 1 }
    }
    if ($leaked -eq 0) { Add-Pass '/settings names no resolved CA-key or secret-key path' }
}

# =========================================================================== 13 an editable confirm page that fails well
Write-Host ($script:SectionMark + '13 Inline form errors on the confirm page (page-map ' + $script:SectionMark + '3)')
# A fresh step A: section 6's signing consumed the staged request, so nothing is pending now.
Get-Page '/csr/sign' (Join-Path $Work 'sign-form2.html') | Out-Null
$token = Get-CsrfToken (Join-Path $Work 'sign-form2.html')
$status = Send-Pem '/csr/sign' (Join-Path $Work 'confirm2.html') $generatedCsr @("csrf_token=$token")
if ($status -eq '200') { Add-Pass 'step A again answers 200' } else { Add-Fail "second step A answered $status" }
$Pending = Get-PendingId (Join-Path $Work 'confirm2.html')
if ([string]::IsNullOrWhiteSpace($Pending)) {
    Add-Fail 'the confirm form carries no ?pending= id - a rejected edit could not survive the round trip'
} else {
    Add-Pass 'the confirm form carries the staged request in its action URL'
    $token = Get-CsrfToken (Join-Path $Work 'confirm2.html')
    # One bad field (a three-letter country) alongside two deliberate edits. Everything else is left as the request said it.
    $status = Send-Form "/csr/sign?pending=$Pending" (Join-Path $Work 'badcountry.html') @(
        "csrf_token=$token", 'confirm=1', 'cert_type=server', 'validity_days=30',
        'common_name=web.internal', 'organization=Renamed By Smoke', 'organizational_unit=',
        'country=XXL', 'state=', 'locality=', 'email=ops@example.test',
        'sans=web.internal, *.lab.local, 10.0.0.7'
    )
    $bad = Read-Body (Join-Path $Work 'badcountry.html')
    if ($status -eq '200') { Add-Pass 'a bad edited country returns the same page at 200 (not an error page)' }
    else { Add-Fail "bad edited country answered $status (expected 200, inline)" }
    $n = Measure-Occurrence $bad 'exactly two letters'
    if ($n -ge 1) { Add-Pass 'the reason names the field and the offending value' } else { Add-Fail 'no inline reason for the bad country' }
    $n = Measure-Occurrence $bad 'value="Renamed By Smoke"'
    if ($n -ge 1) { Add-Pass 'the other edit is preserved in its input' } else { Add-Fail 'a rejected field cost the operator their other edit' }
    $n = Measure-Occurrence $bad 'Nothing was signed'
    if ($n -ge 1) { Add-Pass 'the page says plainly that nothing was signed' } else { Add-Fail "no 'nothing was signed' statement on the rejected confirm" }
    # The staged request must still be there, under the SAME id - otherwise fixing one character means re-pasting a PEM.
    $Pending2 = Get-PendingId (Join-Path $Work 'badcountry.html')
    if (-not [string]::IsNullOrWhiteSpace($Pending2) -and $Pending2 -eq $Pending) { Add-Pass 'the staged request survives with the same ?pending= id' }
    else { Add-Fail "the rejected page lost the staged request (got $(if ($Pending2) { $Pending2 } else { 'none' }), expected $Pending)" }
    # And fixing it works: same pending id, valid country, and the diff block must then name what was changed.
    $token = Get-CsrfToken (Join-Path $Work 'badcountry.html')
    $status = Send-Form "/csr/sign?pending=$Pending" (Join-Path $Work 'edited-issue.html') @(
        "csrf_token=$token", 'confirm=1', 'cert_type=server', 'validity_days=30',
        'common_name=web.internal', 'organization=Renamed By Smoke', 'organizational_unit=',
        'country=DE', 'state=', 'locality=', 'email=ops@example.test',
        'sans=web.internal, *.lab.local, 10.0.0.7'
    )
    if ($status -eq '200') { Add-Pass 'the corrected confirm issues at 200' } else { Add-Fail "corrected confirm answered $status" }
    $edited = Read-Body (Join-Path $Work 'edited-issue.html')
    $n = Measure-Occurrence $edited 'Changed from your request'
    if ($n -ge 1) { Add-Pass ('the issued page names what the operator changed (page-map ' + $script:SectionMark + '3 diff)') }
    else { Add-Fail 'an edited subject was signed without reporting the change' }
    $n = Measure-Occurrence $edited 'Renamed By Smoke'
    if ($n -ge 1) { Add-Pass 'the diff carries the edited value, not just a label' } else { Add-Fail 'the diff omits the edited value' }
}

# =========================================================================== 14 nothing private in any response
Write-Host ($script:SectionMark + '14 No key material in any response (page-map ' + $script:SectionMark + '0)')
# The assertion is against PEM ARMOUR (`-----BEGIN ... PRIVATE KEY-----`), not against the phrase "PRIVATE KEY". The generate
# page legitimately NAMES the format - "the key is returned as ENCRYPTED PRIVATE KEY" is documentation an operator needs - and
# a check that forbade the words would either fail on honest prose or be loosened until it stopped catching real leaks. What
# must never appear is armour. (The section 5 assertion above is deliberately about the CSRF-rejected page, which renders no
# such prose and therefore has no legitimate reason to contain the phrase.)
# 0.2.0 added /about and /settings to this sweep: /settings is the page whose whole purpose is printing configuration, which
# is exactly the kind of page that leaks a path if nobody checks it from outside.
# 0.5.0 adds /inspect - but only as a plain GET, and that distinction is load-bearing. `/inspect` PASTED with a key renders
# `-----BEGIN PRIVATE KEY-----` TWICE on purpose (the armour lines stay so the operator can see which block was redacted; only
# the base64 body is replaced). Feeding a key paste to this sweep would fail a correct app, so section 15 asserts the key case
# against the base64 lines in its own case and this loop stays a GET-only armour sweep.
foreach ($page in @('/', '/csr/generate', '/csr/sign', '/ca', '/issued', '/about', '/inspect', '/settings', '/version')) {
    Get-Page $page (Join-Path $Work 'probe.html') | Out-Null
    $n = Measure-Regex (Read-Body (Join-Path $Work 'probe.html')) '-----BEGIN [A-Z ]*PRIVATE KEY-----'
    if ($n -eq 0) { Add-Pass "$page contains no private-key armour" } else { Add-Fail "$page contains private-key armour ($n occurrence(s))" }
}

# =========================================================================== 15 /inspect reads a paste and refuses nothing
Write-Host ($script:SectionMark + '15 Inspect PEM (page-map ' + $script:SectionMark + '13)')
# The posture this section exists to hold: `/inspect` is a READER. It describes what a PEM says and refuses exactly one thing,
# an oversized body. Every other page in this app refuses input it dislikes; a page that never refuses has no error surface to
# assert on, so section 15 asserts the opposite - that facts appear where a refusal used to be, and that the one refusal that
# does exist is mine rather than the framework's.
#
# The PEM pasted here is the harness's own CA download (ca.crt, fetched in section 9), which makes this section self-referential
# in the useful direction: the bytes section 9 asserted as a download and section 9 asserted as an on-screen block are handed
# back to a THIRD page, and the answer has to agree with both. It also means no fixture is hard-coded here - a host whose CA is
# EC, or RSA-4096, or named differently, still passes, because the assertions below are about structure plus the rows section 9
# already proved.
$status = Get-Page '/inspect' (Join-Path $Work 'inspect-get.html')
if ($status -eq '200') { Add-Pass 'GET /inspect answers 200' } else { Add-Fail "GET /inspect answered $status (expected 200)" }
$inspectGet = Read-Body (Join-Path $Work 'inspect-get.html')
$n = Measure-Occurrence $inspectGet 'name="pem_paste"'
if ($n -eq 1) { Add-Pass "/inspect posts exactly one field, pem_paste ($n) - the whole page is one textarea" }
else { Add-Fail "/inspect's form fields are not the one documented field (pem_paste x$n)" }
$n = Measure-Occurrence $inspectGet 'Nothing pasted yet'
if ($n -eq 1) { Add-Pass '/inspect says plainly that nothing has been pasted yet' } else { Add-Fail "/inspect renders no empty-state statement ($n)" }
$n = Measure-Occurrence $inspectGet '<th scope="row">'
if ($n -eq 0) { Add-Pass "/inspect inventories no facts on an empty paste (no facts table, $n rows)" }
else { Add-Fail "/inspect fabricated $n fact row(s) out of an empty paste" }
$n = Measure-Occurrence $inspectGet 'It does not verify a chain.'
if ($n -eq 1) { Add-Pass '/inspect states that it cannot verify a chain' } else { Add-Fail "/inspect no longer says it does not verify a chain ($n)" }
$n = Measure-Occurrence $inspectGet 'It does not know about revocation.'
# The NEEDLE is unchanged and still true on 0.7.0 (inspect.html:32 reads exactly this); what was stale is the label, which
# said 'no CRL, no OCSP' as if this host published neither. It publishes both now - /inspect just never consults either.
if ($n -eq 1) { Add-Pass '/inspect states that it consults nothing: it reports no CRL or OCSP answer even though this host now publishes both' }
else { Add-Fail "/inspect stopped naming the revocation gap ($n): a reader that implies 'valid' is worse than no reader" }
$n = Measure-Occurrence $inspectGet 'Its findings are not gates.'
if ($n -eq 1) { Add-Pass '/inspect states that its findings are descriptions, not refusals' } else { Add-Fail "/inspect no longer says findings are not gates ($n)" }
$n = Measure-Occurrence $inspectGet 'A private key is named and not opened.'
if ($n -eq 1) { Add-Pass '/inspect promises a pasted key will be named, not opened' } else { Add-Fail "/inspect no longer states the key posture ($n)" }
# The nav has to reach this page from pages that existed before it, or the page does not exist in practice. Each page is
# checked separately (rather than /inspect's own render) because a nav that carried the link only on /inspect would pass a
# count taken from /inspect alone.
foreach ($navPair in @('/ home.html', '/ca ca.html', '/settings settings.html')) {
    $navPage = $navPair.Split(' ')[0]
    $navFile = Join-Path $Work ($navPair.Split(' ')[1])
    if (Test-Path -LiteralPath $navFile -PathType Leaf) {
        $n = Measure-Regex (Read-Body $navFile) 'class="nav-item[^"]*" href="/inspect"'
        if ($n -eq 1) { Add-Pass "$navPage's nav links to /inspect ($n)" } else { Add-Fail "$navPage's nav has no /inspect link ($n)" }
    } else {
        Add-Warn "$navPage was not fetched earlier in this run, so its nav could not be checked for the /inspect link"
    }
}
$n = Measure-Regex (Read-Body (Join-Path $Work 'inspect-get.html')) 'class="nav-item active" href="/inspect"'
if ($n -eq 1) { Add-Pass "/inspect marks its own nav item active ($n)" } else { Add-Fail "/inspect's nav item is not marked active ($n)" }

# --- a real certificate: the CA this harness runs on, read back off the download section 9 already fetched.
$caDownload = Join-Path $Work 'ca.crt'
if ((Test-Path -LiteralPath $caDownload -PathType Leaf) -and ((Get-Item -LiteralPath $caDownload).Length -gt 0)) {
    $token = Get-CsrfToken (Join-Path $Work 'inspect-get.html')
    if ([string]::IsNullOrWhiteSpace($token)) {
        Add-Fail "/inspect's form carries no CSRF token - every section 15 POST below would be untestable"
    } else {
        $status = Send-PemField '/inspect' (Join-Path $Work 'inspect-ca.html') 'pem_paste' $caDownload @('csrf_token=' + $token)
        if ($status -eq '200') { Add-Pass 'POST /inspect with a real CA certificate answers 200' } else { Add-Fail "POST /inspect answered $status (expected 200)" }
        $caRead = Read-Body (Join-Path $Work 'inspect-ca.html')
        $n = Measure-Occurrence $caRead 'CA:TRUE pathLength:0'
        if ($n -eq 1) { Add-Pass "/inspect reads BasicConstraints out of the paste and renders it ($n)" }
        else { Add-Fail "/inspect did not render the root's BasicConstraints CA:TRUE pathLength:0 ($n)" }
        $n = Measure-Occurrence $caRead 'self-signed root'
        if ($n -ge 1) { Add-Pass "/inspect names a self-signed root as a finding ($n)" }
        else { Add-Fail "/inspect described a self-signed certificate without saying so ($n)" }
        # Scoped on purpose, and done inline rather than with a helper because [regex]::Match already returns the block: the
        # lede legitimately contains `not a CA` as an EXAMPLE of what findings look like (MEASURED: page-wide 1, findings block
        # 0). Asserting page-wide absence would fail a correct app; asserting nothing at all would let "not a CA" leak onto the
        # host's own root.
        $findings = [regex]::Match($caRead, '<ul class="findings">(.*?)</ul>', [System.Text.RegularExpressions.RegexOptions]::Singleline)
        if (-not $findings.Success) {
            Add-Fail "/inspect rendered no findings block for a self-signed root, so 'not a CA' could not be scoped"
        } else {
            $n = Measure-Occurrence $findings.Groups[1].Value 'not a CA'
            if ($n -eq 0) { Add-Pass "the host's own root is not called 'not a CA' inside its findings block ($n)" }
            else { Add-Fail "/inspect calls the host's root 'not a CA' inside the findings block ($n): the flag rules are wrong, not the wording" }
        }
        $n = Measure-Occurrence $caRead 'class="findings"'
        if ($n -eq 1) { Add-Pass "a finding renders as the findings class rather than as a form error ($n)" }
        else { Add-Fail "/inspect rendered findings as $n findings block(s): the amber/not-an-error distinction is gone" }
        $n = Measure-Occurrence $caRead 'class="form-errors"'
        if ($n -eq 0) { Add-Pass "/inspect reports nothing as a form error ($n) - it refused nothing, so there is nothing to fix" }
        else { Add-Fail "/inspect wrote a finding into .form-errors ($n): that block promises 'fix this and submit again'" }
        $n = Measure-Occurrence $caRead 'id="pem-1"'
        if ($n -eq 1) { Add-Pass "/inspect echoes the parsed block as an addressable PEM block ($n)" } else { Add-Fail "/inspect echoed no PEM block with id pem-1 ($n)" }
        $n = Measure-Occurrence $caRead 'data-mypki-copy="pem-1"'
        if ($n -eq 1) { Add-Pass "/inspect wires the copy button to that block ($n)" } else { Add-Fail "/inspect's PEM block has no copy button wired to it" }
        $n = Measure-Occurrence $caRead 'SHA-256 of the DER'
        if ($n -eq 1) { Add-Pass "/inspect reports a SHA-256 of the DER it decoded ($n)" } else { Add-Fail '/inspect printed no hash of the bytes it parsed' }
        # Byte parity, the same question section 9 asks of /ca's block, asked of a THIRD rendering of the same certificate.
        # Scoped to the report block rather than handed straight to Extract-Pem, because MEASURED on the first live run:
        # /inspect's textarea carries a PLACEHOLDER that spells out `-----BEGIN CERTIFICATE----- ... -----END CERTIFICATE-----`,
        # so the FIRST such pair on this page is an example, not the parsed block. Unscoped, this assertion hashed placeholder
        # text and reported a byte mismatch against a correct app - a harness bug, found by running the harness.
        $blockMatch = [regex]::Match($caRead, '<pre class="pem" id="pem-1">(.*?)</pre>', [System.Text.RegularExpressions.RegexOptions]::Singleline)
        if ($blockMatch.Success) {
            $pagePem = [System.Net.WebUtility]::HtmlDecode($blockMatch.Groups[1].Value)
            $pagePemFile = Join-Path $Work 'inspect-page.pem'
            # WriteAllText: no BOM and no trailing newline added, so the hash compares the same bytes curl wrote to ca.crt.
            [System.IO.File]::WriteAllText($pagePemFile, $pagePem)
            $pageSha = Get-PemDerSha $pagePemFile
            $dlSha = Get-PemDerSha $caDownload
            if (-not [string]::IsNullOrWhiteSpace($pageSha) -and $pageSha -eq $dlSha) {
                Add-Pass "the block /inspect echoed is the same bytes as the CA download ($pageSha)"
            } else {
                Add-Fail "/inspect's echoed block differs from /ca/certificate (page $pageSha vs download $dlSha)"
            }
        } else {
            Add-Fail '/inspect echoed no report PEM block (id pem-1) to compare against the download'
        }

        # --- a private key pasted by accident: named, redacted, and asserted against the BASE64, never against armour.
        # The sentinel body is not a key - it is fixed text whose base64 this script can name exactly. Asserting that two long
        # base64 lines are ABSENT is a leak test a real key could not be: with a real key there is no string to search for, so
        # the only honest version of this case uses material the harness wrote itself.
        $sentinel = 'MYPKI-SMOKE-SENTINEL-PRIVATE-KEY-BODY-not-a-real-key-0123456789abcdef'
        $sentinelBody = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($sentinel))
        if ($sentinelBody.Length -gt 64) {
            $sentinelBody = $sentinelBody.Substring(0, 64) + [Environment]::NewLine + $sentinelBody.Substring(64)
        }
        $sentinelFile = Join-Path $Work 'sentinel.key'
        [System.IO.File]::WriteAllText($sentinelFile, ('-----BEGIN PRIVATE KEY-----' + [Environment]::NewLine + $sentinelBody + [Environment]::NewLine + '-----END PRIVATE KEY-----' + [Environment]::NewLine))
        $status = Send-PemField '/inspect' (Join-Path $Work 'inspect-key.html') 'pem_paste' $sentinelFile @('csrf_token=' + $token)
        if ($status -eq '200') { Add-Pass 'POST /inspect with a private key answers 200 (it refuses nothing, including this)' }
        else { Add-Fail "POST /inspect with a key answered $status (expected 200 - this page does not refuse)" }
        $keyRead = Read-Body (Join-Path $Work 'inspect-key.html')
        $n = Measure-Occurrence $keyRead 'private-key block(s) were in your paste'
        if ($n -eq 1) { Add-Pass "/inspect says out loud that it redacted a key ($n) - no quiet edit of what was pasted" }
        else { Add-Fail "/inspect redacted a paste without saying so ($n): the quiet edit this project refuses elsewhere" }
        $n = Measure-Occurrence $keyRead 'redacted by mypki'
        if ($n -eq 2) { Add-Pass "the marker appears twice: once in the echoed paste, once naming itself ($n)" }
        else { Add-Fail "/inspect's redaction marker appears $n time(s), expected 2" }
        $n = Measure-Occurrence $keyRead 'this is a private key. mypki did not open it'
        if ($n -eq 1) { Add-Pass "/inspect names the block as a key and says it was not opened ($n)" }
        else { Add-Fail "/inspect did not name the pasted block as a private key ($n)" }
        # THE leak assertion. Every wrapped base64 line of the paste, searched for by name.
        $leaked = 0
        foreach ($line in (($sentinelBody -split '\r?\n'))) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            if ($line.StartsWith('-----')) { continue }
            if ((Measure-Occurrence $keyRead $line) -ge 1) { Add-Fail "the pasted key's base64 came back verbatim: $line"; $leaked = 1 }
        }
        $n = Measure-Regex $keyRead '-----BEGIN [A-Z ]*PRIVATE KEY-----'
        if ($leaked -eq 0) { Add-Pass "no base64 body from the pasted key survives in the response (armour lines present x$n, by design)" }
        $n = Measure-Occurrence $keyRead 'SHA-256 of the DER'
        if ($n -eq 0) { Add-Pass "/inspect hashed nothing it refused to read ($n) - no fingerprint for a key it never opened" }
        else { Add-Fail "/inspect produced a hash for a private key it says it did not open ($n)" }

        # --- the one refusal this page makes, and whose sentence it is.
        $bigFile = Join-Path $Work 'big.txt'
        [System.IO.File]::WriteAllText($bigFile, ('y' * 40000))
        $status = Send-PemField '/inspect' (Join-Path $Work 'inspect-big.html') 'pem_paste' $bigFile @('csrf_token=' + $token)
        $big = Read-Body (Join-Path $Work 'inspect-big.html')
        $n = Measure-Occurrence $big 'MYPKI_MAX_CSR_CHARS'
        if ($status -eq '413' -and $n -ge 1) { Add-Pass "an oversized paste answers 413 naming MYPKI_MAX_CSR_CHARS ($n)" }
        else { Add-Fail "oversized /inspect paste: status $status (expected 413), knob named $n time(s)" }
        $n = Measure-Occurrence $big 'Field exceeded maximum size'
        if ($n -eq 0) { Add-Pass "/inspect's size refusal is mypki's page, not starlette's JSON ($n)" }
        # (double-quoted on purpose: three possessives in one sentence, and single quotes cannot hold them)
        else { Add-Fail "starlette's bare size error surfaced on /inspect instead of mypki's sentence" }

        # --- a missing token: refused BEFORE the paste is read, so the paste never reaches the page.
        $status = Send-PemField '/inspect' (Join-Path $Work 'inspect-notoken.html') 'pem_paste' $caDownload @()
        $notoken = Read-Body (Join-Path $Work 'inspect-notoken.html')
        $n = Measure-Occurrence $notoken 'CSRF'
        if ($status -eq '400' -and $n -ge 1) { Add-Pass "/inspect refuses a tokenless POST at 400 naming CSRF ($n)" }
        else { Add-Fail "/inspect with no token: status $status (expected 400), CSRF named $n time(s)" }
        $n = Measure-Occurrence $notoken '-----BEGIN CERTIFICATE-----'
        if ($n -eq 0) { Add-Pass "the rejected paste is not echoed back ($n) - a refusal is not an echo chamber" }
        else { Add-Fail "/inspect echoed the pasted PEM on its CSRF refusal ($n)" }

        # --- junk: described, not refused. This is the whole point of the page existing.
        $junkFile = Join-Path $Work 'junk.txt'
        [System.IO.File]::WriteAllText($junkFile, 'hello world')
        $status = Send-PemField '/inspect' (Join-Path $Work 'inspect-junk.html') 'pem_paste' $junkFile @('csrf_token=' + $token)
        if ($status -eq '200') { Add-Pass 'text with no PEM armour answers 200 rather than a refusal' } else { Add-Fail "junk paste answered $status (expected 200)" }
        $junk = Read-Body (Join-Path $Work 'inspect-junk.html')
        $n = Measure-Occurrence $junk 'nothing readable'
        if ($n -ge 1) { Add-Pass "/inspect names junk as 'nothing readable' ($n) instead of refusing it" } else { Add-Fail "/inspect refused or ignored a junk paste ($n)" }
        $n = Measure-Occurrence $junk 'nothing to report'
        if ($n -ge 1) { Add-Pass "the finding says what is missing rather than 'invalid input' ($n)" } else { Add-Fail "/inspect's junk case carries no usable finding ($n)" }
    }
} else {
    Add-Warn 'section 9 left no CA download in the work dir, so the certificate, key and oversized cases for /inspect were not exercised'
}

# =========================================================================== 16 dropped extensions need consent (page-map 3 rule 6)
Write-Host ($script:SectionMark + '16 Dropped extensions need consent (page-map ' + $script:SectionMark + '3 rule 6)')
# The two CSRs below are written by openssl itself, not by this harness: basicConstraints = CA:FALSE and
# keyUsage = digitalSignature, keyEncipherment are what a distro [v3_req] puts into every request `openssl req` makes,
# which is the operator report this section exists for. Embedding the PEMs keeps section 16 runnable anywhere the other
# fifteen run (no openssl needed at run time), and the bytes are real openssl output rather than a hand-built
# approximation - both verify against their own signature.
$consentCsr = Join-Path $Work 'consent.csr'
@'
-----BEGIN CERTIFICATE REQUEST-----
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
'@ -replace "`r`n", "`n" | ForEach-Object { [System.IO.File]::WriteAllText($consentCsr, $_ + "`n") }
$privilegedCsr = Join-Path $Work 'privileged.csr'
@'
-----BEGIN CERTIFICATE REQUEST-----
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
'@ -replace "`r`n", "`n" | ForEach-Object { [System.IO.File]::WriteAllText($privilegedCsr, $_ + "`n") }

$n = Measure-Occurrence (Read-Body $consentCsr) '-----BEGIN CERTIFICATE REQUEST-----'
# The byte count needs the `.Length` INSIDE the subexpression. Written as `$(Get-Item $x).Length`, PowerShell interpolates the
# FileInfo object (whose ToString is its full path) and then appends the literal word 'Length', so the label read
# ".../work/consent.csr.Length bytes" - MEASURED on the first live section 16 run. The .sh counterpart prints `wc -c`.
if ($n -eq 1) { Add-Pass "section 16 wrote a well-formed openssl-default CSR ($( (Get-Item $consentCsr).Length ) bytes)" } else { Add-Fail "the consent fixture is not a single PEM block ($n)" }
$n = Measure-Occurrence (Read-Body $privilegedCsr) '-----BEGIN CERTIFICATE REQUEST-----'
if ($n -eq 1) { Add-Pass "section 16 wrote a well-formed CA-privileged CSR ($( (Get-Item $privilegedCsr).Length ) bytes)" } else { Add-Fail "the privileged fixture is not a single PEM block ($n)" }

# --- STEP A: a request carrying ignorable extensions now reaches the panel instead of being refused at step 6.
# `| Out-Null` on every status-only fetch in this section: Get-Page returns curl's %{http_code} text, and a call that neither
# assigns it nor discards it prints a bare number into the log. MEASURED: an unqualified Get-Page here put three stray '200'
# lines inside section 16, which shifts every heading line number SMOKE_TESTING.md records and reads to a reader like a status
# the section asserted without naming one. Every other Get-Page in this file assigns or pipes to Out-Null for exactly this reason.
Get-Page '/csr/sign' (Join-Path $Work 'consent-form.html') | Out-Null
$token = Get-CsrfToken (Join-Path $Work 'consent-form.html')
$status = Send-Pem '/csr/sign' (Join-Path $Work 'consent-confirm.html') $consentCsr @("csrf_token=$token")
if ($status -eq '200') { Add-Pass "a CA:FALSE + keyUsage CSR reaches the confirmation panel at 200 (rule 6's ignorable half)" } else { Add-Fail "the openssl-default CSR answered $status (expected 200, not a 403 refusal)" }
$cconf = Read-Body (Join-Path $Work 'consent-confirm.html')
$n = Measure-Occurrence $cconf 'BasicConstraints CA:FALSE'
if ($n -ge 1) { Add-Pass 'the panel names BasicConstraints CA:FALSE as something it will not copy' } else { Add-Fail 'the confirmation panel omits the extension it is about to drop' }
$n = Measure-Occurrence $cconf 'KeyUsage (digitalSignature, keyEncipherment)'
if ($n -ge 1) { Add-Pass 'the panel names both KeyUsage bits by name, not just KeyUsage' } else { Add-Fail 'the disclosure does not say which usage bits are being dropped' }
$n = Measure-Regex $cconf '<input type="checkbox"[^>]*name="ignore_extensions"'
if ($n -eq 1) { Add-Pass "exactly one consent box is offered ($n)" } else { Add-Fail "the consent control appears $n times (expected exactly 1)" }
$n = Measure-Regex $cconf '<input type="checkbox"[^>]*name="ignore_extensions"[^>]*checked'
if ($n -eq 0) { Add-Pass 'the consent box arrives UNTICKED - default OFF is markup, not a promise' } else { Add-Fail 'the consent box arrived pre-ticked, which would consent before anyone read the list' }
$n = Measure-Occurrence $cconf 'class="checkbox-state state-off">off<'
if ($n -eq 1) { Add-Pass "the word beside the unticked box reads 'off' in the off colour ($n)" } else { Add-Fail "the consent box's state word disagrees with the box next to it ($n)" }
# The reverse case, which is what makes "no box" unambiguous: a CSR mypki generated itself (section 5's output) has SAN
# and nothing else, so it must render no list and no box rather than an empty one. Asserted on its own step A POST so
# this section does not depend on what earlier sections left in a variable - and staging a request signs nothing, so no
# ledger count moves here.
$plainCsr = Join-Path $Work 'generated.csr'
if (Test-Path -LiteralPath $plainCsr) {
    Get-Page '/csr/sign' (Join-Path $Work 'plain-form.html') | Out-Null
    $plainToken = Get-CsrfToken (Join-Path $Work 'plain-form.html')
    Send-Pem '/csr/sign' (Join-Path $Work 'plain-confirm.html') $plainCsr @("csrf_token=$plainToken") | Out-Null
    $plain = Read-Body (Join-Path $Work 'plain-confirm.html')
    $n = Measure-Occurrence $plain 'name="ignore_extensions"'
    if ($n -eq 0) { Add-Pass 'a mypki-generated CSR renders no consent box at all (nothing to consent about)' } else { Add-Fail 'a request with no non-SAN extensions still offered a consent box' }
    $n = Measure-Occurrence $plain 'class="provenance dropped-extensions"'
    if ($n -eq 0) { Add-Pass "and no empty dropped-extension block either ($n)" } else { Add-Fail 'the disclosure block rendered for a request that carried nothing to disclose' }
} else {
    Add-Warn 'section 5 left no generated CSR in the work dir, so the no-consent-box case was not exercised'
}

# --- STEP B, consent WITHHELD: an input to fix, not a refused request. 200, everything named, nothing signed.
$pending = Get-PendingId (Join-Path $Work 'consent-confirm.html')
if ([string]::IsNullOrWhiteSpace($pending)) {
    Add-Fail 'step A staged no pending id - the consent checks below cannot run'
} else {
    $token = Get-CsrfToken (Join-Path $Work 'consent-confirm.html')
    $status = Send-Form "/csr/sign?pending=$pending" (Join-Path $Work 'consent-unticked.html') @(
        "csrf_token=$token", 'confirm=1', 'cert_type=server', 'validity_days=30'
    )
    if ($status -eq '200') { Add-Pass 'confirming without the box answers 200, not 403 (nothing was refused)' } else { Add-Fail "confirming without consent answered $status (expected 200 inline)" }
    $unticked = Read-Body (Join-Path $Work 'consent-unticked.html')
    $n = Measure-Occurrence $unticked 'consent to dropped extensions'
    if ($n -ge 1) { Add-Pass 'the refusal names the decision that is missing' } else { Add-Fail 'no consent reason on the unticked confirm' }
    $n = Measure-Occurrence $unticked 'KeyUsage (digitalSignature, keyEncipherment)'
    if ($n -ge 1) { Add-Pass 'the unticked refusal lists every extension at stake' } else { Add-Fail "the consent refusal says 'some extensions' without naming them" }
    $n = Measure-Occurrence $unticked 'Nothing was signed'
    if ($n -ge 1) { Add-Pass 'the unticked refusal states plainly that nothing was signed' } else { Add-Fail 'an unticked box leaves it unclear whether a certificate was issued' }
    $n = Measure-Occurrence $unticked '<h2>Issued:'
    if ($n -eq 0) { Add-Pass "no certificate card was rendered while consent was withheld ($n)" } else { Add-Fail 'consent was withheld and a certificate was issued anyway' }
    # The staged request has to survive, under the SAME id: 'tick the box' is only fixable without re-pasting a PEM if
    # this page still points at the request it is talking about.
    $pending2 = Get-PendingId (Join-Path $Work 'consent-unticked.html')
    if (-not [string]::IsNullOrWhiteSpace($pending2) -and $pending2 -eq $pending) { Add-Pass 'the staged request survives the unticked refusal (same pending id)' } else { Add-Fail "the unticked refusal lost the staged request (got '$pending2', expected $pending)" }
    $n = Measure-Regex $unticked '<input type="checkbox"[^>]*name="ignore_extensions"'
    if ($n -eq 1) { Add-Pass "the re-rendered page offers the box again ($n) rather than a dead end" } else { Add-Fail 'the unticked refusal no longer offers a way to consent' }

    # --- STEP B, consent GRANTED: issue, and name every dropped extension on the issued page.
    $token = Get-CsrfToken (Join-Path $Work 'consent-unticked.html')
    $status = Send-Form "/csr/sign?pending=$pending" (Join-Path $Work 'consent-issued.html') @(
        "csrf_token=$token", 'confirm=1', 'cert_type=server', 'validity_days=30', 'ignore_extensions=true'
    )
    if ($status -eq '200') { Add-Pass 'confirming with the box issues at 200' } else { Add-Fail "confirming with consent answered $status" }
    $cissued = Read-Body (Join-Path $Work 'consent-issued.html')
    $n = Measure-Occurrence $cissued 'Issued: consent.lab.local'
    if ($n -ge 1) { Add-Pass 'the certificate the operator consented to is the one that was issued' } else { Add-Fail 'no Issued: consent.lab.local card after consent was granted' }
    $n = Measure-Occurrence $cissued 'Changed from your request'
    if ($n -ge 1) { Add-Pass 'a dropped extension lands in the same diff block as an edited name (page-map 3)' } else { Add-Fail 'the issued page signed a request with dropped extensions without reporting them' }
    $n = Measure-Occurrence $cissued 'Extension not copied: BasicConstraints CA:FALSE'
    if ($n -eq 1) { Add-Pass "the diff names the dropped BasicConstraints ($n)" } else { Add-Fail 'the issued page does not name the dropped BasicConstraints' }
    $n = Measure-Occurrence $cissued 'Extension not copied: KeyUsage (digitalSignature, keyEncipherment)'
    if ($n -eq 1) { Add-Pass "the diff names the dropped KeyUsage with its bits ($n)" } else { Add-Fail 'the issued page does not name the dropped KeyUsage' }
    $n = Measure-Occurrence $cissued 'The public key and every extension still came from mypki'
    if ($n -ge 1) { Add-Pass 'the diff closes by stating where the extensions actually came from' } else { Add-Fail 'the issued page omits where a dropped extension replacement came from' }
    # Consent changes what is COPIED, never what is SIGNED: the staged PEM keeps its extensions (a CSR signature covers
    # them), so the only visible trace of the request's own BasicConstraints is this diff block - and the certificate has
    # to read as mypki's profile. Section 10 proved the artifact round trip; here the serial proves a real leaf exists
    # behind the card.
    $cissuedSerial = Get-IssuedSerial (Join-Path $Work 'consent-issued.html')
    if ([string]::IsNullOrWhiteSpace($cissuedSerial)) { Add-Fail 'the consented signing rendered no leaf serial' } else { Add-Pass "the consented signing reports its own leaf serial ($($cissuedSerial.Substring(0, [Math]::Min(12, $cissuedSerial.Length)))...)" }
}

# --- A privilege claim is not a consent question, and ticking the box does not make it one.
Get-Page '/csr/sign' (Join-Path $Work 'priv-form.html') | Out-Null
$token = Get-CsrfToken (Join-Path $Work 'priv-form.html')
$status = Send-Pem '/csr/sign' (Join-Path $Work 'priv-refused.html') $privilegedCsr @("csrf_token=$token", 'ignore_extensions=true')
$priv = Read-Body (Join-Path $Work 'priv-refused.html')
if ($status -eq '403') { Add-Pass 'CA:TRUE is refused at 403 even with the consent field posted' } else { Add-Fail "a CA-privileged CSR answered $status while carrying ignore_extensions=true (expected 403)" }
$n = Measure-Occurrence $priv 'BasicConstraints CA:TRUE'
if ($n -ge 1) { Add-Pass 'the refusal names BasicConstraints CA:TRUE' } else { Add-Fail 'the 403 omits the extension it refused' }
$n = Measure-Occurrence $priv 'keyCertSign'
if ($n -ge 1) { Add-Pass 'the refusal names keyCertSign' } else { Add-Fail 'the 403 omits keyCertSign' }
$n = Measure-Occurrence $priv 'crlSign'
if ($n -ge 1) { Add-Pass 'the refusal names crlSign' } else { Add-Fail 'the 403 omits crlSign' }
# MEASURED wording: app.py's hint closes "... and dropped only when you tick the box there." An earlier draft of this needle
# read 'only if you tick the box', which no build ever printed - it failed here against a correct 403 page, so the NEEDLE was the
# bug, not the page.
$n = Measure-Occurrence $priv 'you tick the box'
if ($n -ge 1) { Add-Pass 'the hint now points at the consent box for the extensions that are ignorable' } else { Add-Fail 'the 403 gives no route to the half of rule 6 that is signable' }
$n = Measure-Occurrence $priv '<h2>Issued:'
if ($n -eq 0) { Add-Pass "refusing signed nothing ($n)" } else { Add-Fail 'a refused privilege claim still produced a certificate card' }

# =========================================================================== report

Write-Host ''
Emit "== summary: $script:Pass pass, $script:Fail fail, $script:Warn warn =="
if ($script:Failures.Count -gt 0) {
    Write-Host 'FAILURES:'
    foreach ($failure in $script:Failures) { Write-Host "  - $failure" }
}
if ($script:Warnings.Count -gt 0) {
    Write-Host 'WARNINGS:'
    foreach ($warning in $script:Warnings) { Write-Host "  - $warning" }
}

if (-not [string]::IsNullOrWhiteSpace($Report)) {
    $head = @(
        '# mypki smoke report'
        ''
        "base: $Base"
        # 'base resolved from' is what an operator needs when a run reports NOTHING WAS CHECKED: it names the layer this harness
        # believed it was reading, so a wrong base traces to a file rather than to a guess. It lives in the report and not on stdout,
        # because both logs start at line 1 with section 1 and SMOKE_TESTING.md records heading line numbers for them.
        "base resolved from: $BaseResolvedFrom"
        "work: $Work"
        "expected version: $(if ([string]::IsNullOrWhiteSpace($Version)) { 'not determined' } else { $Version })"
        "run at: $([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))"
        ''
        "summary: $script:Pass pass, $script:Fail fail, $script:Warn warn"
        ''
    ) -join [Environment]::NewLine
    # WriteAllText rather than Out-File: Out-File on Windows PowerShell 5.1 defaults to UTF-16LE, which a diff tool and every
    # CI artifact reader treats as binary. The report is meant to be attached to a bug report, so it is plain UTF-8 here.
    [System.IO.File]::WriteAllText($Report, ($head + [Environment]::NewLine + $script:ReportBody.ToString()))
    Write-Host "report written to $Report"
}

if ($script:Fail -gt 0) { exit 1 }
exit 0
