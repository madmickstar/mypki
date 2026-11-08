# myPKI

![banner](assets/banner.png)

![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)
[![CI](https://github.com/madmickstar/mypki/actions/workflows/ci.yml/badge.svg)](https://github.com/madmickstar/mypki/actions/workflows/ci.yml)

This is a small, browser based, self-hosted PKI app for personal and lab environments. It is not attempting to be a security product and should never be used in a production environment. It provides a convenient way to manage certificates.

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Where the files live](#where-the-files-live)
- [License](#license)
- [AI](#ai)

Reference detail — what each surface does, the two gotchas, serving and exposure, logging, the stated divergences, known gaps, development, versions and naming — lives in [docs/REFERENCE.md](docs/REFERENCE.md). The Linux install and service unit live in [docs/linux_install.md](docs/linux_install.md).

## Features

- One command creates a single self-signed root CA on your own machine.
- A browser page generates a private key and a matching CSR, shown once.
- A browser page validates a pasted CSR and shows what it actually asks for before anything is signed.
- Certificates are issued from mypki's own extension profile for `server`, `client` or `both`.
- The CA certificate is downloadable with per-OS install instructions and a fingerprint to verify out of band.
- A signed CRL is published at `/crl.pem` and its facts are shown on `/crl`.
- An OCSP responder answers GOOD / REVOKED / UNKNOWN over `POST /ocsp`.
- The issued list shows what has been signed, newest first, and marks records revoked in bulk.
- Any PEM can be pasted into `/inspect` and read back: subject, issuer, SANs, key, validity, serial and fingerprint.
- Every knob is editable on `/settings`, with the four that need a restart marked as such.
- `mypki serve` and `mypki info` run the app and inspect it from a terminal.

## Quick Start

Install and run it on Linux, including as a systemd service: [docs/linux_install.md](docs/linux_install.md).

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
| `MYPKI_LOG_*` | see [docs/REFERENCE.md](docs/REFERENCE.md#logging) | Bounded at `log_max_bytes * (log_backup_count + 1)` |
| `MYPKI_SECRET_KEY` | generated into `<data>/instance/secret_key` (0600) | Explicit value is how sessions survive across hosts; it is then readable by anyone who can read `.env` |

Precedence for the data dir: `--data-dir` > `MYPKI_DATA_DIR` > OS default.

## Where the files live

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

The tree this repository actually ships, taken from `git ls-files --cached --exclude-standard --others` at this commit (78 paths):

```
.env.example
.github/workflows/ci.yml
.gitignore
.pre-commit-config.yaml
AGENTS.md
CHANGELOG.md
LICENSE
Makefile
README.md
SMOKE_TESTING.md
assets/banner.png
deploy/mypki.service
docs/REFERENCE.md
docs/linux_install.md
docs/page-map.md
pyproject.toml
src/mypki/__init__.py
src/mypki/__main__.py
src/mypki/app.py
src/mypki/ca.py
src/mypki/cli.py
src/mypki/config.py
src/mypki/crl.py
src/mypki/csr.py
src/mypki/csrf.py
src/mypki/errors.py
src/mypki/inspect.py
src/mypki/keys.py
src/mypki/logsetup.py
src/mypki/ocsp_responder.py
src/mypki/paths.py
src/mypki/settingsfile.py
src/mypki/signing.py
src/mypki/static/app.js
src/mypki/static/favicon.svg
src/mypki/static/logo.svg
src/mypki/static/style.css
src/mypki/store.py
src/mypki/templates/about.html
src/mypki/templates/base.html
src/mypki/templates/ca_download.html
src/mypki/templates/crl.html
src/mypki/templates/csr_generate.html
src/mypki/templates/csr_sign.html
src/mypki/templates/error.html
src/mypki/templates/inspect.html
src/mypki/templates/issued.html
src/mypki/templates/settings.html
src/mypki/validators.py
tests/conftest.py
tests/test_bulk_revoke.py
tests/test_ca_init.py
tests/test_chain.py
tests/test_cli.py
tests/test_consent.py
tests/test_crl.py
tests/test_csr_generate.py
tests/test_csr_validate.py
tests/test_fast_lane.py
tests/test_inspect.py
tests/test_keys.py
tests/test_nav.py
tests/test_no_key_leakage.py
tests/test_ocsp.py
tests/test_packaging.py
tests/test_paths.py
tests/test_san_validation.py
tests/test_settings_save.py
tests/test_signing.py
tests/test_store.py
tests/test_version.py
tests/test_views.py
tools/banner/make_banner.py
tools/check_version.py
tools/doc_citations.py
tools/e2e_harness.py
tools/fast_lane.py
tools/tree_manifest.py
```

## License

MIT — see [LICENSE](LICENSE).

## AI

Coded using local AI
