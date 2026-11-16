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
- A signed CRL is published at `/revoke.crl` and its facts are shown on `/crl`.
- An OCSP responder answers GOOD / REVOKED / UNKNOWN over `POST /ocsp`.
- The issued list shows what has been signed, newest first, and marks records revoked in bulk.
- Any PEM can be pasted into `/inspect` and read back: subject, issuer, SANs, key, validity, serial and fingerprint.
- Every knob is editable on `/settings`, with the four that need a restart marked as such.
- `mypki serve` and `mypki info` run the app and inspect it from a terminal.

## Quick Start

Python 3.10 or newer. From an unpacked copy of this repository (or a clone), in a virtual environment:

```bash
python3 -m venv .venv
. .venv/bin/activate                      # Windows: .venv\Scripts\activate
pip install ".[dev]"                      # the app plus what working on it needs (pytest, ruff, mypy)
pip install .                             # or just the app, no dev extras

mypki init-ca                             # creates the root CA; the browser cannot do this step
mypki serve                               # http://127.0.0.1:8443
mypki info                                # which CA is loaded, and where its files live
```

`init-ca` has to run before `serve`: serving with no CA exits **3**, which means only "no CA found".
`python -m mypki …` reaches the same CLI in an environment where no console script was installed.

Then, for Linux — installing it as a systemd service, with the unit file that ships in `deploy/`:
[docs/linux_install.md](docs/linux_install.md).

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

What mypki writes at runtime, under its data directory (`--data-dir` > `MYPKI_DATA_DIR` > OS default):

```
<data>/ca/ca_key.pem         # never served, never logged, never in the DB; 0600 on POSIX
<data>/ca/ca_cert.pem        # the only certificate served
<data>/ca/archive/<UTC-ts>/  # what --force replaced; nothing is ever deleted
<data>/instance/secret_key   # session secret, 0600 on POSIX
<data>/issued.db             # SQLite (WAL): metadata only, no keys and no PEM bodies
```

How those files are protected — POSIX modes that are asserted after the write, what `os.chmod` does **not** do on
Windows, and what protects the key instead — is stated in full in
[docs/REFERENCE.md](docs/REFERENCE.md#key-protection-and-the-data-directory).

The tree this repository actually ships, taken from `git ls-files --cached --exclude-standard --others` at this commit (76 paths):

```
mypki/
├── .github/
│   └── workflows/
│       └── ci.yml
├── assets/
│   └── banner.png
├── deploy/
│   └── mypki.service
├── docs/
│   ├── REFERENCE.md
│   ├── linux_install.md
│   └── page-map.md
├── src/
│   └── mypki/
│       ├── static/
│       │   ├── app.js
│       │   ├── favicon.svg
│       │   ├── logo.svg
│       │   └── style.css
│       ├── templates/
│       │   ├── about.html
│       │   ├── base.html
│       │   ├── ca_download.html
│       │   ├── crl.html
│       │   ├── csr_generate.html
│       │   ├── csr_sign.html
│       │   ├── error.html
│       │   ├── inspect.html
│       │   ├── issued.html
│       │   └── settings.html
│       ├── __init__.py
│       ├── __main__.py
│       ├── app.py
│       ├── ca.py
│       ├── cli.py
│       ├── config.py
│       ├── crl.py
│       ├── csr.py
│       ├── csrf.py
│       ├── errors.py
│       ├── inspect.py
│       ├── keys.py
│       ├── logsetup.py
│       ├── ocsp_responder.py
│       ├── paths.py
│       ├── settingsfile.py
│       ├── signing.py
│       ├── store.py
│       └── validators.py
├── tests/
│   ├── conftest.py
│   ├── test_bulk_revoke.py
│   ├── test_ca_init.py
│   ├── test_chain.py
│   ├── test_cli.py
│   ├── test_consent.py
│   ├── test_crl.py
│   ├── test_csr_generate.py
│   ├── test_csr_validate.py
│   ├── test_fast_lane.py
│   ├── test_inspect.py
│   ├── test_keys.py
│   ├── test_nav.py
│   ├── test_no_key_leakage.py
│   ├── test_ocsp.py
│   ├── test_packaging.py
│   ├── test_paths.py
│   ├── test_san_validation.py
│   ├── test_settings_save.py
│   ├── test_signing.py
│   ├── test_store.py
│   ├── test_version.py
│   └── test_views.py
├── tools/
│   ├── banner/
│   │   └── make_banner.py
│   ├── check_version.py
│   ├── doc_citations.py
│   ├── e2e_harness.py
│   ├── fast_lane.py
│   └── tree_manifest.py
├── .env.example
├── .gitignore
├── .pre-commit-config.yaml
├── CHANGELOG.md
├── LICENSE
├── Makefile
├── README.md
└── pyproject.toml
```

## License

MIT — see [LICENSE](LICENSE).

## AI

Coded using local AI
