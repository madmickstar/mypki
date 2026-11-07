# Install and run mypki as a service on Linux

Everything below is measured on this checkout (`mypki 0.7.2`, Python 3.12 in `.venv`, Debian container, systemd 257).
Two things are stated rather than measured, and they are named at the end: starting this unit on a real host, and what
`systemctl status` prints once it is running there.

## Install from a checkout

```bash
python3 -m venv .venv && . .venv/bin/activate      # Python 3.10 or newer
pip install -e ".[dev]"                            # or: pip install mypki (after the first release)

mypki init-ca                                      # creates the root CA; the GUI cannot do this
mypki serve                                        # http://127.0.0.1:8443
mypki info                                         # what CA is loaded, and where the data lives
```

`mypki init-ca` must run before `mypki serve`: serving with no CA exits **3**, and that exit code means only "no CA
found" ([REFERENCE.md](REFERENCE.md#what-it-does) records the whole exit-code table).

## Where it puts its files

Precedence, for both directories: `--data-dir` > `MYPKI_DATA_DIR` > OS default.

- Default data dir on Linux: `$XDG_DATA_HOME/mypki`, else `~/.local/share/mypki`.
- Default config dir (where `/settings` writes `mypki.env`): `$XDG_CONFIG_HOME/mypki`, else `~/.config/mypki`.
- For a service account, set the data dir explicitly and put it somewhere you can back up:

```bash
Environment=MYPKI_DATA_DIR=/var/lib/mypki     # in the unit file
# or, in the shell that runs the command:
export MYPKI_DATA_DIR=/var/lib/mypki
```

The contents of `<data>/` and what each file is for are listed in the README under
[Where the files live](../README.md#where-the-files-live).

## Settings layers

A knob can arrive from three places, and the order matters:

1. a real environment variable — wins over both files;
2. `<config-dir>/mypki.env` — what `/settings` writes; wins over `.env`;
3. `./.env` in the working directory — the layer you edit by hand (`cp .env.example .env`).

So a value saved through the browser overrides the same value in `.env`, and an operator who exports the variable in
front of the process overrides both. A relative path in any of the three is resolved against the **working directory**,
which is why a service unit has to set `WorkingDirectory` deliberately rather than inherit whatever systemd gave it.

## `mypki serve` flags

Measured spelling, from `mypki serve --help` on this checkout — every flag below exists; nothing here is inferred:

```
mypki serve [-h] [--host HOST] [--port PORT] [--ssl-cert SSL_CERT] [--ssl-key SSL_KEY]
            [--data-dir DATA_DIR] [--passphrase-env NAME] [--log-level LOG_LEVEL]
            [--log-file LOG_FILE] [--no-console-log]
```

| Flag | Default | What it does |
| --- | --- | --- |
| `--host` | `127.0.0.1` | Anything non-loopback prints a warning naming what that means for signing access |
| `--port` | `MYPKI_PORT` = 8443 | A port already held exits **1** with a `cannot bind` line, not 3 |
| `--ssl-cert` / `--ssl-key` | unset (plain HTTP) | Both or neither. Each file must exist and be readable, or `serve` exits 1 naming the knob and the path before uvicorn is reached |
| `--data-dir` | `MYPKI_DATA_DIR` or the OS default | Overrides both |
| `--passphrase-env` | `MYPKI_CA_PASSPHRASE` | Name of the variable holding the CA key passphrase. If the key is encrypted and the variable is unset, `serve` prompts on the terminal — which a service unit has no terminal for, so set the variable (see below) |
| `--log-level` | `MYPKI_LOG_LEVEL` = INFO | `CRITICAL\|ERROR\|WARNING\|INFO\|DEBUG`; an unknown name is a usage error, exit 1 |
| `--log-file` | `logs/mypki.log` | Relative to the working directory. An empty value means console-only |
| `--no-console-log` | off (console mirroring is on) | Stops mirroring logs to stderr |

`init-ca` and `info` accept `--data-dir` and the same three logging flags; `init-ca` also takes the CA-shaping flags
(`--common-name`, `--key-type`, `--key-size`, `--curve`, `--days`, `--encrypt`, `--passphrase-env`, `--force`,
`--secure-acl`).

## Logging under a supervisor

Three facts decide what journald actually shows you:

- `MYPKI_LOG_FILE` is relative to the working directory unless it is absolute, and mypki writes the resolved absolute
  path as the **first line** of the log file, so "where did it land?" is answerable from the log itself. In the unit
  below `WorkingDirectory=/var/lib/mypki` plus `--log-file logs/mypki.log` means `/var/lib/mypki/logs/mypki.log`
(a path stated from the rule, not observed: this box never started the unit).
- An empty `MYPKI_LOG_FILE=` (or `--log-file ""`) means console-only: mypki logs that choice, naming the cwd it chose.
- `log_to_console` defaults to **true**, so with a file handler attached every line is written twice — once to the file
  and once to stderr, which journald captures. Pass `--no-console-log` if you want journald to carry only uvicorn's own
  lines and let mypki's records live in the file; leave it off if you want them in journald too and accept that the same
  line appears in both places.

Rotation is size-bounded at `MYPKI_LOG_MAX_BYTES * (MYPKI_LOG_BACKUP_COUNT + 1)` and is per-process: one worker per log
file. The full logging section is [REFERENCE.md#logging](REFERENCE.md#logging).

## Run it as a systemd service

The unit file is [../deploy/mypki.service](../deploy/mypki.service). It is written from the flags, paths and logging
facts above and nothing else — no `Type=notify` (mypki never calls `sd_notify`; MEASURED: no `sd_notify` call exists in
`src/` or `tools/`), one process, an explicit `WorkingDirectory`, and `--no-console-log`.

```bash
# 1. Install the package where the unit expects it (paths in the unit are examples — edit them to match your host).
sudo mkdir -p /srv/mypki && sudo cp -r . /srv/mypki
cd /srv/mypki && python3 -m venv .venv && .venv/bin/pip install .

# 2. Create the CA as the account that will run the service. If the key is encrypted, a unit has no terminal to
#    prompt on, so the passphrase must come from the environment:
sudo -u mypki MYPKI_DATA_DIR=/var/lib/mypki /srv/mypki/.venv/bin/mypki init-ca --encrypt
sudo install -d -o mypki -g mypki -m 0700 /var/lib/mypki

# 3. Install the unit and start it.
sudo cp deploy/mypki.service /etc/systemd/system/mypki.service
sudo systemctl daemon-reload
sudo systemctl enable --now mypki.service
systemctl status mypki.service
journalctl -u mypki.service -n 50
```

Then point a browser at `http://127.0.0.1:8443`. To reach it from another machine, either bind mypki to a routable
address and firewall the port (the warning `serve` prints says exactly this) or leave it on loopback and terminate TLS
in nginx/Caddy in front of it — see [REFERENCE.md#serving-and-exposure](REFERENCE.md#serving-and-exposure). Session
cookies become `Secure` only when **both** TLS knobs are set on mypki itself.

## What was and was not verified on this box

- MEASURED here: `systemctl is-system-running` prints `offline` (exit 1) in this container, PID 1 is `tini`, and
  `systemd-analyze` 257 (`/usr/bin/systemd-analyze`) is present. So the unit file was **written** from measured facts
  and **never started**; there is no service start, no `systemctl status` output, and no journald line to report.
- MEASURED here, the static check only: `systemd-analyze verify deploy/mypki.service` exits **1** with exactly one
  finding — `mypki.service: Command /srv/mypki/.venv/bin/mypki is not executable: No such file or directory`. That is
  the placeholder `ExecStart` path, which does not exist on this box; nothing else about the unit was reported, and no
  syntax or dependency error was found. Point `ExecStart` at the interpreter you actually installed and re-run the
  verify on the host that will run it.
- The `Documentation=` line and every `/srv/mypki`, `/var/lib/mypki` path in the unit and in the commands above are
  **example install locations**, not measured ones: this checkout lives in a working tree, not in `/srv`.
- NOT MEASURABLE from this box: whether `systemctl enable --now mypki.service` succeeds on a real host, what journald
  duplication looks like in practice with `--no-console-log` omitted, whether a passphrase prompt is reached under a
  supervisor (the code path exists; the supervisor behaviour does not run here), and anything about browser rendering.
