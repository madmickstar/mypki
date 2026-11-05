"""mypki-raised failures, one type per condition. Handlers live in `app.py`; this module only *names* things.

Why a separate module: `validators.py`, `csr.py`, `signing.py` and `store.py` do the security-critical work, and a
test must be able to import them without pulling FastAPI into the process. If the exception types lived in
`app.py`, every one of those unit tests would drag the web framework along with it -- and the pure modules would be
one import away from becoming HTTP layers. Same posture as the reference project's `errors.py`.

Why a separate *type* per condition, instead of one `MypkiError("bad CSR")`: each type carries the fact its
handler needs, and a dedicated handler can turn that fact into the right page, exit code or status. A single
catch-all type flattens three genuinely different answers into one:

  * `CaAlreadyExistsError` is a **refusal** -- the operator asked for something destructive without `--force`.
    The CLI maps it to exit 2 so a wrapper script can tell "refused" from "broken" without parsing stderr.
  * `CaNotFoundError` is **missing state** -- nothing is wrong with the request, the host is not initialised.
    Exit 3, and the message names the command that fixes it (`mypki init-ca`).
  * `CsrValidationError` / `KeyPolicyError` / `CaPrivilegeRequestedError` are **rejections of user input**, each
    naming what specifically failed, because "invalid CSR" is not an answer an operator can act on (page-map §9).

Why not reuse Starlette's `HTTPException`: raising one from `csr.py` would make `csr.py` a web module, and a
validation failure raised during a CLI run (`mypki serve` validates nothing, but a future `--import-ca` might)
would carry an HTTP status into a non-HTTP context. Status is the handler's decision, not the raiser's.

Why not let `ValueError`/`x509.Error` escape directly: cryptography raises the same generic type for "this PEM is
garbage" and "this extension is malformed", and starlette answers an unhandled exception with a 500 plus a traceback
in the log. mypki's rule (page-map §0) is that every validation failure names its specific reason **on the page**,
so each library failure is translated here, at the boundary where it is caught, into a type whose message already
says what to do about it.
"""

from __future__ import annotations


class MypkiError(RuntimeError):
    """Base for every mypki-raised failure. Never raised directly -- always a named subclass."""


class CsrValidationError(MypkiError):
    """A pasted or generated CSR fails a validation rule (page-map §3 step A, §9).

    `field` names the input that failed (`csr_pem`, `common_name`, `sans[3]`, ...) and `reason` carries the
    sentence rendered on the page. Both exist so the message can be built where the check is -- next to the
    value being checked, where the position and the offending text are still in scope -- rather than
    reconstructed later from a generic "invalid CSR".
    """

    def __init__(self, reason: str, field: str | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.field = field


class CaPrivilegeRequestedError(MypkiError):
    """The CSR asks for CA powers. mypki signs end-entity certificates only (page-map §3 step A, rule 6).

    `extension` names what was rejected (`BasicConstraints CA:TRUE`, `KeyUsage keyCertSign`, ...), because the
    operator needs to know which line of their request to change -- and because a refusal that does not name the
    extension reads like the app is broken rather than like the request was refused on purpose.
    """

    def __init__(self, extension: str) -> None:
        super().__init__(f"This CSR requests CA privileges ({extension}). mypki signs end-entity certificates only.")
        self.extension = extension


class KeyPolicyError(MypkiError):
    """The key behind a CSR is too weak or on an unlisted curve (page-map §3 step A, rule 5).

    `spec` names the rejected spec as measured from the key itself ("RSA-1024", "EC P-224"), so the message says
    what was found and what is allowed instead of just "weak key".
    """

    def __init__(self, spec: str, allowed: str) -> None:
        super().__init__(f"{spec} is not an accepted key. Allowed: {allowed}.")
        self.spec = spec


class CaAlreadyExistsError(MypkiError):
    """A CA is already on disk and `--force` was not given (page-map §6).

    Carries `.path` so `cli.py` can print the refusal naming the file, exit **2**, and never dump a traceback for
    an expected condition. This is the only mypki error whose meaning is "no, and here is what would make it yes".
    """

    def __init__(self, path: object) -> None:
        super().__init__(f"CA already exists at {path}. Use --force to replace it.")
        self.path = path


class CaNotFoundError(MypkiError):
    """Required state is missing: no CA on this host (page-map §6).

    `cli.py` maps this to exit **3** and appends "run `mypki init-ca` first"; the web layer renders it as the
    one-line notice on `/`, `/csr/sign` and `/ca` (page-map §1). The GUI cannot create a CA, by design, so the
    only correct message is the command that fixes it.
    """

    def __init__(self, path: object) -> None:
        super().__init__(f"No CA found at {path}. Run `mypki init-ca` first.")
        self.path = path


class CaPassphraseError(MypkiError):
    """The CA key is encrypted and the passphrase supplied does not decrypt it.

    The message names the **env var** to set, never the secret, and never repeats any part of the key file: a
    wrong-passphrase failure is exactly the moment a logging layer is most likely to be read by someone other than
    the operator (page-map §8).
    """

    def __init__(self, passphrase_env: str = "MYPKI_CA_PASSPHRASE") -> None:
        super().__init__(
            f"The CA private key is encrypted and could not be decrypted. "
            f"Set the passphrase in the environment variable {passphrase_env} (or run init-ca with --encrypt)."
        )


class CsrfValidationError(MypkiError):
    """A POST arrived without a usable CSRF token (page-map §0).

    Its own type rather than a generic 400 because the handler must be able to say something specific: **nothing was
    signed**. A CSRF rejection that looks like every other bad request leaves an operator wondering whether a
    certificate
    was issued with a wrong name, when in fact no signing code ran at all. `field` names the form field that was
    missing or
    wrong so the page can point at it.

    The message never quotes either token value: a log line or a page containing a valid token is a second way to
    steal it
    (see `csrf.py`).
    """

    def __init__(self, reason: str, field: str | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.field = field


class RequestTooLargeError(MypkiError):
    """A submitted body exceeds mypki's own cap (page-map §0, §3).

    Exists because starlette answers an oversized form part with **400** and a bare JSON
    `{"detail":"Field exceeded maximum size of 1024KB."}` (starlette's own answer): correct status, wrong
    artifact -- mypki promises its own error page naming its own limit (`MYPKI_MAX_CSR_CHARS`), so the size check
    runs before starlette's parser can answer first, and this type is what that check raises.
    """

    def __init__(self, actual: int, limit: int, knob: str) -> None:
        super().__init__(f"Input is {actual:,} characters; the limit is {limit:,} (`{knob}`).")
        self.actual = actual
        self.limit = limit


class RevocationRecordNotFoundError(MypkiError):
    """A revoke request named a serial this host has no record of (page-map §5).

    Its own type because the honest answer is about *this host's records*, not about the certificate: mypki can only
    revoke what it logged, and an operator who pasted a serial from another machine's CA needs to be told that the name
    is unknown here rather than being shown a stack trace or, worse, a success message for a revocation that did not
    happen. `path` names the database so the operator can check which data dir this server is actually reading.
    """

    def __init__(self, serial_hex: str, db_file: object) -> None:
        super().__init__(
            f"No issued record with serial {serial_hex} in {db_file}. mypki can only revoke certificates this host "
            "signed and recorded."
        )
        self.serial_hex = serial_hex
        self.path = db_file


class OneShotExpiredError(MypkiError):
    """A download link points at an artifact that has already expired or left this process (page-map §10).

    Rendered as a 404 page, not a redirect back to the form: re-running the generation would mint a different key,
    and silently doing that behind a stale bookmark is worse than saying "that one-shot output is gone".
    """
