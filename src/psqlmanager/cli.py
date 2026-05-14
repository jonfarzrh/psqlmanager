"""psqlmanager command-line interface.

Designed for both humans and agents:

  * Every command supports a `--json` flag for machine-readable output.
  * Errors emit a stable JSON envelope on stderr when --json is set, with a
    short `code` ("locked", "not_found", "exists", "no_psql", ...) and a
    human-readable `error` message.
  * Passwords can be supplied via --password-stdin or the PSQLMANAGER_PASSWORD
    env var; interactive prompts only fire when stdin is a TTY.
  * Exit codes are stable: 0 success, 1 generic, 2 misuse (typer/click
    default), 3 locked store, 4 missing entry, 5 psql not installed,
    6 IAM token mint failed.
"""

from __future__ import annotations

import json
import os
import sys
from enum import Enum
from typing import Annotated, Any, Optional
from urllib.parse import unquote, urlparse

import click
import typer

from . import __version__
from .auth import (
    IAM_METHODS,
    SUPPORTED_METHODS,
    AuthError,
    clear_cache,
    list_cache,
    resolve_password,
)
from .psql import find_psql, exec_psql, run_psql
from .store import (
    PASSPHRASE_ENV,
    Credential,
    CredentialStore,
    LockedError,
    StoreError,
    file_mode_octal,
)

EXIT_OK = 0
EXIT_GENERIC = 1
EXIT_LOCKED = 3
EXIT_NOT_FOUND = 4
EXIT_NO_PSQL = 5
EXIT_AUTH_FAILED = 6

PASSWORD_ENV = "PSQLMANAGER_PASSWORD"


class AuthMethod(str, Enum):
    """Authentication methods supported by --auth.

    Inherits from `str` so existing code comparing the value against bare
    strings ("password", "iam-rds", ...) keeps working.
    """

    password = "password"
    iam_rds = "iam-rds"
    iam_gcp = "iam-gcp"
    iam_azure = "iam-azure"


# Sanity check: keep the Enum and the auth module's SUPPORTED_METHODS in sync.
assert tuple(m.value for m in AuthMethod) == SUPPORTED_METHODS


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _emit(obj: Any, *, json_mode: bool, human: str | None = None) -> None:
    if json_mode:
        click.echo(json.dumps(obj, indent=2, sort_keys=True))
    elif human is not None:
        click.echo(human)


def _fail(message: str, *, code: str, json_mode: bool, exit_code: int) -> None:
    if json_mode:
        click.echo(
            json.dumps({"error": message, "code": code}, sort_keys=True),
            err=True,
        )
    else:
        click.echo(f"error: {message}", err=True)
    raise typer.Exit(code=exit_code)


def _store(passphrase: str | None) -> CredentialStore:
    store = CredentialStore()
    store.unlock(passphrase=passphrase)
    return store


def _resolve_password_input(
    *,
    password: str | None,
    password_stdin: bool,
    no_password: bool,
    interactive_label: str,
) -> str:
    """Pick a password from the available sources, in order:
       --password-stdin > --password > PSQLMANAGER_PASSWORD > prompt > "".
    """
    if no_password:
        return ""
    if password_stdin:
        data = sys.stdin.read()
        return data.rstrip("\n")
    if password is not None:
        return password
    env_pw = os.environ.get(PASSWORD_ENV)
    if env_pw is not None:
        return env_pw
    if sys.stdin.isatty():
        return click.prompt(interactive_label, hide_input=True, default="", show_default=False)
    return ""


def _parse_url(url: str) -> dict[str, Any]:
    parsed = urlparse(url)
    if parsed.scheme not in ("postgres", "postgresql"):
        raise typer.BadParameter(
            f"Unsupported URL scheme {parsed.scheme!r}; expected postgres:// or postgresql://"
        )
    fields: dict[str, Any] = {}
    if parsed.hostname:
        fields["host"] = parsed.hostname
    if parsed.port:
        fields["port"] = parsed.port
    if parsed.username:
        fields["user"] = unquote(parsed.username)
    if parsed.password:
        fields["password"] = unquote(parsed.password)
    if parsed.path and parsed.path.lstrip("/"):
        fields["dbname"] = unquote(parsed.path.lstrip("/"))
    if parsed.query:
        from urllib.parse import parse_qsl

        options: dict[str, str] = {}
        for k, v in parse_qsl(parsed.query, keep_blank_values=False):
            if k == "sslmode":
                fields["sslmode"] = v
            else:
                options[k] = v
        if options:
            fields["options"] = options
    return fields


def _version_callback(value: bool) -> None:
    if value:
        click.echo(f"psqlmanager {__version__}")
        raise typer.Exit()


# ---------------------------------------------------------------------------
# main app
# ---------------------------------------------------------------------------

main = typer.Typer(
    name="psqlmanager",
    help=(
        "Encrypted credential manager and psql wrapper.\n\n"
        "Run `psqlmanager init` once to set up the encrypted store, then `add` a "
        "named credential and use `connect` or `exec` to launch psql."
    ),
    context_settings={"help_option_names": ["-h", "--help"]},
    no_args_is_help=True,
    add_completion=False,
)


@main.callback()
def _root(
    version: Annotated[
        Optional[bool],
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Show the version and exit.",
        ),
    ] = None,
) -> None:
    """Root callback. Holds the global --version flag."""


# ---------------------------------------------------------------------------
# init / info / destroy
# ---------------------------------------------------------------------------


@main.command()
def init(
    use_passphrase: Annotated[
        bool,
        typer.Option("--passphrase", help="Use passphrase mode instead of the OS keyring."),
    ] = False,
    json_mode: Annotated[bool, typer.Option("--json", help="Emit JSON on success.")] = False,
) -> None:
    """Initialize the encrypted credential store."""
    store = CredentialStore()
    if store.exists:
        _fail(
            f"Store already exists at {store.path}. Use `destroy` to remove it.",
            code="exists",
            json_mode=json_mode,
            exit_code=EXIT_GENERIC,
        )

    if use_passphrase:
        env_pw = os.environ.get(PASSPHRASE_ENV)
        if env_pw:
            passphrase = env_pw
        elif sys.stdin.isatty():
            passphrase = click.prompt(
                "Set master passphrase",
                hide_input=True,
                confirmation_prompt="Confirm master passphrase",
            )
        else:
            _fail(
                f"Passphrase mode requested but no passphrase provided. "
                f"Set {PASSPHRASE_ENV}.",
                code="no_passphrase",
                json_mode=json_mode,
                exit_code=EXIT_GENERIC,
            )
        try:
            store.initialize(mode="passphrase", passphrase=passphrase)
        except StoreError as e:
            _fail(str(e), code="init_failed", json_mode=json_mode, exit_code=EXIT_GENERIC)
    else:
        try:
            store.initialize(mode="keyring")
        except StoreError as e:
            _fail(str(e), code="no_keyring", json_mode=json_mode, exit_code=EXIT_GENERIC)

    _emit(
        {"status": "initialized", "path": str(store.path), "mode": store.mode},
        json_mode=json_mode,
        human=f"Initialized credential store at {store.path} (mode: {store.mode}).",
    )


@main.command()
def info(
    json_mode: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Print store metadata (path, mode, permissions, entry count)."""
    store = CredentialStore()
    payload: dict[str, Any] = {
        "path": str(store.path),
        "exists": store.exists,
        "permissions": file_mode_octal(store.path) if store.exists else None,
        "psql_path": None,
    }
    try:
        payload["psql_path"] = find_psql()
    except FileNotFoundError:
        payload["psql_path"] = None

    if store.exists:
        try:
            store.unlock()
            payload["mode"] = store.mode
            payload["count"] = len(store.list_names())
            payload["locked"] = False
        except LockedError as e:
            payload["locked"] = True
            payload["lock_reason"] = str(e)
        except StoreError as e:
            payload["error"] = str(e)

    if json_mode:
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
        return

    click.echo(f"path:        {payload['path']}")
    click.echo(f"exists:      {payload['exists']}")
    if payload["exists"]:
        click.echo(f"permissions: {payload['permissions']}")
        if "mode" in payload:
            click.echo(f"mode:        {payload['mode']}")
            click.echo(f"count:       {payload['count']}")
        elif payload.get("locked"):
            click.echo(f"locked:      yes ({payload['lock_reason']})")
    click.echo(f"psql:        {payload['psql_path'] or 'not found on PATH'}")


@main.command()
def destroy(
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip confirmation.")] = False,
    json_mode: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Delete the credential store and its master key."""
    store = CredentialStore()
    if not store.exists:
        _fail(
            "No store to destroy.",
            code="not_found",
            json_mode=json_mode,
            exit_code=EXIT_NOT_FOUND,
        )
    if not yes:
        if not sys.stdin.isatty():
            _fail(
                "Refusing to destroy non-interactively without --yes.",
                code="needs_confirmation",
                json_mode=json_mode,
                exit_code=EXIT_GENERIC,
            )
        click.confirm(
            f"Permanently delete {store.path} and the keyring entry?",
            abort=True,
        )
    try:
        store.unlock()
    except StoreError:
        pass
    store.destroy()
    _emit(
        {"status": "destroyed"},
        json_mode=json_mode,
        human="Credential store destroyed.",
    )


# ---------------------------------------------------------------------------
# CRUD on named credentials
# ---------------------------------------------------------------------------

PassphraseOpt = Annotated[
    Optional[str],
    typer.Option(
        "--passphrase",
        envvar=PASSPHRASE_ENV,
        help=f"Passphrase for passphrase-mode stores (or set {PASSPHRASE_ENV}).",
    ),
]


@main.command()
def add(
    name: Annotated[str, typer.Argument(help="Credential name.")],
    host: Annotated[Optional[str], typer.Option(help="Host name.")] = None,
    port: Annotated[Optional[int], typer.Option(help="TCP port.")] = None,
    user: Annotated[Optional[str], typer.Option(help="Database user.")] = None,
    dbname: Annotated[Optional[str], typer.Option(help="Database name.")] = None,
    sslmode: Annotated[Optional[str], typer.Option(help="libpq sslmode.")] = None,
    url: Annotated[
        Optional[str],
        typer.Option(help="Parse a postgres:// connection string."),
    ] = None,
    password: Annotated[
        Optional[str],
        typer.Option(help="Password (NOT recommended; appears in shell history)."),
    ] = None,
    password_stdin: Annotated[
        bool, typer.Option("--password-stdin", help="Read password from stdin.")
    ] = False,
    no_password: Annotated[
        bool, typer.Option("--no-password", help="Store an empty password.")
    ] = False,
    auth_method: Annotated[
        AuthMethod,
        typer.Option(
            "--auth",
            help="Authentication method. IAM methods mint short-lived tokens at psql time.",
        ),
    ] = AuthMethod.password,
    aws_region: Annotated[
        Optional[str], typer.Option(help="AWS region for iam-rds.")
    ] = None,
    aws_profile: Annotated[
        Optional[str], typer.Option(help="AWS named profile for iam-rds.")
    ] = None,
    gcp_account: Annotated[
        Optional[str],
        typer.Option(help="gcloud account for iam-gcp (defaults to active account)."),
    ] = None,
    azure_tenant: Annotated[
        Optional[str], typer.Option(help="Azure tenant ID for iam-azure.")
    ] = None,
    readonly: Annotated[
        bool,
        typer.Option(
            "--readonly/--no-readonly",
            help=(
                "Enforce server-side read-only transactions (rejects "
                "INSERT/UPDATE/DELETE/DDL). Recommended for credentials handed "
                "to AI agents."
            ),
        ),
    ] = False,
    force: Annotated[bool, typer.Option("--force", help="Overwrite an existing entry.")] = False,
    json_mode: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
    passphrase: PassphraseOpt = None,
) -> None:
    """Add or update a named credential."""
    try:
        store = _store(passphrase)
    except LockedError as e:
        _fail(str(e), code="locked", json_mode=json_mode, exit_code=EXIT_LOCKED)
    except StoreError as e:
        _fail(str(e), code="store_error", json_mode=json_mode, exit_code=EXIT_GENERIC)

    fields: dict[str, Any] = {}
    if url:
        fields.update(_parse_url(url))
    if host is not None:
        fields["host"] = host
    if port is not None:
        fields["port"] = port
    if user is not None:
        fields["user"] = user
    if dbname is not None:
        fields["dbname"] = dbname
    if sslmode is not None:
        fields["sslmode"] = sslmode

    auth_params: dict[str, str] = {}
    method_str = auth_method.value
    if method_str == "iam-rds":
        if not aws_region:
            _fail(
                "--auth iam-rds requires --aws-region.",
                code="missing_param",
                json_mode=json_mode,
                exit_code=EXIT_GENERIC,
            )
        auth_params["region"] = aws_region
        if aws_profile:
            auth_params["profile"] = aws_profile
    elif method_str == "iam-gcp":
        if gcp_account:
            auth_params["account"] = gcp_account
    elif method_str == "iam-azure":
        if azure_tenant:
            auth_params["tenant"] = azure_tenant
    fields["auth_method"] = method_str
    fields["auth_params"] = auth_params
    fields["readonly"] = readonly

    if method_str in IAM_METHODS:
        if password is not None or password_stdin:
            _fail(
                f"--password/--password-stdin not valid with --auth {method_str}; "
                "IAM tokens are minted automatically.",
                code="bad_auth_combo",
                json_mode=json_mode,
                exit_code=EXIT_GENERIC,
            )
        fields["password"] = ""
        if not fields.get("sslmode"):
            fields["sslmode"] = "require"
    else:
        explicit_pw_requested = password is not None or password_stdin or no_password
        if explicit_pw_requested or "password" not in fields:
            fields["password"] = _resolve_password_input(
                password=password,
                password_stdin=password_stdin,
                no_password=no_password,
                interactive_label=f"Password for {name}",
            )

    cred = Credential(name=name, **{k: v for k, v in fields.items() if v is not None})

    try:
        existed = store.upsert(cred, force=force)
    except StoreError as e:
        _fail(str(e), code="exists", json_mode=json_mode, exit_code=EXIT_GENERIC)

    if method_str in IAM_METHODS or existed:
        clear_cache(name)

    _emit(
        {
            "status": "updated" if existed else "created",
            "credential": cred.public_dict(reveal=False),
        },
        json_mode=json_mode,
        human=f"{'Updated' if existed else 'Added'} credential {name!r}.",
    )


@main.command(name="list")
def list_cmd(
    json_mode: Annotated[
        bool, typer.Option("--json", help="Emit JSON (full sanitized records).")
    ] = False,
    passphrase: PassphraseOpt = None,
) -> None:
    """List stored credential names."""
    try:
        store = _store(passphrase)
    except LockedError as e:
        _fail(str(e), code="locked", json_mode=json_mode, exit_code=EXIT_LOCKED)
    except StoreError as e:
        _fail(str(e), code="store_error", json_mode=json_mode, exit_code=EXIT_GENERIC)

    names = store.list_names()
    if json_mode:
        click.echo(
            json.dumps(
                {"credentials": [store.get(n).public_dict(reveal=False) for n in names]},
                indent=2,
                sort_keys=True,
            )
        )
        return

    if not names:
        click.echo("(no credentials)")
        return
    for n in names:
        c = store.get(n)
        target = f"{c.user + '@' if c.user else ''}{c.host}:{c.port}/{c.dbname or ''}".rstrip("/")
        flag = " [ro]" if c.readonly else ""
        click.echo(f"{n}\t{target}{flag}")


@main.command()
def show(
    name: Annotated[str, typer.Argument()],
    reveal: Annotated[
        bool, typer.Option("--reveal", help="Include the password in the output.")
    ] = False,
    json_mode: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
    passphrase: PassphraseOpt = None,
) -> None:
    """Show fields for a single credential."""
    try:
        store = _store(passphrase)
    except LockedError as e:
        _fail(str(e), code="locked", json_mode=json_mode, exit_code=EXIT_LOCKED)
    except StoreError as e:
        _fail(str(e), code="store_error", json_mode=json_mode, exit_code=EXIT_GENERIC)

    try:
        cred = store.get(name)
    except StoreError as e:
        _fail(str(e), code="not_found", json_mode=json_mode, exit_code=EXIT_NOT_FOUND)

    data = cred.public_dict(reveal=reveal)
    if json_mode:
        click.echo(json.dumps(data, indent=2, sort_keys=True))
        return
    width = max(len(k) for k in data)
    for k in sorted(data):
        click.echo(f"{k.ljust(width)}  {data[k]}")


@main.command()
def rm(
    name: Annotated[str, typer.Argument()],
    json_mode: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
    passphrase: PassphraseOpt = None,
) -> None:
    """Delete a credential."""
    try:
        store = _store(passphrase)
    except LockedError as e:
        _fail(str(e), code="locked", json_mode=json_mode, exit_code=EXIT_LOCKED)
    except StoreError as e:
        _fail(str(e), code="store_error", json_mode=json_mode, exit_code=EXIT_GENERIC)

    try:
        store.delete(name)
    except StoreError as e:
        _fail(str(e), code="not_found", json_mode=json_mode, exit_code=EXIT_NOT_FOUND)
    _emit(
        {"status": "deleted", "name": name},
        json_mode=json_mode,
        human=f"Removed credential {name!r}.",
    )


@main.command()
def rename(
    old: Annotated[str, typer.Argument()],
    new: Annotated[str, typer.Argument()],
    json_mode: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
    passphrase: PassphraseOpt = None,
) -> None:
    """Rename a credential."""
    try:
        store = _store(passphrase)
    except LockedError as e:
        _fail(str(e), code="locked", json_mode=json_mode, exit_code=EXIT_LOCKED)
    except StoreError as e:
        _fail(str(e), code="store_error", json_mode=json_mode, exit_code=EXIT_GENERIC)

    try:
        store.rename(old, new)
    except StoreError as e:
        code = "exists" if "already exists" in str(e) else "not_found"
        exit_code = EXIT_GENERIC if code == "exists" else EXIT_NOT_FOUND
        _fail(str(e), code=code, json_mode=json_mode, exit_code=exit_code)
    _emit(
        {"status": "renamed", "old": old, "new": new},
        json_mode=json_mode,
        human=f"Renamed {old!r} -> {new!r}.",
    )


# ---------------------------------------------------------------------------
# psql invocation
# ---------------------------------------------------------------------------


def _load_and_authenticate(name: str, passphrase: str | None) -> tuple[Credential, str]:
    """Common path for connect/exec: unlock store, fetch cred, mint/lookup password."""
    try:
        store = _store(passphrase)
        cred = store.get(name)
    except LockedError as e:
        _fail(str(e), code="locked", json_mode=False, exit_code=EXIT_LOCKED)
    except StoreError as e:
        code = "not_found" if "No credential" in str(e) else "store_error"
        exit_code = EXIT_NOT_FOUND if code == "not_found" else EXIT_GENERIC
        _fail(str(e), code=code, json_mode=False, exit_code=exit_code)

    try:
        password = resolve_password(cred)
    except AuthError as e:
        _fail(str(e), code=e.code, json_mode=False, exit_code=EXIT_AUTH_FAILED)
    return cred, password


def _warn_if_overriding_readonly(cred: Credential, allow_write: bool) -> None:
    if cred.readonly and allow_write:
        click.echo(
            f"WARNING: --allow-write is overriding read-only protection on credential "
            f"{cred.name!r}. This invocation can issue INSERT/UPDATE/DELETE/DDL.",
            err=True,
        )


def _strip_leading_separator(psql_args: tuple[str, ...]) -> tuple[str, ...]:
    """`psqlmanager exec NAME -- -c "..."` is the natural shell syntax, but
    Click leaves the `--` in psql_args, where psql then treats it as
    end-of-options and mis-parses the following `-c`. Strip it ourselves."""
    if psql_args and psql_args[0] == "--":
        return psql_args[1:]
    return psql_args


# Shared context settings: any token that looks like an option (e.g. `-c`)
# is forwarded to psql verbatim instead of being parsed by typer/click.
_PASSTHROUGH = {
    "ignore_unknown_options": True,
    "allow_interspersed_args": False,
    "help_option_names": ["-h", "--help"],
}


@main.command(context_settings=_PASSTHROUGH)
def connect(
    name: Annotated[str, typer.Argument()],
    allow_write: Annotated[
        bool,
        typer.Option(
            "--allow-write",
            help=(
                "Bypass the credential's read-only protection for this invocation. "
                "Emits a warning to stderr."
            ),
        ),
    ] = False,
    passphrase: PassphraseOpt = None,
    psql_args: Annotated[
        Optional[list[str]],
        typer.Argument(
            metavar="[-- PSQL_ARGS...]",
            help="Anything after NAME is forwarded to psql.",
        ),
    ] = None,
) -> None:
    """Open an interactive psql shell with the named credential."""
    cred, password = _load_and_authenticate(name, passphrase)
    _warn_if_overriding_readonly(cred, allow_write)
    extra = _strip_leading_separator(tuple(psql_args or ()))
    try:
        exec_psql(cred, password, extra, allow_write=allow_write)
    except FileNotFoundError as e:
        _fail(str(e), code="no_psql", json_mode=False, exit_code=EXIT_NO_PSQL)


@main.command(name="exec", context_settings=_PASSTHROUGH)
def exec_cmd(
    name: Annotated[str, typer.Argument()],
    allow_write: Annotated[
        bool,
        typer.Option(
            "--allow-write",
            help=(
                "Bypass the credential's read-only protection for this invocation. "
                "Emits a warning to stderr."
            ),
        ),
    ] = False,
    passphrase: PassphraseOpt = None,
    psql_args: Annotated[
        Optional[list[str]],
        typer.Argument(
            metavar="[-- PSQL_ARGS...]",
            help="Anything after NAME is forwarded to psql.",
        ),
    ] = None,
) -> None:
    """Run psql once with the named credential and forwarded args."""
    cred, password = _load_and_authenticate(name, passphrase)
    _warn_if_overriding_readonly(cred, allow_write)
    extra = _strip_leading_separator(tuple(psql_args or ()))
    try:
        rc = run_psql(cred, password, extra, allow_write=allow_write)
    except FileNotFoundError as e:
        _fail(str(e), code="no_psql", json_mode=False, exit_code=EXIT_NO_PSQL)
    raise typer.Exit(code=rc)


# ---------------------------------------------------------------------------
# Cache management for IAM tokens
# ---------------------------------------------------------------------------

cache_app = typer.Typer(
    help="Manage cached IAM auth tokens.",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)
main.add_typer(cache_app, name="cache")


@cache_app.command("list")
def cache_list_cmd(
    json_mode: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Show cached tokens and their remaining TTL."""
    entries = list_cache()
    if json_mode:
        click.echo(json.dumps({"cache": entries}, indent=2, sort_keys=True))
        return
    if not entries:
        click.echo("(cache empty)")
        return
    for e in entries:
        ttl = e["expires_in_seconds"]
        status = "EXPIRED" if e["expired"] else f"{ttl}s left"
        click.echo(f"{e['name']}\t{e['method']}\t{status}")


@cache_app.command("clear")
def cache_clear_cmd(
    name: Annotated[Optional[str], typer.Argument()] = None,
    json_mode: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Remove cached tokens. With NAME, clears one; otherwise clears all."""
    removed = clear_cache(name)
    _emit(
        {"status": "cleared", "removed": removed, "name": name},
        json_mode=json_mode,
        human=f"Removed {removed} cache entr{'y' if removed == 1 else 'ies'}.",
    )


if __name__ == "__main__":
    main()
