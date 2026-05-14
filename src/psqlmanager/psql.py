"""Wrappers around the psql binary.

The effective password is passed in as an argument (resolved by the CLI from
either the static stored password or a freshly-minted IAM token) and set on
the child process via PGPASSWORD. It never appears in argv, so it can't leak
through /proc/<pid>/cmdline. We also clear PGPASSWORD/PGPASSFILE from the
child env when no password is set to avoid ambient credentials sneaking in.

Read-only credentials are enforced server-side by prepending
`-c default_transaction_read_only=on` to PGOPTIONS. The Postgres server
rejects writes with `ERROR: cannot execute INSERT in a read-only transaction`,
so no SQL parsing is needed on our side.
"""

from __future__ import annotations

import os
import shutil
import sys
from typing import Iterable

from .store import Credential


def find_psql() -> str:
    path = shutil.which("psql")
    if not path:
        raise FileNotFoundError(
            "psql executable not found on PATH. Install PostgreSQL client tools."
        )
    return path


def build_env(
    cred: Credential,
    password: str,
    base_env: dict[str, str] | None = None,
    allow_write: bool = False,
) -> dict[str, str]:
    env = dict(base_env if base_env is not None else os.environ)
    if password:
        env["PGPASSWORD"] = password
    else:
        env.pop("PGPASSWORD", None)
    env.pop("PGPASSFILE", None)
    if cred.sslmode:
        env["PGSSLMODE"] = cred.sslmode

    opts: list[str] = []
    if cred.readonly and not allow_write:
        opts.append("-c default_transaction_read_only=on")
    for k, v in (cred.options or {}).items():
        opts.append(f"-c {k}={v}")
    if opts:
        existing = env.get("PGOPTIONS", "").strip()
        added = " ".join(opts)
        env["PGOPTIONS"] = f"{existing} {added}".strip() if existing else added
    return env


def build_argv(cred: Credential, extra: Iterable[str] = ()) -> list[str]:
    argv = [find_psql()]
    if cred.host:
        argv += ["-h", cred.host]
    if cred.port:
        argv += ["-p", str(cred.port)]
    if cred.user:
        argv += ["-U", cred.user]
    if cred.dbname:
        argv += ["-d", cred.dbname]
    argv += list(extra)
    return argv


def exec_psql(
    cred: Credential,
    password: str,
    extra: Iterable[str] = (),
    allow_write: bool = False,
) -> None:
    """Replace the current process with psql. Never returns on success."""
    argv = build_argv(cred, extra)
    env = build_env(cred, password, allow_write=allow_write)
    os.execvpe(argv[0], argv, env)


def run_psql(
    cred: Credential,
    password: str,
    extra: Iterable[str] = (),
    allow_write: bool = False,
) -> int:
    """Spawn psql, wait, return its exit code."""
    import subprocess

    argv = build_argv(cred, extra)
    env = build_env(cred, password, allow_write=allow_write)
    proc = subprocess.run(argv, env=env, stdin=sys.stdin)
    return proc.returncode
