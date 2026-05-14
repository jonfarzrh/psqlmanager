"""Unit tests for psql argv/env construction.

These tests avoid actually launching psql; they verify that we put the right
flags on argv and the right secrets in the child env.
"""

from __future__ import annotations

from psqlmanager import psql
from psqlmanager.store import Credential


def test_argv_includes_host_port_user_dbname(monkeypatch) -> None:
    monkeypatch.setattr(psql, "find_psql", lambda: "/usr/bin/psql")
    cred = Credential(
        name="prod", host="h", port=5433, user="u", dbname="db", password="p"
    )
    argv = psql.build_argv(cred, extra=("-c", "select 1"))
    assert argv == [
        "/usr/bin/psql",
        "-h", "h",
        "-p", "5433",
        "-U", "u",
        "-d", "db",
        "-c", "select 1",
    ]


def test_argv_omits_empty_fields(monkeypatch) -> None:
    monkeypatch.setattr(psql, "find_psql", lambda: "/usr/bin/psql")
    cred = Credential(name="prod", host="", port=0, user="", dbname="")
    assert psql.build_argv(cred) == ["/usr/bin/psql"]


def test_password_never_in_argv(monkeypatch) -> None:
    """A password must never reach argv where it could leak via /proc/<pid>/cmdline."""
    monkeypatch.setattr(psql, "find_psql", lambda: "/usr/bin/psql")
    secret = "SUPER_SECRET_DO_NOT_LEAK"
    cred = Credential(
        name="prod", host="h", port=5432, user="u", dbname="db", password=secret
    )
    argv = psql.build_argv(cred, extra=("-c", "select 1"))
    assert secret not in argv
    assert not any(secret in tok for tok in argv)


def test_env_sets_pgpassword_from_arg() -> None:
    cred = Credential(name="prod")
    env = psql.build_env(cred, password="s3cret", base_env={})
    assert env["PGPASSWORD"] == "s3cret"


def test_env_strips_ambient_pgpassword_when_empty() -> None:
    cred = Credential(name="prod")
    env = psql.build_env(
        cred, password="", base_env={"PGPASSWORD": "leftover", "PGPASSFILE": "/x"}
    )
    assert "PGPASSWORD" not in env
    assert "PGPASSFILE" not in env


def test_env_password_can_be_iam_token() -> None:
    """A freshly-minted IAM token is just a string from build_env's point of view."""
    cred = Credential(name="prod", auth_method="iam-rds", auth_params={"region": "us-east-1"})
    iam_token = "https://rds-iam-token..." + "X" * 100
    env = psql.build_env(cred, password=iam_token, base_env={})
    assert env["PGPASSWORD"] == iam_token


def test_env_sets_sslmode() -> None:
    cred = Credential(name="prod", sslmode="require")
    env = psql.build_env(cred, password="", base_env={})
    assert env["PGSSLMODE"] == "require"


def test_env_appends_to_existing_pgoptions() -> None:
    cred = Credential(name="prod", options={"statement_timeout": "5s"})
    env = psql.build_env(
        cred, password="", base_env={"PGOPTIONS": "-c search_path=public"}
    )
    assert "search_path=public" in env["PGOPTIONS"]
    assert "statement_timeout=5s" in env["PGOPTIONS"]


def test_pgpassfile_always_dropped() -> None:
    cred = Credential(name="prod")
    env = psql.build_env(cred, password="s3cret", base_env={"PGPASSFILE": "/etc/passwd"})
    assert "PGPASSFILE" not in env


def test_readonly_credential_sets_default_transaction_read_only() -> None:
    cred = Credential(name="prod", readonly=True)
    env = psql.build_env(cred, password="pw", base_env={})
    assert "default_transaction_read_only=on" in env["PGOPTIONS"]


def test_readonly_credential_with_allow_write_drops_enforcement() -> None:
    cred = Credential(name="prod", readonly=True)
    env = psql.build_env(cred, password="pw", base_env={}, allow_write=True)
    assert "default_transaction_read_only" not in env.get("PGOPTIONS", "")


def test_readwrite_credential_has_no_readonly_pgoption() -> None:
    cred = Credential(name="prod", readonly=False)
    env = psql.build_env(cred, password="pw", base_env={})
    assert "default_transaction_read_only" not in env.get("PGOPTIONS", "")


def test_readonly_preserves_existing_pgoptions() -> None:
    cred = Credential(name="prod", readonly=True, options={"statement_timeout": "5s"})
    env = psql.build_env(
        cred, password="pw", base_env={"PGOPTIONS": "-c search_path=public"}
    )
    pgopts = env["PGOPTIONS"]
    assert "default_transaction_read_only=on" in pgopts
    assert "statement_timeout=5s" in pgopts
    assert "search_path=public" in pgopts
