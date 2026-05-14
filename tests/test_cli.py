"""End-to-end CLI tests using Click's CliRunner."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from psqlmanager import auth as auth_mod
from psqlmanager import psql as psql_mod
from psqlmanager.cli import (
    EXIT_AUTH_FAILED,
    EXIT_GENERIC,
    EXIT_LOCKED,
    EXIT_NOT_FOUND,
    EXIT_NO_PSQL,
    main,
)
from tests.conftest import TEST_PASSPHRASE


@pytest.fixture
def cli() -> CliRunner:
    # Click 8.3 keeps stdout/stderr separate by default; older versions need mix_stderr=False.
    try:
        return CliRunner(mix_stderr=False)  # type: ignore[call-arg]
    except TypeError:
        return CliRunner()


def _run(cli: CliRunner, *args: str, input: str | None = None):
    return cli.invoke(main, list(args), input=input, catch_exceptions=False)


def _stderr_envelope(result) -> dict:
    """Decode the JSON error envelope written on stderr."""
    return json.loads(result.stderr.strip())


def test_init_emits_json_status(sandbox_home: Path, cli: CliRunner) -> None:
    result = _run(cli, "init", "--passphrase", "--json")
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "initialized"
    assert payload["mode"] == "passphrase"
    assert payload["path"].endswith("creds.json")


def test_init_twice_errors(sandbox_home: Path, cli: CliRunner) -> None:
    _run(cli, "init", "--passphrase", "--json")
    result = _run(cli, "init", "--passphrase", "--json")
    assert result.exit_code == EXIT_GENERIC
    assert _stderr_envelope(result)["code"] == "exists"


def test_add_via_flags_with_password_stdin(sandbox_home: Path, cli: CliRunner) -> None:
    _run(cli, "init", "--passphrase", "--json")
    result = _run(
        cli,
        "add",
        "prod",
        "--host", "db.example.com",
        "--port", "5433",
        "--user", "u",
        "--dbname", "db",
        "--sslmode", "require",
        "--password-stdin",
        "--json",
        input="topsecret\n",
    )
    assert result.exit_code == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "created"
    assert "topsecret" not in result.stdout
    assert payload["credential"]["password"] == "***"


def test_add_via_url_parses_all_fields(sandbox_home: Path, cli: CliRunner) -> None:
    _run(cli, "init", "--passphrase", "--json")
    url = "postgresql://an%40lyst:p%40ss@db.example.com:5433/wh?sslmode=require"
    result = _run(cli, "add", "prod", "--url", url, "--json")
    assert result.exit_code == 0, result.stderr
    cred = json.loads(result.stdout)["credential"]
    assert cred["user"] == "an@lyst"
    assert cred["host"] == "db.example.com"
    assert cred["port"] == 5433
    assert cred["dbname"] == "wh"
    assert cred["sslmode"] == "require"
    show = _run(cli, "show", "prod", "--reveal", "--json")
    assert json.loads(show.stdout)["password"] == "p@ss"


def test_add_duplicate_without_force(sandbox_home: Path, cli: CliRunner) -> None:
    _run(cli, "init", "--passphrase", "--json")
    _run(cli, "add", "prod", "--host", "h", "--no-password", "--json")
    result = _run(cli, "add", "prod", "--host", "other", "--no-password", "--json")
    assert result.exit_code == EXIT_GENERIC
    assert _stderr_envelope(result)["code"] == "exists"


def test_add_duplicate_with_force(sandbox_home: Path, cli: CliRunner) -> None:
    _run(cli, "init", "--passphrase", "--json")
    _run(cli, "add", "prod", "--host", "h", "--no-password", "--json")
    result = _run(
        cli, "add", "prod", "--host", "other", "--no-password", "--force", "--json"
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "updated"
    assert payload["credential"]["host"] == "other"


def test_add_uses_password_env_var(
    sandbox_home: Path, cli: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    _run(cli, "init", "--passphrase", "--json")
    monkeypatch.setenv("PSQLMANAGER_PASSWORD", "env-secret")
    result = _run(cli, "add", "prod", "--host", "h", "--json")
    assert result.exit_code == 0
    show = _run(cli, "show", "prod", "--reveal", "--json")
    assert json.loads(show.stdout)["password"] == "env-secret"


def test_list_human_and_json(sandbox_home: Path, cli: CliRunner) -> None:
    _run(cli, "init", "--passphrase", "--json")
    _run(cli, "add", "prod", "--host", "h", "--user", "u", "--dbname", "d", "--no-password")
    human = _run(cli, "list")
    assert "prod" in human.stdout
    js = _run(cli, "list", "--json")
    payload = json.loads(js.stdout)
    assert [c["name"] for c in payload["credentials"]] == ["prod"]


def test_show_masks_password_by_default(sandbox_home: Path, cli: CliRunner) -> None:
    _run(cli, "init", "--passphrase", "--json")
    _run(cli, "add", "prod", "--host", "h", "--password", "leak-me", "--json")
    result = _run(cli, "show", "prod", "--json")
    payload = json.loads(result.stdout)
    assert payload["password"] == "***"
    assert "leak-me" not in result.stdout


def test_show_reveal_returns_password(sandbox_home: Path, cli: CliRunner) -> None:
    _run(cli, "init", "--passphrase", "--json")
    _run(cli, "add", "prod", "--host", "h", "--password", "real-pw", "--json")
    result = _run(cli, "show", "prod", "--reveal", "--json")
    assert json.loads(result.stdout)["password"] == "real-pw"


def test_show_not_found_returns_exit_4(sandbox_home: Path, cli: CliRunner) -> None:
    _run(cli, "init", "--passphrase", "--json")
    result = _run(cli, "show", "nope", "--json")
    assert result.exit_code == EXIT_NOT_FOUND
    assert _stderr_envelope(result)["code"] == "not_found"


def test_locked_store_returns_exit_3(
    sandbox_home: Path, cli: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    _run(cli, "init", "--passphrase", "--json")
    monkeypatch.delenv("PSQLMANAGER_PASSPHRASE")
    result = _run(cli, "list", "--json")
    assert result.exit_code == EXIT_LOCKED
    assert _stderr_envelope(result)["code"] == "locked"


def test_rm_then_show_not_found(sandbox_home: Path, cli: CliRunner) -> None:
    _run(cli, "init", "--passphrase", "--json")
    _run(cli, "add", "prod", "--host", "h", "--no-password", "--json")
    rm = _run(cli, "rm", "prod", "--json")
    assert rm.exit_code == 0
    show = _run(cli, "show", "prod", "--json")
    assert show.exit_code == EXIT_NOT_FOUND


def test_rename_round_trip(sandbox_home: Path, cli: CliRunner) -> None:
    _run(cli, "init", "--passphrase", "--json")
    _run(cli, "add", "a", "--host", "h", "--no-password", "--json")
    rename = _run(cli, "rename", "a", "b", "--json")
    assert rename.exit_code == 0
    listed = json.loads(_run(cli, "list", "--json").stdout)
    assert [c["name"] for c in listed["credentials"]] == ["b"]


def test_rename_conflict_returns_exit_1(sandbox_home: Path, cli: CliRunner) -> None:
    _run(cli, "init", "--passphrase", "--json")
    _run(cli, "add", "a", "--host", "h", "--no-password", "--json")
    _run(cli, "add", "b", "--host", "h", "--no-password", "--json")
    result = _run(cli, "rename", "a", "b", "--json")
    assert result.exit_code == EXIT_GENERIC
    assert _stderr_envelope(result)["code"] == "exists"


def test_info_reports_locked_when_no_passphrase(
    sandbox_home: Path, cli: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    _run(cli, "init", "--passphrase", "--json")
    monkeypatch.delenv("PSQLMANAGER_PASSPHRASE")
    result = _run(cli, "info", "--json")
    payload = json.loads(result.stdout)
    assert payload["exists"] is True
    assert payload["locked"] is True


def test_info_shows_count_and_permissions(sandbox_home: Path, cli: CliRunner) -> None:
    _run(cli, "init", "--passphrase", "--json")
    _run(cli, "add", "a", "--host", "h", "--no-password", "--json")
    result = _run(cli, "info", "--json")
    payload = json.loads(result.stdout)
    assert payload["count"] == 1
    assert payload["permissions"] == "0o600"
    assert payload["mode"] == "passphrase"


def test_destroy_requires_yes_non_interactive(
    sandbox_home: Path, cli: CliRunner
) -> None:
    _run(cli, "init", "--passphrase", "--json")
    result = _run(cli, "destroy", "--json")
    assert result.exit_code == EXIT_GENERIC
    assert _stderr_envelope(result)["code"] == "needs_confirmation"


def test_destroy_with_yes(sandbox_home: Path, cli: CliRunner) -> None:
    _run(cli, "init", "--passphrase", "--json")
    result = _run(cli, "destroy", "--yes", "--json")
    assert result.exit_code == 0
    assert json.loads(result.stdout)["status"] == "destroyed"
    again = _run(cli, "init", "--passphrase", "--json")
    assert again.exit_code == 0


def test_exec_forwards_args_and_propagates_exit_code(
    sandbox_home: Path,
    cli: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict = {}

    def fake_run(cred, password, extra, allow_write=False):
        captured["argv"] = psql_mod.build_argv(cred, extra)
        captured["env"] = psql_mod.build_env(cred, password)
        captured["password"] = password
        return 7

    monkeypatch.setattr("psqlmanager.cli.run_psql", fake_run)
    monkeypatch.setattr(psql_mod, "find_psql", lambda: "/usr/bin/psql")

    _run(cli, "init", "--passphrase", "--json")
    _run(
        cli,
        "add", "prod",
        "--host", "h", "--port", "5432", "--user", "u", "--dbname", "d",
        "--password", "the-pw",
        "--json",
    )
    result = _run(cli, "exec", "prod", "--", "-c", "select 1")
    assert result.exit_code == 7

    argv = captured["argv"]
    assert "-h" in argv and "h" in argv
    assert "-c" in argv and "select 1" in argv
    assert "the-pw" not in argv
    assert captured["password"] == "the-pw"
    assert captured["env"]["PGPASSWORD"] == "the-pw"


def test_exec_reports_missing_psql(
    sandbox_home: Path,
    cli: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(*_args, **_kwargs):
        raise FileNotFoundError("psql executable not found on PATH.")

    monkeypatch.setattr("psqlmanager.cli.run_psql", boom)

    _run(cli, "init", "--passphrase", "--json")
    _run(cli, "add", "prod", "--host", "h", "--no-password", "--json")
    result = _run(cli, "exec", "prod", "--", "-c", "select 1")
    assert result.exit_code == EXIT_NO_PSQL
    assert "psql executable not found" in result.stderr


def test_connect_invokes_process_replacement(
    sandbox_home: Path,
    cli: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict = {}

    def fake_exec(cred, password, extra, allow_write=False):
        captured["argv"] = psql_mod.build_argv(cred, extra)
        captured["env"] = psql_mod.build_env(cred, password)
        raise SystemExit(0)

    monkeypatch.setattr("psqlmanager.cli.exec_psql", fake_exec)
    monkeypatch.setattr(psql_mod, "find_psql", lambda: "/usr/bin/psql")

    _run(cli, "init", "--passphrase", "--json")
    _run(cli, "add", "prod", "--host", "h", "--password", "pw", "--json")
    result = _run(cli, "connect", "prod", "--", "-q")
    assert result.exit_code == 0
    assert "-q" in captured["argv"]
    assert captured["env"]["PGPASSWORD"] == "pw"


def test_keyring_mode_init_via_cli(
    sandbox_home: Path,
    cli: CliRunner,
    mock_keyring: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("PSQLMANAGER_PASSPHRASE")
    result = _run(cli, "init", "--json")
    assert result.exit_code == 0, result.stderr
    assert json.loads(result.stdout)["mode"] == "keyring"
    assert "master-key" in mock_keyring


def test_keyring_mode_unavailable_emits_no_keyring_code(
    sandbox_home: Path, cli: CliRunner, broken_keyring: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("PSQLMANAGER_PASSPHRASE")
    result = _run(cli, "init", "--json")
    assert result.exit_code == EXIT_GENERIC
    assert _stderr_envelope(result)["code"] == "no_keyring"


# ---------------------------------------------------------------------------
# IAM auth
# ---------------------------------------------------------------------------


def _patch_aws_mint(monkeypatch: pytest.MonkeyPatch, token: str = "IAM-TOKEN") -> dict:
    """Make auth.shutil.which find `aws` and auth._run_subprocess return token."""
    state = {"calls": 0}

    def fake_which(cmd: str, *_a, **_k) -> str | None:
        return f"/usr/local/bin/{cmd}" if cmd == "aws" else None

    def fake_run(argv: list[str]) -> tuple[int, str, str]:
        state["calls"] += 1
        state["last_argv"] = argv
        return (0, token, "")

    monkeypatch.setattr(auth_mod.shutil, "which", fake_which)
    monkeypatch.setattr(auth_mod, "_run_subprocess", fake_run)
    return state


def test_add_iam_rds_requires_region(sandbox_home: Path, cli: CliRunner) -> None:
    _run(cli, "init", "--passphrase", "--json")
    result = _run(
        cli, "add", "prod-aws",
        "--host", "mydb.example.com",
        "--user", "db_user",
        "--auth", "iam-rds",
        "--json",
    )
    assert result.exit_code == EXIT_GENERIC
    assert _stderr_envelope(result)["code"] == "missing_param"


def test_add_iam_rds_rejects_password_flag(sandbox_home: Path, cli: CliRunner) -> None:
    _run(cli, "init", "--passphrase", "--json")
    result = _run(
        cli, "add", "prod-aws",
        "--host", "h", "--user", "u",
        "--auth", "iam-rds", "--aws-region", "us-east-1",
        "--password", "static-no-good",
        "--json",
    )
    assert result.exit_code == EXIT_GENERIC
    assert _stderr_envelope(result)["code"] == "bad_auth_combo"


def test_add_iam_rds_stores_params_and_defaults_sslmode(
    sandbox_home: Path, cli: CliRunner
) -> None:
    _run(cli, "init", "--passphrase", "--json")
    result = _run(
        cli, "add", "prod-aws",
        "--host", "h", "--user", "db_user",
        "--auth", "iam-rds",
        "--aws-region", "us-east-1", "--aws-profile", "prod",
        "--json",
    )
    assert result.exit_code == 0, result.stderr
    cred = json.loads(result.stdout)["credential"]
    assert cred["auth_method"] == "iam-rds"
    assert cred["auth_params"] == {"region": "us-east-1", "profile": "prod"}
    assert cred["password"] == ""  # No static password for IAM.
    # sslmode should default to require for IAM.
    assert cred["sslmode"] == "require"


def test_add_iam_gcp(sandbox_home: Path, cli: CliRunner) -> None:
    _run(cli, "init", "--passphrase", "--json")
    result = _run(
        cli, "add", "prod-gcp",
        "--host", "h", "--user", "svc@p.iam.gserviceaccount.com",
        "--auth", "iam-gcp", "--gcp-account", "me@example.com",
        "--json",
    )
    assert result.exit_code == 0
    cred = json.loads(result.stdout)["credential"]
    assert cred["auth_method"] == "iam-gcp"
    assert cred["auth_params"] == {"account": "me@example.com"}
    assert cred["sslmode"] == "require"


def test_add_iam_azure(sandbox_home: Path, cli: CliRunner) -> None:
    _run(cli, "init", "--passphrase", "--json")
    result = _run(
        cli, "add", "prod-azure",
        "--host", "h", "--user", "me@tenant",
        "--auth", "iam-azure", "--azure-tenant", "00000000-0000-0000-0000-000000000000",
        "--json",
    )
    assert result.exit_code == 0
    cred = json.loads(result.stdout)["credential"]
    assert cred["auth_method"] == "iam-azure"
    assert cred["auth_params"]["tenant"] == "00000000-0000-0000-0000-000000000000"


def test_exec_iam_rds_mints_and_passes_token(
    sandbox_home: Path, cli: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _patch_aws_mint(monkeypatch, token="RDS-TOKEN-FOO")

    captured: dict = {}

    def fake_run(cred, password, extra, allow_write=False):
        captured["password"] = password
        captured["argv"] = psql_mod.build_argv(cred, extra)
        return 0

    monkeypatch.setattr("psqlmanager.cli.run_psql", fake_run)
    monkeypatch.setattr(psql_mod, "find_psql", lambda: "/usr/bin/psql")

    _run(cli, "init", "--passphrase", "--json")
    _run(
        cli, "add", "prod-aws",
        "--host", "mydb.us-east-1.rds.amazonaws.com",
        "--user", "db_user",
        "--auth", "iam-rds", "--aws-region", "us-east-1",
        "--json",
    )
    result = _run(cli, "exec", "prod-aws", "--", "-c", "select 1")
    assert result.exit_code == 0
    assert captured["password"] == "RDS-TOKEN-FOO"
    # Token must never leak into argv.
    assert "RDS-TOKEN-FOO" not in captured["argv"]
    # aws CLI was actually called once.
    assert state["calls"] == 1


def test_exec_iam_rds_reuses_cached_token(
    sandbox_home: Path, cli: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _patch_aws_mint(monkeypatch, token="CACHED-TOKEN")

    def fake_run(cred, password, extra, allow_write=False):
        return 0

    monkeypatch.setattr("psqlmanager.cli.run_psql", fake_run)
    monkeypatch.setattr(psql_mod, "find_psql", lambda: "/usr/bin/psql")

    _run(cli, "init", "--passphrase", "--json")
    _run(
        cli, "add", "prod-aws",
        "--host", "h", "--user", "u",
        "--auth", "iam-rds", "--aws-region", "us-east-1",
        "--json",
    )
    _run(cli, "exec", "prod-aws", "--", "-c", "select 1")
    _run(cli, "exec", "prod-aws", "--", "-c", "select 2")
    _run(cli, "exec", "prod-aws", "--", "-c", "select 3")
    assert state["calls"] == 1  # Subsequent calls hit the cache.


def test_exec_iam_mint_failure_surfaces_code(
    sandbox_home: Path, cli: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_which(cmd: str, *_a, **_k) -> str | None:
        return None  # aws CLI not installed

    monkeypatch.setattr(auth_mod.shutil, "which", fake_which)

    _run(cli, "init", "--passphrase", "--json")
    _run(
        cli, "add", "prod-aws",
        "--host", "h", "--user", "u",
        "--auth", "iam-rds", "--aws-region", "us-east-1",
        "--json",
    )
    result = _run(cli, "exec", "prod-aws", "--", "-c", "select 1")
    assert result.exit_code == EXIT_AUTH_FAILED
    assert "aws" in result.stderr


def test_re_adding_invalidates_cache(
    sandbox_home: Path, cli: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _patch_aws_mint(monkeypatch, token="T1")

    def fake_run(cred, password, extra, allow_write=False):
        return 0

    monkeypatch.setattr("psqlmanager.cli.run_psql", fake_run)
    monkeypatch.setattr(psql_mod, "find_psql", lambda: "/usr/bin/psql")

    _run(cli, "init", "--passphrase", "--json")
    _run(
        cli, "add", "prod-aws", "--host", "h", "--user", "u",
        "--auth", "iam-rds", "--aws-region", "us-east-1", "--json",
    )
    _run(cli, "exec", "prod-aws", "--", "-c", "select 1")
    assert state["calls"] == 1

    # Re-add with --force; cache should be cleared.
    _run(
        cli, "add", "prod-aws", "--host", "h", "--user", "u",
        "--auth", "iam-rds", "--aws-region", "us-west-2", "--force", "--json",
    )
    _run(cli, "exec", "prod-aws", "--", "-c", "select 1")
    assert state["calls"] == 2


# ---------------------------------------------------------------------------
# cache subcommand
# ---------------------------------------------------------------------------


def test_cache_list_empty(sandbox_home: Path, cli: CliRunner) -> None:
    _run(cli, "init", "--passphrase", "--json")
    result = _run(cli, "cache", "list", "--json")
    assert json.loads(result.stdout)["cache"] == []


def test_cache_list_shows_entries(
    sandbox_home: Path, cli: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_aws_mint(monkeypatch, token="T")
    monkeypatch.setattr("psqlmanager.cli.run_psql", lambda c, p, e, allow_write=False: 0)
    monkeypatch.setattr(psql_mod, "find_psql", lambda: "/usr/bin/psql")

    _run(cli, "init", "--passphrase", "--json")
    _run(
        cli, "add", "p", "--host", "h", "--user", "u",
        "--auth", "iam-rds", "--aws-region", "us-east-1", "--json",
    )
    _run(cli, "exec", "p", "--", "-c", "select 1")
    result = _run(cli, "cache", "list", "--json")
    entries = json.loads(result.stdout)["cache"]
    assert len(entries) == 1
    assert entries[0]["name"] == "p"
    assert entries[0]["method"] == "iam-rds"
    assert entries[0]["expires_in_seconds"] > 0


def test_cache_clear_one(
    sandbox_home: Path, cli: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_aws_mint(monkeypatch, token="T")
    monkeypatch.setattr("psqlmanager.cli.run_psql", lambda c, p, e, allow_write=False: 0)
    monkeypatch.setattr(psql_mod, "find_psql", lambda: "/usr/bin/psql")

    _run(cli, "init", "--passphrase", "--json")
    for n in ("a", "b"):
        _run(
            cli, "add", n, "--host", "h", "--user", "u",
            "--auth", "iam-rds", "--aws-region", "us-east-1", "--json",
        )
        _run(cli, "exec", n, "--", "-c", "select 1")

    result = _run(cli, "cache", "clear", "a", "--json")
    assert json.loads(result.stdout) == {"name": "a", "removed": 1, "status": "cleared"}

    listed = json.loads(_run(cli, "cache", "list", "--json").stdout)["cache"]
    assert [e["name"] for e in listed] == ["b"]


def test_cache_clear_all(
    sandbox_home: Path, cli: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_aws_mint(monkeypatch, token="T")
    monkeypatch.setattr("psqlmanager.cli.run_psql", lambda c, p, e, allow_write=False: 0)
    monkeypatch.setattr(psql_mod, "find_psql", lambda: "/usr/bin/psql")

    _run(cli, "init", "--passphrase", "--json")
    for n in ("a", "b", "c"):
        _run(
            cli, "add", n, "--host", "h", "--user", "u",
            "--auth", "iam-rds", "--aws-region", "us-east-1", "--json",
        )
        _run(cli, "exec", n, "--", "-c", "select 1")

    result = _run(cli, "cache", "clear", "--json")
    assert json.loads(result.stdout)["removed"] == 3
    assert json.loads(_run(cli, "cache", "list", "--json").stdout)["cache"] == []


# ---------------------------------------------------------------------------
# Read-only enforcement
# ---------------------------------------------------------------------------


def test_add_readonly_credential(sandbox_home: Path, cli: CliRunner) -> None:
    _run(cli, "init", "--passphrase", "--json")
    result = _run(
        cli, "add", "prod-ro", "--host", "h", "--user", "u",
        "--no-password", "--readonly", "--json",
    )
    assert result.exit_code == 0
    cred = json.loads(result.stdout)["credential"]
    assert cred["readonly"] is True


def test_add_defaults_to_readwrite(sandbox_home: Path, cli: CliRunner) -> None:
    _run(cli, "init", "--passphrase", "--json")
    result = _run(
        cli, "add", "prod", "--host", "h", "--user", "u", "--no-password", "--json",
    )
    cred = json.loads(result.stdout)["credential"]
    assert cred["readonly"] is False


def test_exec_on_readonly_credential_sets_pgoptions(
    sandbox_home: Path, cli: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict = {}

    def fake_run(cred, password, extra, allow_write=False):
        captured["env"] = psql_mod.build_env(cred, password, allow_write=allow_write)
        captured["allow_write"] = allow_write
        return 0

    monkeypatch.setattr("psqlmanager.cli.run_psql", fake_run)
    monkeypatch.setattr(psql_mod, "find_psql", lambda: "/usr/bin/psql")

    _run(cli, "init", "--passphrase", "--json")
    _run(
        cli, "add", "agent-ro", "--host", "h", "--user", "u",
        "--no-password", "--readonly", "--json",
    )
    result = _run(cli, "exec", "agent-ro", "--", "-c", "select 1")
    assert result.exit_code == 0
    assert captured["allow_write"] is False
    assert "default_transaction_read_only=on" in captured["env"]["PGOPTIONS"]


def test_exec_allow_write_overrides_readonly_with_warning(
    sandbox_home: Path, cli: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict = {}

    def fake_run(cred, password, extra, allow_write=False):
        captured["env"] = psql_mod.build_env(cred, password, allow_write=allow_write)
        captured["allow_write"] = allow_write
        return 0

    monkeypatch.setattr("psqlmanager.cli.run_psql", fake_run)
    monkeypatch.setattr(psql_mod, "find_psql", lambda: "/usr/bin/psql")

    _run(cli, "init", "--passphrase", "--json")
    _run(
        cli, "add", "agent-ro", "--host", "h", "--user", "u",
        "--no-password", "--readonly", "--json",
    )
    result = _run(
        cli, "exec", "--allow-write", "agent-ro", "--", "-c", "update t set x=1"
    )
    assert result.exit_code == 0
    assert captured["allow_write"] is True
    assert "default_transaction_read_only" not in captured["env"].get("PGOPTIONS", "")
    # The override must be loud — visible on stderr.
    assert "WARNING" in result.stderr
    assert "allow-write" in result.stderr
    assert "agent-ro" in result.stderr


def test_exec_allow_write_on_readwrite_credential_is_silent(
    sandbox_home: Path, cli: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """--allow-write on a non-readonly credential should not emit a warning."""
    monkeypatch.setattr("psqlmanager.cli.run_psql", lambda c, p, e, allow_write=False: 0)
    monkeypatch.setattr(psql_mod, "find_psql", lambda: "/usr/bin/psql")

    _run(cli, "init", "--passphrase", "--json")
    _run(
        cli, "add", "prod", "--host", "h", "--user", "u", "--no-password", "--json",
    )
    result = _run(cli, "exec", "--allow-write", "prod", "--", "-c", "select 1")
    assert "WARNING" not in result.stderr


def test_list_human_marks_readonly_credentials(
    sandbox_home: Path, cli: CliRunner
) -> None:
    _run(cli, "init", "--passphrase", "--json")
    _run(cli, "add", "agent", "--host", "h", "--user", "u",
         "--no-password", "--readonly", "--json")
    _run(cli, "add", "human", "--host", "h", "--user", "u", "--no-password", "--json")
    result = _run(cli, "list")
    lines = {l.split("\t")[0]: l for l in result.stdout.strip().splitlines()}
    assert "[ro]" in lines["agent"]
    assert "[ro]" not in lines["human"]


def test_show_includes_readonly_field(sandbox_home: Path, cli: CliRunner) -> None:
    _run(cli, "init", "--passphrase", "--json")
    _run(cli, "add", "agent-ro", "--host", "h", "--user", "u",
         "--no-password", "--readonly", "--json")
    data = json.loads(_run(cli, "show", "agent-ro", "--json").stdout)
    assert data["readonly"] is True


def test_iam_credentials_can_also_be_readonly(
    sandbox_home: Path, cli: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Read-only mode composes with IAM auth."""
    _patch_aws_mint(monkeypatch, token="T")
    captured: dict = {}

    def fake_run(cred, password, extra, allow_write=False):
        captured["env"] = psql_mod.build_env(cred, password, allow_write=allow_write)
        return 0

    monkeypatch.setattr("psqlmanager.cli.run_psql", fake_run)
    monkeypatch.setattr(psql_mod, "find_psql", lambda: "/usr/bin/psql")

    _run(cli, "init", "--passphrase", "--json")
    _run(
        cli, "add", "agent-aws", "--host", "h", "--user", "u",
        "--auth", "iam-rds", "--aws-region", "us-east-1",
        "--readonly", "--json",
    )
    _run(cli, "exec", "agent-aws", "--", "-c", "select 1")
    assert "default_transaction_read_only=on" in captured["env"]["PGOPTIONS"]
    assert captured["env"]["PGPASSWORD"] == "T"


# ---------------------------------------------------------------------------
# Test-isolation safety net
# ---------------------------------------------------------------------------


def test_autouse_blocks_unmocked_cloud_subprocess(
    sandbox_home: Path, cli: CliRunner
) -> None:
    """The autouse fixture in conftest must raise when a test forgets to
    mock auth._run_subprocess. Verifying it actually fires."""
    # Make `aws` look available so we get past the which() guard, but do NOT
    # mock _run_subprocess. The autouse raiser should fire.
    from psqlmanager import auth as auth_mod

    real_which = auth_mod.shutil.which
    try:
        auth_mod.shutil.which = lambda c, *a, **k: "/usr/bin/aws" if c == "aws" else None

        _run(cli, "init", "--passphrase", "--json")
        _run(
            cli, "add", "prod-aws", "--host", "h", "--user", "u",
            "--auth", "iam-rds", "--aws-region", "us-east-1", "--json",
        )
        with pytest.raises(RuntimeError, match="Unmocked call"):
            cli.invoke(
                main,
                ["exec", "prod-aws", "--", "-c", "select 1"],
                catch_exceptions=False,
            )
    finally:
        auth_mod.shutil.which = real_which


def test_autouse_clears_aws_profile_envvars(monkeypatch: pytest.MonkeyPatch) -> None:
    assert "AWS_PROFILE" not in os.environ
    assert "AWS_DEFAULT_PROFILE" not in os.environ
    assert os.environ["AWS_ACCESS_KEY_ID"] == "testing"


def test_show_includes_auth_fields(sandbox_home: Path, cli: CliRunner) -> None:
    _run(cli, "init", "--passphrase", "--json")
    _run(
        cli, "add", "p", "--host", "h", "--user", "u",
        "--auth", "iam-rds", "--aws-region", "us-east-1", "--json",
    )
    result = _run(cli, "show", "p", "--json")
    data = json.loads(result.stdout)
    assert data["auth_method"] == "iam-rds"
    assert data["auth_params"] == {"region": "us-east-1"}
