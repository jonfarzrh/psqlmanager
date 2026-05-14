"""Tests for IAM token minting and on-disk caching.

Provider CLIs (`aws`, `gcloud`, `az`) are never actually invoked — we
monkeypatch `auth._run_subprocess` and `shutil.which` instead.
"""

from __future__ import annotations

import json
import os
import stat
import time
from pathlib import Path
from typing import Any

import pytest

from psqlmanager import auth
from psqlmanager.auth import AuthError, resolve_password
from psqlmanager.store import Credential


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _patch_which(monkeypatch: pytest.MonkeyPatch, available: set[str]) -> None:
    """Make shutil.which return a path only for tools in `available`."""

    def fake_which(cmd: str, *_args: Any, **_kwargs: Any) -> str | None:
        return f"/usr/local/bin/{cmd}" if cmd in available else None

    monkeypatch.setattr(auth.shutil, "which", fake_which)


def _patch_runner(
    monkeypatch: pytest.MonkeyPatch,
    handler,
) -> list[list[str]]:
    """Replace auth._run_subprocess; record each argv it sees."""
    calls: list[list[str]] = []

    def fake_run(argv: list[str]) -> tuple[int, str, str]:
        calls.append(argv)
        return handler(argv)

    monkeypatch.setattr(auth, "_run_subprocess", fake_run)
    return calls


# ---------------------------------------------------------------------------
# password method
# ---------------------------------------------------------------------------


def test_resolve_password_static(sandbox_home: Path) -> None:
    cred = Credential(name="prod", password="static-pw")
    assert resolve_password(cred) == "static-pw"


def test_unknown_method_raises(sandbox_home: Path) -> None:
    cred = Credential(name="prod", auth_method="iam-nope")
    with pytest.raises(AuthError, match="Unknown auth method") as excinfo:
        resolve_password(cred)
    assert excinfo.value.code == "unknown_method"


# ---------------------------------------------------------------------------
# iam-rds
# ---------------------------------------------------------------------------


def test_rds_mint_invokes_aws_with_expected_args(
    sandbox_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_which(monkeypatch, {"aws"})
    calls = _patch_runner(monkeypatch, lambda argv: (0, "TOKEN-RDS-1", ""))

    cred = Credential(
        name="prod-aws",
        host="mydb.us-east-1.rds.amazonaws.com",
        port=5432,
        user="db_iam_user",
        auth_method="iam-rds",
        auth_params={"region": "us-east-1", "profile": "prod"},
    )
    token = resolve_password(cred)
    assert token == "TOKEN-RDS-1"

    argv = calls[0]
    assert argv[:3] == ["aws", "rds", "generate-db-auth-token"]
    assert "--hostname" in argv and "mydb.us-east-1.rds.amazonaws.com" in argv
    assert "--region" in argv and "us-east-1" in argv
    assert "--username" in argv and "db_iam_user" in argv
    assert "--profile" in argv and "prod" in argv


def test_rds_requires_region(sandbox_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_which(monkeypatch, {"aws"})
    _patch_runner(monkeypatch, lambda argv: (0, "X", ""))
    cred = Credential(name="prod", host="h", user="u", auth_method="iam-rds")
    with pytest.raises(AuthError) as excinfo:
        resolve_password(cred)
    assert excinfo.value.code == "missing_param"


def test_rds_missing_aws_cli_raises(
    sandbox_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_which(monkeypatch, set())  # nothing available
    cred = Credential(
        name="prod", host="h", user="u",
        auth_method="iam-rds", auth_params={"region": "us-east-1"},
    )
    with pytest.raises(AuthError) as excinfo:
        resolve_password(cred)
    assert excinfo.value.code == "aws_cli_missing"


def test_rds_nonzero_exit_raises_mint_failed(
    sandbox_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_which(monkeypatch, {"aws"})
    _patch_runner(monkeypatch, lambda argv: (255, "", "credentials expired"))
    cred = Credential(
        name="prod", host="h", user="u",
        auth_method="iam-rds", auth_params={"region": "us-east-1"},
    )
    with pytest.raises(AuthError, match="credentials expired") as excinfo:
        resolve_password(cred)
    assert excinfo.value.code == "mint_failed"


# ---------------------------------------------------------------------------
# iam-gcp
# ---------------------------------------------------------------------------


def test_gcp_mint_basic(sandbox_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_which(monkeypatch, {"gcloud"})
    calls = _patch_runner(monkeypatch, lambda argv: (0, "ya29.GCP_TOKEN\n", ""))
    cred = Credential(name="prod-gcp", host="h", user="svc@p.iam.gserviceaccount.com",
                      auth_method="iam-gcp")
    token = resolve_password(cred)
    assert token == "ya29.GCP_TOKEN"
    assert calls[0] == ["gcloud", "auth", "print-access-token"]


def test_gcp_mint_with_account(sandbox_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_which(monkeypatch, {"gcloud"})
    calls = _patch_runner(monkeypatch, lambda argv: (0, "TOKEN", ""))
    cred = Credential(
        name="prod-gcp", host="h", user="svc@p.iam.gserviceaccount.com",
        auth_method="iam-gcp", auth_params={"account": "me@example.com"},
    )
    resolve_password(cred)
    assert "--account=me@example.com" in calls[0]


def test_gcp_missing_cli(sandbox_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_which(monkeypatch, set())
    cred = Credential(name="p", auth_method="iam-gcp")
    with pytest.raises(AuthError) as excinfo:
        resolve_password(cred)
    assert excinfo.value.code == "gcp_cli_missing"


# ---------------------------------------------------------------------------
# iam-azure
# ---------------------------------------------------------------------------


def test_azure_mint_parses_expires_on_unix_timestamp(
    sandbox_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_which(monkeypatch, {"az"})
    future_ts = int(time.time()) + 3600
    response = json.dumps(
        {
            "accessToken": "eyJ.AZ_TOKEN",
            "expires_on": future_ts,
            "expiresOn": "2099-01-01 00:00:00.000000",
            "tokenType": "Bearer",
        }
    )
    _patch_runner(monkeypatch, lambda argv: (0, response, ""))
    cred = Credential(name="prod-azure", host="h", user="me@tenant",
                      auth_method="iam-azure")
    assert resolve_password(cred) == "eyJ.AZ_TOKEN"

    # The cache should hold the unix-timestamp expiry.
    entries = auth.list_cache()
    assert entries and abs(entries[0]["expires_at"] - future_ts) < 1


def test_azure_falls_back_to_string_expiry(
    sandbox_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_which(monkeypatch, {"az"})
    # No expires_on, only the human-readable expiresOn.
    future = "2099-01-01 00:00:00.000000"
    response = json.dumps({"accessToken": "eyJ.AZ_TOKEN", "expiresOn": future})
    _patch_runner(monkeypatch, lambda argv: (0, response, ""))
    cred = Credential(name="p", auth_method="iam-azure")
    token = resolve_password(cred)
    assert token == "eyJ.AZ_TOKEN"


def test_azure_invalid_json(sandbox_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_which(monkeypatch, {"az"})
    _patch_runner(monkeypatch, lambda argv: (0, "not-json", ""))
    cred = Credential(name="p", auth_method="iam-azure")
    with pytest.raises(AuthError) as excinfo:
        resolve_password(cred)
    assert excinfo.value.code == "mint_failed"


# ---------------------------------------------------------------------------
# Caching
# ---------------------------------------------------------------------------


def test_cache_reuses_token_on_second_call(
    sandbox_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_which(monkeypatch, {"aws"})
    counter = {"n": 0}

    def runner(argv: list[str]) -> tuple[int, str, str]:
        counter["n"] += 1
        return (0, f"TOKEN-{counter['n']}", "")

    monkeypatch.setattr(auth, "_run_subprocess", runner)
    cred = Credential(
        name="prod", host="h", user="u",
        auth_method="iam-rds", auth_params={"region": "us-east-1"},
    )

    first = resolve_password(cred)
    second = resolve_password(cred)
    assert first == second == "TOKEN-1"
    assert counter["n"] == 1


def test_cache_remints_when_expired(
    sandbox_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_which(monkeypatch, {"aws"})
    counter = {"n": 0}

    def runner(argv: list[str]) -> tuple[int, str, str]:
        counter["n"] += 1
        return (0, f"TOKEN-{counter['n']}", "")

    monkeypatch.setattr(auth, "_run_subprocess", runner)
    cred = Credential(
        name="prod", host="h", user="u",
        auth_method="iam-rds", auth_params={"region": "us-east-1"},
    )
    first = resolve_password(cred)

    # Manually expire the cache file.
    cache_files = list((sandbox_home / "cache").iterdir())
    assert len(cache_files) == 1
    data = json.loads(cache_files[0].read_text())
    data["expires_at"] = time.time() - 1
    cache_files[0].write_text(json.dumps(data))

    second = resolve_password(cred)
    assert first == "TOKEN-1"
    assert second == "TOKEN-2"
    assert counter["n"] == 2


def test_cache_respects_refresh_margin(
    sandbox_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_which(monkeypatch, {"aws"})
    counter = {"n": 0}

    def runner(argv: list[str]) -> tuple[int, str, str]:
        counter["n"] += 1
        return (0, f"TOKEN-{counter['n']}", "")

    monkeypatch.setattr(auth, "_run_subprocess", runner)
    cred = Credential(
        name="prod", host="h", user="u",
        auth_method="iam-rds", auth_params={"region": "us-east-1"},
    )
    resolve_password(cred)

    cache_files = list((sandbox_home / "cache").iterdir())
    data = json.loads(cache_files[0].read_text())
    # Set expiry within the refresh margin (less than 60s away).
    data["expires_at"] = time.time() + 30
    cache_files[0].write_text(json.dumps(data))

    resolve_password(cred)
    assert counter["n"] == 2


def test_cache_bypassed_with_use_cache_false(
    sandbox_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_which(monkeypatch, {"aws"})
    counter = {"n": 0}

    def runner(argv: list[str]) -> tuple[int, str, str]:
        counter["n"] += 1
        return (0, f"TOKEN-{counter['n']}", "")

    monkeypatch.setattr(auth, "_run_subprocess", runner)
    cred = Credential(
        name="prod", host="h", user="u",
        auth_method="iam-rds", auth_params={"region": "us-east-1"},
    )
    resolve_password(cred)
    resolve_password(cred, use_cache=False)
    assert counter["n"] == 2


def test_cache_file_perms_are_0600(
    sandbox_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_which(monkeypatch, {"aws"})
    _patch_runner(monkeypatch, lambda argv: (0, "TOKEN", ""))
    cred = Credential(
        name="prod", host="h", user="u",
        auth_method="iam-rds", auth_params={"region": "us-east-1"},
    )
    resolve_password(cred)
    cache_dir = sandbox_home / "cache"
    assert stat.S_IMODE(cache_dir.stat().st_mode) == 0o700
    files = list(cache_dir.iterdir())
    assert len(files) == 1
    assert stat.S_IMODE(files[0].stat().st_mode) == 0o600


def test_clear_cache_single(
    sandbox_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_which(monkeypatch, {"aws"})
    _patch_runner(monkeypatch, lambda argv: (0, "T", ""))
    cred_a = Credential(
        name="a", host="h", user="u",
        auth_method="iam-rds", auth_params={"region": "us-east-1"},
    )
    cred_b = Credential(
        name="b", host="h", user="u",
        auth_method="iam-rds", auth_params={"region": "us-east-1"},
    )
    resolve_password(cred_a)
    resolve_password(cred_b)
    assert len(auth.list_cache()) == 2

    removed = auth.clear_cache("a")
    assert removed == 1
    remaining = [e["name"] for e in auth.list_cache()]
    assert remaining == ["b"]


def test_clear_cache_all(
    sandbox_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_which(monkeypatch, {"aws"})
    _patch_runner(monkeypatch, lambda argv: (0, "T", ""))
    for n in ("a", "b", "c"):
        resolve_password(
            Credential(
                name=n, host="h", user="u",
                auth_method="iam-rds", auth_params={"region": "us-east-1"},
            )
        )
    removed = auth.clear_cache()
    assert removed == 3
    assert auth.list_cache() == []


def test_clear_cache_missing_is_noop(sandbox_home: Path) -> None:
    # No cache dir exists yet.
    assert auth.clear_cache() == 0
    assert auth.clear_cache("nope") == 0


def test_list_cache_reports_expired_status(
    sandbox_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_which(monkeypatch, {"aws"})
    _patch_runner(monkeypatch, lambda argv: (0, "T", ""))
    resolve_password(
        Credential(
            name="prod", host="h", user="u",
            auth_method="iam-rds", auth_params={"region": "us-east-1"},
        )
    )
    cache_files = list((sandbox_home / "cache").iterdir())
    data = json.loads(cache_files[0].read_text())
    data["expires_at"] = time.time() - 100
    cache_files[0].write_text(json.dumps(data))
    [entry] = auth.list_cache()
    assert entry["expired"] is True
    assert entry["expires_in_seconds"] == 0
