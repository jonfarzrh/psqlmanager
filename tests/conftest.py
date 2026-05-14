"""Shared fixtures.

Every test runs against a fresh, sandboxed PSQLMANAGER_HOME under tmp_path.
We default to passphrase mode so tests never touch the host's real OS keyring;
keyring-mode tests opt in explicitly via the `mock_keyring` fixture.

Two autouse fixtures harden against accidentally hitting live cloud services:

  block_live_cloud_credentials
      Overwrites AWS/GCP/Azure credential env vars with bogus values and
      unsets profile vars. If a cloud SDK ever gets invoked unmocked it
      will fail at the auth boundary instead of using the developer's SSO.

  fail_on_unmocked_cloud_subprocess
      Replaces psqlmanager.auth._run_subprocess with a raiser. Any
      IAM-token mint path that escapes mocking fails the test loudly
      with a clear message rather than running `aws`/`gcloud`/`az` for
      real. Tests that need the function override it per-test via
      monkeypatch.setattr; that overrides the autouse default.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from psqlmanager import auth as auth_mod
from psqlmanager import store as store_mod
from psqlmanager.store import CredentialStore

TEST_PASSPHRASE = "correct horse battery staple"


@pytest.fixture(autouse=True)
def block_live_cloud_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    # AWS — bogus statics + unset profiles so botocore can't fall back to SSO.
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_CONFIG_FILE", "/nonexistent-psqlmgr-tests")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent-psqlmgr-tests")
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    monkeypatch.delenv("AWS_DEFAULT_PROFILE", raising=False)
    # GCP — point ADC at a nonexistent file so any unmocked gcloud invocation fails fast.
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "/nonexistent-psqlmgr-tests")
    monkeypatch.setenv("CLOUDSDK_CONFIG", "/nonexistent-psqlmgr-tests")
    monkeypatch.setenv("CLOUDSDK_CORE_PROJECT", "psqlmgr-tests")
    monkeypatch.delenv("CLOUDSDK_AUTH_ACCESS_TOKEN", raising=False)
    # Azure — clear SP credentials and pin the config dir somewhere harmless.
    monkeypatch.setenv("AZURE_CONFIG_DIR", "/nonexistent-psqlmgr-tests")
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_SECRET", raising=False)


@pytest.fixture(autouse=True)
def fail_on_unmocked_cloud_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(argv: list[str]) -> tuple[int, str, str]:
        raise RuntimeError(
            f"Unmocked call to auth._run_subprocess(argv={argv!r}). "
            "Tests must never invoke real cloud SDKs; override this in your "
            "test via monkeypatch.setattr(psqlmanager.auth, '_run_subprocess', ...)."
        )

    monkeypatch.setattr(auth_mod, "_run_subprocess", boom)


@pytest.fixture
def sandbox_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    home = tmp_path / "psqlmgr"
    monkeypatch.setenv("PSQLMANAGER_HOME", str(home))
    monkeypatch.setenv("PSQLMANAGER_PASSPHRASE", TEST_PASSPHRASE)
    monkeypatch.delenv("PSQLMANAGER_PASSWORD", raising=False)
    return home


@pytest.fixture
def fresh_store(sandbox_home: Path) -> CredentialStore:
    store = CredentialStore()
    store.initialize(mode="passphrase", passphrase=TEST_PASSPHRASE)
    return store


@pytest.fixture
def mock_keyring(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """Patch the keyring helpers to use an in-memory dict.

    Returns the backing dict so tests can assert what got stored.
    """
    backing: dict[str, str] = {}

    def fake_set(key: bytes) -> bool:
        backing["master-key"] = key.decode("ascii")
        return True

    def fake_get() -> bytes | None:
        v = backing.get("master-key")
        return v.encode("ascii") if v else None

    def fake_delete() -> None:
        backing.pop("master-key", None)

    monkeypatch.setattr(store_mod, "_set_keyring_key", fake_set)
    monkeypatch.setattr(store_mod, "_get_keyring_key", fake_get)
    monkeypatch.setattr(store_mod, "_delete_keyring_key", fake_delete)
    return backing


@pytest.fixture
def broken_keyring(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(store_mod, "_set_keyring_key", lambda key: False)
    monkeypatch.setattr(store_mod, "_get_keyring_key", lambda: None)
    monkeypatch.setattr(store_mod, "_delete_keyring_key", lambda: None)
