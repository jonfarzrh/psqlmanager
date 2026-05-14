"""Unit tests for the encrypted credential store."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from psqlmanager.store import (
    Credential,
    CredentialStore,
    LockedError,
    StoreError,
)
from tests.conftest import TEST_PASSPHRASE


def test_initialize_creates_file_with_secure_perms(sandbox_home: Path) -> None:
    store = CredentialStore()
    store.initialize(mode="passphrase", passphrase=TEST_PASSPHRASE)

    assert store.path.exists()
    file_mode = stat.S_IMODE(store.path.stat().st_mode)
    dir_mode = stat.S_IMODE(store.path.parent.stat().st_mode)
    assert file_mode == 0o600
    assert dir_mode == 0o700


def test_initialize_twice_errors(fresh_store: CredentialStore) -> None:
    other = CredentialStore()
    with pytest.raises(StoreError, match="already exists"):
        other.initialize(mode="passphrase", passphrase=TEST_PASSPHRASE)


def test_initialize_passphrase_requires_passphrase(sandbox_home: Path) -> None:
    store = CredentialStore()
    with pytest.raises(StoreError, match="non-empty passphrase"):
        store.initialize(mode="passphrase", passphrase="")


def test_initialize_keyring_uses_keyring(sandbox_home: Path, mock_keyring: dict[str, str]) -> None:
    store = CredentialStore()
    store.initialize(mode="keyring")
    assert "master-key" in mock_keyring
    assert store.mode == "keyring"


def test_initialize_keyring_fails_without_backend(
    sandbox_home: Path, broken_keyring: None
) -> None:
    store = CredentialStore()
    with pytest.raises(StoreError, match="keyring is not available"):
        store.initialize(mode="keyring")


def test_upsert_and_get_roundtrip(fresh_store: CredentialStore) -> None:
    cred = Credential(
        name="prod",
        host="db.example.com",
        port=5433,
        user="analytics",
        password="s3cret",
        dbname="warehouse",
        sslmode="require",
    )
    fresh_store.upsert(cred)

    # Read it back through a fresh store object to prove durability.
    reread = CredentialStore()
    reread.unlock(passphrase=TEST_PASSPHRASE)
    got = reread.get("prod")
    assert got == cred


def test_upsert_without_force_rejects_duplicate(fresh_store: CredentialStore) -> None:
    fresh_store.upsert(Credential(name="prod", host="a"))
    with pytest.raises(StoreError, match="already exists"):
        fresh_store.upsert(Credential(name="prod", host="b"))


def test_upsert_with_force_overwrites(fresh_store: CredentialStore) -> None:
    fresh_store.upsert(Credential(name="prod", host="a"))
    existed = fresh_store.upsert(Credential(name="prod", host="b"), force=True)
    assert existed is True
    assert fresh_store.get("prod").host == "b"


def test_delete_missing_errors(fresh_store: CredentialStore) -> None:
    with pytest.raises(StoreError, match="No credential"):
        fresh_store.delete("nope")


def test_rename_round_trip(fresh_store: CredentialStore) -> None:
    fresh_store.upsert(Credential(name="a", host="h"))
    fresh_store.rename("a", "b")
    assert fresh_store.list_names() == ["b"]
    assert fresh_store.get("b").name == "b"


def test_rename_conflicts(fresh_store: CredentialStore) -> None:
    fresh_store.upsert(Credential(name="a", host="h"))
    fresh_store.upsert(Credential(name="b", host="h"))
    with pytest.raises(StoreError, match="already exists"):
        fresh_store.rename("a", "b")


def test_list_names_sorted(fresh_store: CredentialStore) -> None:
    for n in ("zebra", "alpha", "middle"):
        fresh_store.upsert(Credential(name=n))
    assert fresh_store.list_names() == ["alpha", "middle", "zebra"]


def test_password_never_appears_in_plaintext_on_disk(fresh_store: CredentialStore) -> None:
    secret = "ULTRASECRETPASSWORD_DO_NOT_LEAK"
    fresh_store.upsert(Credential(name="prod", password=secret))
    raw = fresh_store.path.read_bytes()
    assert secret.encode() not in raw


def test_wrong_passphrase_raises_locked(fresh_store: CredentialStore) -> None:
    fresh_store.upsert(Credential(name="prod", password="x"))
    other = CredentialStore()
    with pytest.raises(LockedError, match="Failed to decrypt"):
        other.unlock(passphrase="not the right one")


def test_missing_passphrase_raises_locked(
    monkeypatch: pytest.MonkeyPatch, fresh_store: CredentialStore
) -> None:
    monkeypatch.delenv("PSQLMANAGER_PASSPHRASE", raising=False)
    other = CredentialStore()
    with pytest.raises(LockedError, match="passphrase-protected"):
        other.unlock()


def test_keyring_mode_roundtrip(sandbox_home: Path, mock_keyring: dict[str, str]) -> None:
    store = CredentialStore()
    store.initialize(mode="keyring")
    store.upsert(Credential(name="prod", password="kr-secret"))

    fresh = CredentialStore()
    fresh.unlock()
    assert fresh.get("prod").password == "kr-secret"


def test_keyring_lost_key_locks_store(
    sandbox_home: Path, mock_keyring: dict[str, str]
) -> None:
    store = CredentialStore()
    store.initialize(mode="keyring")
    mock_keyring.clear()
    fresh = CredentialStore()
    with pytest.raises(LockedError, match="Master key not found"):
        fresh.unlock()


def test_destroy_removes_file_and_keyring_entry(
    sandbox_home: Path, mock_keyring: dict[str, str]
) -> None:
    store = CredentialStore()
    store.initialize(mode="keyring")
    assert "master-key" in mock_keyring
    store.destroy()
    assert not store.path.exists()
    assert "master-key" not in mock_keyring


def test_atomic_write_leaves_no_tmp_file(fresh_store: CredentialStore) -> None:
    fresh_store.upsert(Credential(name="a"))
    leftover = [
        p for p in fresh_store.path.parent.iterdir() if p.suffix.endswith(".tmp")
    ]
    assert leftover == []


def test_file_layout_has_expected_fields(fresh_store: CredentialStore) -> None:
    fresh_store.upsert(Credential(name="a"))
    data = json.loads(fresh_store.path.read_text())
    assert set(data) == {"version", "mode", "kdf", "token"}
    assert data["version"] == 1
    assert data["mode"] == "passphrase"
    assert data["kdf"]["algorithm"] == "pbkdf2-hmac-sha256"
    assert data["kdf"]["iterations"] == 600_000


def test_readonly_credential_round_trip(fresh_store: CredentialStore) -> None:
    cred = Credential(name="prod-ro", host="h", user="u", readonly=True)
    fresh_store.upsert(cred)
    reread = CredentialStore()
    reread.unlock(passphrase=TEST_PASSPHRASE)
    assert reread.get("prod-ro").readonly is True


def test_iam_credential_round_trip(fresh_store: CredentialStore) -> None:
    cred = Credential(
        name="prod-aws",
        host="mydb.us-east-1.rds.amazonaws.com",
        port=5432,
        user="db_iam_user",
        dbname="warehouse",
        sslmode="require",
        auth_method="iam-rds",
        auth_params={"region": "us-east-1", "profile": "prod"},
    )
    fresh_store.upsert(cred)

    reread = CredentialStore()
    reread.unlock(passphrase=TEST_PASSPHRASE)
    got = reread.get("prod-aws")
    assert got == cred
    assert got.password == ""  # IAM credentials store no static password.


def test_psqlmanager_home_overrides_xdg(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    custom = tmp_path / "custom-location"
    monkeypatch.setenv("PSQLMANAGER_HOME", str(custom))
    monkeypatch.setenv("PSQLMANAGER_PASSPHRASE", "p")
    store = CredentialStore()
    store.initialize(mode="passphrase", passphrase="p")
    assert store.path.parent == custom
