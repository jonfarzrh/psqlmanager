"""Encrypted credential storage.

Credentials are encrypted with Fernet (AES-128-CBC + HMAC-SHA256). The Fernet
key is held in the OS keyring under service `psqlmanager`. If the keyring
backend is unavailable the user can opt into a passphrase mode by setting
PSQLMANAGER_PASSPHRASE; the key is then derived via PBKDF2-HMAC-SHA256 and
the salt is stored alongside the ciphertext.

On-disk layout (single file, `creds.json`, mode 0600):

    {
      "version": 1,
      "mode": "keyring" | "passphrase",
      "kdf": null | {"algorithm": "pbkdf2-hmac-sha256",
                     "salt": "<b64>",
                     "iterations": 600000},
      "token": "<fernet token, str>"
    }
"""

from __future__ import annotations

import base64
import json
import os
import stat
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

KEYRING_SERVICE = "psqlmanager"
KEYRING_USER = "master-key"
PBKDF2_ITERATIONS = 600_000
FILE_VERSION = 1
PASSPHRASE_ENV = "PSQLMANAGER_PASSPHRASE"


class StoreError(Exception):
    """Recoverable storage error reported to the CLI."""


class LockedError(StoreError):
    """Raised when no key is available to decrypt the store."""


@dataclass
class Credential:
    name: str
    host: str = "localhost"
    port: int = 5432
    user: str = "postgres"
    password: str = ""
    dbname: str = ""
    sslmode: str = ""
    options: dict[str, str] = field(default_factory=dict)
    # IAM/auth support. "password" preserves the v1 behavior; other methods
    # mint short-lived tokens at psql invocation time (see psqlmanager.auth).
    auth_method: str = "password"
    auth_params: dict[str, str] = field(default_factory=dict)
    # When true, every transaction in the psql session is forced read-only
    # via PGOPTIONS=-c default_transaction_read_only=on. Postgres itself
    # rejects INSERT/UPDATE/DELETE/DDL; no client-side SQL parsing required.
    readonly: bool = False

    def public_dict(self, reveal: bool = False) -> dict[str, Any]:
        d = asdict(self)
        if not reveal:
            d["password"] = "***" if self.password else ""
        return d


def data_dir() -> Path:
    override = os.environ.get("PSQLMANAGER_HOME")
    if override:
        return Path(override).expanduser()
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "psqlmanager"


def _store_path() -> Path:
    return data_dir() / "creds.json"


def _ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass


def _write_file_secure(path: Path, payload: bytes) -> None:
    _ensure_dir(path.parent)
    tmp = path.with_suffix(path.suffix + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(tmp, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(payload)
    except Exception:
        try:
            os.unlink(tmp)
        finally:
            raise
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _derive_passphrase_key(passphrase: str, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    raw = kdf.derive(passphrase.encode("utf-8"))
    return base64.urlsafe_b64encode(raw)


def _keyring():
    import keyring
    return keyring


def _get_keyring_key() -> bytes | None:
    try:
        kr = _keyring()
        value = kr.get_password(KEYRING_SERVICE, KEYRING_USER)
    except Exception:
        return None
    if not value:
        return None
    return value.encode("ascii")


def _set_keyring_key(key: bytes) -> bool:
    try:
        kr = _keyring()
        kr.set_password(KEYRING_SERVICE, KEYRING_USER, key.decode("ascii"))
        return True
    except Exception:
        return False


def _delete_keyring_key() -> None:
    try:
        kr = _keyring()
        kr.delete_password(KEYRING_SERVICE, KEYRING_USER)
    except Exception:
        pass


@dataclass
class _Wrapper:
    version: int
    mode: str
    kdf: dict[str, Any] | None
    token: str

    @classmethod
    def from_bytes(cls, raw: bytes) -> "_Wrapper":
        data = json.loads(raw.decode("utf-8"))
        return cls(
            version=int(data.get("version", 1)),
            mode=data["mode"],
            kdf=data.get("kdf"),
            token=data["token"],
        )

    def to_bytes(self) -> bytes:
        return json.dumps(
            {
                "version": self.version,
                "mode": self.mode,
                "kdf": self.kdf,
                "token": self.token,
            },
            indent=2,
            sort_keys=True,
        ).encode("utf-8")


class CredentialStore:
    """Loads, decrypts, mutates and persists the credential file."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or _store_path()
        self._credentials: dict[str, Credential] = {}
        self._mode: str = "keyring"
        self._kdf: dict[str, Any] | None = None
        self._key: bytes | None = None
        self._loaded = False

    @property
    def mode(self) -> str:
        return self._mode

    @property
    def exists(self) -> bool:
        return self.path.exists()

    def initialize(self, mode: str = "keyring", passphrase: str | None = None) -> None:
        """Create a new (empty) store. Errors if a store already exists."""
        if self.exists:
            raise StoreError(f"Store already exists at {self.path}")
        if mode not in ("keyring", "passphrase"):
            raise StoreError(f"Unknown mode: {mode}")

        if mode == "keyring":
            key = Fernet.generate_key()
            if not _set_keyring_key(key):
                raise StoreError(
                    "OS keyring is not available. Re-run with --passphrase or "
                    f"set {PASSPHRASE_ENV} to use passphrase mode."
                )
            self._key = key
            self._mode = "keyring"
            self._kdf = None
        else:
            if not passphrase:
                raise StoreError("Passphrase mode requires a non-empty passphrase.")
            salt = os.urandom(16)
            self._kdf = {
                "algorithm": "pbkdf2-hmac-sha256",
                "salt": base64.b64encode(salt).decode("ascii"),
                "iterations": PBKDF2_ITERATIONS,
            }
            self._key = _derive_passphrase_key(passphrase, salt, PBKDF2_ITERATIONS)
            self._mode = "passphrase"

        self._credentials = {}
        self._loaded = True
        self._save()

    def unlock(self, passphrase: str | None = None) -> None:
        """Load and decrypt the store. Idempotent."""
        if self._loaded:
            return
        if not self.exists:
            raise StoreError(
                f"No credential store found at {self.path}. "
                "Run `psqlmanager init` first."
            )
        wrapper = _Wrapper.from_bytes(self.path.read_bytes())
        self._mode = wrapper.mode
        self._kdf = wrapper.kdf

        if wrapper.mode == "keyring":
            key = _get_keyring_key()
            if not key:
                raise LockedError(
                    "Master key not found in OS keyring. The keyring may be "
                    "locked, the entry may have been deleted, or this store "
                    "was created on a different machine."
                )
            self._key = key
        elif wrapper.mode == "passphrase":
            pw = passphrase if passphrase is not None else os.environ.get(PASSPHRASE_ENV)
            if not pw:
                raise LockedError(
                    f"This store is passphrase-protected. Set {PASSPHRASE_ENV} "
                    "or pass --passphrase."
                )
            if not wrapper.kdf:
                raise StoreError("Corrupt store: passphrase mode but no KDF metadata.")
            salt = base64.b64decode(wrapper.kdf["salt"])
            iterations = int(wrapper.kdf["iterations"])
            self._key = _derive_passphrase_key(pw, salt, iterations)
        else:
            raise StoreError(f"Unknown store mode: {wrapper.mode}")

        try:
            plaintext = Fernet(self._key).decrypt(wrapper.token.encode("ascii"))
        except InvalidToken as e:
            raise LockedError(
                "Failed to decrypt credentials (wrong key or tampered file)."
            ) from e

        payload = json.loads(plaintext.decode("utf-8"))
        self._credentials = {
            name: Credential(name=name, **fields)
            for name, fields in payload.get("credentials", {}).items()
        }
        self._loaded = True

    def _save(self) -> None:
        if self._key is None:
            raise StoreError("Store is not unlocked.")
        body = {
            "credentials": {
                name: {k: v for k, v in asdict(c).items() if k != "name"}
                for name, c in self._credentials.items()
            }
        }
        token = Fernet(self._key).encrypt(json.dumps(body, sort_keys=True).encode("utf-8"))
        wrapper = _Wrapper(
            version=FILE_VERSION,
            mode=self._mode,
            kdf=self._kdf,
            token=token.decode("ascii"),
        )
        _write_file_secure(self.path, wrapper.to_bytes())

    def list_names(self) -> list[str]:
        self._require_loaded()
        return sorted(self._credentials.keys())

    def get(self, name: str) -> Credential:
        self._require_loaded()
        if name not in self._credentials:
            raise StoreError(f"No credential named {name!r}.")
        return self._credentials[name]

    def upsert(self, cred: Credential, *, force: bool = False) -> bool:
        """Insert or replace. Returns True if the entry already existed."""
        self._require_loaded()
        existed = cred.name in self._credentials
        if existed and not force:
            raise StoreError(
                f"Credential {cred.name!r} already exists. Use --force to overwrite."
            )
        self._credentials[cred.name] = cred
        self._save()
        return existed

    def delete(self, name: str) -> None:
        self._require_loaded()
        if name not in self._credentials:
            raise StoreError(f"No credential named {name!r}.")
        del self._credentials[name]
        self._save()

    def rename(self, old: str, new: str) -> None:
        self._require_loaded()
        if old not in self._credentials:
            raise StoreError(f"No credential named {old!r}.")
        if new in self._credentials:
            raise StoreError(f"Credential {new!r} already exists.")
        cred = self._credentials.pop(old)
        cred.name = new
        self._credentials[new] = cred
        self._save()

    def destroy(self) -> None:
        """Delete the store file and (if applicable) the keyring entry."""
        if self._mode == "keyring":
            _delete_keyring_key()
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass

    def _require_loaded(self) -> None:
        if not self._loaded:
            raise StoreError("Store is not unlocked.")


def file_mode_octal(path: Path) -> str:
    try:
        return oct(stat.S_IMODE(path.stat().st_mode))
    except FileNotFoundError:
        return "-"
