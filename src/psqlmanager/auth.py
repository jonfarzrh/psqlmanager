"""Token minting and caching for IAM-based Postgres auth.

Supported methods:

  password     Static password stored in the encrypted credential file.
  iam-rds      AWS RDS / Aurora IAM auth. Uses `aws rds generate-db-auth-token`.
               Token TTL is hard-coded by AWS at 15 minutes.
  iam-gcp      GCP Cloud SQL IAM auth. Uses `gcloud auth print-access-token`.
               Token TTL is typically 1 hour; we treat as 55 min to be safe.
  iam-azure    Azure Database for PostgreSQL. Uses
               `az account get-access-token --resource-type oss-rdbms`; we
               parse the real expiry out of the JSON response.

The minted token is set as PGPASSWORD on the child process. We never store
long-lived cloud credentials — those live in the cloud SDK's own config.

Tokens are cached on disk under `<data_dir>/cache/<sha256(name)>.json` with
mode 0600. A token is treated as expired CACHE_REFRESH_MARGIN_SECONDS before
its real expiry so callers never see a token that dies mid-query.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from .store import Credential, data_dir

CACHE_REFRESH_MARGIN_SECONDS = 60
DEFAULT_TTL_RDS = 900  # AWS-imposed limit on RDS auth tokens.
DEFAULT_TTL_GCP = 3300  # Real TTL is ~3600s; refresh slightly early.

SUPPORTED_METHODS = ("password", "iam-rds", "iam-gcp", "iam-azure")
IAM_METHODS = ("iam-rds", "iam-gcp", "iam-azure")


class AuthError(Exception):
    """A token mint failed. `code` is the stable string surfaced via --json."""

    def __init__(self, message: str, code: str = "auth_failed") -> None:
        super().__init__(message)
        self.code = code


def _cache_dir() -> Path:
    return data_dir() / "cache"


def _cache_path(name: str) -> Path:
    digest = hashlib.sha256(name.encode("utf-8")).hexdigest()[:16]
    return _cache_dir() / f"{digest}.json"


def _now() -> float:
    return time.time()


def _ensure_cache_dir() -> Path:
    cdir = _cache_dir()
    cdir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(cdir, 0o700)
    except OSError:
        pass
    return cdir


def _read_cache(name: str) -> dict[str, Any] | None:
    path = _cache_path(name)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def _write_cache(name: str, token: str, expires_at: float, method: str) -> None:
    _ensure_cache_dir()
    path = _cache_path(name)
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(
                {
                    "name": name,
                    "method": method,
                    "token": token,
                    "expires_at": expires_at,
                },
                f,
            )
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


def get_cached_token(name: str) -> str | None:
    data = _read_cache(name)
    if not data:
        return None
    expires_at = float(data.get("expires_at", 0))
    if _now() > expires_at - CACHE_REFRESH_MARGIN_SECONDS:
        return None
    token = data.get("token")
    return token if isinstance(token, str) and token else None


def clear_cache(name: str | None = None) -> int:
    cdir = _cache_dir()
    if not cdir.exists():
        return 0
    if name is not None:
        path = _cache_path(name)
        if path.exists():
            path.unlink()
            return 1
        return 0
    count = 0
    for p in cdir.iterdir():
        if p.suffix == ".json":
            p.unlink()
            count += 1
    return count


def list_cache() -> list[dict[str, Any]]:
    cdir = _cache_dir()
    if not cdir.exists():
        return []
    out: list[dict[str, Any]] = []
    for p in sorted(cdir.iterdir()):
        if p.suffix != ".json":
            continue
        try:
            data = json.loads(p.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        expires_at = float(data.get("expires_at", 0))
        out.append(
            {
                "name": data.get("name"),
                "method": data.get("method"),
                "expires_at": expires_at,
                "expires_in_seconds": max(0, int(expires_at - _now())),
                "expired": _now() > expires_at - CACHE_REFRESH_MARGIN_SECONDS,
            }
        )
    return out


def _run_subprocess(argv: list[str]) -> tuple[int, str, str]:
    """Indirection point so tests can mock provider CLI invocations."""
    proc = subprocess.run(argv, capture_output=True, text=True)
    return proc.returncode, proc.stdout, proc.stderr


def _which_or_raise(cmd: str, code: str) -> str:
    path = shutil.which(cmd)
    if not path:
        raise AuthError(
            f"{cmd!r} not found on PATH; install the cloud SDK or update PATH.",
            code=code,
        )
    return path


def _mint_rds(cred: Credential) -> tuple[str, float]:
    params = cred.auth_params or {}
    region = params.get("region")
    if not region:
        raise AuthError(
            "iam-rds requires auth_params.region; pass --aws-region when adding.",
            code="missing_param",
        )
    if not cred.user:
        raise AuthError("iam-rds requires a database user.", code="missing_param")
    _which_or_raise("aws", code="aws_cli_missing")
    argv = [
        "aws", "rds", "generate-db-auth-token",
        "--hostname", cred.host,
        "--port", str(cred.port),
        "--region", region,
        "--username", cred.user,
    ]
    profile = params.get("profile")
    if profile:
        argv += ["--profile", profile]
    rc, stdout, stderr = _run_subprocess(argv)
    if rc != 0:
        raise AuthError(
            f"aws rds generate-db-auth-token failed (rc={rc}): "
            f"{(stderr or stdout).strip()}",
            code="mint_failed",
        )
    token = stdout.strip()
    if not token:
        raise AuthError(
            "aws rds generate-db-auth-token returned empty output.",
            code="mint_failed",
        )
    return token, _now() + DEFAULT_TTL_RDS


def _mint_gcp(cred: Credential) -> tuple[str, float]:
    params = cred.auth_params or {}
    account = params.get("account")
    _which_or_raise("gcloud", code="gcp_cli_missing")
    argv = ["gcloud", "auth", "print-access-token"]
    if account:
        argv += [f"--account={account}"]
    rc, stdout, stderr = _run_subprocess(argv)
    if rc != 0:
        raise AuthError(
            f"gcloud auth print-access-token failed (rc={rc}): {stderr.strip()}",
            code="mint_failed",
        )
    token = stdout.strip()
    if not token:
        raise AuthError(
            "gcloud auth print-access-token returned empty output.",
            code="mint_failed",
        )
    return token, _now() + DEFAULT_TTL_GCP


def _parse_azure_expiry(value: Any) -> float:
    if isinstance(value, (int, float)) and value > 0:
        return float(value)
    if isinstance(value, str) and value.strip():
        s = value.strip()
        try:
            return float(s)
        except ValueError:
            pass
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(s, fmt).timestamp()
            except ValueError:
                continue
    raise AuthError(f"Could not parse Azure expiry: {value!r}", code="mint_failed")


def _mint_azure(cred: Credential) -> tuple[str, float]:
    _which_or_raise("az", code="azure_cli_missing")
    argv = [
        "az", "account", "get-access-token",
        "--resource-type", "oss-rdbms",
        "--output", "json",
    ]
    params = cred.auth_params or {}
    tenant = params.get("tenant")
    if tenant:
        argv += ["--tenant", tenant]
    rc, stdout, stderr = _run_subprocess(argv)
    if rc != 0:
        raise AuthError(
            f"az account get-access-token failed (rc={rc}): {stderr.strip()}",
            code="mint_failed",
        )
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as e:
        raise AuthError(f"az returned non-JSON output: {e}", code="mint_failed") from e
    token = data.get("accessToken")
    if not token:
        raise AuthError("az response missing accessToken.", code="mint_failed")
    expires_value = data.get("expires_on", data.get("expiresOn", 0))
    expires_at = _parse_azure_expiry(expires_value)
    return token, expires_at


_MINTERS = {
    "iam-rds": _mint_rds,
    "iam-gcp": _mint_gcp,
    "iam-azure": _mint_azure,
}


def resolve_password(cred: Credential, *, use_cache: bool = True) -> str:
    """Return the effective password for `cred`.

    For static-password credentials this is the stored password verbatim.
    For IAM credentials a token is fetched from the disk cache when fresh,
    otherwise minted via the relevant cloud SDK and re-cached.
    """
    if cred.auth_method == "password":
        return cred.password
    if cred.auth_method not in _MINTERS:
        raise AuthError(
            f"Unknown auth method: {cred.auth_method!r}",
            code="unknown_method",
        )

    if use_cache:
        cached = get_cached_token(cred.name)
        if cached is not None:
            return cached

    token, expires_at = _MINTERS[cred.auth_method](cred)
    _write_cache(cred.name, token, expires_at, cred.auth_method)
    return token
