# psqlmanager

Encrypted credential manager and `psql` wrapper, designed for humans **and** AI
agents. Store named Postgres credentials once; never expose them on the
command line, in shell history, or to an AI tool that's driving your terminal.

## Why

Modern dev workflows hand the terminal to AI coding agents that should be able
to query a database but **should not** see the password. `psqlmanager` keeps
credentials in an encrypted file at `~/.local/share/psqlmanager/creds.json`
(mode `0600`), with the master key in the OS keyring. An agent invokes
`psqlmanager exec prod -- -c "select ..."`; the password is read from the
keyring, passed to `psql` through `PGPASSWORD` in a child env, and never
appears in the agent's view of the terminal.

## Install

```sh
# From PyPI:
uv tool install psqlmanager
# or
pipx install psqlmanager
# or
pip install psqlmanager
```

This installs a `psqlmanager` binary on your `PATH`.

For local development against a checkout of this repo:

```sh
uv sync
# now `uv run psqlmanager ...` uses the working tree
```

## Quick start

```sh
# One-time setup — generates a Fernet master key and stores it in the OS keyring.
psqlmanager init

# Add a credential (password read from stdin so it never hits argv/history).
echo "$PGPASSWORD" | psqlmanager add prod \
    --host db.example.com --port 5432 \
    --user analytics --dbname warehouse \
    --sslmode require --password-stdin

# Or from a connection URL:
psqlmanager add staging --url "postgres://user:pw@host:5432/db?sslmode=require"

# Interactive shell:
psqlmanager connect prod

# One-shot query (anything after `--` is forwarded to psql):
psqlmanager exec prod -- -c "select now()"
```

## Giving an AI agent database access

The intended pattern: create a **read-only credential** for the agent, hand it
the credential name (not the password), and let it call `exec`. Postgres
itself rejects writes — there is no client-side SQL parser to bypass.

```sh
# One-time setup by the human:
psqlmanager add agent-prod \
    --host db.example.com --user analytics_ro --dbname warehouse \
    --sslmode require --password-stdin \
    --readonly < ~/.secrets/analytics_ro

# The agent then runs queries by name only — never sees the password:
psqlmanager exec agent-prod -- -c "select count(*) from orders"
```

Under the hood, `--readonly` sets `PGOPTIONS=-c default_transaction_read_only=on`
on the child psql, so the server rejects INSERT/UPDATE/DELETE/DDL with
`ERROR: cannot execute … in a read-only transaction`. The enforcement is
server-side; nothing the agent passes via `-c` can defeat it short of
explicitly issuing `SET default_transaction_read_only = off`, which still
requires a read-write database role.

If a human needs to issue a one-off write against a read-only credential,
the override is intentionally noisy:

```sh
psqlmanager exec --allow-write agent-prod -- -c "delete from staging.tmp"
# stderr: WARNING: --allow-write is overriding read-only protection on credential 'agent-prod'...
```

Agents will see that warning in their tool output, which is the point —
it's visible in transcripts and easy to assert on in audit logs.

> The `--readonly` flag composes with IAM auth (`--auth iam-rds` etc.) so
> you can give an agent a short-lived, IAM-minted, read-only credential.

## Commands

| Command | Description |
|---|---|
| `init [--passphrase]`           | Initialize the encrypted store. |
| `add NAME [...] [--readonly]`   | Add or update a named credential. |
| `list [--json]`                 | List credential names (sanitized). |
| `show NAME [--reveal] [--json]` | Show one credential; password masked unless `--reveal`. |
| `rm NAME`                       | Delete a credential. |
| `rename OLD NEW`                | Rename a credential. |
| `connect [--allow-write] NAME [-- ...]` | Exec into an interactive psql shell. |
| `exec [--allow-write] NAME [-- ...]`    | Run psql once and propagate its exit code. |
| `cache list [--json]`           | Show cached IAM tokens and remaining TTL. |
| `cache clear [NAME] [--json]`   | Clear one or all cached IAM tokens. |
| `info [--json]`                 | Show store path, mode, permissions, entry count. |
| `destroy [--yes]`               | Delete the store and the keyring entry. |

## IAM authentication (AWS RDS, GCP Cloud SQL, Azure)

For managed Postgres, `psqlmanager` can mint short-lived IAM tokens instead of
storing a static password. The token is fetched from a per-credential disk
cache when fresh, otherwise minted via the relevant cloud SDK and re-cached.

```sh
# AWS RDS / Aurora IAM:
psqlmanager add prod-aws \
    --host mydb.us-east-1.rds.amazonaws.com \
    --user db_iam_user --dbname app \
    --auth iam-rds --aws-region us-east-1 [--aws-profile prod]

# GCP Cloud SQL Postgres IAM:
psqlmanager add prod-gcp \
    --host 10.0.0.1 --user svc@project.iam.gserviceaccount.com \
    --dbname app \
    --auth iam-gcp [--gcp-account me@example.com]

# Azure Database for PostgreSQL:
psqlmanager add prod-azure \
    --host my-pg.postgres.database.azure.com \
    --user me@my-pg \
    --dbname app \
    --auth iam-azure [--azure-tenant <tenant-id>]
```

Notes:

* `sslmode` defaults to `require` for IAM credentials (all three providers
  reject IAM auth without TLS).
* `--password*` flags are rejected with `--auth iam-*` since the token is
  always minted.
* The relevant cloud CLI (`aws`, `gcloud`, or `az`) must be on `PATH` at
  `connect`/`exec` time, and your usual SSO/SDK config is what authorizes
  the mint. `psqlmanager` does **not** store cloud credentials.
* Token TTLs: AWS RDS = 15 min (hard limit), GCP = ~55 min, Azure uses the
  real expiry from the response. Cached tokens are refreshed 60 s early.

### Cache

```sh
psqlmanager cache list                 # show what's cached and remaining TTL
psqlmanager cache clear prod-aws       # force a re-mint on next exec
psqlmanager cache clear                # nuke the whole cache
```

Cache files live at `<data_dir>/cache/<sha256(name)>.json` with mode `0600`.
Re-running `add NAME` (with `--force` or for a new entry) automatically
invalidates that name's cache so a stale token can't outlive its config.

## Agent-friendly conventions

* `--json` is supported on every data-emitting command. Errors emit a stable
  JSON envelope on stderr (`{"error": "...", "code": "..."}`) when `--json`
  is set.
* Error codes are stable strings: `locked`, `not_found`, `exists`, `no_psql`,
  `no_keyring`, `store_error`, `init_failed`, `needs_confirmation`,
  `bad_auth_combo`, `missing_param`, `aws_cli_missing`, `gcp_cli_missing`,
  `azure_cli_missing`, `mint_failed`, `unknown_method`.
* Exit codes are stable: `0` success, `1` generic, `2` misuse, `3` locked
  store, `4` missing entry, `5` psql not installed, `6` IAM token mint failed.
* No command will block on a TTY prompt unless `stdin` is a real TTY. Pass
  `--password-stdin`, set `PSQLMANAGER_PASSWORD`, or use `--no-password`.
* Passwords (and IAM tokens) are passed to `psql` via the `PGPASSWORD` env
  var of the child process (never via argv) and are scrubbed from the parent
  env if unset.

## Storage & encryption

* **Location:** `$XDG_DATA_HOME/psqlmanager/creds.json`, falling back to
  `~/.local/share/psqlmanager/creds.json`. Override with `PSQLMANAGER_HOME`.
* **Permissions:** the data directory is `0700`; the credentials file is
  `0600`. The file is written atomically via temp-file + rename.
* **Encryption:** Fernet (AES-128-CBC + HMAC-SHA256) with a 32-byte
  randomly-generated key.
* **Key custody (default):** the key is stored in the OS keyring under service
  `psqlmanager`, user `master-key` (Secret Service on Linux, Keychain on
  macOS, Credential Manager on Windows).
* **Passphrase mode:** if you don't have a keyring backend, run
  `psqlmanager init --passphrase`; the key is derived from your passphrase
  via PBKDF2-HMAC-SHA256 (600k iterations, 16-byte random salt) and the salt
  is stored in the file header. Set `PSQLMANAGER_PASSPHRASE` to avoid
  prompts.

## Environment variables

| Variable                 | Purpose |
|---|---|
| `PSQLMANAGER_HOME`       | Override the storage directory. |
| `PSQLMANAGER_PASSWORD`   | Default password for `add` when no other source given. |
| `PSQLMANAGER_PASSPHRASE` | Master passphrase (passphrase-mode stores). |

## Testing

Run the full suite with `uv run pytest`. The test setup deliberately makes
live cloud services unreachable:

* A session-wide autouse fixture overwrites `AWS_ACCESS_KEY_ID` /
  `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` with bogus statics,
  unsets `AWS_PROFILE` / `AWS_DEFAULT_PROFILE`, points
  `AWS_CONFIG_FILE` / `GOOGLE_APPLICATION_CREDENTIALS` / `AZURE_CONFIG_DIR`
  at non-existent paths, and clears Azure SP env vars. A botocore/gcloud/az
  call that somehow escapes mocking will fail at the auth boundary instead
  of consuming the developer's SSO session.
* A second autouse fixture replaces `psqlmanager.auth._run_subprocess` with
  a `RuntimeError`-raising stub. Tests that need to mint a token override
  it per-test via `monkeypatch.setattr` — the override wins for the
  duration of that test. Any future test that forgets to mock fails loudly
  with `RuntimeError: Unmocked call to auth._run_subprocess(...)` rather
  than silently invoking the real `aws` / `gcloud` / `az` CLI.

Tests also never touch the real OS keyring: keyring-mode tests use the
`mock_keyring` fixture (in-memory dict); everything else runs in
passphrase mode against a `tmp_path` directory.

## Threat model — what this does and doesn't protect against

**Protects:** another user on the same machine reading your credential file
(file is `0600` and encrypted); credentials leaking through shell history or
process listings; an AI agent driving your shell seeing passwords in tool
output.

**Does not protect:** an attacker who already has code execution as your user
(they can read the keyring or your decrypted memory); a compromised `psql`
binary; shoulder-surfing of `--reveal` output. Treat the keyring entry as
sensitive as your SSH key.
