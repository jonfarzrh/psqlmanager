# Releasing psqlmanager

The release pipeline runs on every `v*` tag. It re-runs CI on the tagged
commit, verifies the tag matches `pyproject.toml`, builds an sdist and a
wheel, publishes them to PyPI via Trusted Publishing (no API token in
GitHub secrets), and creates a GitHub Release with the artifacts attached.

## One-time setup

You need to do this once, before the first release.

### 1. Reserve the project name on PyPI

Make sure `psqlmanager` doesn't already exist. If it does and isn't yours,
pick a different name (and update `pyproject.toml` plus `release.yml`'s
`url: https://pypi.org/p/psqlmanager` accordingly).

### 2. Configure PyPI Trusted Publishing

This is the modern OIDC-based flow — no long-lived API token sits in your
GitHub repo secrets.

Sign in to PyPI and go to **Account settings → Publishing → Add a new
pending publisher**. Fill in:

| Field                  | Value                              |
|------------------------|------------------------------------|
| PyPI Project Name      | `psqlmanager`                      |
| Owner                  | `jonfarzrh`                        |
| Repository name        | `psqlmanager`                      |
| Workflow name          | `release.yml`                      |
| Environment name       | `pypi`                             |

After your first successful release the publisher is no longer "pending"
and becomes a normal trusted publisher tied to the project.

### 3. Create the `pypi` environment in GitHub

In the repo, go to **Settings → Environments → New environment** and
create one called `pypi`. You don't need any secrets in it; the
environment exists so:

* The `publish` job in `release.yml` can attach to it (the OIDC token
  PyPI checks for is scoped to the environment name).
* You can optionally add **required reviewers** so every PyPI publish
  needs human approval before running.

Adding a required reviewer is recommended — it makes the publish step a
two-person operation in practice and gives you a chance to spot a bad
tag before it goes out.

## Cutting a release

```sh
# 1. Bump the version in pyproject.toml. Use semver:
#    - patch (0.1.0 -> 0.1.1) for fixes
#    - minor (0.1.0 -> 0.2.0) for features
#    - major (0.1.0 -> 1.0.0) for breaking changes
$EDITOR pyproject.toml

# 2. Commit and merge to main via PR (CI runs on the PR).
git commit -am "release 0.1.1"

# 3. Tag the commit on main. The tag MUST match pyproject.toml exactly,
#    prefixed with `v`. The release workflow fails the run otherwise.
git tag v0.1.1
git push origin main v0.1.1
```

That last `git push` triggers `release.yml`. The flow is:

1. **`verify-version`** — parses `pyproject.toml`, compares to the
   stripped tag, fails fast on mismatch.
2. **`test`** — calls `ci.yml` as a reusable workflow; runs the full
   pytest matrix (`3.10`–`3.14`) and the `uv build` + wheel sanity check.
3. **`publish`** — downloads the wheel + sdist artifact, publishes to
   PyPI via OIDC. If you set required reviewers on the `pypi`
   environment, this is the step that waits for approval.
4. **`github-release`** — creates `vX.Y.Z` on GitHub with auto-generated
   release notes and the wheel + sdist attached.

## Troubleshooting

| Symptom                                                | Likely cause |
|--------------------------------------------------------|--------------|
| `Tag (X) does not match pyproject version (Y)`         | Forgot to bump `pyproject.toml` before tagging. Delete the tag, fix, re-tag. |
| `invalid-publisher: valid token, but no corresponding publisher` | PyPI Trusted Publisher config doesn't match (owner / repo / workflow / environment). Re-check the form. |
| `403 Forbidden` on publish                             | Project name already taken on PyPI by someone else, or your Trusted Publisher is for a different project name. |
| `Resource not accessible by integration` on GH Release | The `github-release` job needs `permissions: contents: write` — already set in the workflow; check you didn't restrict the repo's default workflow permissions to read-only. |

## TestPyPI dry runs (optional)

To verify the build before publishing for real, add a second Trusted
Publisher on `test.pypi.org` (same form, different host) and a manual
workflow:

```yaml
# .github/workflows/testpypi.yml
on: workflow_dispatch
jobs:
  publish:
    runs-on: ubuntu-latest
    environment: testpypi
    permissions: { id-token: write }
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v3
      - run: uv build
      - uses: pypa/gh-action-pypi-publish@release/v1
        with:
          repository-url: https://test.pypi.org/legacy/
```

Not wired up by default — add it when you actually want it.

## Yanking a bad release

If a release ships broken:

```sh
# Mark the broken version as yanked (still installable by explicit pin,
# but `pip install psqlmanager` skips it).
uvx twine yank psqlmanager==0.1.1 -m "broke <reason>"
```

Then bump the version (e.g. `0.1.2`) with the fix and cut a new release
normally. Don't delete the tag/release — yanking is the supported path.
