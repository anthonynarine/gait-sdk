# Publishing gait-sdk to PyPI: a tutorial

This guide assumes you've never published a Python package. Part 1 explains the moving parts, Part 2 is the one-time setup, Part 3 is what you do for every release, and Part 4 covers consuming the package safely.

---

## Part 1: How it works

**PyPI** (pypi.org) is the public registry `pip install` downloads from. Publishing means uploading built files there under a project name (`gait-sdk`) and a version (`0.5.0`).

**What gets uploaded: two "distributions"**

| File | What it is | Who uses it |
|---|---|---|
| `gait_sdk-0.5.0-py3-none-any.whl` (**wheel**) | Ready-to-install zip of the package | `pip` uses it by default. Fast, nothing to build. |
| `gait_sdk-0.5.0.tar.gz` (**sdist**) | The source, plus instructions to build it | Fallback, auditing, packagers |

Both are built from `pyproject.toml` by one command: `python -m build`.

**What decides their contents: `pyproject.toml`**
- `[project]` is the identity card: name, version, description, `requires-python`, dependencies, links. PyPI shows all of it.
- `readme = "README.md"` makes the README **the package's PyPI front page**.
- `[tool.setuptools.packages.find] include` lists which folders ship. Everything else (tests, docs, CI files) stays out.

**Versions are forever.** Once `0.5.0` is on PyPI, that exact version can **never be re-uploaded or changed**, not even by you. That's a security feature: `gait-sdk==0.5.0` means the same bytes for everyone, always. A mistake means publishing `0.5.1`. See [Yanking](#yanking-a-bad-release) for how to discourage a broken release.

**Version numbers (semantic versioning), `MAJOR.MINOR.PATCH`:**
- **PATCH** (0.5.0 → 0.5.1): bug or security fix, no behavior change for correct callers.
- **MINOR** (0.5 → 0.6): new features, or deprecation removals while we're in 0.x.
- **MAJOR** (→ 1.0): a stable public API, after which breaking changes only happen in majors.

**How the upload is authenticated: Trusted Publishing**
The old way was to create a PyPI password or API token and paste it into CI secrets. If it leaked, anyone could publish malicious code as you.

Trusted Publishing removes that secret entirely:
1. You tell PyPI, once: "trust uploads that come from repo `anthonynarine/gait-sdk`, workflow file `publish.yml`, environment `pypi`."
2. When that workflow runs, GitHub gives the job a short-lived, signed identity token saying exactly which repo and workflow it is.
3. PyPI checks the token against what you registered, and accepts the upload only if it matches.

Nothing is stored anywhere to steal. The only way to publish is to run *your* workflow in *your* repo, and the workflow only runs when you push a version tag.

**The release pipeline (`.github/workflows/publish.yml`)**
```
you push tag v0.5.0
      │
      ▼
tests (Python 3.10–3.12) ─► build wheel + sdist ─► check tag == pyproject version ─► twine check
      │                                                                                    │
      └── any failure stops the release ◄──────────────────────────────────────────────────┘
      ▼
"pypi" environment ── optional: waits for YOU to click Approve in GitHub
      ▼
upload to PyPI (Trusted Publishing, with signed attestations)
```

---

## Part 2: One-time setup (≈15 minutes)

### 2.1 Create and secure your PyPI account
1. Register at https://pypi.org/account/register/ and verify your email.
2. **Turn on 2FA** (Account settings → Two factor authentication). PyPI requires it to publish. Use an authenticator app or a security key, and store the recovery codes somewhere safe.

### 2.2 Register the "pending" trusted publisher
Because the project doesn't exist on PyPI yet, you register a *pending* publisher. The first successful upload then creates the project and links it.

1. Go to https://pypi.org/manage/account/publishing/
2. Under **"Add a new pending publisher" → GitHub**, fill in **exactly**:

| Field | Value |
|---|---|
| PyPI Project Name | `gait-sdk` |
| Owner | `anthonynarine` |
| Repository name | `gait-sdk` |
| Workflow name | `publish.yml` |
| Environment name | `pypi` |

3. Click **Add**. There's no token to copy, and that's the point.

### 2.3 Create the `pypi` environment in GitHub (your approval gate)
1. Go to github.com/anthonynarine/gait-sdk → **Settings → Environments → New environment** → name it `pypi`.
2. Under **Deployment protection rules**, tick **Required reviewers** and add yourself. From now on, every publish pauses until you click **Approve**. It's a last human check before code goes public.
3. Optionally, under **Deployment branches and tags**, choose **Selected branches and tags** and add a rule for tags matching `v*`.

### 2.4 Protect the repository
- **Settings → Branches → Add rule** for `main`: require a pull request and require status checks (the **Tests** workflow) to pass.
- **Settings → Rules → Rulesets → New tag ruleset** for `v*`: block deletion and updates, so a release tag can never be moved to different code.
- **Settings → Code security**: enable **Private vulnerability reporting** (`docs/SECURITY.md` tells people to use it), plus Dependabot alerts.
- Your GitHub account: **2FA on**.

---

## Part 3: Releasing a version

### 3.1 Prepare
1. Make sure `main` has everything, merged through a PR with green **Tests**.
2. Bump the version in `pyproject.toml` (`version = "0.5.1"`).
3. Add a section for it at the top of `docs/CHANGELOG.md`.
4. Commit through a PR: `chore(release): 0.5.1`.

### 3.2 Dry-run locally (recommended, and it teaches you what the pipeline does)
```bash
python -m pip install --upgrade build twine
python -m build                      # creates dist/*.whl and dist/*.tar.gz
twine check --strict dist/*          # validates metadata + README rendering
python -m venv /tmp/try && /tmp/try/bin/pip install dist/*.whl   # (Windows: \tmp\try\Scripts\pip)
/tmp/try/bin/python -c "import gait_sdk; print(gait_sdk.__version__)"
```
Look inside the wheel with `python -m zipfile -l dist/*.whl`. You should see `gait_sdk/…` and `auth_integration/__init__.py`, and **no** tests or docs.

### 3.3 Tag and push
```bash
git checkout main && git pull
git tag -a v0.5.1 -m "gait-sdk 0.5.1"
git push origin v0.5.1
```
The tag **must** equal the pyproject version. The workflow refuses to publish otherwise.

### 3.4 Watch and approve
1. GitHub → **Actions → Publish to PyPI**. Watch tests → build go green.
2. The **publish** job waits on the `pypi` environment. Click **Review deployments → Approve**.
3. Done: https://pypi.org/project/gait-sdk/ shows the new version within a minute.

### 3.5 Create the GitHub Release
**Releases → Draft a new release**, choose the tag, and paste the changelog section. The tag is what installs; the Release is what people read.

### Yanking a bad release
If a release is broken, go to PyPI → your project → Manage → Releases → **Yank**. Pip then stops choosing it for `>=` / unpinned installs, while anyone pinned to that exact version can still install it, so you don't break them. Then publish a fixed patch version. You can't overwrite a version, and you shouldn't delete one unless it contains a secret.

### Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `invalid-publisher` / `403` at upload | The pending publisher fields don't match *exactly*: repo name, `publish.yml`, environment `pypi` |
| "File already exists" | That version was already published. Bump the version. |
| "Tag does not match pyproject version" | Fix the tag or the version. Delete the local tag with `git tag -d vX.Y.Z` (it isn't on PyPI yet). |
| Publish job never starts | It's waiting for your approval on the `pypi` environment |
| README looks broken on PyPI | Run `twine check --strict` locally; relative links should be full GitHub URLs |

---

## Part 4: Consuming safely

- **Pin exact versions:** `gait-sdk[django]==0.5.0`, never `>=` in an application's requirements.
- **Optional, stronger:** hash-pinning. Generate a lock with hashes (`pip-compile --generate-hashes`, or `uv pip compile --generate-hashes`) and install with `pip install --require-hashes -r requirements.txt`. Pip then refuses anything whose bytes differ from what you reviewed.
- **Watch for fixes:** `pip list --outdated` and `pip-audit` in CI; Dependabot does both automatically.
- **Read the changelog** before bumping. Security fixes are listed in `docs/SECURITY.md`.

### Before PyPI (history)
Until 0.5.0 this package was installed straight from GitHub (`auth_integration @ git+https://github.com/…@<commit sha>`). That works and is immutable when pinned by SHA, but it needs GitHub credentials on every build machine (the repo is private) and is invisible to upgrade and vulnerability tooling. That's why it moved to PyPI.
