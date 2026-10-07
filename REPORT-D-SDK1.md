# D-SDK1 report: gait-sdk README and CHANGELOG

Docs agent, 2026-09-28. Branch `docs/reference` @ `ad70856`, pushed by name, not merged. Worktree `D:\wt\docs-sdk1` from
GitHub `origin/main` @ `0a7b4ac`, which is the same code as `v0.5.1`: nothing has been merged since that tag. The local
checkout wasn't touched (its uncommitted `README.md` / `client.py` edits are still there).

**Docs only:** 3 files, +178 / −44. No code, version or tag changes.

## README

- **Both jobs up front.**
  - Report security checks, with a new quick start whose env vars and code match the website's `snippets.js` exactly.
  - Verify users, marked *early access*.
- **Introspection first.**
  - The Django and FastAPI user quick starts now need only `GAIT_AUTH_URL = "https://api.gaitobservatory.com/api"`.
  - A new **"Choosing a verifier"** section says `jwks` needs Gait's key set to list at least one key, and to check that
    before switching. It's worded to stay true once production publishes keys.
  - The configuration table no longer calls jwks "recommended" and introspection "legacy".
  - Source: the default is `VERIFIER_INTROSPECTION` (`gait_sdk/verification.py:59, 520`), which needs only
    `GAIT_AUTH_URL` (`:526-527`).
- **Line 31 (availability):** now reads "reporting security checks is self-service (Quickstart); verifying your own
  product's users is in early access (request it)", and keeps the local `examples/` path. No Lumen.
- **Line 50 (pin):** now `gait-sdk==0.5.1`, phrased as an example.
- **What is Gait?** Removed "a security observatory with automated investigation" (operator surface). Added the
  workspace, applications and findings, with links to How it works and People and applications. "Publishing the public
  keys" is out, since the key set is empty today. "Log out everywhere" was checked against Gait
  (`user/urls.py:31`, `logout-all/`).
- **Compatibility table:** Python 3.10+ (CI matrix 3.10/3.11/3.12); Django ≥4.2 with DRF ≥3.14; FastAPI ≥0.100 with
  Starlette ≥0.27; httpx ≥0.25; python-decouple ≥3.6. All from `pyproject.toml` and `.github/workflows/python-tests.yml`.
- **Reference of the public API:** extracted from the source with `ast` (signatures, fields, `status_code`s, `Raises`
  docstrings, and actual `raise` statements):
  - `send_security_signal` (params, `KNOWN_RESULTS`, return, raises);
  - DRF `ExternalJWTAuthentication`, `ClaimsUser`, `require_live_session`;
  - FastAPI `verify_token`, `require_live_session`, `validate_configuration`, `get_current_user`;
  - `VerifiedIdentity` (introspection leaves `session_id`, `token_id` and `issuer` as `None`), `get_token_verifier`,
    `set_token_verifier`, `check_session_live` / `acheck_session_live`;
  - `verify_application` and `ApplicationPrincipal`;
  - `SecurityContext`;
  - the exception table (401 / 401 / 400 / 503 / config);
  - the deprecated role helpers.
  - The "DRF `APIException`" wording is qualified: without DRF, they fall back to plain exceptions
    (`gait_sdk/exceptions.py:15-22`).
- **Security, in one screen:** each guarantee is tied to its mode. RS256 strictness is jwks-only. "Gait unreachable →
  503" becomes "if Gait is needed and can't be reached", because cached keys keep working in jwks mode. For revocation,
  introspection asks every request, while jwks lags up to 15 minutes.
- **Links to the website:** Quickstart, Getting started, Connecting your software, How it works, People and
  applications, `/early-access`, and `/docs/gait-sdk`.
  - `/docs/gait-sdk` only exists once AuthFlow `docs/for-developers` merges, so merge that first, or at least before any
    PyPI release.

## CHANGELOG (`docs/CHANGELOG.md`, same path, so `GAIT_SDK.md`'s link is still right)

- **Unreleased:** a "documentation only" entry for this change.
- **0.4.0:** the four "Not yet tagged/released" notes are gone (`v0.4.0` is tagged at `69d83c8`). Added a line saying
  module paths use the old name, `auth_integration`.
- **Compare links** for every tag, v0.3.9 to v0.5.1 and Unreleased.
- **Checked against git:** the tag dates match the entries. 0.3.9 and 0.3.10 are dated 2026-01-05 in the file and were
  committed on 01-04 at 22:26 and 22:30 −0500, which is 01-05 in UTC, so the dates are left as they are. Nothing has
  merged since `v0.5.1`.
- **Dead pointer fixed:** 0.3.12 pointed to a README "Correctness guarantee" section that no longer exists. It now
  points to `docs/SECURITY.md` → Audit log, which records that fix. The same dead pointer in
  `gait_sdk/django/docs/authentication.md:16` is fixed too.

## Verification

- Every Python block in the README parses (`ast`). The signature block ends in `: ...` so it's valid too.
- Rendered on GitHub (branch view): code blocks, tables, and the `#choosing-a-verifier` / `#upgrading-from-auth_integration`
  anchors all render and resolve.
- The README contains no Lumen, no company, and no operator surfaces ("observatory" only as the domain).
- SDK tests weren't run: no code changed.

## Left alone, flagged

- **CHANGELOG history names Lumen** (0.5.0 "Flow-Diagram.md … belongs in Lumen"; 0.4.0 "Lumen callers", "Lumen's role
  vocabulary", "no Lumen-domain fields"). These are accurate history, so I kept them. Your call if the public repo
  shouldn't name it.
- A test comment still points to the dead README section (`tests/test_django_authentication.py:190`). It's in a test
  file, so it isn't mine to edit under "no code changes".
- **Other SDK docs still lead with jwks:**
  - `docs/SECURITY.md:45` puts `GAIT_TOKEN_VERIFIER=jwks` in the **hardening checklist**, which would break against
    production today.
  - `docs/INTEGRATION_GUIDE.md:81` is the cut-over runbook, where jwks is expected.
  - `examples/` uses jwks against the local dev issuer, which does publish keys, so that's fine.

  The `SECURITY.md` item is worth a follow-up ("once Gait publishes keys").

## What a release would involve (Anthony's decision)

PyPI shows the README from the last *release*. The new one reaches PyPI only through a new version. Per
`docs/PUBLISHING.md` Part 3:

1. Merge `docs/reference` through a PR with green Tests.
2. Bump `version` in `pyproject.toml` (a docs release would be `0.5.2`), turn `[Unreleased]` into `[0.5.2] - <date>`, and
   update the pin example in the README to `0.5.2`, all through a `chore(release): 0.5.2` PR.
3. `git tag -a v0.5.2 -m "gait-sdk 0.5.2"`, then `git push origin v0.5.2`. The tag must equal the pyproject version.
4. Approve the `pypi` environment in Actions (the manual gate). Trusted Publishing uploads it; no token is involved.
5. Draft the GitHub Release from the changelog section.

The website pins `SDK_VERSION = "0.5.1"` in `snippets.js`. A 0.5.2 docs release wouldn't need the site to change, but
bumping `SDK_VERSION` afterwards keeps the "pin exact" advice current.

## Follow-up (planner, same day), commit on `docs/reference`

- (a) The CHANGELOG's historical Lumen mentions are kept (the planner's call: accurate history, and Anthony's own app).
- (b) `tests/test_django_authentication.py:190`: the comment's dead README pointer now points to `docs/SECURITY.md`,
  Audit log: 0.3.12. **This is a comment inside a docstring only**, allowed per the planner. No test code changed.
- (c) `docs/SECURITY.md`: `GAIT_TOKEN_VERIFIER=jwks` is out of the hardening checklist and in a note below it: switch
  once Gait publishes signing keys, after checking that `/.well-known/jwks.json` lists at least one key; until then
  introspection is the mode that works. **Addition, flagged:** the checklist item it replaced is now "`GAIT_AUTH_URL` is
  `https` (plain `http` only for `localhost`)", which the SDK already enforces at startup
  (`gait_sdk/verification.py:516-518`). That keeps the checklist's transport check without requiring jwks.
- The CHANGELOG's Unreleased entry mentions the security-guide change.
