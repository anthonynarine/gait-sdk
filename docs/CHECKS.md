# Built-in checks

gait-sdk 0.6.0 (unreleased) ships built-in check packs. A pack reads your application's own configuration, decides an outcome for each check, and reports each result to Gait as its own security signal. There are 27 checks in three packs, each at v1.0.0:

| Pack | Checks | Reads |
|---|---|---|
| `django` | 21 | Your Django settings |
| `fastapi` | 5 | Your FastAPI app object (imported, never started) |
| `deps` | 1 | Known vulnerabilities in the installed Python packages, via pip-audit or osv-scanner |

- [Running the checks](#running-the-checks)
- [What is sent (and what never is)](#what-is-sent-and-what-never-is)
- [Outcomes and results](#outcomes-and-results)
- [The Django pack](#the-django-pack)
- [Django's own deployment checks](#djangos-own-deployment-checks)
- [The FastAPI pack](#the-fastapi-pack)
- [The dependencies pack](#the-dependencies-pack)
- [How results are delivered](#how-results-are-delivered)
- [CI and scheduling](#ci-and-scheduling)
- [Exit codes](#exit-codes)

## Running the checks

Inside a Django project (add `"gait_sdk"` to `INSTALLED_APPS`). This runs the `django` pack. Dependency checks are opt-in: add `--pack deps` in CI to include them (they send your package names and versions to PyPI/OSV and can take up to 2 minutes):

```bash
python manage.py gait_check --dry-run
python manage.py gait_check
```

Without `manage.py` (the `gait-check` command is installed with the package; it runs the `django` pack unless you pick packs):

```bash
gait-check --pack django --settings mysite.settings --dry-run
gait-check --pack fastapi --app mypackage.main:app --dry-run
gait-check --pack deps --dry-run
```

Sending needs the same two settings as any other signal: `GAIT_AUTH_URL` and `GAIT_APPLICATION_CREDENTIAL` (the application's connection key). `--dry-run` and `--no-send` need neither.

| Flag | Meaning |
|---|---|
| `--pack PACK` | Pack to run (repeatable): `django`, `fastapi`, `deps`. Default: `django`, for both `gait-check` and `manage.py gait_check` (where `fastapi` doesn't apply). `deps` runs only when you pass `--pack deps`. Anything else is a usage error. |
| `--settings MODULE` | `gait-check` only: sets `DJANGO_SETTINGS_MODULE`, then runs `django.setup()`. (`manage.py` has its own `--settings`.) |
| `--app MODULE:ATTR` | `gait-check` only, required for `--pack fastapi`: the app object, e.g. `mypackage.main:app`. |
| `--strict` | Stricter rules where a check has them. Today: FastAPI API docs exposed in production are FAIL instead of WARNING. |
| `--deps-tool {pip-audit,osv-scanner}` | Scanner for the `deps` pack. Default `pip-audit`. |
| `--no-batch` | Send one request per check even when Gait accepts batches. |
| `--dry-run` | Run the checks and print the exact signals that would be sent. Sends nothing, needs no key. |
| `--no-send` | Run the checks and exit with the usual codes, without contacting Gait. For gating CI. |
| `--environment X` | When sending: an **assertion only**. The environment always comes from the key's application; a mismatch exits 3 and sends nothing. With `--dry-run`/`--no-send`: the environment to evaluate (default `production`). One of `local`, `test`, `ci`, `staging`, `production`. |
| `--json` | Print a JSON report: `{run_id, application, environment, results: [{id, outcome, result, facts, sent, error}], unmapped_django_ids}`. With `--dry-run` it also has `dry_run: true` and `requests` (the bodies). |
| `--fail-on {fail,warning,never}` | Exit 1 when a result is at or above this level. Default `fail`. |
| `--fail-on-unknown` | Also exit 1 on `unknown` or `error` outcomes. |
| `--run-id ID` | The `source_reference` of every signal in the run: letters, digits and `: . _ -` only, at most 128 characters (Gait rejects anything else). Default `run:<uuid4>`. In CI use something stable per job, like `ci:<sha>:<job>`, so a retried job doesn't record the run twice. |
| `--only ID` / `--skip ID` | Run only, or skip, these check ids (repeatable). Skipped checks send nothing. |

Each check is one signal: `signal_type` is the check id, `result` is the mapped result, `source_reference` is the run id. How they travel (batches, retries) is in [How results are delivered](#how-results-are-delivered).

## What is sent (and what never is)

Each signal carries one fixed-shape payload:

```json
{
  "signal_type": "CHK.DJANGO.HSTS",
  "result": "WARNING",
  "source_reference": "ci:3611eb6:build-1842",
  "payload": {
    "v": 1, "pack": "django", "pack_version": "1.0.0", "sdk_version": "0.6.0",
    "outcome": "weak",
    "facts": {"hsts_seconds": 86400, "include_subdomains": false, "preload": false,
              "django_ids": ["security.W005", "security.W021"]}
  }
}
```

The design keeps patient data and secrets out by construction:

- **Only typed configuration facts.** Every fact is a boolean, a bounded integer, a value from a fixed list, a pattern-checked string list (Django check ids, which must match `^[a-z_]{1,20}\.[EW][0-9]{3}$`), or, for the `deps` check only, at most 10 records whose fields are pattern-checked package names, versions and advisory ids. There is no free-text field anywhere.
- **Never a setting value.** Checks read only the named settings, plus `INSTALLED_APPS` and the URL resolver where a check needs them. They report facts *about* a setting ("is HSTS at least a year?"), never the value itself. The SECRET_KEY and any fallback keys are measured (length, distinct characters, known prefix, known placeholder) and never copied, logged or printed.
- **Never request data.** Checks don't look at requests, users, sessions or database rows. The FastAPI pack never starts your app, so it can't reach your database at all.
- **Never your dependency list.** The `deps` check sends counts and at most 10 vulnerable packages. Scanner output text is never sent or printed.
- **A fixed registry.** Check ids, fact names, types and limits come from `gait_sdk/checks/checks_v1.json`, which Gait's server vendors byte for byte. Fact names avoid words Gait's audit log redacts (`password`, `token`, `secret`, `cookie`, `patient`, and others); the registry refuses to load if one appears.
- **Checked twice.** The SDK validates every payload against the registry before sending and never sends one that fails (it's shown as a local error). Gait's server enforces the same schema and rejects anything else, which is the real guarantee: anyone holding a connection key can call the API directly.
- **You can see it first.** `--dry-run` prints exactly what would leave the process.

These checks report configuration, not behavior, and Gait labels them as reported by your application, not verified by Gait.

## Outcomes and results

| Outcome | Result sent | Meaning |
|---|---|---|
| `ok` | PASS | The check passed. |
| `fail` | FAIL | The check failed. Gait opens a finding for this check and application. |
| `weak` | WARNING | Works, but should be stronger. |
| `not_applicable` | INFORMATIONAL | Doesn't apply here (feature not installed, or an environment-gated check in `local`/`test`). Never counts as a pass. |
| `unknown` | INFORMATIONAL | Couldn't be determined (for example the dependency scanner is missing or can't reach its service). Never counts as a pass. |
| `error` | INFORMATIONAL | The check raised an exception. Its facts are empty; the other checks still run. |

**Environment gating.** Checks marked *gated* below report `not_applicable` with no facts when the environment is `local` or `test`, because a development machine is expected to run with DEBUG on and without HTTPS.

## The Django pack

Severity is what a failure means for the finding Gait opens.

| Check id | Severity | Gated | What it checks |
|---|---|---|---|
| `CHK.DJANGO.DEBUG_OFF` | High | yes | DEBUG is off |
| `CHK.DJANGO.ALLOWED_HOSTS` | Medium | yes | ALLOWED_HOSTS is an explicit allow-list |
| `CHK.DJANGO.SIGNING_KEY_STRENGTH` | High | no | The Django signing key is strong |
| `CHK.DJANGO.SIGNING_KEY_FALLBACKS` | Medium | no | Old signing keys are strong and few |
| `CHK.DJANGO.DB_CREDENTIALS_SET` | High | yes | Network databases require credentials |
| `CHK.DJANGO.SECURITY_MIDDLEWARE` | High | no | SecurityMiddleware is enabled |
| `CHK.DJANGO.CSRF_MIDDLEWARE` | High | no | CSRF protection is enabled |
| `CHK.DJANGO.CLICKJACKING` | Medium | no | Pages can't be framed by other sites |
| `CHK.DJANGO.SSL_REDIRECT` | High | yes | HTTP is redirected to HTTPS |
| `CHK.DJANGO.HSTS` | Medium | yes | HSTS is set for at least a year |
| `CHK.DJANGO.NOSNIFF` | Low | no | Browsers don't guess content types |
| `CHK.DJANGO.SESSION_COOKIE_FLAGS` | High | yes | Session cookies are Secure and HttpOnly |
| `CHK.DJANGO.CSRF_COOKIE_SECURE` | Medium | yes | The CSRF cookie is Secure |
| `CHK.DJANGO.REFERRER_POLICY` | Low | no | A referrer policy is set |
| `CHK.DJANGO.COOP` | Low | no | A cross-origin opener policy is set |
| `CHK.DJANGO.CORS_NOT_WILDCARD` | High | no | CORS isn't open to every origin |
| `CHK.DJANGO.ADMIN_URL` | Low | no | The Django admin isn't at `/admin/` |
| `CHK.DJANGO.DRF_DEFAULT_DENY` | High | no | Django REST framework denies by default |
| `CHK.DJANGO.PASSWORD_POLICY` | Medium | no | Password rules are strong |
| `CHK.DJANGO.DB_TLS` | High | yes | Database connections use TLS |
| `CHK.DJANGO.EMAIL_TLS` | Medium | yes | Outgoing email uses TLS |

### CHK.DJANGO.DEBUG_OFF
- **Facts:** `debug`.
- **PASS** when `DEBUG` is False. **FAIL** when True.
- **Fix:** set `DEBUG = False` in every deployed environment. Read it from the environment and default to False.

### CHK.DJANGO.ALLOWED_HOSTS
- **Facts:** `host_count`, `wildcard`.
- **PASS** when `ALLOWED_HOSTS` is non-empty and has no `"*"`. **FAIL** when it is empty or contains `"*"`.
- **Fix:** list your real host names; never use `"*"`.

### CHK.DJANGO.SIGNING_KEY_STRENGTH
- **Facts:** `length`, `unique_chars`, `insecure_prefix` (starts with `django-insecure-`), `placeholder` (the whole value is a known placeholder such as `changeme`, `secret`, `dev`, `test`, `insecure`, `replace-me`). The key itself is never sent.
- **PASS** when the key is at least 50 characters, has at least 5 distinct characters, has no `django-insecure-` prefix, and isn't a placeholder. **FAIL** otherwise.
- **Fix:** generate a random key of at least 50 characters (`django.core.management.utils.get_random_secret_key()`), keep it out of source control, and load it from the environment.

### CHK.DJANGO.SIGNING_KEY_FALLBACKS
- **Facts:** `fallback_count`, `weak_fallbacks` (how many `SECRET_KEY_FALLBACKS` fail the strength rule above).
- **PASS** when no fallback is weak and there are at most 2. **WARNING** when none is weak but there are more than 2. **FAIL** when any is weak.
- **Fix:** keep at most two fallbacks during a rotation, make each one strong, and remove them once sessions have rolled over.

### CHK.DJANGO.DB_CREDENTIALS_SET
- **Facts:** `network_databases` (DATABASES entries that aren't SQLite and whose HOST isn't empty, `localhost`, `127.0.0.1`, `::1` or a socket path starting with `/`), `missing_credentials` (those with an empty USER or PASSWORD).
- **PASS** when none is missing credentials. **FAIL** otherwise. **Not applicable** with no network databases.
- **Fix:** give every network database connection a user and a strong password loaded from the environment.

### CHK.DJANGO.SECURITY_MIDDLEWARE
- **Facts:** `present`.
- **PASS** when `django.middleware.security.SecurityMiddleware` is in `MIDDLEWARE`. **FAIL** otherwise. Without it, the HSTS, nosniff, referrer-policy, COOP and SSL-redirect settings have no effect.
- **Fix:** add it near the top of `MIDDLEWARE`.

### CHK.DJANGO.CSRF_MIDDLEWARE
- **Facts:** `present`.
- **PASS** when `django.middleware.csrf.CsrfViewMiddleware` is in `MIDDLEWARE`. **FAIL** otherwise.
- **Fix:** keep it in `MIDDLEWARE`.

### CHK.DJANGO.CLICKJACKING
- **Facts:** `middleware_present` (XFrameOptionsMiddleware), `frame_option` (`DENY`, `SAMEORIGIN`, `unset` or `other`; Django's default is `DENY`).
- **PASS** with the middleware and `DENY`. **WARNING** with the middleware and `SAMEORIGIN` (or another value). **FAIL** without the middleware.
- **Fix:** enable `django.middleware.clickjacking.XFrameOptionsMiddleware` and set `X_FRAME_OPTIONS = "DENY"`.

### CHK.DJANGO.SSL_REDIRECT
- **Facts:** `ssl_redirect`, `proxy_header_set` (`SECURE_PROXY_SSL_HEADER` is set).
- **PASS** when `SECURE_SSL_REDIRECT` is True. **FAIL** otherwise.
- **Fix:** set `SECURE_SSL_REDIRECT = True`, and `SECURE_PROXY_SSL_HEADER` if you run behind a TLS-terminating proxy (Heroku, a load balancer).

### CHK.DJANGO.HSTS
- **Facts:** `hsts_seconds`, `include_subdomains`, `preload`.
- **PASS** when `SECURE_HSTS_SECONDS` is at least 31536000 (one year). **WARNING** when it is above 0 but shorter. **FAIL** when it is 0.
- **Fix:** once HTTPS works everywhere, set `SECURE_HSTS_SECONDS = 31536000`. Add `SECURE_HSTS_INCLUDE_SUBDOMAINS` only when every subdomain serves HTTPS.

### CHK.DJANGO.NOSNIFF
- **Facts:** `nosniff`.
- **PASS** when `SECURE_CONTENT_TYPE_NOSNIFF` is True (Django's default). **FAIL** otherwise.
- **Fix:** set `SECURE_CONTENT_TYPE_NOSNIFF = True`.

### CHK.DJANGO.SESSION_COOKIE_FLAGS
- **Facts:** `session_secure`, `session_httponly`.
- **PASS** when both `SESSION_COOKIE_SECURE` and `SESSION_COOKIE_HTTPONLY` are True. **FAIL** otherwise.
- **Fix:** set `SESSION_COOKIE_SECURE = True` and `SESSION_COOKIE_HTTPONLY = True`.

### CHK.DJANGO.CSRF_COOKIE_SECURE
- **Facts:** `csrf_secure`.
- **PASS** when `CSRF_COOKIE_SECURE` is True. **FAIL** otherwise.
- **Fix:** set `CSRF_COOKIE_SECURE = True`.

### CHK.DJANGO.REFERRER_POLICY
- **Facts:** `policy` (the first value of `SECURE_REFERRER_POLICY`; `unset`, or `other` for an unknown value).
- **PASS** for `no-referrer`, `same-origin`, `strict-origin`, `strict-origin-when-cross-origin`, `origin`, `origin-when-cross-origin`. **WARNING** when unset, `unsafe-url`, `no-referrer-when-downgrade` or unknown.
- **Fix:** set `SECURE_REFERRER_POLICY = "same-origin"` (or `"strict-origin-when-cross-origin"`).

### CHK.DJANGO.COOP
- **Facts:** `policy` (`SECURE_CROSS_ORIGIN_OPENER_POLICY`).
- **PASS** for `same-origin` and `same-origin-allow-popups`. **WARNING** for `unsafe-none`, unset, or anything else.
- **Fix:** set `SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"`.

### CHK.DJANGO.CORS_NOT_WILDCARD
- **Facts:** `cors_installed` (`corsheaders` in `INSTALLED_APPS`), `allow_all` (`CORS_ALLOW_ALL_ORIGINS` or the older `CORS_ORIGIN_ALLOW_ALL`), `catch_all_regex` (a `CORS_ALLOWED_ORIGIN_REGEXES` entry of `.*`, `^.*$`, `.+`, `^.+$` or `^https?://.*$`), `allow_credentials`.
- **FAIL** when allow-all or a catch-all regex is combined with credentials. **WARNING** for allow-all or a catch-all without credentials. **PASS** otherwise. **Not applicable** without django-cors-headers.
- **Fix:** list exact origins in `CORS_ALLOWED_ORIGINS`; never combine allow-all or a catch-all regex with credentials.

### CHK.DJANGO.ADMIN_URL
- **Facts:** `admin_installed`, `default_path` (`/admin/` resolves to the Django admin).
- **PASS** when the admin is mounted elsewhere. **WARNING** when it's at `/admin/`. **Not applicable** without `django.contrib.admin`.
- **Fix:** mount the admin at a less guessable path. This only reduces automated noise; the admin still needs strong sign-in.

### CHK.DJANGO.DRF_DEFAULT_DENY
- **Facts:** `drf_installed`, `classes_set` (`DEFAULT_PERMISSION_CLASSES` is in `REST_FRAMEWORK`), `default_allow_any` (not set, empty, or includes `AllowAny`; DRF's own default is `AllowAny`).
- **PASS** when the default is not allow-any. **FAIL** otherwise. **Not applicable** without `rest_framework`.
- **Fix:** set `REST_FRAMEWORK["DEFAULT_PERMISSION_CLASSES"]` to `IsAuthenticated` (or stricter) and open endpoints one at a time.

### CHK.DJANGO.PASSWORD_POLICY
- **Facts:** `validator_count`, `min_length` (from `MinimumLengthValidator`'s `min_length`, 8 when the validator has no option, 0 without the validator), `common_list_check`, `numeric_check`, `similarity_check`.
- **PASS** with a minimum of at least 12 and the common-password check. **WARNING** with a minimum of 8 to 11 and the common-password check. **FAIL** otherwise.
- **Fix:** enable Django's validators with `MinimumLengthValidator` `min_length` of at least 12 and `CommonPasswordValidator`.

### CHK.DJANGO.DB_TLS
- **Facts:** `network_databases` (network PostgreSQL databases, same "network" rule as above), `tls_required` (those whose `OPTIONS["sslmode"]` is `require`, `verify-ca` or `verify-full`).
- **PASS** when all require TLS. **FAIL** otherwise. **Not applicable** with no network PostgreSQL databases.
- **Fix:** set `OPTIONS = {"sslmode": "require"}` (or `verify-full`) on every network PostgreSQL database. With `dj-database-url`, pass `ssl_require=True`.

### CHK.DJANGO.EMAIL_TLS
- **Facts:** `smtp_backend` (`EMAIL_BACKEND` is Django's SMTP backend, the default), `tls` (`EMAIL_USE_TLS` or `EMAIL_USE_SSL`).
- **PASS** with TLS. **FAIL** without. **Not applicable** with a non-SMTP backend.
- **Fix:** set `EMAIL_USE_TLS = True` (port 587) or `EMAIL_USE_SSL = True` (port 465).

## Django's own deployment checks

The pack also runs `django.core.checks.run_checks(include_deployment_checks=True, tags=["security"])` (what `manage.py check --deploy` reports) and attaches each returned id to the matching check as its `django_ids` fact. These are supporting facts only: the pack's own rule always decides the outcome. Only the id is kept, never the message text.

Mapping, from Django 4.2 through 5.2:

| Django id | Check |
|---|---|
| `security.W001` | SECURITY_MIDDLEWARE |
| `security.W002`, `security.W019` | CLICKJACKING |
| `security.W003` | CSRF_MIDDLEWARE |
| `security.W004`, `security.W005`, `security.W021` | HSTS |
| `security.W006` | NOSNIFF |
| `security.W008` | SSL_REDIRECT |
| `security.W009` | SIGNING_KEY_STRENGTH |
| `security.W010` - `security.W015` | SESSION_COOKIE_FLAGS |
| `security.W016` | CSRF_COOKIE_SECURE |
| `security.W018` | DEBUG_OFF |
| `security.W020` | ALLOWED_HOSTS |
| `security.W022`, `security.E023` | REFERRER_POLICY |
| `security.E024` | COOP |
| `security.W025` | SIGNING_KEY_FALLBACKS |

`security.W007` and `security.W017` were retired before Django 4.2. Any other id (`security.E101`/`E102` for a broken `CSRF_FAILURE_VIEW`, or a third-party package's security check) is shown locally as "unmapped" in the table and the JSON report, and is never sent.

## The FastAPI pack

```bash
gait-check --pack fastapi --app mypackage.main:app
```

**The app is never started.** The pack imports the module and reads attributes of the app object: `debug`, `docs_url`, `redoc_url`, `openapi_url` and `user_middleware` (the middleware you added and the arguments you passed). It never runs the lifespan or startup/shutdown handlers, never builds a test client, never sends a request, never calls the app and never builds its middleware stack, so it can't connect to your database or any other service. (Importing the module runs its top-level code, as any import does. Keep connections out of import time.) A missing module or attribute, or an object that isn't a FastAPI/Starlette app, is a usage error (exit 3).

Facts are booleans only: no URL, origin or host name is sent.

| Check id | Severity | Gated | What it checks |
|---|---|---|---|
| `CHK.FASTAPI.DEBUG_OFF` | High | yes | Debug mode is off |
| `CHK.FASTAPI.DOCS_HIDDEN` | Low | yes (production only) | API docs aren't public in production |
| `CHK.FASTAPI.CORS_NOT_WILDCARD` | High | no | CORS isn't open to every origin |
| `CHK.FASTAPI.TRUSTED_HOST` | Medium | yes | Requests are limited to your own host names |
| `CHK.FASTAPI.HTTPS_REDIRECT` | Medium | yes | HTTP is redirected to HTTPS |

### CHK.FASTAPI.DEBUG_OFF
- **Facts:** `debug`.
- **PASS** when `app.debug` is False. **FAIL** when True.
- **Fix:** create the app with `FastAPI(debug=False)` in every deployed environment; read the flag from the environment, default False.

### CHK.FASTAPI.DOCS_HIDDEN
- **Facts:** `docs_url_set`, `redoc_url_set`, `openapi_url_set`.
- Evaluated only when the environment is `production`; **not applicable** everywhere else.
- **PASS** when all three are None. **WARNING** when any is set, or **FAIL** with `--strict`.
- **Fix:** pass `docs_url=None, redoc_url=None, openapi_url=None` in production, or put the docs behind authentication.

### CHK.FASTAPI.CORS_NOT_WILDCARD
- **Facts:** `cors_installed` (CORSMiddleware added), `allow_all` (`"*"` in `allow_origins`), `catch_all_regex` (`allow_origin_regex` is `.*`, `^.*$`, `.+`, `^.+$` or `^https?://.*$`), `allow_credentials`.
- **FAIL** when `*` or a catch-all regex is combined with credentials. **WARNING** for either without credentials. **PASS** otherwise. **Not applicable** without CORSMiddleware.
- **Fix:** list exact origins in `CORSMiddleware(allow_origins=[...])`; don't combine `*` or a catch-all regex with `allow_credentials=True`.

### CHK.FASTAPI.TRUSTED_HOST
- **Facts:** `trusted_host_installed`, `wildcard` (`"*"` in `allowed_hosts`, which is also the middleware's default).
- **PASS** with TrustedHostMiddleware and no `*`. **WARNING** otherwise.
- **Fix:** add `TrustedHostMiddleware(allowed_hosts=[...])` with your real host names.

### CHK.FASTAPI.HTTPS_REDIRECT
- **Facts:** `https_redirect_installed`.
- **PASS** with HTTPSRedirectMiddleware. **WARNING** without: your proxy or load balancer may redirect instead, which the SDK can't see.
- **Fix:** add `HTTPSRedirectMiddleware`, or confirm your proxy redirects HTTP to HTTPS.

## The dependencies pack

```bash
pip install 'gait-sdk[deps]'      # installs pip-audit
gait-check --pack deps
gait-check --pack deps --deps-tool osv-scanner
```

**pip-audit / osv-scanner send your package names and versions to PyPI / OSV to look them up; Gait receives only the vulnerable packages, versions and advisory ids.** That lookup is between you and PyPI or OSV; gait-sdk keeps no vulnerability database of its own. The full dependency list is never sent to Gait, and nothing the scanner prints (stdout or stderr) is ever put into facts or the report.

Exactly what runs (120-second timeout):

| `--deps-tool` | Command |
|---|---|
| `pip-audit` (default) | `<python> -m pip_audit -f json --progress-spinner off`, auditing the running Python environment |
| `osv-scanner` | `osv-scanner --format json --lockfile requirements.txt:<tempfile>`, where the temporary file lists the running environment's installed distributions as `name==version` and is deleted afterwards. `osv-scanner` must be on PATH. |

### CHK.DEPS.KNOWN_VULNS
- **Severity:** High. Not gated. Gait treats this evidence as stale after 2 days, so run it daily.
- **Facts:** `tool`, `vulnerable_count` (distinct vulnerable package versions), `unfixed_count` (those with no fixed version yet), `items` (at most 10 of them, fixable first: `package`, `version`, `advisory_id`, and `fixed_in`, the lowest fixed version, when there is one). The advisory id is a PYSEC, GHSA, CVE or OSV id; a vulnerability with no such id is counted but not listed.
- **PASS** with no vulnerable packages. **FAIL** when any vulnerable package has a fix. **WARNING** when every one of them is still unfixed.
- **Unknown, never PASS**, with facts `{tool, reason}` only:
  - `tool_missing`: pip-audit isn't installed, or osv-scanner isn't on PATH (`tool` is `none`);
  - `timeout`: the scan took longer than 120 seconds;
  - `network`: the scanner failed and its error output shows a connection, DNS, proxy, TLS or HTTP error, or rate limiting;
  - `unparseable`: the output wasn't the JSON expected, or the scanner failed without a recognisable network error.
- **Fix:** upgrade each listed package to its fixed version (`pip install -U <package>`) and redeploy; for advisories with no fix yet, check the advisory for a workaround.

## How results are delivered

- **Accepted checks first.** When sending, gait-sdk asks Gait once per run which check ids it accepts (`GET /security/tenant-signals/types/`). A check your Gait server doesn't know yet is skipped locally ("not sent: not supported by this Gait server") and doesn't fail the run. An older server without that endpoint gets every check.
- **Batches.** When Gait advertises a batch size, results go in chunks of at most that many per request (`POST /security/tenant-signals/batch/`). A batch is all or nothing: if Gait rejects it (400), nothing in it is recorded, the report names the item and field Gait pointed at, and the run exits 2. Without batch support, or with `--no-batch`, it's one request per check, and a rejected check doesn't stop the others.
- **Retries.** Only when Gait is unreachable or answers unexpectedly: up to three retries after 1, 2 and 4 seconds, with the same `source_reference`. Gait records an (application, check, run id) triple only once, so a retry can't double-count. If it still fails, the rest of the run isn't attempted. A rate limit (429) on a batch waits for Gait's Retry-After (at most 60 seconds) once and retries once. A rejected check (400) or key (401) is never retried; a rejected key stops the run.

## CI and scheduling

Run the checks where your real configuration lives: the deployed environment's settings, with its own connection key.

- **On every staging and production deploy**, as a release or post-deploy step:
  ```bash
  python manage.py gait_check --run-id "deploy:$GIT_SHA"
  ```
- **Daily in production** (Heroku Scheduler, cron or a Kubernetes CronJob), so drift and newly published advisories show up even without a deploy. Gait treats configuration evidence older than 7 days, and dependency evidence older than 2 days, as stale.
  ```bash
  python manage.py gait_check --run-id "daily:$(date -u +%F)"
  ```
- **In CI**, gate the build without contacting Gait, using the settings your deploy will use:
  ```bash
  python manage.py gait_check --no-send --environment production --fail-on fail
  ```
- **FastAPI services:** `gait-check --pack fastapi --app mypackage.main:app --pack deps --run-id "deploy:$GIT_SHA"`, with the same schedule.
- Use a **stable `--run-id` per job** (`ci:<sha>:<job>`). A retried job then re-sends the same source reference and Gait keeps the first result instead of recording the run twice.
- **Never give fork or pull-request builds a production connection key.** Use `--no-send` there.
- Review what leaves your system with `--dry-run` before you first send, and after upgrading gait-sdk.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Nothing at or above `--fail-on`. |
| 1 | At least one result at or above `--fail-on`. With `--fail-on-unknown`, also any `unknown` or `error` outcome. |
| 2 | Delivery failure: the key was rejected (401), Gait was unreachable after retries, Gait rejected at least one check or batch (400), Gait rate-limited the run twice (429), or a payload failed local validation. Takes precedence over 1. A check Gait doesn't support yet is not a failure. |
| 3 | Usage or configuration error (bad flag, unknown pack or check id, no settings module, `--pack fastapi` without a valid `--app`, no connection key when sending), or `--environment` doesn't match the key's application. Nothing is sent. |
