# Examples: try gait-sdk in five minutes

Two tiny apps (FastAPI and Django) protected by gait-sdk, plus `dev_issuer.py`, a **local stand-in for Gait**, so you can try everything without a Gait account.

```
dev_issuer.py  ──(public keys)──►  your example app (gait-sdk inside)  ◄──(Bearer token)──  curl
   │                                                                                           ▲
   └──────────────────────────── `python dev_issuer.py token alice` ──────────────────────────┘
```

`dev_issuer.py` does what Gait does: it signs RS256 access tokens with a private key, and publishes the matching **public** key at `/.well-known/jwks.json`. The apps verify tokens with that public key. **Never use it in production.** It exists so the examples need nothing but your laptop.

## FastAPI

```bash
cd examples
pip install "gait-sdk[fastapi]" uvicorn

# terminal 1: the stand-in for Gait
python dev_issuer.py serve

# terminal 2: the app
export GAIT_TOKEN_VERIFIER=jwks
export GAIT_JWKS_URL=http://localhost:9000/.well-known/jwks.json
export GAIT_ISSUER=http://localhost:9000
export GAIT_AUDIENCE=urn:gait:example
uvicorn fastapi_app:app --port 8001

# terminal 3: call it
curl -H "Authorization: Bearer $(python dev_issuer.py token alice)" http://localhost:8001/me
```

**PowerShell:** set variables with `$env:GAIT_TOKEN_VERIFIER = "jwks"` (and so on), and use `$t = python dev_issuer.py token alice; curl.exe -H "Authorization: Bearer $t" http://localhost:8001/me`.

## Django REST Framework

```bash
cd examples
pip install "gait-sdk[django]"
python dev_issuer.py serve                  # terminal 1 (skip if already running)
python django_app.py runserver 8002         # terminal 2: settings are inside the file
curl -H "Authorization: Bearer $(python dev_issuer.py token alice)" http://localhost:8002/me
```

## What to try

| Request | Expected | What it shows |
|---|---|---|
| `GET /me` with alice's token | `200` + her identity + `"your_app_role": "editor"` | gait-sdk proves **who**; your app adds **what they may do** |
| `GET /me` with no token | `401` | Unauthenticated requests are rejected, with a real 401 |
| `GET /me` with `Bearer x.y.z` | `401` | Garbage or forged tokens never pass |
| `POST /articles` as alice | `200` | She's an editor in *your app's* table |
| `POST /articles` as bob (`token bob`) | `403` | gait-sdk verified Bob fine; **your app** said no. That's the boundary. |
| Stop `dev_issuer.py`, then call `/me` again | still `200` | Keys are cached: normal requests don't need the issuer to be up |

Both apps were run exactly as written here against `gait-sdk` installed from PyPI before each release.
