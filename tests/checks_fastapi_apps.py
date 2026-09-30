"""FastAPI apps for the fastapi-pack tests (importable as --app tests.checks_fastapi_apps:<name>).

`SENTINEL` records any startup, shutdown or lifespan code that runs, and any
request the app serves. The pack must leave it empty.
"""

import contextlib
import warnings

from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

SENTINEL: list = []


@contextlib.asynccontextmanager
async def lifespan(app):
    SENTINEL.append("lifespan-start")  # would connect to the database here
    yield
    SENTINEL.append("lifespan-stop")


def _record(event):
    def handler():
        SENTINEL.append(event)

    return handler


# A hardened app: every check passes in production.
secure = FastAPI(debug=False, docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
secure.add_middleware(HTTPSRedirectMiddleware)
secure.add_middleware(TrustedHostMiddleware, allowed_hosts=["api.example.com"])
secure.add_middleware(CORSMiddleware, allow_origins=["https://app.example.com"], allow_credentials=True)


@secure.get("/")
def root():
    SENTINEL.append("request")
    return {"ok": True}


# FastAPI's defaults: debug off, docs on, no middleware.
default = FastAPI()

# Startup/shutdown handlers (the older API) instead of lifespan.
with warnings.catch_warnings():
    warnings.simplefilter("ignore", DeprecationWarning)
    with_handlers = FastAPI(on_startup=[_record("startup")], on_shutdown=[_record("shutdown")])

not_an_app = {"debug": True}
