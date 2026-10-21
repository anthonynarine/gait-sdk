"""Candidate confidential BFF protocol. Responses do not replace JWT verification."""
from __future__ import annotations

import asyncio
import base64
from dataclasses import dataclass, field
from datetime import datetime
import json
import math
import re
from urllib.parse import urlsplit
from uuid import UUID

import httpx


class ConfidentialError(Exception):
    """Constant, secret-free upstream failure."""


class ConfidentialDenied(ConfidentialError):
    pass


class ConfidentialThrottled(ConfidentialError):
    pass


class ConfidentialUnavailable(ConfidentialError):
    pass


class ConfidentialProtocolError(ConfidentialError):
    pass


class AmbiguousRefresh(ConfidentialError):
    """Do not retry: rotation might already have consumed the supplied token."""


class StaleActivity(ConfidentialError):
    """Reconcile status; never replay the old interaction."""


def _uuid(value):
    if type(value) is not str:
        raise ValueError("Invalid confidential configuration.")
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError):
        raise ValueError("Invalid confidential configuration.") from None
    if str(parsed) != value:
        raise ValueError("Invalid confidential configuration.")
    return value


def _text(value, limit=16384):
    return type(value) is str and 0 < len(value) <= limit and all(32 < ord(c) < 127 for c in value)


@dataclass(frozen=True)
class ConfidentialConfig:
    api_base_url: str
    application_id: str
    audience: str
    credential: str = field(repr=False)

    def __post_init__(self):
        try:
            url = urlsplit(self.api_base_url)
            host = url.hostname or ""
            labels = host.split(".")
            valid = (url.scheme == "https" and url.netloc == host and url.path == "/api"
                     and not url.query and not url.fragment and len(labels) >= 2 and len(host) <= 253
                     and all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x) for x in labels)
                     and labels[-1] not in ("localhost", "local")
                     and not re.fullmatch(r"(?:[0-9]+|0x[0-9a-f]+)", labels[-1])
                     and self.api_base_url == "https://" + host + "/api")
            _uuid(self.application_id)
            prefix = "urn:gait:application:"
            if not self.audience.startswith(prefix):
                valid = False
            else:
                _uuid(self.audience[len(prefix):])
            # Current issued application credentials are 32-byte URL-safe values.
            valid = valid and type(self.credential) is str and bool(re.fullmatch(r"[A-Za-z0-9_-]{43}", self.credential))
        except (TypeError, AttributeError, ValueError):
            valid = False
        if not valid:
            raise ValueError("Invalid confidential configuration.")


class AsyncConfidentialClient:
    """No ambient credentials, proxies, redirects, retries or browser headers.

    `transport` is an explicit trusted test/infrastructure hook, not browser input.
    An external AsyncClient is deliberately unsupported. Each request gets a new
    cookie jar so upstream Set-Cookie cannot become ambient authentication.
    """
    def __init__(self, config: ConfidentialConfig, *, transport: httpx.AsyncBaseTransport | None = None,
                 timeout: float = 8.0):
        if type(config) is not ConfidentialConfig or type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 30:
            raise ValueError("Invalid confidential configuration.")
        if transport is not None and not isinstance(transport, httpx.AsyncBaseTransport):
            raise ValueError("Invalid confidential transport.")
        self._config, self._transport, self._timeout = config, transport, timeout

    def __repr__(self):
        return "AsyncConfidentialClient(application_id=" + repr(self._config.application_id) + ")"

    async def login(self, *, email: str, password: str):
        return await self._request("login", {"email": email, "password": password})

    async def complete_mfa(self, *, mfa_transaction: str, otp: str | None = None, recovery_code: str | None = None):
        if (otp is None) == (recovery_code is None):
            raise ValueError("Provide exactly one second-factor proof.")
        return await self._request("mfa", {"mfa_transaction": mfa_transaction,
                            **({"otp": otp} if otp is not None else {"recovery_code": recovery_code})})

    async def refresh(self, *, refresh_token: str):
        return await self._request("refresh", {"refresh_token": refresh_token})

    async def logout(self, *, refresh_token: str):
        return await self._request("logout", {"refresh_token": refresh_token})

    async def status(self, *, access_token: str):
        return await self._request("status", {"access_token": access_token})

    async def activity(self, *, access_token: str, generation: int):
        return await self._request("activity", {"access_token": access_token, "generation": generation})

    async def _request(self, operation, body):
        try:
            return await asyncio.wait_for(self._send(operation, body), timeout=self._timeout)
        except asyncio.TimeoutError:
            error = AmbiguousRefresh if operation == "refresh" else ConfidentialUnavailable
            raise error("Refresh outcome is unknown; sign in again." if operation == "refresh" else "Authentication service unavailable.") from None

    async def _send(self, operation, body):
        schemas = {"login": [{"email", "password"}], "mfa": [{"mfa_transaction", "otp"}, {"mfa_transaction", "recovery_code"}],
                   "refresh": [{"refresh_token"}], "logout": [{"refresh_token"}], "status": [{"access_token"}],
                   "activity": [{"access_token", "generation"}]}
        if operation not in schemas or type(body) is not dict or set(body) not in schemas[operation]:
            raise ValueError("Invalid confidential operation.")
        for key, value in body.items():
            if key == "generation":
                valid = type(value) is int and 0 <= value < 9223372036854775807
            else:
                # Passwords may contain Unicode/spaces; only bound size here.
                valid = type(value) is str and 0 < len(value) <= (16384 if key.endswith("_token") else 1024)
            if not valid:
                raise ValueError("Invalid confidential input.")
        endpoint = self._config.api_base_url + "/application-auth/" + self._config.application_id + "/" + operation + "/"
        try:
            async with httpx.AsyncClient(transport=(self._transport if self._transport is not None else
                    httpx.AsyncHTTPTransport(retries=0, verify=True, trust_env=False)), trust_env=False, verify=True,
                    follow_redirects=False, timeout=self._timeout) as client:
                async with client.stream("POST", endpoint, json=body, headers={
                        "Gait-Application-Credential": self._config.credential, "Accept": "application/json"}) as response:
                    if response.status_code in (401, 403):
                        raise ConfidentialDenied("Authentication denied.")
                    if response.status_code == 429:
                        raise ConfidentialThrottled("Authentication throttled.")
                    if response.status_code == 409 and operation == "activity":
                        raise StaleActivity("Activity generation is stale.")
                    if response.status_code >= 500:
                        raise ConfidentialUnavailable("Authentication service unavailable.")
                    if response.status_code != 200:
                        raise ConfidentialProtocolError("Unexpected authentication response.")
                    if response.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
                        raise ConfidentialProtocolError("Unexpected authentication response.")
                    content = bytearray()
                    async for chunk in response.aiter_bytes(chunk_size=16384):
                        content.extend(chunk)
                        if len(content) > 131072:
                            raise ConfidentialProtocolError("Unexpected authentication response.")
                    try:
                        data = json.loads(content)
                        self._validate(operation, data)
                    except (ValueError, TypeError, KeyError, OverflowError):
                        raise ConfidentialProtocolError("Unexpected authentication response.") from None
                    return data
        except (httpx.HTTPError, OSError):
            error = AmbiguousRefresh if operation == "refresh" else ConfidentialUnavailable
            raise error("Refresh outcome is unknown; sign in again." if operation == "refresh" else "Authentication service unavailable.") from None
        except (ConfidentialProtocolError, ConfidentialUnavailable) as exc:
            if operation == "refresh":
                raise AmbiguousRefresh("Refresh outcome is unknown; sign in again.") from None
            raise exc from None

    def _validate(self, operation, data):
        if type(data) is not dict:
            raise ValueError()
        if operation == "login":
            if set(data) != {"mfa_required", "mfa_transaction", "expires_in"} or data["mfa_required"] is not True or not _text(data["mfa_transaction"], 128) or type(data["expires_in"]) is not int or not 0 < data["expires_in"] <= 120:
                raise ValueError()
        elif operation in ("mfa", "refresh"):
            required = {"access_token", "refresh_token", "token_type"} | ({"sid", "aud"} if operation == "mfa" else set())
            if set(data) != required or data["token_type"] != "Bearer" or not _text(data["access_token"]) or not _text(data["refresh_token"]):
                raise ValueError()
            # Envelope consistency ONLY. No signature/issuer verification claim.
            parts = data["access_token"].split(".")
            if len(parts) != 3:
                raise ValueError()
            claims = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
            if type(claims) is not dict or claims.get("aud") != self._config.audience:
                raise ValueError()
            _uuid(claims.get("sid"))
            if operation == "mfa" and (data["aud"] != self._config.audience or data["sid"] != claims["sid"]):
                raise ValueError()
        elif operation == "logout":
            if data != {"revoked": True} or type(data["revoked"]) is not bool:
                raise ValueError()
        else:
            fields = {"sid", "aud", "policy_enabled", "server_time", "idle_expires_at", "overall_expires_at", "activity_generation"}
            if operation == "status":
                fields.add("assurance")
            if set(data) != fields or data["aud"] != self._config.audience or data["policy_enabled"] is not True:
                raise ValueError()
            _uuid(data["sid"])
            if type(data["activity_generation"]) is not int or not 0 <= data["activity_generation"] < 9223372036854775807:
                raise ValueError()
            dates = []
            for key in ("server_time", "idle_expires_at", "overall_expires_at"):
                if type(data[key]) is not str or len(data[key]) > 64:
                    raise ValueError()
                value = datetime.fromisoformat(data[key].replace("Z", "+00:00"))
                if value.tzinfo is None:
                    raise ValueError()
                dates.append(value)
            if min(dates[1:]) <= dates[0]:
                raise ValueError()
            if operation == "status":
                assurance = data["assurance"]
                if type(assurance) is not dict or not {"amr", "acr"} <= set(assurance) <= {"amr", "acr", "auth_time", "gait_mfa_time"} or type(assurance["amr"]) is not list or not all(_text(x, 32) for x in assurance["amr"]) or not _text(assurance["acr"], 128):
                    raise ValueError()
                for key in ("auth_time", "gait_mfa_time"):
                    if key in assurance and (type(assurance[key]) is not int or assurance[key] < 0):
                        raise ValueError()
                contexts = {
                    "urn:gait:assurance:unknown": [],
                    "urn:gait:assurance:password": ["pwd"],
                    "urn:gait:assurance:password-totp": ["pwd", "otp", "mfa"],
                    "urn:gait:assurance:recovery-code": ["pwd"],
                    "urn:gait:assurance:otp-only": ["otp"],
                }
                if assurance["acr"] not in contexts or assurance["amr"] != contexts[assurance["acr"]]:
                    raise ValueError()
                if assurance["acr"] == "urn:gait:assurance:unknown":
                    if set(assurance) != {"acr", "amr"}:
                        raise ValueError()
                elif "auth_time" not in assurance or assurance["auth_time"] > dates[0].timestamp():
                    raise ValueError()
                if assurance["acr"] == "urn:gait:assurance:password-totp":
                    if assurance.get("gait_mfa_time") != assurance.get("auth_time"):
                        raise ValueError()
                elif "gait_mfa_time" in assurance:
                    raise ValueError()
