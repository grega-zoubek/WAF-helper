"""Single-operator, signed-cookie authentication for the HTTPS control plane."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


COOKIE_NAME = "waf_operator_session"
SESSION_TTL_SECONDS = 8 * 60 * 60


class AuthConfigurationError(RuntimeError):
    pass


def _secret(path_env: str, minimum: int = 1) -> bytes:
    path = os.getenv(path_env, "")
    if not path:
        raise AuthConfigurationError("Operator authentication is not configured")
    try:
        value = Path(path).read_bytes().strip()
    except OSError as exc:
        raise AuthConfigurationError("Operator authentication is not configured") from exc
    if len(value) < minimum:
        raise AuthConfigurationError("Operator authentication is not configured")
    return value


def configured_username() -> str:
    value = _secret("WAF_OPERATOR_USERNAME_FILE")
    try:
        username = value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AuthConfigurationError("Operator authentication is not configured") from exc
    if not username or len(username) > 128 or any(ord(char) < 33 for char in username):
        raise AuthConfigurationError("Operator authentication is not configured")
    return username


def verify_credentials(username: str, password: str) -> bool:
    try:
        expected_user = configured_username().encode("utf-8")
        expected_password = _secret("WAF_OPERATOR_PASSWORD_FILE", 16)
        session_key = _secret("WAF_SESSION_SECRET_FILE", 32)
    except AuthConfigurationError:
        raise
    return hmac.compare_digest(username.encode("utf-8"), expected_user) and hmac.compare_digest(
        password.encode("utf-8"), expected_password
    ) and bool(session_key)


def _signing_key() -> bytes:
    return _secret("WAF_SESSION_SECRET_FILE", 32)


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def create_session(username: str, now: int | None = None) -> tuple[str, str, int]:
    issued = int(time.time() if now is None else now)
    csrf = _encode(os.urandom(32))
    payload = _encode(json.dumps({"sub": username, "iat": issued, "exp": issued + SESSION_TTL_SECONDS, "csrf": csrf}, separators=(",", ":")).encode())
    signature = _encode(hmac.new(_signing_key(), payload.encode("ascii"), hashlib.sha256).digest())
    return f"{payload}.{signature}", csrf, issued + SESSION_TTL_SECONDS


def verify_session(token: str, now: int | None = None) -> dict[str, Any] | None:
    try:
        payload, signature = token.split(".", 1)
        expected = hmac.new(_signing_key(), payload.encode("ascii"), hashlib.sha256).digest()
        if not hmac.compare_digest(_decode(signature), expected):
            return None
        data = json.loads(_decode(payload))
        current = int(time.time() if now is None else now)
        if not isinstance(data, dict) or not isinstance(data.get("sub"), str) or not data["sub"]:
            return None
        if not isinstance(data.get("iat"), int) or not isinstance(data.get("exp"), int):
            return None
        if data["iat"] > current + 60 or data["exp"] <= current or data["exp"] - data["iat"] > SESSION_TTL_SECONDS:
            return None
        if not isinstance(data.get("csrf"), str) or len(data["csrf"]) < 32:
            return None
        return data
    except (AuthConfigurationError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return None


def request_is_secure_same_origin(headers: Any) -> bool:
    origin = str(headers.get("origin", ""))
    forwarded_proto = str(headers.get("x-forwarded-proto", "")).split(",", 1)[0].strip().lower()
    host = str(headers.get("host", "")).lower()
    try:
        parsed = urlsplit(origin)
    except ValueError:
        return False
    return bool(
        forwarded_proto == "https"
        and parsed.scheme == "https"
        and parsed.netloc.lower() == host
        and parsed.hostname
        and not parsed.username
        and not parsed.password
    )
