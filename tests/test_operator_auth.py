import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx
from app.main import app, _candidate_model_for_status
from app.positive_model import DecisionMode, EndpointModel, Environment, Lifecycle, PositiveModelDocument
from app.operator_auth import (
    AuthConfigurationError,
    create_session,
    request_is_secure_same_origin,
    verify_credentials,
    verify_session,
)


class OperatorAuthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        values = {
            "WAF_OPERATOR_USERNAME_FILE": (root / "username", b"operator"),
            "WAF_OPERATOR_PASSWORD_FILE": (root / "password", b"a-long-test-password-42"),
            "WAF_SESSION_SECRET_FILE": (root / "session-key", b"s" * 48),
        }
        for path, value in values.values():
            path.write_bytes(value)
        self.env = patch.dict(os.environ, {name: str(path) for name, (path, _) in values.items()})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def test_login_and_signed_session(self):
        self.assertTrue(verify_credentials("operator", "a-long-test-password-42"))
        self.assertFalse(verify_credentials("operator", "wrong-password"))
        token, csrf, expires = create_session("operator", now=1000)
        session = verify_session(token, now=1001)
        self.assertEqual(session["sub"], "operator")
        self.assertEqual(session["csrf"], csrf)
        self.assertEqual(session["exp"], expires)

    def test_tampered_and_expired_sessions_are_rejected(self):
        token, _, _ = create_session("operator", now=1000)
        self.assertIsNone(verify_session(token + "tampered", now=1001))
        self.assertIsNone(verify_session(token, now=1000 + 8 * 60 * 60))

    def test_same_origin_requires_https_and_exact_host(self):
        good = {"origin": "https://192.168.11.90", "host": "192.168.11.90", "x-forwarded-proto": "https"}
        self.assertTrue(request_is_secure_same_origin(good))
        self.assertFalse(request_is_secure_same_origin({**good, "x-forwarded-proto": "http"}))
        self.assertFalse(request_is_secure_same_origin({**good, "origin": "https://attacker.invalid"}))

    def test_missing_auth_secret_fails_closed(self):
        with patch.dict(os.environ, {"WAF_OPERATOR_PASSWORD_FILE": str(Path(self.temp.name) / "missing")}):
            with self.assertRaises(AuthConfigurationError):
                verify_credentials("operator", "a-long-test-password-42")

    def test_candidate_review_never_enables_enforcement(self):
        endpoint = EndpointModel(path_template="/", method="GET", lifecycle=Lifecycle.ENFORCED, decision_mode=DecisionMode.BLOCK)
        model = PositiveModelDocument(model_id="candidate", application_id="app", hostname="example.test", environment=Environment.TEST, lifecycle=Lifecycle.ENFORCED, endpoints=[endpoint])
        accepted = _candidate_model_for_status(model, "accepted")
        self.assertEqual(accepted.lifecycle, Lifecycle.REVIEWED)
        self.assertEqual(accepted.endpoints[0].decision_mode, DecisionMode.OBSERVE)
        self.assertEqual(accepted.endpoints[0].lifecycle, Lifecycle.REVIEWED)


class OperatorAuthMiddlewareTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.files = {
            "WAF_OPERATOR_USERNAME_FILE": root / "username",
            "WAF_OPERATOR_PASSWORD_FILE": root / "password",
            "WAF_SESSION_SECRET_FILE": root / "session-key",
        }
        self.files["WAF_OPERATOR_USERNAME_FILE"].write_text("operator", encoding="utf-8")
        self.files["WAF_OPERATOR_PASSWORD_FILE"].write_text("a-long-test-password-42", encoding="utf-8")
        self.files["WAF_SESSION_SECRET_FILE"].write_bytes(b"s" * 48)
        self.env = patch.dict(os.environ, {key: str(value) for key, value in self.files.items()})
        self.env.start()
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://waf.test")

    async def asyncTearDown(self):
        await self.client.aclose()
        self.env.stop()
        self.temp.cleanup()

    async def test_api_requires_session_and_csrf_but_health_is_public(self):
        self.assertEqual((await self.client.get("/healthz")).status_code, 200)
        self.assertEqual((await self.client.get("/api/positive-model/schema")).status_code, 401)
        headers = {"Origin": "https://waf.test", "X-Forwarded-Proto": "https"}
        login = await self.client.post("/api/auth/login", headers=headers, json={"username": "operator", "password": "a-long-test-password-42"})
        self.assertEqual(login.status_code, 200, login.text)
        self.assertIn("secure", login.headers.get("set-cookie", "").lower())
        self.assertEqual((await self.client.get("/api/positive-model/schema")).status_code, 200)
        denied = await self.client.post("/api/positive-model/validate", headers=headers, json={})
        self.assertEqual(denied.status_code, 403)
        allowed = await self.client.post("/api/positive-model/validate", headers={**headers, "X-CSRF-Token": login.json()["csrf_token"]}, json={})
        self.assertEqual(allowed.status_code, 422)

    async def test_insecure_origin_cannot_login(self):
        response = await self.client.post("/api/auth/login", headers={"Origin": "http://waf.test", "X-Forwarded-Proto": "http"}, json={"username": "operator", "password": "a-long-test-password-42"})
        self.assertEqual(response.status_code, 403)


if __name__ == "__main__":
    unittest.main()
