import http.client
import json
import threading
import unittest
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer

from kubit.app import State, handler
from kubit.auth import AuthService, hash_password
from kubit.models import Component
from kubit.source_validation import FetchResponse, SourceValidator


class MemoryStore:
    def __init__(self):
        self.users = {
            "admin": {
                "id": 1,
                "username": "admin",
                "password_hash": hash_password("initial admin password"),
                "role": "admin",
                "enabled": True,
            }
        }
        self.sessions = {}
        self.proposals = []

    def user_by_username(self, username):
        return self.users.get(username)

    def create_session(self, user_id, session_hash, csrf_hash, expires_at):
        user = next(item for item in self.users.values() if item["id"] == user_id)
        self.sessions[session_hash] = {
            "user_id": user_id,
            "username": user["username"],
            "role": user["role"],
            "csrf_hash": csrf_hash,
        }

    def session(self, session_hash):
        return self.sessions.get(session_hash)

    def delete_session(self, session_hash):
        self.sessions.pop(session_hash, None)

    def update_session_csrf(self, session_hash, csrf_hash):
        self.sessions[session_hash]["csrf_hash"] = csrf_hash

    def audit(self, *args):
        pass

    def create_user(self, username, password_hash, role, actor_id):
        user = {
            "id": len(self.users) + 1,
            "username": username,
            "password_hash": password_hash,
            "role": role,
            "enabled": True,
            "created_at": datetime.now(timezone.utc),
        }
        self.users[username] = user
        return {key: value for key, value in user.items() if key != "password_hash"}

    def list_users(self):
        return [
            {key: value for key, value in user.items() if key != "password_hash"}
            for user in self.users.values()
        ]

    def create_source_proposal(self, component, source_url, notes, validation, actor_id):
        proposal = {
            "id": len(self.proposals) + 1,
            "component": component,
            "source_url": source_url,
            "notes": notes,
            "state": "candidate",
            "validation": validation,
            "proposed_by": actor_id,
        }
        self.proposals.append(proposal)
        return proposal

    def list_source_proposals(self):
        return list(self.proposals)


class AuthenticationAPITest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.store = MemoryStore()
        cls.validator = SourceValidator(
            resolver=lambda host, port, type: [
                (2, type, 6, "", ("93.184.216.34", port))
            ],
            transport=lambda url, addresses: FetchResponse(
                200,
                {"content-type": "text/plain"},
                b"Example compatibility with Kubernetes v1.31 and v1.32",
            ),
        )
        try:
            state = State()
            state.components = [Component("example", "1.0.0", "test")]
            cls.server = ThreadingHTTPServer(
                ("127.0.0.1", 0),
                handler(
                    state,
                    AuthService(
                        cls.store,
                        login_attempts_per_minute=2,
                        global_login_attempts_per_minute=20,
                    ),
                    secure_cookies=False,
                    source_validator=cls.validator,
                ),
            )
        except PermissionError as error:
            raise unittest.SkipTest("local sandbox does not permit loopback sockets") from error
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)
        payload = json.dumps(body) if body is not None else None
        request_headers = {"Content-Type": "application/json", **(headers or {})}
        connection.request(method, path, payload, request_headers)
        response = connection.getresponse()
        data = json.loads(response.read())
        response_headers = dict(response.getheaders())
        connection.close()
        return response.status, data, response_headers

    def test_login_role_csrf_user_creation_and_source_proposal(self):
        status, login, headers = self.request(
            "POST",
            "/api/v1/auth/login",
            {"username": "admin", "password": "initial admin password"},  # pragma: allowlist secret
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers["Server"].strip(), "Kubit")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertIn("max-age=31536000", headers["Strict-Transport-Security"])
        self.assertIn("camera=()", headers["Permissions-Policy"])
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        csrf = login["csrf_token"]

        status, current, _ = self.request("GET", "/api/v1/auth/me", headers={"Cookie": cookie})
        self.assertEqual((status, current["role"]), (200, "admin"))
        csrf = current["csrf_token"]

        status, _, _ = self.request(
            "POST",
            "/api/v1/admin/users",
            {"username": "reader", "password": "reader password value", "role": "viewer"},  # pragma: allowlist secret
            {"Cookie": cookie},
        )
        self.assertEqual(status, 401)

        auth_headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
        status, created, _ = self.request(
            "POST",
            "/api/v1/admin/users",
            {"username": "reader", "password": "reader password value", "role": "viewer"},  # pragma: allowlist secret
            auth_headers,
        )
        self.assertEqual((status, created["user"]["role"]), (201, "viewer"))

        status, unknown_component, _ = self.request(
            "POST",
            "/api/v1/source-validations",
            {
                "component": "not-in-inventory",
                "source_url": "https://example.org/compatibility",
            },
            auth_headers,
        )
        self.assertEqual(status, 400)
        self.assertIn("not present", unknown_component["error"])

        status, missing_validation, _ = self.request(
            "POST",
            "/api/v1/source-proposals",
            {
                "component": "example",
                "source_url": "https://example.org/compatibility",
                "notes": "candidate only",
            },
            auth_headers,
        )
        self.assertEqual((status, "validation" in missing_validation["error"]), (409, True))

        status, checked, _ = self.request(
            "POST",
            "/api/v1/source-validations",
            {
                "component": "example",
                "source_url": "https://example.org/compatibility",
            },
            auth_headers,
        )
        self.assertEqual((status, checked["validation"]["eligible"]), (200, True))

        status, proposal, _ = self.request(
            "POST",
            "/api/v1/source-proposals",
            {
                "component": "example",
                "source_url": "https://example.org/compatibility",
                "notes": "candidate only",
                "validation_token": checked["validation"]["validation_token"],
            },
            auth_headers,
        )
        self.assertEqual((status, proposal["proposal"]["state"]), (201, "candidate"))
        self.assertTrue(proposal["proposal"]["validation"]["eligible"])

        for _ in range(2):
            status, failed, _ = self.request(
                "POST",
                "/api/v1/auth/login",
                {"username": "admin", "password": "incorrect password"},  # pragma: allowlist secret
            )
            self.assertEqual((status, failed["error"]), (401, "invalid username or password"))
        status, limited, limited_headers = self.request(
            "POST",
            "/api/v1/auth/login",
            {"username": "admin", "password": "correct but blocked"},  # pragma: allowlist secret
        )
        self.assertEqual(status, 429)
        self.assertIn("rate limit", limited["error"])
        self.assertEqual(limited_headers["Retry-After"], "60")


if __name__ == "__main__":
    unittest.main()
