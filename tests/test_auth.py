import unittest
from datetime import datetime, timezone

from kubit.auth import (
    AuthenticationBusy,
    AuthService,
    Principal,
    hash_password,
    normalize_username,
    token_hash,
    validate_role,
    verify_password,
)


class FakeStore:
    def __init__(self):
        self.users = {
            "operator": {
                "id": 7,
                "username": "operator",
                "password_hash": hash_password("correct horse battery staple"),
                "role": "operator",
                "enabled": True,
            }
        }
        self.sessions = {}
        self.events = []

    def user_by_username(self, username):
        return self.users.get(username)

    def create_session(self, user_id, session_hash, csrf_hash, expires_at):
        self.sessions[session_hash] = {
            "user_id": user_id,
            "username": "operator",
            "role": "operator",
            "csrf_hash": csrf_hash,
            "expires_at": expires_at,
        }

    def session(self, session_hash):
        return self.sessions.get(session_hash)

    def delete_session(self, session_hash):
        self.sessions.pop(session_hash, None)

    def update_session_csrf(self, session_hash, csrf_hash):
        self.sessions[session_hash]["csrf_hash"] = csrf_hash

    def audit(self, actor_id, action, target_type, target_id, details):
        self.events.append((actor_id, action, target_type, target_id, details))


class AuthenticationTest(unittest.TestCase):
    def test_scrypt_password_round_trip_and_rejects_short_password(self):
        encoded = hash_password("correct horse battery staple")
        self.assertTrue(verify_password("correct horse battery staple", encoded))
        self.assertFalse(verify_password("incorrect password", encoded))
        with self.assertRaises(ValueError):
            hash_password("too-short")

    def test_username_and_role_validation(self):
        self.assertEqual(normalize_username("  Alice.Admin  "), "alice.admin")
        self.assertEqual(validate_role("operator"), "operator")
        with self.assertRaises(ValueError):
            normalize_username("bad name")
        with self.assertRaises(ValueError):
            validate_role("owner")

    def test_login_session_csrf_and_logout(self):
        store = FakeStore()
        service = AuthService(store)
        login = service.login("OPERATOR", "correct horse battery staple")
        self.assertIsNotNone(login)
        session_token, principal = login
        self.assertEqual(principal.role, "operator")
        self.assertTrue(principal.permits("viewer"))
        self.assertFalse(principal.permits("admin"))

        restored = service.principal(session_token, principal.csrf_token)
        self.assertEqual(restored, principal)
        self.assertEqual(service.principal(session_token, "wrong").csrf_token, "")
        self.assertIn(token_hash(session_token), store.sessions)
        rotated = service.issue_csrf(session_token)
        self.assertTrue(rotated.csrf_token)
        self.assertEqual(service.principal(session_token, principal.csrf_token).csrf_token, "")
        self.assertEqual(service.principal(session_token, rotated.csrf_token), rotated)

        service.logout(session_token)
        self.assertIsNone(service.principal(session_token))

    def test_invalid_or_disabled_user_cannot_login(self):
        store = FakeStore()
        service = AuthService(store)
        self.assertIsNone(service.login("missing", "some invalid password"))
        store.users["operator"]["enabled"] = False
        self.assertIsNone(service.login("operator", "correct horse battery staple"))
        self.assertEqual([event[1] for event in store.events], ["auth.login_failed", "auth.login_failed"])

    def test_login_attempts_are_rate_limited_and_expire(self):
        clock = [1_000.0]
        store = FakeStore()
        service = AuthService(
            store,
            login_attempts_per_minute=2,
            global_login_attempts_per_minute=3,
            clock=lambda: clock[0],
        )
        self.assertIsNone(service.login("operator", "wrong password"))
        self.assertIsNone(service.login("operator", "wrong password"))
        with self.assertRaises(AuthenticationBusy):
            service.login("operator", "correct horse battery staple")
        self.assertEqual(store.events[-1][1], "auth.login_rate_limited")
        clock[0] += 61
        self.assertIsNotNone(service.login("operator", "correct horse battery staple"))
        with self.assertRaisesRegex(ValueError, "must be positive"):
            AuthService(store, login_attempts_per_minute=0)


if __name__ == "__main__":
    unittest.main()
