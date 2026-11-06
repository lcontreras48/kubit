import hashlib
import hmac
import secrets
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


UTC = timezone.utc
ROLES = {"viewer", "operator", "admin"}
SCRYPT_N = 1 << 14
SCRYPT_R = 8
SCRYPT_P = 1


class AuthenticationBusy(RuntimeError):
    pass


def normalize_username(value: str) -> str:
    username = value.strip().lower()
    if not 3 <= len(username) <= 64:
        raise ValueError("username must contain between 3 and 64 characters")
    if not all(character.isalnum() or character in {"-", "_", "."} for character in username):
        raise ValueError("username contains unsupported characters")
    return username


def validate_role(role: str) -> str:
    if role not in ROLES:
        raise ValueError(f"role must be one of: {', '.join(sorted(ROLES))}")
    return role


def hash_password(password: str, salt: bytes | None = None) -> str:
    if len(password) < 12:
        raise ValueError("password must contain at least 12 characters")
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=32,
    )
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, n, r, p, salt, expected = encoded.split("$", 5)
        if algorithm != "scrypt":
            return False
        digest = hashlib.scrypt(
            password.encode("utf-8"),
            salt=bytes.fromhex(salt),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(bytes.fromhex(expected)),
        )
        return hmac.compare_digest(digest.hex(), expected)
    except (ValueError, TypeError):
        return False


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Principal:
    id: int
    username: str
    role: str
    csrf_token: str = ""

    def permits(self, required: str) -> bool:
        levels = {"viewer": 1, "operator": 2, "admin": 3}
        return levels.get(self.role, 0) >= levels[required]


class AuthService:
    def __init__(
        self,
        store,
        session_hours: int = 12,
        login_attempts_per_minute: int = 10,
        global_login_attempts_per_minute: int = 60,
        clock=None,
    ):
        if login_attempts_per_minute < 1 or global_login_attempts_per_minute < 1:
            raise ValueError("login attempt limits must be positive")
        self.store = store
        self.session_hours = session_hours
        self.login_attempts_per_minute = login_attempts_per_minute
        self.global_login_attempts_per_minute = global_login_attempts_per_minute
        self.clock = clock or time.monotonic
        self._attempt_lock = threading.Lock()
        self._login_attempts: dict[str, list[float]] = {}
        self._global_login_attempts: list[float] = []
        self._last_attempt_cleanup = self.clock()

    def login(self, username: str, password: str) -> tuple[str, Principal] | None:
        try:
            normalized = normalize_username(username)
        except ValueError:
            normalized = "invalid"
        self._record_login_attempt(normalized)
        user = self.store.user_by_username(normalized)
        # Perform the expensive hash even for unknown users to reduce account enumeration.
        encoded = user["password_hash"] if user else hash_password("invalid-password-value")
        valid = verify_password(password, encoded)
        if not user or not valid or not user["enabled"]:
            self.store.audit(None, "auth.login_failed", "user", normalized, {})
            return None
        with self._attempt_lock:
            self._login_attempts.pop(normalized, None)
        session_token = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        expires_at = datetime.now(UTC) + timedelta(hours=self.session_hours)
        self.store.create_session(
            user["id"], token_hash(session_token), token_hash(csrf_token), expires_at
        )
        self.store.audit(user["id"], "auth.login", "user", str(user["id"]), {})
        return session_token, Principal(user["id"], user["username"], user["role"], csrf_token)

    def _record_login_attempt(self, username: str) -> None:
        now = self.clock()
        cutoff = now - 60
        with self._attempt_lock:
            global_attempts = [value for value in self._global_login_attempts if value > cutoff]
            if now - self._last_attempt_cleanup >= 60:
                self._login_attempts = {
                    name: recent
                    for name, attempts in self._login_attempts.items()
                    if (recent := [value for value in attempts if value > cutoff])
                }
                self._last_attempt_cleanup = now
            user_attempts = [
                value for value in self._login_attempts.get(username, []) if value > cutoff
            ]
            if (
                len(global_attempts) >= self.global_login_attempts_per_minute
                or len(user_attempts) >= self.login_attempts_per_minute
            ):
                self._global_login_attempts = global_attempts
                self._login_attempts[username] = user_attempts
                self.store.audit(None, "auth.login_rate_limited", "user", username, {})
                raise AuthenticationBusy("login rate limit exceeded; try again shortly")
            global_attempts.append(now)
            user_attempts.append(now)
            self._global_login_attempts = global_attempts
            self._login_attempts[username] = user_attempts

    # The empty optional anti-CSRF token is not a password.
    def principal(self, session_token: str, csrf_token: str = "") -> Principal | None:  # nosec B107
        if not session_token:
            return None
        session = self.store.session(token_hash(session_token))
        if not session:
            return None
        return Principal(
            session["user_id"],
            session["username"],
            session["role"],
            csrf_token if csrf_token and hmac.compare_digest(token_hash(csrf_token), session["csrf_hash"]) else "",
        )

    def issue_csrf(self, session_token: str) -> Principal | None:
        if not session_token:
            return None
        session = self.store.session(token_hash(session_token))
        if not session:
            return None
        csrf_token = secrets.token_urlsafe(32)
        self.store.update_session_csrf(token_hash(session_token), token_hash(csrf_token))
        return Principal(session["user_id"], session["username"], session["role"], csrf_token)

    def logout(self, session_token: str) -> None:
        if session_token:
            self.store.delete_session(token_hash(session_token))
