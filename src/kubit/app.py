import json
import logging
import os
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .auth import AuthenticationBusy, AuthService, hash_password, normalize_username, validate_role
from .collector import Collector, KubernetesAPI
from .database import PostgresStore, configured_database_url
from .engine import Engine
from .metrics import render
from .providers import ProviderManager, default_manager
from .security import SecurityCollector, empty_security
from .source_validation import SourceValidationBusy, SourceValidationError, SourceValidator
from .upgrade import evaluate_kubernetes_target
from .version import application_version


LOG = logging.getLogger("kubit")
WEB_ROOT = Path(__file__).with_name("web")
WEB_ASSETS = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/assets/styles.css": ("styles.css", "text/css; charset=utf-8"),
    "/assets/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/assets/favicon.svg": ("favicon.svg", "image/svg+xml"),
}


def environment_flag(name: str, default: bool = True) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off"}


class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.components = []
        self.results = []
        self.providers = []
        self.security = empty_security()
        self.rule_document = {"schema_version": 1, "rules": []}
        self.metrics = render([], [], False, 0)
        self.error: str | None = None
        self.ready = False
        self.last_success_timestamp = 0.0
        self.cluster_name = os.getenv("CLUSTER_NAME", "cluster")

    def update(self, components, results, providers, rule_document, security, duration: float):
        with self.lock:
            self.components, self.results, self.providers = components, results, providers
            self.security = security
            self.rule_document = rule_document
            self.last_success_timestamp = time.time()
            self.metrics = render(
                components,
                results,
                True,
                duration,
                self.last_success_timestamp,
                providers,
                security,
            )
            self.error, self.ready = None, True

    def fail(self, error: Exception, duration: float):
        with self.lock:
            self.error = str(error)
            self.metrics = render(
                self.components,
                self.results,
                False,
                duration,
                self.last_success_timestamp,
                self.providers,
                self.security,
            )


def scanner(state: State, interval: int, providers: ProviderManager, store: PostgresStore | None = None):
    previous_signature = None
    while True:
        started = time.monotonic()
        try:
            api = KubernetesAPI()
            components = Collector(
                api,
                discover_argocd=environment_flag("ARGOCD_APPLICATIONS_ENABLED"),
            ).collect()
            signature = tuple(
                (
                    item.name,
                    item.version,
                    item.instance,
                    item.metadata.get("chart_name", ""),
                    item.metadata.get("chart_version", ""),
                )
                for item in components
            )
            rule_document, provider_states = providers.rules(
                force=signature != previous_signature,
                components=components,
            )
            results = Engine(rule_document).evaluate(components)
            if environment_flag("TRIVY_REPORTS_ENABLED"):
                try:
                    security = SecurityCollector(api).collect(components)
                except Exception:
                    LOG.exception("security report collection failed")
                    security = empty_security()
                    security["errors"] = ["security report collection failed"]
            else:
                security = empty_security(enabled=False)
            state.update(
                components,
                results,
                provider_states,
                rule_document,
                security,
                time.monotonic() - started,
            )
            if store:
                try:
                    store.record_scan(current_report(state))
                except Exception:
                    LOG.exception("unable to persist scan report")
            previous_signature = signature
            LOG.info(
                "scan complete: %d components, %d results, providers=%s",
                len(components),
                len(results),
                ",".join(f"{item.name}:{item.status}" for item in provider_states),
            )
        except Exception as error:  # keep serving the last successful report
            state.fail(error, time.monotonic() - started)
            LOG.exception("scan failed")
        time.sleep(interval)


def current_report(state: State) -> dict:
    with state.lock:
        return {
            "kubit_version": application_version(),
            "cluster": state.cluster_name,
            "ready": state.ready,
            "error": state.error,
            "components": [item.as_dict() for item in state.components],
            "results": [item.as_dict() for item in state.results],
            "providers": [item.as_dict() for item in state.providers],
            "security": state.security,
        }


def official_evidence_hosts(state: State) -> set[str]:
    with state.lock:
        urls = [item.source_url for item in state.providers]
        urls.extend(item.evidence for item in state.results)
    hosts = set()
    for value in urls:
        try:
            hostname = urlsplit(value).hostname if value else ""
        except ValueError:
            continue
        if hostname:
            hosts.add(hostname.lower())
    return hosts


def require_discovered_component(state: State, value: str) -> str:
    component = value.strip()
    with state.lock:
        discovered = {item.name for item in state.components}
    if component not in discovered:
        raise SourceValidationError(
            "component is not present in the latest discovered inventory"
        )
    return component


def handler(
    state: State,
    auth: AuthService | None = None,
    secure_cookies: bool = True,
    source_validator: SourceValidator | None = None,
):
    class Handler(BaseHTTPRequestHandler):
        server_version = "Kubit"
        sys_version = ""

        def do_GET(self):
            request = urlsplit(self.path)
            if request.path in WEB_ASSETS:
                filename, content_type = WEB_ASSETS[request.path]
                try:
                    return self._reply(200, (WEB_ROOT / filename).read_bytes(), content_type)
                except OSError:
                    LOG.exception("web asset unavailable: %s", filename)
                    return self._reply(500, "web interface unavailable\n", "text/plain; charset=utf-8")
            if request.path == "/metrics":
                return self._reply(200, state.metrics, "text/plain; version=0.0.4")
            if request.path == "/healthz":
                return self._reply(200, "ok\n", "text/plain")
            if request.path == "/readyz":
                return self._reply(200 if state.ready else 503, "ready\n" if state.ready else "not ready\n", "text/plain")
            if request.path == "/api/v1/report":
                report = current_report(state)
                return self._reply(200, json.dumps(report, indent=2) + "\n", "application/json")
            if request.path == "/api/v1/auth/me":
                principal = auth.issue_csrf(self._session_token()) if auth else None
                if not principal:
                    return self._json(401, {"error": "authentication required"})
                return self._json(200, {
                    "id": principal.id,
                    "username": principal.username,
                    "role": principal.role,
                    "csrf_token": principal.csrf_token,
                })
            if request.path == "/api/v1/admin/users":
                principal = self._authorize("admin")
                if not principal:
                    return None
                return self._json(200, {"users": auth.store.list_users()})
            if request.path == "/api/v1/source-proposals":
                principal = self._authorize("viewer")
                if not principal:
                    return None
                return self._json(200, {"proposals": auth.store.list_source_proposals()})
            if request.path == "/api/v1/upgrade-readiness":
                target = parse_qs(request.query).get("kubernetes", [""])[0]
                if not target:
                    return self._reply(400, json.dumps({"error": "missing kubernetes query parameter"}) + "\n", "application/json")
                try:
                    with state.lock:
                        hypothetical, results = evaluate_kubernetes_target(
                            state.components,
                            state.rule_document,
                            target,
                        )
                    summary = {}
                    for result in results:
                        summary[result.status] = summary.get(result.status, 0) + 1
                    report = {
                        "target_kubernetes": target,
                        "summary": summary,
                        "components": [item.as_dict() for item in hypothetical],
                        "results": [item.as_dict() for item in results],
                    }
                    return self._reply(200, json.dumps(report, indent=2) + "\n", "application/json")
                except ValueError as error:
                    return self._reply(400, json.dumps({"error": str(error)}) + "\n", "application/json")
            return self._reply(404, "not found\n", "text/plain")

        def do_POST(self):
            request = urlsplit(self.path)
            if request.path == "/api/v1/auth/login":
                if not auth:
                    return self._json(503, {"error": "local authentication is not configured"})
                body = self._json_body()
                if body is None:
                    return None
                try:
                    login = auth.login(
                        str(body.get("username", "")), str(body.get("password", ""))
                    )
                except AuthenticationBusy as error:
                    return self._json(429, {"error": str(error)}, {"Retry-After": "60"})
                if not login:
                    return self._json(401, {"error": "invalid username or password"})
                session_token, principal = login
                attributes = "Path=/; HttpOnly; SameSite=Strict"
                if secure_cookies:
                    attributes += "; Secure"
                return self._json(
                    200,
                    {
                        "user": {"id": principal.id, "username": principal.username, "role": principal.role},
                        "csrf_token": principal.csrf_token,
                    },
                    {"Set-Cookie": f"kubit_session={session_token}; {attributes}"},
                )
            if request.path == "/api/v1/auth/logout":
                principal = self._authorize("viewer", csrf=True)
                if not principal:
                    return None
                auth.logout(self._session_token())
                return self._json(
                    200,
                    {"status": "logged_out"},
                    {"Set-Cookie": "kubit_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"},
                )
            if request.path == "/api/v1/admin/users":
                principal = self._authorize("admin", csrf=True)
                if not principal:
                    return None
                body = self._json_body()
                if body is None:
                    return None
                try:
                    username = normalize_username(str(body.get("username", "")))
                    role = validate_role(str(body.get("role", "")))
                    password_hash = hash_password(str(body.get("password", "")))
                    user = auth.store.create_user(username, password_hash, role, principal.id)
                except ValueError as error:
                    return self._json(400, {"error": str(error)})
                except Exception:
                    LOG.exception("unable to create user")
                    return self._json(409, {"error": "username already exists or database rejected the user"})
                return self._json(201, {"user": user})
            if request.path == "/api/v1/source-validations":
                principal = self._authorize("operator", csrf=True)
                if not principal:
                    return None
                if not source_validator:
                    return self._json(503, {"error": "source validation is not configured"})
                body = self._json_body()
                if body is None:
                    return None
                component = str(body.get("component", ""))
                source_url = str(body.get("source_url", ""))
                try:
                    component = require_discovered_component(state, component)
                    validation = source_validator.validate(
                        component,
                        source_url,
                        official_evidence_hosts(state),
                        principal.id,
                    )
                except SourceValidationBusy as error:
                    return self._json(429, {"error": str(error)})
                except SourceValidationError as error:
                    return self._json(400, {"error": str(error)})
                auth.store.audit(
                    principal.id,
                    "source.validate",
                    "source_url",
                    validation["source_url"],
                    {
                        "component": component.strip(),
                        "eligible": validation["eligible"],
                        "reason": validation["reason"],
                    },
                )
                return self._json(200, {"validation": validation})
            if request.path == "/api/v1/source-proposals":
                principal = self._authorize("operator", csrf=True)
                if not principal:
                    return None
                body = self._json_body()
                if body is None:
                    return None
                try:
                    component = require_discovered_component(
                        state, str(body.get("component", ""))
                    )
                    source_url = str(body.get("source_url", "")).strip()
                    notes = str(body.get("notes", "")).strip()
                    if len(notes) > 2000:
                        raise ValueError("notes cannot exceed 2000 characters")
                    if not source_validator:
                        return self._json(503, {"error": "source validation is not configured"})
                    component, source_url, validation = source_validator.consume(
                        component,
                        source_url,
                        str(body.get("validation_token", "")),
                        principal.id,
                    )
                    proposal = auth.store.create_source_proposal(
                        component, source_url, notes, validation, principal.id
                    )
                except (ValueError, SourceValidationError) as error:
                    return self._json(409, {"error": str(error)})
                return self._json(201, {"proposal": proposal})
            return self._reply(404, "not found\n", "text/plain")

        def _json_body(self) -> dict | None:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = 0
            if length <= 0 or length > 16 * 1024:
                self._json(400, {"error": "request body must be JSON and no larger than 16 KiB"})
                return None
            try:
                body = json.loads(self.rfile.read(length))
            except (json.JSONDecodeError, UnicodeDecodeError):
                self._json(400, {"error": "invalid JSON request"})
                return None
            if not isinstance(body, dict):
                self._json(400, {"error": "JSON request must be an object"})
                return None
            return body

        def _session_token(self) -> str:
            cookie = SimpleCookie()
            try:
                cookie.load(self.headers.get("Cookie", ""))
            except Exception:
                return ""
            return cookie["kubit_session"].value if "kubit_session" in cookie else ""

        def _principal(self, csrf: bool = False):
            if not auth:
                return None
            csrf_token = self.headers.get("X-CSRF-Token", "") if csrf else ""
            principal = auth.principal(self._session_token(), csrf_token)
            if csrf and principal and not principal.csrf_token:
                return None
            return principal

        def _authorize(self, role: str, csrf: bool = False):
            principal = self._principal(csrf)
            if not principal:
                self._json(401, {"error": "authentication required"})
                return None
            if not principal.permits(role):
                self._json(403, {"error": f"{role} role required"})
                return None
            return principal

        def _json(self, status: int, body: dict, headers: dict[str, str] | None = None):
            return self._reply(
                status,
                json.dumps(body, indent=2, default=lambda value: value.isoformat()) + "\n",
                "application/json",
                headers,
            )

        def _reply(self, status: int, body: str | bytes, content_type: str, headers: dict[str, str] | None = None):
            payload = body if isinstance(body, bytes) else body.encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", "default-src 'self'; img-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
            self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format, *args):
            LOG.info(format, *args)

    return Handler


def main():
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(message)s")
    state = State()
    providers = default_manager(
        os.getenv("CACHE_DIR", "/var/cache/kubit"),
        int(os.getenv("EVIDENCE_REFRESH_INTERVAL_SECONDS", "21600")),
        int(os.getenv("EVIDENCE_STALE_AFTER_SECONDS", "604800")),
    )
    store = None
    auth = None
    source_validator = None
    database_url = configured_database_url()
    if database_url:
        store = PostgresStore(
            database_url,
            retention_days=int(os.getenv("SCAN_HISTORY_RETENTION_DAYS", "30")),
        )
        store.initialize()
        if store.user_count() == 0:
            username = normalize_username(os.getenv("KUBIT_BOOTSTRAP_ADMIN_USERNAME", "admin"))
            password_file = os.getenv("KUBIT_BOOTSTRAP_ADMIN_PASSWORD_FILE", "")
            if not password_file:
                raise RuntimeError(
                    "KUBIT_BOOTSTRAP_ADMIN_PASSWORD_FILE is required when the database has no users"
                )
            password = Path(password_file).read_text(encoding="utf-8").strip()
            store.bootstrap_admin(username, hash_password(password))
            LOG.warning("bootstrapped the initial Kubit administrator %s", username)
        auth = AuthService(
            store,
            session_hours=int(os.getenv("AUTH_SESSION_HOURS", "12")),
            login_attempts_per_minute=int(os.getenv("AUTH_LOGIN_ATTEMPTS_PER_MINUTE", "10")),
            global_login_attempts_per_minute=int(
                os.getenv("AUTH_GLOBAL_LOGIN_ATTEMPTS_PER_MINUTE", "60")
            ),
        )
        source_validator = SourceValidator(
            timeout=float(os.getenv("SOURCE_VALIDATION_TIMEOUT_SECONDS", "8")),
            max_bytes=int(os.getenv("SOURCE_VALIDATION_MAX_BYTES", str(1024 * 1024))),
            max_redirects=int(os.getenv("SOURCE_VALIDATION_MAX_REDIRECTS", "5")),
            ticket_ttl_seconds=int(os.getenv("SOURCE_VALIDATION_TICKET_TTL_SECONDS", "600")),
            max_concurrent=int(os.getenv("SOURCE_VALIDATION_MAX_CONCURRENT", "2")),
            attempts_per_minute=int(os.getenv("SOURCE_VALIDATION_ATTEMPTS_PER_MINUTE", "10")),
        )
    thread = threading.Thread(
        target=scanner,
        args=(state, int(os.getenv("SCAN_INTERVAL_SECONDS", "900")), providers, store),
        daemon=True,
    )
    thread.start()
    server = ThreadingHTTPServer(
        # The container must listen on its Pod interface for the Kubernetes Service.
        ("0.0.0.0", int(os.getenv("PORT", "8080"))),  # nosec B104
        handler(
            state,
            auth,
            os.getenv("AUTH_SECURE_COOKIES", "true").lower() != "false",
            source_validator,
        ),
    )
    LOG.info("Kubit %s listening on :%s", application_version(), server.server_port)
    server.serve_forever()


if __name__ == "__main__":
    main()
