import hashlib
import html
import http.client
import ipaddress
import re
import secrets
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit


UTC = timezone.utc
ALLOWED_CONTENT_TYPES = {
    "application/json",
    "application/ld+json",
    "application/xml",
    "application/xhtml+xml",
    "application/yaml",
    "application/x-yaml",
}
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
VERSION_PATTERN = re.compile(r"(?<![\w.])v?(\d+\.\d+(?:\.\d+)?)(?![\w.])", re.IGNORECASE)


class SourceValidationError(ValueError):
    pass


class SourceValidationBusy(RuntimeError):
    pass


@dataclass(frozen=True)
class FetchResponse:
    status: int
    headers: dict[str, str]
    body: bytes


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection pinned to a DNS result while preserving TLS hostname checks."""

    def __init__(self, hostname: str, address: str, timeout: float, context: ssl.SSLContext):
        super().__init__(hostname, 443, timeout=timeout, context=context)
        self.address = address

    def connect(self):
        raw_socket = socket.create_connection((self.address, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw_socket, server_hostname=self.host)
        except Exception:
            raw_socket.close()
            raise


class SourceValidator:
    def __init__(
        self,
        timeout: float = 8,
        max_bytes: int = 1024 * 1024,
        max_redirects: int = 5,
        ticket_ttl_seconds: int = 600,
        max_concurrent: int = 2,
        attempts_per_minute: int = 10,
        resolver=None,
        transport=None,
        clock=None,
    ):
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.max_redirects = max_redirects
        self.ticket_ttl_seconds = ticket_ttl_seconds
        self.attempts_per_minute = attempts_per_minute
        self.resolver = resolver or socket.getaddrinfo
        self.transport = transport
        self.clock = clock or time.time
        self.context = ssl.create_default_context()
        self._capacity = threading.BoundedSemaphore(max_concurrent)
        self._lock = threading.Lock()
        self._tickets: dict[str, dict] = {}
        self._attempts: dict[int, list[float]] = {}

    @staticmethod
    def normalize(component: str, source_url: str) -> tuple[str, str]:
        component = component.strip()
        source_url = source_url.strip()
        if not 1 <= len(component) <= 128:
            raise SourceValidationError("component must contain between 1 and 128 characters")
        if len(source_url) > 2048:
            raise SourceValidationError("source URL cannot exceed 2048 characters")
        try:
            parsed = urlsplit(source_url)
            port = parsed.port
        except ValueError as error:
            raise SourceValidationError("source URL is malformed") from error
        if (
            parsed.scheme.lower() != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or port not in {None, 443}
            or parsed.fragment
            or "\\" in source_url
        ):
            raise SourceValidationError(
                "source URL must be HTTPS on port 443 without credentials, fragments, or backslashes"
            )
        try:
            hostname = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError as error:
            raise SourceValidationError("source URL hostname is invalid") from error
        if "." not in hostname or hostname == "localhost" or hostname.endswith(".local"):
            raise SourceValidationError("source URL must use a public DNS hostname")
        sensitive_query_names = {
            "access_token", "api_key", "apikey", "auth", "authorization", "credential",
            "key", "password", "secret", "signature", "token",
        }
        if any(
            name.lower() in sensitive_query_names
            for name, _ in parse_qsl(parsed.query, keep_blank_values=True)
        ):
            raise SourceValidationError("source URL cannot contain credentials or tokens in its query")
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            pass
        else:
            raise SourceValidationError("source URL must use a DNS hostname, not an IP address")
        netloc = hostname
        path = parsed.path or "/"
        return component, urlunsplit(("https", netloc, path, parsed.query, ""))

    def validate(
        self,
        component: str,
        source_url: str,
        known_official_hosts: set[str] | None = None,
        actor_id: int | None = None,
    ) -> dict:
        component, source_url = self.normalize(component, source_url)
        self._record_attempt(actor_id)
        if not self._capacity.acquire(blocking=False):
            raise SourceValidationBusy("source validation capacity is busy; try again shortly")
        try:
            result = self._validate(component, source_url, known_official_hosts or set())
            if result["eligible"]:
                token = secrets.token_urlsafe(32)
                expires_at = self.clock() + self.ticket_ttl_seconds
                with self._lock:
                    self._purge_expired_locked()
                    self._tickets[token] = {
                        "component": component,
                        "source_url": source_url,
                        "validation": result,
                        "expires_at": expires_at,
                        "actor_id": actor_id,
                    }
                result = {
                    **result,
                    "validation_token": token,
                    "expires_at": datetime.fromtimestamp(expires_at, UTC).isoformat(),
                }
            return result
        finally:
            self._capacity.release()

    def consume(
        self,
        component: str,
        source_url: str,
        token: str,
        actor_id: int | None = None,
    ) -> tuple[str, str, dict]:
        component, source_url = self.normalize(component, source_url)
        if not token:
            raise SourceValidationError("an eligible source validation is required")
        with self._lock:
            self._purge_expired_locked()
            ticket = self._tickets.pop(token, None)
        if not ticket:
            raise SourceValidationError("source validation is missing, expired, or already used")
        if ticket["component"] != component or ticket["source_url"] != source_url:
            raise SourceValidationError("source validation does not match the proposed component and URL")
        if ticket["actor_id"] != actor_id:
            raise SourceValidationError("source validation belongs to a different operator")
        validation = dict(ticket["validation"])
        validation.pop("validation_token", None)
        return component, source_url, validation

    def _purge_expired_locked(self):
        now = self.clock()
        self._tickets = {
            token: ticket for token, ticket in self._tickets.items() if ticket["expires_at"] > now
        }

    def _record_attempt(self, actor_id: int | None):
        if actor_id is None:
            return
        now = self.clock()
        with self._lock:
            attempts = [value for value in self._attempts.get(actor_id, []) if value > now - 60]
            if len(attempts) >= self.attempts_per_minute:
                raise SourceValidationBusy("source validation rate limit exceeded; try again shortly")
            attempts.append(now)
            self._attempts[actor_id] = attempts

    def _validate(self, component: str, source_url: str, known_official_hosts: set[str]) -> dict:
        checks = [
            {"name": "url", "status": "passed", "detail": "HTTPS URL syntax is safe"},
        ]
        current_url = source_url
        redirects = []
        deadline = time.monotonic() + self.timeout
        try:
            for redirect_count in range(self.max_redirects + 1):
                parsed = urlsplit(current_url)
                addresses = self._public_addresses(parsed.hostname)
                checks.append({
                    "name": "destination",
                    "status": "passed",
                    "detail": f"{parsed.hostname} resolves only to public addresses",
                })
                if time.monotonic() >= deadline:
                    raise SourceValidationError("source validation exceeded the total timeout")
                response = self._request(current_url, addresses, deadline)
                response = FetchResponse(
                    response.status,
                    {name.lower(): value for name, value in response.headers.items()},
                    response.body,
                )
                if response.status in REDIRECT_STATUSES:
                    if redirect_count >= self.max_redirects:
                        raise SourceValidationError("source exceeded the redirect limit")
                    location = response.headers.get("location", "").strip()
                    if not location:
                        raise SourceValidationError("source returned a redirect without a location")
                    _, next_url = self.normalize(component, urljoin(current_url, location))
                    redirects.append({"from": current_url, "to": next_url, "status": response.status})
                    current_url = next_url
                    continue
                if response.status != 200:
                    raise SourceValidationError(f"source returned HTTP {response.status}, expected 200")
                meta_location = self._meta_refresh_location(response)
                if meta_location:
                    if redirect_count >= self.max_redirects:
                        raise SourceValidationError("source exceeded the redirect limit")
                    _, next_url = self.normalize(component, urljoin(current_url, meta_location))
                    redirects.append({"from": current_url, "to": next_url, "status": "meta-refresh"})
                    current_url = next_url
                    continue
                break
            else:  # pragma: no cover - loop always exits by response or exception
                raise SourceValidationError("source redirect handling failed")

            content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
            if not (content_type.startswith("text/") or content_type in ALLOWED_CONTENT_TYPES):
                raise SourceValidationError(
                    f"source content type {content_type or 'unknown'} is not text, JSON, XML, or YAML"
                )
            checks.append({
                "name": "response",
                "status": "passed",
                "detail": f"HTTP 200 with {content_type or 'unspecified text'}",
            })
            text = response.body.decode("utf-8", errors="replace")
            canonical_text = re.sub(r"[^a-z0-9]+", "", text.lower())
            canonical_component = re.sub(r"[^a-z0-9]+", "", component.lower())
            component_mentioned = len(canonical_component) >= 3 and canonical_component in canonical_text
            kubernetes_mentioned = bool(re.search(r"\bkubernetes\b|\bk8s\b", text, re.IGNORECASE))
            versions = sorted({match.group(1) for match in VERSION_PATTERN.finditer(text)})[:50]
            checks.extend([
                {
                    "name": "component",
                    "status": "passed" if component_mentioned else "failed",
                    "detail": (
                        f"Content mentions {component}"
                        if component_mentioned
                        else f"Content does not identify {component}"
                    ),
                },
                {
                    "name": "kubernetes",
                    "status": "passed" if kubernetes_mentioned else "failed",
                    "detail": (
                        "Content references Kubernetes"
                        if kubernetes_mentioned
                        else "Content does not reference Kubernetes or k8s"
                    ),
                },
                {
                    "name": "versions",
                    "status": "passed" if versions else "failed",
                    "detail": (
                        f"Detected {len(versions)} version token(s)"
                        if versions
                        else "No version tokens were detected"
                    ),
                },
            ])
            hostname = urlsplit(current_url).hostname or ""
            known_origin = hostname.lower() in {item.lower() for item in known_official_hosts}
            checks.append({
                "name": "known_origin",
                "status": "passed" if known_origin else "review",
                "detail": (
                    "Hostname is already used by active official evidence"
                    if known_origin
                    else "Hostname requires administrator authority review"
                ),
            })
            eligible = component_mentioned and kubernetes_mentioned and bool(versions)
            reason = (
                "Source is safe, reachable, and contains component/Kubernetes version evidence"
                if eligible
                else "Source is reachable but does not contain enough relevant version evidence"
            )
            return {
                "eligible": eligible,
                "reason": reason,
                "source_url": source_url,
                "final_url": current_url,
                "content_type": content_type,
                "content_bytes": len(response.body),
                "content_sha256": hashlib.sha256(response.body).hexdigest(),
                "versions_detected": versions,
                "redirects": redirects,
                "known_official_origin": known_origin,
                "validated_at": datetime.now(UTC).isoformat(),
                "checks": checks,
            }
        except (OSError, ssl.SSLError, http.client.HTTPException, SourceValidationError) as error:
            checks.append({"name": "validation", "status": "failed", "detail": str(error)})
            return {
                "eligible": False,
                "reason": str(error),
                "source_url": source_url,
                "final_url": current_url,
                "redirects": redirects,
                "validated_at": datetime.now(UTC).isoformat(),
                "checks": checks,
            }

    def _public_addresses(self, hostname: str) -> list[str]:
        try:
            records = self.resolver(hostname, 443, type=socket.SOCK_STREAM)
        except OSError as error:
            raise SourceValidationError(f"source hostname could not be resolved: {error}") from error
        addresses = sorted({record[4][0] for record in records})
        if not addresses:
            raise SourceValidationError("source hostname returned no addresses")
        for address in addresses:
            try:
                parsed = ipaddress.ip_address(address)
            except ValueError as error:
                raise SourceValidationError("source hostname returned an invalid address") from error
            if not parsed.is_global:
                raise SourceValidationError(
                    "source hostname resolves to a private, local, reserved, or non-global address"
                )
        return addresses

    @staticmethod
    def _meta_refresh_location(response: FetchResponse) -> str:
        content_type = response.headers.get("content-type", "").lower()
        if not content_type.startswith("text/html"):
            return ""
        document = response.body[:16 * 1024].decode("utf-8", errors="replace")
        tag = re.search(r"<meta\b[^>]*http-equiv\s*=\s*['\"]?refresh['\"]?[^>]*>", document, re.IGNORECASE)
        if not tag:
            return ""
        content = re.search(
            r"content\s*=\s*(['\"])(.*?)\1|content\s*=\s*([^\s>]+)",
            tag.group(0),
            re.IGNORECASE,
        )
        if not content:
            return ""
        value = html.unescape(content.group(2) or content.group(3) or "")
        target = re.search(r"(?:^|;)\s*url\s*=\s*(.+?)\s*$", value, re.IGNORECASE)
        return target.group(1).strip(" '\"") if target else ""

    def _request(
        self,
        source_url: str,
        addresses: list[str],
        deadline: float | None = None,
    ) -> FetchResponse:
        if self.transport:
            return self.transport(source_url, addresses)
        parsed = urlsplit(source_url)
        target = parsed.path or "/"
        if parsed.query:
            target += f"?{parsed.query}"
        last_error = None
        for address in addresses:
            remaining = (deadline - time.monotonic()) if deadline else self.timeout
            if remaining <= 0:
                raise SourceValidationError("source validation exceeded the total timeout")
            connection = _PinnedHTTPSConnection(parsed.hostname, address, remaining, self.context)
            try:
                connection.request(
                    "GET",
                    target,
                    headers={
                        "Accept": "text/html,text/plain,application/json,application/xml,application/yaml;q=0.9",
                        "Accept-Encoding": "identity",
                        "User-Agent": "Kubit-Source-Validator/0.1",
                    },
                )
                response = connection.getresponse()
                content_length = response.getheader("Content-Length")
                if content_length:
                    try:
                        declared_length = int(content_length)
                    except ValueError as error:
                        raise SourceValidationError("source returned an invalid Content-Length") from error
                    if declared_length > self.max_bytes:
                        raise SourceValidationError(f"source exceeds the {self.max_bytes}-byte limit")
                body = bytearray()
                if response.status not in REDIRECT_STATUSES:
                    while len(body) <= self.max_bytes:
                        remaining = (deadline - time.monotonic()) if deadline else self.timeout
                        if remaining <= 0:
                            raise SourceValidationError("source validation exceeded the total timeout")
                        if connection.sock:
                            connection.sock.settimeout(remaining)
                        chunk = response.read1(min(64 * 1024, self.max_bytes + 1 - len(body)))
                        if not chunk:
                            break
                        body.extend(chunk)
                if len(body) > self.max_bytes:
                    raise SourceValidationError(f"source exceeds the {self.max_bytes}-byte limit")
                headers = {name.lower(): value for name, value in response.getheaders()}
                return FetchResponse(response.status, headers, bytes(body))
            except (OSError, ssl.SSLError, http.client.HTTPException) as error:
                last_error = error
            finally:
                connection.close()
        raise SourceValidationError(f"unable to retrieve source over HTTPS: {last_error}")
