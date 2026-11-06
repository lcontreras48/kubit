import os
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

from .models import Component


TRIVY_API = "/apis/aquasecurity.github.io/v1alpha1"
REPORT_PATHS = {
    "vulnerability": f"{TRIVY_API}/vulnerabilityreports",
    "config_audit": f"{TRIVY_API}/configauditreports",
    "exposed_secret": f"{TRIVY_API}/exposedsecretreports",
    "sbom": f"{TRIVY_API}/sbomreports",
}
SEVERITIES = ("critical", "high", "medium", "low", "unknown")
WORKLOAD_KINDS = {"cronjob", "daemonset", "deployment", "job", "pod", "replicaset", "statefulset"}
MAX_FINDINGS_PER_REPORT = 50
MIN_HIGH_FINDINGS_PER_REPORT = 10
MAX_SBOM_COMPONENTS_PER_REPORT = 50


class SecurityCollector:
    """Read and sanitize Trivy Operator reports without affecting compatibility."""

    def __init__(self, api, stale_after_seconds: int | None = None, retry_delay_seconds: float = 1.0):
        self.api = api
        configured = stale_after_seconds or int(os.getenv("SECURITY_REPORT_STALE_AFTER_SECONDS", "86400"))
        self.stale_after_seconds = max(configured, 60)
        self.retry_delay_seconds = max(retry_delay_seconds, 0)

    def collect(self, components: list[Component]) -> dict:
        now = datetime.now(timezone.utc)
        reports = []
        available = False
        errors = []
        for report_type, path in REPORT_PATHS.items():
            try:
                document = self._get_with_retry(path)
                available = True
            except RuntimeError as error:
                errors.append(str(error))
                continue
            for item in document.get("items", []):
                parsed = self._parse(report_type, item, components, now)
                if parsed:
                    reports.append(parsed)

        reports.sort(
            key=lambda item: (
                -item["summary"]["critical"],
                -item["summary"]["high"],
                item["namespace"],
                item["workload_name"],
                item["report_type"],
            )
        )
        return self._result(available, reports, components, errors, now)

    def _get_with_retry(self, path: str) -> dict:
        for attempt in range(3):
            try:
                return self.api.get(path)
            except RuntimeError as error:
                status = getattr(error, "status", 0)
                if status not in {429, 500, 502, 503, 504} or attempt == 2:
                    raise
                retry_after = min(max(getattr(error, "retry_after", 0), 0), 10)
                time.sleep(retry_after or self.retry_delay_seconds * (attempt + 1))
        raise RuntimeError("unreachable security report retry state")

    def _parse(self, report_type: str, item: dict, components: list[Component], now: datetime) -> dict | None:
        metadata = item.get("metadata", {})
        labels = metadata.get("labels", {})
        report = item.get("report", {})
        namespace = labels.get("trivy-operator.resource.namespace") or metadata.get("namespace", "")
        workload_kind = labels.get("trivy-operator.resource.kind", "")
        workload_name = labels.get("trivy-operator.resource.name", "")
        container = labels.get("trivy-operator.container.name", "")
        if report_type == "config_audit" and workload_kind.lower() not in WORKLOAD_KINDS:
            return None

        timestamp = report.get("updateTimestamp") or metadata.get("creationTimestamp", "")
        age_seconds = _age_seconds(timestamp, now)
        status = "unknown" if age_seconds is None else "stale" if age_seconds > self.stale_after_seconds else "fresh"
        artifact = report.get("artifact", {})
        scanner = report.get("scanner", {})
        summary = _severity_summary(report.get("summary", {}))
        component = _match_component(components, namespace, workload_kind, workload_name, container, artifact)
        findings = []
        finding_count = 0
        sbom_packages = []
        sbom_component_count = int(report.get("summary", {}).get("componentsCount", 0) or 0)
        fixable = 0
        if report_type == "vulnerability":
            vulnerabilities = report.get("vulnerabilities", [])
            finding_count = len(vulnerabilities)
            fixable = sum(bool(item.get("fixedVersion")) for item in vulnerabilities)
            findings = _prioritized_vulnerabilities(vulnerabilities)
        elif report_type == "config_audit":
            failed = [check for check in report.get("checks", []) if not check.get("success", False)]
            finding_count = len(failed)
            findings = sorted(
                (_config_check(check) for check in failed),
                key=lambda item: (_severity_rank(item["severity"]), item["id"]),
            )[:MAX_FINDINGS_PER_REPORT]
        elif report_type == "sbom":
            raw_sbom_packages = report.get("components", {}).get("components", [])
            sbom_component_count = max(sbom_component_count, len(raw_sbom_packages))
            sbom_packages = sorted(
                (_sbom_package(item) for item in raw_sbom_packages),
                key=lambda item: (item["name"].lower(), item["version"].lower(), item["type"].lower()),
            )[:MAX_SBOM_COMPONENTS_PER_REPORT]

        return {
            "report_type": report_type,
            "namespace": namespace,
            "workload_kind": workload_kind,
            "workload_name": workload_name,
            "container": container,
            "component": component.name if component else "",
            "component_instance": component.instance if component else "",
            "application": component.metadata.get("application", "") if component else "",
            "inventory": {
                "namespace": component.metadata.get("namespace", ""),
                "workload_kind": component.metadata.get("workload_kind", ""),
                "workload_name": component.metadata.get("workload_name", ""),
                "container": component.metadata.get("container", ""),
            } if component else None,
            "image": _image(artifact, report.get("registry", {})),
            "image_digest": artifact.get("digest", ""),
            "scanner": {
                "name": scanner.get("name", ""),
                "vendor": scanner.get("vendor", ""),
                "version": scanner.get("version", ""),
            },
            "generated_at": timestamp,
            "age_seconds": age_seconds,
            "status": status,
            "summary": summary,
            "fixable": fixable,
            "sbom_components": sbom_component_count,
            "sbom_packages": sbom_packages,
            "sbom_packages_truncated": sbom_component_count > len(sbom_packages),
            "findings": findings,
            "findings_truncated": finding_count > len(findings),
        }

    def _result(self, available: bool, reports: list[dict], components: list[Component], errors: list[str], now: datetime) -> dict:
        vulnerability_reports = [item for item in reports if item["report_type"] == "vulnerability"]
        vuln_summary = {severity: sum(item["summary"][severity] for item in vulnerability_reports) for severity in SEVERITIES}
        config_reports = [item for item in reports if item["report_type"] == "config_audit"]
        secret_reports = [item for item in reports if item["report_type"] == "exposed_secret"]
        sbom_reports = [item for item in reports if item["report_type"] == "sbom"]
        eligible = [item for item in components if item.metadata.get("container")]
        scanned = {
            (
                item["inventory"]["namespace"],
                item["inventory"]["workload_kind"].lower(),
                item["inventory"]["workload_name"],
                item["inventory"]["container"],
            )
            for item in vulnerability_reports
            if item["inventory"]
        }
        covered = sum(
            (
                item.metadata.get("namespace", ""),
                item.metadata.get("workload_kind", "").lower(),
                item.metadata.get("workload_name", ""),
                item.metadata.get("container", ""),
            ) in scanned
            for item in eligible
        )
        if not available or errors or not reports:
            status = "unknown"
        elif any(item["status"] != "fresh" for item in reports):
            status = "stale"
        else:
            status = "fresh"
        return {
            "enabled": True,
            "available": available,
            "status": status,
            "collected_at": now.isoformat().replace("+00:00", "Z"),
            "stale_after_seconds": self.stale_after_seconds,
            "errors": errors,
            "summary": {
                **vuln_summary,
                "vulnerabilities": sum(vuln_summary.values()),
                "fixable": sum(item["fixable"] for item in vulnerability_reports),
                "misconfigurations": sum(sum(item["summary"].values()) for item in config_reports),
                "exposed_secrets": sum(sum(item["summary"].values()) for item in secret_reports),
                "sbom_components": sum(item["sbom_components"] for item in sbom_reports),
                "reports": len(reports),
                "eligible_containers": len(eligible),
                "covered_containers": covered,
            },
            "reports": reports,
        }


def empty_security(enabled: bool = True) -> dict:
    summary = {severity: 0 for severity in SEVERITIES}
    summary.update(
        vulnerabilities=0,
        fixable=0,
        misconfigurations=0,
        exposed_secrets=0,
        sbom_components=0,
        reports=0,
        eligible_containers=0,
        covered_containers=0,
    )
    return {
        "enabled": enabled,
        "available": False,
        "status": "unknown",
        "collected_at": "",
        "stale_after_seconds": 86400,
        "errors": [],
        "summary": summary,
        "reports": [],
    }


def _severity_summary(summary: dict) -> dict:
    return {
        severity: int(summary.get(f"{severity}Count", 0) or 0)
        for severity in SEVERITIES
    }


def _age_seconds(value: str, now: datetime) -> int | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return max(0, int((now - parsed).total_seconds()))
    except (TypeError, ValueError):
        return None


def _match_component(components, namespace, kind, name, container, artifact):
    exact = [
        item for item in components
        if item.metadata.get("namespace") == namespace
        and item.metadata.get("workload_kind", "").lower() == kind.lower()
        and item.metadata.get("workload_name") == name
        and (not container or item.metadata.get("container") == container)
    ]
    if exact:
        return exact[0]
    repository = artifact.get("repository", "")
    return next(
        (
            item for item in components
            if item.metadata.get("namespace") == namespace
            and (not container or item.metadata.get("container") == container)
            and repository
            and repository in item.metadata.get("image", "")
        ),
        None,
    )


def _image(artifact: dict, registry: dict) -> str:
    repository = artifact.get("repository", "")
    server = registry.get("server", "")
    tag = artifact.get("tag", "")
    base = "/".join(part.strip("/") for part in (server, repository) if part)
    return f"{base}:{tag}" if tag else base


def _safe_https_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return ""
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        return ""
    return value[:2048]


def _vulnerability(item: dict) -> dict:
    return {
        "id": str(item.get("vulnerabilityID", ""))[:128],
        "severity": str(item.get("severity", "UNKNOWN")).lower(),
        "package": str(item.get("resource", ""))[:256],
        "installed_version": str(item.get("installedVersion", ""))[:256],
        "fixed_version": str(item.get("fixedVersion", ""))[:256],
        "title": str(item.get("title", ""))[:512],
        "url": _safe_https_url(item.get("primaryLink", "")),
    }


def _prioritized_vulnerabilities(vulnerabilities: list[dict]) -> list[dict]:
    findings = sorted(
        (_vulnerability(item) for item in vulnerabilities),
        key=lambda item: (_severity_rank(item["severity"]), item["id"]),
    )
    if len(findings) <= MAX_FINDINGS_PER_REPORT:
        return findings

    critical = [item for item in findings if item["severity"] == "critical"]
    high = [item for item in findings if item["severity"] == "high"]
    if not critical or not high:
        return findings[:MAX_FINDINGS_PER_REPORT]

    high_count = min(len(high), MIN_HIGH_FINDINGS_PER_REPORT)
    critical_count = min(len(critical), MAX_FINDINGS_PER_REPORT - high_count)
    selected = critical[:critical_count] + high[:high_count]
    remaining = critical[critical_count:] + high[high_count:] + [
        item for item in findings if item["severity"] not in {"critical", "high"}
    ]
    return selected + remaining[:MAX_FINDINGS_PER_REPORT - len(selected)]


def _config_check(item: dict) -> dict:
    return {
        "id": str(item.get("checkID", ""))[:128],
        "severity": str(item.get("severity", "UNKNOWN")).lower(),
        "title": str(item.get("title", ""))[:512],
    }


def _sbom_package(item: dict) -> dict:
    licenses = []
    for entry in item.get("licenses", [])[:5]:
        license_data = entry.get("license", {})
        value = entry.get("expression") or license_data.get("id") or license_data.get("name")
        if value and value not in licenses:
            licenses.append(str(value)[:128])
    return {
        "name": str(item.get("name", ""))[:256],
        "version": str(item.get("version", ""))[:256],
        "type": str(item.get("type", ""))[:64],
        "group": str(item.get("group", ""))[:256],
        "purl": str(item.get("purl", ""))[:512],
        "licenses": licenses,
    }


def _severity_rank(value: str) -> int:
    try:
        return SEVERITIES.index(value.lower())
    except ValueError:
        return len(SEVERITIES)
