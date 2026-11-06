from collections import Counter

from .models import Component, ProviderState, Result


def _escape(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _labels(**labels: object) -> str:
    return ",".join(f'{name}="{_escape(value)}"' for name, value in labels.items())


def render(
    components: list[Component],
    results: list[Result],
    scan_success: bool,
    duration: float,
    last_success_timestamp: float = 0,
    providers: list[ProviderState] | None = None,
    security: dict | None = None,
) -> str:
    providers = providers or []
    security = security or {}
    component_metadata = {
        (component.name, component.version, component.instance): component.metadata
        for component in components
    }
    lines = [
        "# HELP kubit_component_info Components and versions discovered in the cluster.",
        "# TYPE kubit_component_info gauge",
    ]
    for component in components:
        lines.append(
            f"kubit_component_info{{{_labels(component=component.name, version=component.version, source=component.source, component_namespace=component.metadata.get('namespace', ''), component_instance=component.instance, application=component.metadata.get('application', ''), application_role=component.metadata.get('application_role', ''), version_mode=component.metadata.get('version_mode', ''))}}} 1"
        )
    lines.extend(
        [
            "# HELP kubit_component_runtime_pods Pods observed for an application component.",
            "# TYPE kubit_component_runtime_pods gauge",
        ]
    )
    for component in components:
        if "pod_total" not in component.metadata:
            continue
        labels = dict(
            component=component.name,
            version=component.version,
            component_namespace=component.metadata.get("namespace", ""),
            component_instance=component.instance,
            application=component.metadata.get("application", ""),
        )
        lines.append(
            f"kubit_component_runtime_pods{{{_labels(**labels, state='observed')}}} {component.metadata.get('pod_total', 0)}"
        )
        lines.append(
            f"kubit_component_runtime_pods{{{_labels(**labels, state='ready')}}} {component.metadata.get('pod_ready', 0)}"
        )
    lines.extend(
        [
            "# HELP kubit_compatibility_status Compatibility evaluation by component.",
            "# TYPE kubit_compatibility_status gauge",
        ]
    )
    for result in results:
        metadata = component_metadata.get((result.component, result.version, result.instance), {})
        lines.append(
            f"kubit_compatibility_status{{{_labels(component=result.component, version=result.version, dependency=result.dependency, dependency_version=result.dependency_version, status=result.status, reason=result.reason, rule=result.rule, component_namespace=metadata.get('namespace', ''), component_instance=result.instance, application=metadata.get('application', ''), application_role=metadata.get('application_role', ''), evidence_status=result.evidence_status, evidence_provider=result.evidence_provider, evidence_title=result.evidence_title, evidence_url=result.evidence)}}} 1"
        )
    counts = Counter(result.status for result in results)
    lines.extend(["# HELP kubit_compatibility_results Number of compatibility results by status.", "# TYPE kubit_compatibility_results gauge"])
    for status in ("supported", "unsupported", "incompatible", "stale", "unknown"):
        lines.append(f'kubit_compatibility_results{{status="{status}"}} {counts[status]}')
    lines.extend(
        [
            "# HELP kubit_evidence_provider_info State of an automatic evidence provider.",
            "# TYPE kubit_evidence_provider_info gauge",
            "# HELP kubit_evidence_provider_age_seconds Age of the provider's last valid evidence.",
            "# TYPE kubit_evidence_provider_age_seconds gauge",
        ]
    )
    for provider in providers:
        labels = _labels(
            provider=provider.name,
            source_url=provider.source_url,
            status=provider.status,
            checksum=provider.checksum,
        )
        lines.append(f"kubit_evidence_provider_info{{{labels}}} 1")
        lines.append(f'kubit_evidence_provider_age_seconds{{provider="{_escape(provider.name)}"}} {provider.age_seconds:.0f}')
    security_summary = security.get("summary", {})
    lines.extend(
        [
            "# HELP kubit_security_collector_enabled Whether Trivy report collection is enabled.",
            "# TYPE kubit_security_collector_enabled gauge",
            f"kubit_security_collector_enabled {1 if security.get('enabled', True) else 0}",
            "# HELP kubit_security_collector_available Whether Trivy report APIs were readable.",
            "# TYPE kubit_security_collector_available gauge",
            f"kubit_security_collector_available {1 if security.get('available') else 0}",
            "# HELP kubit_security_summary Security totals reported by Trivy without CVE label cardinality.",
            "# TYPE kubit_security_summary gauge",
        ]
    )
    for finding_type in ("vulnerabilities", "fixable", "misconfigurations", "exposed_secrets", "sbom_components"):
        lines.append(
            f'kubit_security_summary{{finding_type="{finding_type}"}} {int(security_summary.get(finding_type, 0) or 0)}'
        )
    lines.extend(
        [
            "# HELP kubit_security_coverage_containers Inventory containers by Trivy coverage state.",
            "# TYPE kubit_security_coverage_containers gauge",
            f'kubit_security_coverage_containers{{state="eligible"}} {int(security_summary.get("eligible_containers", 0) or 0)}',
            f'kubit_security_coverage_containers{{state="covered"}} {int(security_summary.get("covered_containers", 0) or 0)}',
            "# HELP kubit_security_report_findings Findings in each Trivy report by severity.",
            "# TYPE kubit_security_report_findings gauge",
            "# HELP kubit_security_report_age_seconds Age of each Trivy report, or -1 when unknown.",
            "# TYPE kubit_security_report_age_seconds gauge",
            "# HELP kubit_security_report_fixable Fixable vulnerabilities in each Trivy report.",
            "# TYPE kubit_security_report_fixable gauge",
        ]
    )
    for report in security.get("reports", []):
        labels = dict(
            report_type=report.get("report_type", ""),
            component_namespace=report.get("namespace", ""),
            workload_kind=report.get("workload_kind", ""),
            workload=report.get("workload_name", ""),
            container=report.get("container", ""),
            component=report.get("component", ""),
            application=report.get("application", ""),
            status=report.get("status", "unknown"),
            scanner=report.get("scanner", {}).get("name", ""),
            scanner_version=report.get("scanner", {}).get("version", ""),
        )
        for severity in ("critical", "high", "medium", "low", "unknown"):
            lines.append(
                f"kubit_security_report_findings{{{_labels(**labels, severity=severity)}}} {int(report.get('summary', {}).get(severity, 0) or 0)}"
            )
        age = report.get("age_seconds")
        lines.append(f"kubit_security_report_age_seconds{{{_labels(**labels)}}} {-1 if age is None else int(age)}")
        if report.get("report_type") == "vulnerability":
            lines.append(f"kubit_security_report_fixable{{{_labels(**labels)}}} {int(report.get('fixable', 0) or 0)}")
    lines.extend(
        [
            "# HELP kubit_last_scan_timestamp_seconds Unix timestamp of the latest completed scan.",
            "# TYPE kubit_last_scan_timestamp_seconds gauge",
            f"kubit_last_scan_timestamp_seconds {last_success_timestamp:.0f}",
            "# HELP kubit_last_scan_success Whether the latest scan succeeded.",
            "# TYPE kubit_last_scan_success gauge",
            f"kubit_last_scan_success {1 if scan_success else 0}",
            "# HELP kubit_last_scan_duration_seconds Duration of the latest scan.",
            "# TYPE kubit_last_scan_duration_seconds gauge",
            f"kubit_last_scan_duration_seconds {duration:.6f}",
        ]
    )
    return "\n".join(lines) + "\n"
