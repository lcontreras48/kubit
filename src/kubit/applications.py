from collections.abc import Iterable

from .models import Component


def build_application_components(
    components: Iterable[Component],
    discovered: dict[str, dict] | None = None,
) -> list[Component]:
    """Build one logical component for every discovered delivery application."""
    groups: dict[str, dict] = {}
    discovered = discovered or {}
    for component in components:
        application = component.metadata.get("application")
        namespace = component.metadata.get("namespace")
        if application and namespace and not component.metadata.get("application_group"):
            application_id = component.metadata.get("application_id") or f"namespace:{namespace}:{application}"
            group = groups.setdefault(
                application_id,
                {"name": application, "namespace": namespace, "members": []},
            )
            group["members"].append(component)

    for name, application in discovered.items():
        namespace = application.get("destination_namespace") or application.get("namespace")
        if namespace:
            group = groups.setdefault(
                f"argocd:{name}",
                {"name": name, "namespace": namespace, "members": []},
            )
            group["namespace"] = namespace

    applications = []
    for application_id, group in groups.items():
        name = group["name"]
        namespace = group["namespace"]
        members = group["members"]
        application = discovered.get(name, {})
        version, mode = _application_version(members)
        charts = sorted(
            {
                (item.metadata.get("chart_name"), item.metadata.get("chart_version"))
                for item in members
                if item.metadata.get("chart_name") and item.metadata.get("chart_version")
            }
        )
        parent_chart = next((chart for chart in charts if chart[0] == name), ("", ""))
        methods = {item.metadata.get("deployment_method", "unknown") for item in members}
        deployment_method = _deployment_method(methods, bool(application))
        workloads = {}
        for member in members:
            key = member.metadata.get("workload", member.source)
            workloads.setdefault(key, member.metadata)
        pod_total = sum(item.get("pod_total", 0) for item in workloads.values())
        pod_ready = sum(item.get("pod_ready", 0) for item in workloads.values())
        applications.append(
            Component(
                name,
                version,
                f"application-group/{deployment_method}",
                namespace,
                {
                    "namespace": namespace,
                    "application": name,
                    "application_id": application_id,
                    "application_role": "application",
                    "application_group": True,
                    "version_mode": mode,
                    "deployment_method": deployment_method,
                    "grouping_evidence": "argocd-application" if application else "workload-metadata",
                    "chart_name": parent_chart[0],
                    "chart_version": parent_chart[1],
                    "charts": [
                        {"name": chart_name, "version": chart_version}
                        for chart_name, chart_version in charts
                    ],
                    "members": sorted({item.name for item in members}),
                    "member_count": len(members),
                    "workload_count": len(workloads),
                    "pod_total": pod_total,
                    "pod_ready": pod_ready,
                    "sync_status": application.get("sync_status", "unknown"),
                    "health_status": application.get("health_status", "unknown"),
                    "source_revision": application.get("source_revision", ""),
                    "source_repositories": application.get("source_repositories", []),
                },
            )
        )
    return applications


def _application_version(members: list[Component]) -> tuple[str, str]:
    core = [
        item
        for item in members
        if item.metadata.get("application_role") == "core"
        and item.version
        and item.version != "unknown"
    ]
    versioned = core or [
        item
        for item in members
        if item.metadata.get("application_role") not in {"dependency", "addon", "sidecar", "hook"}
        and item.version
        and item.version != "unknown"
    ]
    by_product: dict[str, set[str]] = {}
    for item in versioned:
        by_product.setdefault(item.name, set()).add(item.version)
    if any(len(versions) > 1 for versions in by_product.values()):
        return "mixed", "skew"
    versions = sorted({item.version for item in versioned})
    if len(versions) == 1:
        return versions[0], "uniform"
    if len(versions) > 1 or len({item.name for item in members}) > 1:
        return "multiple", "composite"
    return "unknown", "unknown"


def _deployment_method(methods: set[str], argo_application: bool) -> str:
    if "argocd-helm" in methods:
        return "argocd-helm"
    if argo_application or "argocd" in methods:
        return "argocd"
    if "helm" in methods:
        return "helm"
    return "unknown"
