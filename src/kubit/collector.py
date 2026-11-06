import json
import os
import re
import ssl
import urllib.error
import urllib.request
from collections.abc import Iterable
from urllib.parse import urlsplit

from .applications import build_application_components
from .models import Component
from .versions import image_tag, parse


# Path to the projected ServiceAccount token; the literal is not a credential.
TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"  # nosec B105
CA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"


class KubernetesAPIError(RuntimeError):
    def __init__(self, path: str, status: int, retry_after: int = 0):
        super().__init__(f"Kubernetes API {path} returned HTTP {status}")
        self.status = status
        self.retry_after = retry_after


class KubernetesAPI:
    def __init__(self, base_url: str | None = None, token_path: str = TOKEN_PATH):
        host = os.getenv("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
        port = os.getenv("KUBERNETES_SERVICE_PORT_HTTPS", "443")
        self.base_url = base_url or f"https://{host}:{port}"
        parsed = urlsplit(self.base_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Kubernetes API base URL must be an HTTPS origin")
        with open(token_path, encoding="utf-8") as token_file:
            self.token = token_file.read().strip()
        self.context = ssl.create_default_context(cafile=CA_PATH)

    def get(self, path: str) -> dict:
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            headers={"Authorization": f"Bearer {self.token}", "Accept": "application/json"},
        )
        try:
            # The origin is constrained to HTTPS during initialization.
            with urllib.request.urlopen(request, context=self.context, timeout=20) as response:  # nosec B310
                return json.load(response)
        except urllib.error.HTTPError as error:
            try:
                retry_after = int(error.headers.get("Retry-After", "0"))
            except (AttributeError, TypeError, ValueError):
                retry_after = 0
            raise KubernetesAPIError(path, error.code, retry_after) from error

    def get_optional(self, path: str) -> dict:
        try:
            return self.get(path)
        except RuntimeError:
            return {}


class Collector:
    WORKLOAD_PATHS = (
        ("deployment", "/apis/apps/v1/deployments"),
        ("daemonset", "/apis/apps/v1/daemonsets"),
        ("statefulset", "/apis/apps/v1/statefulsets"),
        ("job", "/apis/batch/v1/jobs"),
    )
    APPLICATION_DETECTORS = {
        "cloudnativepg": re.compile(r"(?:cloudnative-pg|/cnpg)(?:[:/@-]|$)", re.I),
        "kasten-k10": re.compile(r"(?:^|/)(?:k10|kasten)(?:/|:|@|-)", re.I),
        "argocd": re.compile(r"(?:^|/)argocd(?::|@)", re.I),
        "prometheus-operator": re.compile(r"(?:^|/)prometheus-operator(?::|@)", re.I),
        "prometheus-config-reloader": re.compile(r"(?:^|/)prometheus-config-reloader(?::|@)", re.I),
        "prometheus": re.compile(r"(?:^|/)prometheus(?::|@)", re.I),
        "alertmanager": re.compile(r"(?:^|/)alertmanager(?::|@)", re.I),
    }
    POD_PREFIXES = {
        "kube-apiserver-": "kube-apiserver",
        "kube-controller-manager-": "kube-controller-manager",
        "kube-scheduler-": "kube-scheduler",
        "cloud-controller-manager-": "cloud-controller-manager",
        "kube-proxy-": "kube-proxy",
        "etcd-": "etcd",
        "kube-flannel-": "flannel",
        "cilium-": "cilium",
    }
    NODE_AGENT_WORKLOADS = {
        "kube-proxy": "kube-proxy",
        "kube-flannel": "flannel",
        "cilium": "cilium",
    }

    def __init__(self, api: KubernetesAPI):
        self.api = api

    def collect(self) -> list[Component]:
        components: list[Component] = []
        version = self.api.get("/version").get("gitVersion", "unknown")
        components.append(Component("kubernetes", version, "kubernetes-api"))
        components.extend(self._nodes(self.api.get("/api/v1/nodes").get("items", [])))
        pods = self.api.get("/api/v1/pods").get("items", [])
        replicasets = self.api.get("/apis/apps/v1/replicasets").get("items", [])
        applications = self._applications(
            self.api.get_optional("/apis/argoproj.io/v1alpha1/applications").get("items", [])
        )
        resource_owners = self._application_resources(applications)
        pod_runtime = self._pod_runtime(pods, replicasets)
        pod_components = self._pods(pods)
        components.extend(pod_components)
        if not any(component.name == "kube-apiserver" for component in components):
            components.append(Component("kube-apiserver", version, "kubernetes-api", "api-endpoint"))
        collected_node_agents = {
            component.name for component in pod_components if component.name in self.NODE_AGENT_WORKLOADS.values()
        }
        for kind, path in self.WORKLOAD_PATHS:
            components.extend(
                self._workloads(
                    kind,
                    self.api.get(path).get("items", []),
                    collected_node_agents,
                    resource_owners,
                    pod_runtime,
                )
            )
        crds = self.api.get("/apis/apiextensions.k8s.io/v1/customresourcedefinitions")
        components.append(Component("crds", str(len(crds.get("items", []))), "kubernetes-api"))
        components.extend(build_application_components(components, applications))
        return _deduplicate(components)

    def _applications(self, items: Iterable[dict]) -> dict[str, dict]:
        found = {}
        for item in items:
            metadata = item.get("metadata", {})
            spec = item.get("spec", {})
            status = item.get("status", {})
            name = metadata.get("name", "")
            if not name:
                continue
            sources = spec.get("sources") or ([spec.get("source", {})] if spec.get("source") else [])
            found[name] = {
                "name": name,
                "namespace": metadata.get("namespace", ""),
                "destination_namespace": spec.get("destination", {}).get("namespace", ""),
                "sync_status": status.get("sync", {}).get("status", "unknown"),
                "health_status": status.get("health", {}).get("status", "unknown"),
                "source_revision": status.get("sync", {}).get("revision", ""),
                "source_repositories": sorted(
                    {source.get("repoURL", "") for source in sources if source.get("repoURL")}
                ),
                "resources": status.get("resources", []),
            }
        return found

    @staticmethod
    def _application_resources(applications: dict[str, dict]) -> dict[tuple[str, str, str], str]:
        owners = {}
        for name, application in applications.items():
            destination = application.get("destination_namespace", "")
            for resource in application.get("resources", []):
                kind = resource.get("kind", "").lower()
                resource_name = resource.get("name", "")
                namespace = resource.get("namespace") or destination
                if kind and resource_name and namespace:
                    owners[(kind, namespace, resource_name)] = name
        return owners

    @staticmethod
    def _pod_runtime(pods: Iterable[dict], replicasets: Iterable[dict]) -> dict[tuple[str, str, str], list[dict]]:
        replica_owners = {}
        for replicaset in replicasets:
            metadata = replicaset.get("metadata", {})
            owner = _controller_owner(metadata)
            if owner and owner.get("kind") == "Deployment":
                replica_owners[(metadata.get("namespace", "default"), metadata.get("name", ""))] = owner.get("name", "")

        runtime: dict[tuple[str, str, str], list[dict]] = {}
        for pod in pods:
            metadata = pod.get("metadata", {})
            namespace = metadata.get("namespace", "default")
            owner = _controller_owner(metadata)
            if not owner:
                continue
            owner_kind = owner.get("kind", "").lower()
            owner_name = owner.get("name", "")
            if owner_kind == "replicaset":
                owner_name = replica_owners.get((namespace, owner_name), "")
                owner_kind = "deployment"
            if owner_kind not in {"deployment", "statefulset", "daemonset", "job"} or not owner_name:
                continue
            spec = pod.get("spec", {})
            status = pod.get("status", {})
            declared = {
                container.get("name", ""): container.get("image", "")
                for container in spec.get("containers", []) + spec.get("initContainers", [])
            }
            statuses = status.get("containerStatuses", []) + status.get("initContainerStatuses", [])
            by_name = {container.get("name", ""): container for container in statuses}
            for container_name, image in declared.items():
                container_status = by_name.get(container_name, {})
                phase = status.get("phase", "Unknown")
                runtime.setdefault((owner_kind, namespace, owner_name), []).append(
                    {
                        "pod": metadata.get("name", ""),
                        "container": container_name,
                        "image": container_status.get("image", image),
                        "image_id": container_status.get("imageID", ""),
                        "phase": phase,
                        "ready": bool(container_status.get("ready")) or phase == "Succeeded",
                    }
                )
        return runtime

    def _nodes(self, nodes: Iterable[dict]) -> list[Component]:
        found: list[Component] = []
        for node in nodes:
            name = node.get("metadata", {}).get("name", "unknown")
            info = node.get("status", {}).get("nodeInfo", {})
            found.append(Component("kubelet", info.get("kubeletVersion", "unknown"), "node", name))
            runtime = info.get("containerRuntimeVersion", "unknown")
            found.append(Component("containerd", runtime.split("://")[-1], "node", name))
            os_image = info.get("osImage", "unknown")
            if "talos" in os_image.lower():
                version = parse(os_image)
                normalized = f"{version.major}.{version.minor}.{version.patch}" if version else os_image
                found.append(Component("talos", normalized, "node", name))
        return found

    def _pods(self, pods: Iterable[dict]) -> list[Component]:
        found: list[Component] = []
        for pod in pods:
            metadata = pod.get("metadata", {})
            if metadata.get("namespace") != "kube-system":
                continue
            name = metadata.get("name", "")
            component = next(
                (value for prefix, value in self.POD_PREFIXES.items() if name.startswith(prefix)),
                None,
            )
            if not component:
                continue
            node = pod.get("spec", {}).get("nodeName", "unknown")
            containers = pod.get("spec", {}).get("containers", [])
            image = next(
                (
                    container.get("image", "")
                    for container in containers
                    if component in container.get("image", "")
                    or (component == "flannel" and "flannel" in container.get("image", ""))
                ),
                containers[0].get("image", "") if containers else "",
            )
            found.append(
                Component(
                    component,
                    image_tag(image),
                    f"pod/kube-system/{name}",
                    node,
                    {"image": image, "pod": name, "namespace": "kube-system"},
                )
            )
        return found

    def _workloads(
        self,
        kind: str,
        workloads: Iterable[dict],
        collected_node_agents: set[str] | None = None,
        resource_owners: dict[tuple[str, str, str], str] | None = None,
        pod_runtime: dict[tuple[str, str, str], list[dict]] | None = None,
    ) -> list[Component]:
        found: list[Component] = []
        collected_node_agents = collected_node_agents or set()
        resource_owners = resource_owners or {}
        pod_runtime = pod_runtime or {}
        for workload in workloads:
            metadata = workload.get("metadata", {})
            namespace = metadata.get("namespace", "default")
            name = metadata.get("name", "unknown")
            node_agent = self._node_agent_component(name)
            if namespace == "kube-system" and kind == "daemonset" and node_agent in collected_node_agents:
                continue
            labels = metadata.get("labels", {})
            annotations = metadata.get("annotations", {})
            tracked_application = _tracked_application(annotations)
            application = (
                tracked_application
                or resource_owners.get((kind, namespace, name), "")
                or _application_name(labels)
            )
            grouping_evidence = (
                "argocd-tracking-id"
                if tracked_application
                else "argocd-status-resource"
                if resource_owners.get((kind, namespace, name))
                else "standard-label"
                if application
                else "unattributed"
            )
            chart_name, chart_version = _chart_identity(labels.get("helm.sh/chart", ""))
            managed_by = labels.get("app.kubernetes.io/managed-by", "")
            argo_owned = bool(tracked_application or resource_owners.get((kind, namespace, name)))
            application_id = (
                f"argocd:{application}"
                if application and argo_owned
                else f"namespace:{namespace}:{application}"
                if application
                else ""
            )
            deployment_method = (
                "argocd-helm"
                if argo_owned and (managed_by.lower() == "helm" or chart_name)
                else "argocd"
                if argo_owned
                else "helm"
                if managed_by.lower() == "helm"
                else "unknown"
            )
            pod_spec = workload.get("spec", {}).get("template", {}).get("spec", {})
            containers = pod_spec.get("containers", []) + pod_spec.get("initContainers", [])
            runtime_entries = pod_runtime.get((kind, namespace, name), [])
            for container_index, container in enumerate(containers):
                image = container.get("image", "")
                if not image:
                    continue
                detected_component = self._component_name(image, name, namespace)
                component = detected_component or labels.get("app.kubernetes.io/name") or _image_name(image)
                label_version = labels.get("app.kubernetes.io/version")
                application_role = _application_role(
                    application,
                    image,
                    labels,
                    kind,
                    container_index,
                )
                # Product detectors bind a concrete image to its product, so
                # the image tag is authoritative. Workload labels frequently
                # contain the Helm chart version instead (for example the
                # kube-prometheus-stack chart on Prometheus StatefulSets).
                # The same applies to a core member whose application identity
                # is independently established from Argo/Helm ownership.
                version = (
                    image_tag(image)
                    if detected_component or application_role == "core"
                    else label_version or image_tag(image)
                )
                container_name = container.get("name", "")
                observed = [entry for entry in runtime_entries if entry["container"] == container_name]
                found.append(
                    Component(
                        component,
                        version,
                        f"{kind}/{namespace}/{name}",
                        namespace,
                        {
                            "image": image,
                            "namespace": namespace,
                            "application": application,
                            "application_id": application_id,
                            "application_role": application_role,
                            "grouping_evidence": grouping_evidence,
                            "deployment_method": deployment_method,
                            "chart_name": chart_name,
                            "chart_version": chart_version,
                            "workload": f"{kind}/{namespace}/{name}",
                            "workload_kind": kind,
                            "workload_name": name,
                            "container": container_name,
                            "pod_total": len({entry["pod"] for entry in observed}),
                            "pod_ready": len({entry["pod"] for entry in observed if entry["ready"]}),
                            "pod_phases": sorted({entry["phase"] for entry in observed}),
                            "running_images": sorted({entry["image"] for entry in observed if entry["image"]}),
                            "running_image_ids": sorted(
                                {entry["image_id"] for entry in observed if entry["image_id"]}
                            ),
                        },
                    )
                )
        return found

    def _node_agent_component(self, name: str) -> str | None:
        # These DaemonSets are already collected from their Pods so that Kubit
        # can preserve the node identity required by instance-matched rules.
        # Keeping the logical DaemonSet as well creates a duplicate cluster-wide
        # component which cannot be matched to a node (for example kube-proxy).
        return next(
            (
                component
                for base, component in self.NODE_AGENT_WORKLOADS.items()
                if name == base or name.startswith(f"{base}-")
            ),
            None,
        )

    def _component_name(self, image: str, name: str, namespace: str) -> str | None:
        for component, detector in self.APPLICATION_DETECTORS.items():
            if detector.search(image):
                return component
        return None


def _deduplicate(components: Iterable[Component]) -> list[Component]:
    # Operators such as Kasten and Argo CD have several workloads carrying the
    # same product version. Report one product instance per namespace/version.
    unique = {(item.name, item.version, item.instance): item for item in components}
    return sorted(unique.values(), key=lambda item: (item.name, item.instance, item.version))


def _image_name(image: str) -> str:
    without_digest = image.split("@", 1)[0]
    return without_digest.rsplit("/", 1)[-1].split(":", 1)[0] or "unknown-image"


def _tracked_application(annotations: dict) -> str:
    tracking_id = annotations.get("argocd.argoproj.io/tracking-id", "")
    return tracking_id.split(":", 1)[0] if tracking_id else ""


def _application_name(labels: dict) -> str:
    return labels.get("app.kubernetes.io/part-of") or labels.get("app.kubernetes.io/instance") or ""


def _chart_identity(value: str) -> tuple[str, str]:
    match = re.match(r"^(.+)-(v?\d+\.\d+\.\d+(?:[-+].*)?)$", value)
    return match.groups() if match else ("", "")


def _application_role(
    application: str,
    image: str,
    labels: dict,
    kind: str,
    container_index: int,
) -> str:
    if not application:
        return "unassigned"
    if kind == "job":
        return "hook"
    if container_index:
        return "sidecar"
    part_of = labels.get("app.kubernetes.io/part-of", "")
    if part_of and part_of != application:
        return "addon"
    normalized_application = re.sub(r"[^a-z0-9]", "", application.lower())
    # Match the product image name, not registry organizations such as
    # prometheuscommunity; those can host unrelated add-ons.
    normalized_image = re.sub(r"[^a-z0-9]", "", _image_name(image).lower())
    if normalized_application and normalized_application in normalized_image:
        return "core"
    if part_of == application:
        return "dependency"
    instance = labels.get("app.kubernetes.io/instance", "")
    if instance and instance != application:
        return "dependency"
    return "component"


def _controller_owner(metadata: dict) -> dict | None:
    owners = metadata.get("ownerReferences", [])
    return next((owner for owner in owners if owner.get("controller")), owners[0] if owners else None)
