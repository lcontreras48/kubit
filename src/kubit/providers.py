import hashlib
import html
import json
import os
import re
import ssl
import urllib.request
# Input is bounded, and XML declarations/entities are rejected before parsing.
import xml.etree.ElementTree as ET  # nosec B405
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlsplit

from .models import Component, ProviderState


UTC = timezone.utc


@dataclass(frozen=True)
class Snapshot:
    provider: str
    source_url: str
    retrieved_at: str
    checksum: str
    rules: list[dict]


class TextClient:
    def __init__(self, timeout: int = 20, max_bytes: int = 2 * 1024 * 1024):
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.context = ssl.create_default_context()

    def get_text(self, url: str) -> str:
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.fragment
        ):
            raise ValueError("official evidence URL must use HTTPS without credentials or fragments")
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "text/plain, application/json, application/vnd.github+json",
                "User-Agent": "kubit-compatibility-monitor/0.1",
            },
        )
        # The complete URL is constrained above; file and custom schemes cannot reach urlopen.
        with urllib.request.urlopen(request, context=self.context, timeout=self.timeout) as response:  # nosec B310
            content = response.read(self.max_bytes + 1)
        if len(content) > self.max_bytes:
            raise ValueError(f"official evidence exceeds {self.max_bytes} bytes")
        return content.decode("utf-8")


class EvidenceCache:
    def __init__(self, directory: str):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)

    def save(self, snapshot: Snapshot) -> None:
        target = self.directory / f"{snapshot.provider}.json"
        temporary = target.with_suffix(".tmp")
        temporary.write_text(json.dumps(asdict(snapshot), sort_keys=True), encoding="utf-8")
        os.replace(temporary, target)

    def load(self, provider: str) -> Snapshot | None:
        target = self.directory / f"{provider}.json"
        if not target.exists():
            return None
        data = json.loads(target.read_text(encoding="utf-8"))
        return Snapshot(**data)


class Provider:
    name = "provider"
    source_url = ""
    evidence_url = ""
    parser_version = "1"
    fallback = False

    def prepare(self, components: list[Component]) -> None:
        pass

    def fetch(self, client: TextClient, now: datetime) -> Snapshot:
        content = client.get_text(self.source_url)
        rules = self.parse(content)
        if not rules:
            raise ValueError(f"{self.name} returned no compatibility rules")
        return Snapshot(
            provider=self.name,
            source_url=self.source_url,
            retrieved_at=now.astimezone(UTC).isoformat().replace("+00:00", "Z"),
            checksum=hashlib.sha256(content.encode()).hexdigest(),
            rules=rules,
        )

    def parse(self, content: str) -> list[dict]:
        raise NotImplementedError


class KubernetesSkewProvider(Provider):
    name = "kubernetes-version-skew"
    source_url = "https://raw.githubusercontent.com/kubernetes/website/main/content/en/releases/version-skew-policy.md"
    evidence_url = "https://kubernetes.io/releases/version-skew-policy/"

    def parse(self, content: str) -> list[dict]:
        apiserver = _markdown_section(content, "### kube-apiserver", "### kubelet")
        kubelet = _markdown_section(content, "### kubelet", "### kube-proxy")
        proxy = _markdown_section(content, "### kube-proxy", "### kube-controller-manager")
        managers = _markdown_section(content, "### kube-controller-manager", "### kubectl")

        api_spread = _word_number(_require(apiserver, r"within ([a-z]+) minor version"))
        kubelet_older = _word_number(_require(kubelet, r"up to ([a-z]+) minor versions older"))
        kubelet_legacy_series, kubelet_legacy_older = _legacy_skew(kubelet, "kubelet")
        proxy_older = _word_number(_require(proxy, r"up to ([a-z]+) minor versions older"))
        proxy_absolute = _word_number(_require(proxy, r"up to ([a-z]+) minor versions older or newer"))
        proxy_legacy_series, proxy_legacy_older = _legacy_skew(proxy, "kube-proxy")
        manager_older = _word_number(_require(managers, r"up to ([a-z]+) minor version older"))
        if any(
            not re.search(r"must\s+not\s+be\s+newer", section, re.I)
            for section in (kubelet, proxy, managers)
        ):
            raise ValueError("Kubernetes never-newer policy markers changed")

        common = {"provider": self.name, "evidence": self.evidence_url, "parser_version": self.parser_version}
        return [
            {
                **common,
                "id": "kubernetes-apiserver-ha-skew",
                "type": "version_spread",
                "subject": "kube-apiserver",
                "max_minor_spread": api_spread,
            },
            {
                **common,
                "id": "kubernetes-kubelet-apiserver-skew",
                "type": "version_skew",
                "subject": "kubelet",
                "dependency": "kube-apiserver",
                "never_newer": True,
                "max_older_minors": kubelet_older,
                "legacy_before_series": kubelet_legacy_series,
                "legacy_max_older_minors": kubelet_legacy_older,
            },
            {
                **common,
                "id": "kubernetes-kube-proxy-apiserver-skew",
                "type": "version_skew",
                "subject": "kube-proxy",
                "dependency": "kube-apiserver",
                "never_newer": True,
                "max_older_minors": proxy_older,
                "legacy_before_series": proxy_legacy_series,
                "legacy_max_older_minors": proxy_legacy_older,
            },
            {
                **common,
                "id": "kubernetes-kube-proxy-kubelet-skew",
                "type": "version_skew",
                "subject": "kube-proxy",
                "dependency": "kubelet",
                "max_older_minors": proxy_absolute,
                "max_newer_minors": proxy_absolute,
                "legacy_before_series": proxy_legacy_series,
                "legacy_max_older_minors": proxy_legacy_older,
                "legacy_max_newer_minors": proxy_legacy_older,
                "match_instance": True,
            },
            *[
                {
                    **common,
                    "id": f"kubernetes-{component}-apiserver-skew",
                    "type": "version_skew",
                    "subject": component,
                    "dependency": "kube-apiserver",
                    "never_newer": True,
                    "max_older_minors": manager_older,
                }
                for component in ("kube-controller-manager", "kube-scheduler", "cloud-controller-manager")
            ],
        ]


class CloudNativePGProvider(Provider):
    name = "cloudnativepg-supported-releases"
    source_url = "https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/main/docs/src/supported_releases.md"
    evidence_url = "https://cloudnative-pg.io/documentation/current/supported_releases/"

    def parse(self, content: str) -> list[dict]:
        current = _table_after(content, "| Version         | Currently supported")
        old = _table_after(content, "| Version         | Release date", after="## Old releases")
        entries: list[dict] = []
        for cells in current:
            if len(cells) < 7 or not re.fullmatch(r"\d+\.\d+\.x", cells[0]):
                continue
            entry = {
                "subject_series": cells[0].removesuffix(".x"),
                "currently_supported": cells[1].lower() == "yes",
                "supported_dependency_series": _version_list(cells[4]),
                "tested_dependency_series": _version_list(cells[5]),
            }
            end_of_life = _exact_date(cells[3])
            if end_of_life:
                entry["end_of_life"] = end_of_life
            entries.append(entry)
        for cells in old:
            if len(cells) < 4 or not re.fullmatch(r"\d+\.\d+\.x", cells[0]):
                continue
            entry = {
                "subject_series": cells[0].removesuffix(".x"),
                "currently_supported": False,
                "supported_dependency_series": _version_list(cells[3]),
                "tested_dependency_series": [],
            }
            end_of_life = _exact_date(cells[2])
            if end_of_life:
                entry["end_of_life"] = end_of_life
            entries.append(entry)
        if not entries or not any(item["currently_supported"] for item in entries):
            raise ValueError("CloudNativePG support table format changed or has no supported releases")
        return [
            {
                "id": "cloudnativepg-kubernetes-support-matrix",
                "type": "matrix",
                "subject": "cloudnativepg",
                "dependency": "kubernetes",
                "provider": self.name,
                "parser_version": self.parser_version,
                "evidence": self.evidence_url,
                "entries": entries,
            }
        ]


class ContainerdCompatibilityProvider(Provider):
    name = "containerd-kubernetes-recommendations"
    source_url = "https://raw.githubusercontent.com/containerd/containerd/main/RELEASES.md"
    evidence_url = "https://github.com/containerd/containerd/blob/main/RELEASES.md#kubernetes-support"

    def parse(self, content: str) -> list[dict]:
        entries_by_constraint: dict[str, set[str]] = {}
        for cells in _table_after(content, "| Kubernetes Version | containerd Version"):
            if len(cells) < 3:
                continue
            kubernetes = re.fullmatch(r"v?(\d+\.\d+)", cells[0])
            if not kubernetes:
                continue
            for minimum in re.findall(r"v?(\d+\.\d+\.\d+)\+", cells[1]):
                version = parse_release_tag(minimum)
                if not version:
                    continue
                major, minor = map(int, version.split("."))
                constraint = f">={minimum} <{major}.{minor + 1}.0"
                entries_by_constraint.setdefault(constraint, set()).add(kubernetes.group(1))
        if not entries_by_constraint:
            raise ValueError("containerd Kubernetes support table contains no recommendations")
        return [
            {
                "id": "containerd-kubernetes-recommendations",
                "type": "constraint_matrix",
                "subject": "containerd",
                "dependency": "kubernetes",
                "provider": self.name,
                "parser_version": self.parser_version,
                "evidence": self.evidence_url,
                "evidence_title": "containerd Kubernetes support matrix",
                "evidence_basis": "tested",
                "evidence_confidence": "high",
                "outside_status": "unknown",
                "outside_reason": "This containerd/Kubernetes combination is not in the upstream recommendation matrix.",
                "entries": [
                    {
                        "subject_constraints": [constraint],
                        "dependency_constraints": sorted(kubernetes),
                        "status": "supported",
                        "reason": "containerd is in the version range recommended and tested for this Kubernetes release.",
                    }
                    for constraint, kubernetes in sorted(entries_by_constraint.items())
                ],
            }
        ]


class KubeStateMetricsCompatibilityProvider(Provider):
    name = "kube-state-metrics-compatibility"
    source_url = "https://raw.githubusercontent.com/kubernetes/kube-state-metrics/main/README.md"
    evidence_url = "https://github.com/kubernetes/kube-state-metrics#compatibility-matrix"

    def parse(self, content: str) -> list[dict]:
        entries = []
        for cells in _table_after(content, "| kube-state-metrics | Kubernetes client-go Version |"):
            if len(cells) < 2:
                continue
            release = re.search(r"\bv?(\d+\.\d+\.\d+)\b", cells[0])
            kubernetes = re.search(r"\bv?1\.(\d+)\b", cells[1])
            if not release or not kubernetes:
                continue
            series = f"1.{kubernetes.group(1)}"
            entries.append(
                {
                    "subject_constraints": [release.group(1)],
                    "dependency_constraints": [series],
                    "status": "supported",
                    "reason": f"The official kube-state-metrics matrix maps this release to Kubernetes client-go {series}.",
                    "outside_reason": f"This kube-state-metrics release is built for Kubernetes client-go {series}; other Kubernetes versions are documented as best-effort rather than fully supported.",
                }
            )
        if not entries:
            raise ValueError("kube-state-metrics compatibility table contains no release mappings")
        return [
            {
                "id": "kube-state-metrics-kubernetes-compatibility",
                "type": "constraint_matrix",
                "subject": "kube-state-metrics",
                "dependency": "kubernetes",
                "provider": self.name,
                "parser_version": self.parser_version,
                "evidence": self.evidence_url,
                "evidence_title": "kube-state-metrics compatibility matrix",
                "evidence_basis": "supported",
                "evidence_confidence": "high",
                "outside_status": "unknown",
                "entries": entries,
            }
        ]


class KubeRbacProxyAdvisoryProvider(Provider):
    name = "kube-rbac-proxy-project-status"
    source_url = "https://raw.githubusercontent.com/kube-rbac-proxy/kube-rbac-proxy/master/README.md"
    evidence_url = "https://github.com/kube-rbac-proxy/kube-rbac-proxy"

    def parse(self, content: str) -> list[dict]:
        plain = re.sub(r"[*_`]", "", content)
        if not re.search(r"project is alpha stage", plain, re.I):
            raise ValueError("kube-rbac-proxy project-status marker changed")
        return [
            {
                "id": "kube-rbac-proxy-kubernetes-advisory",
                "type": "constraint_matrix",
                "subject": "kube-rbac-proxy",
                "dependency": "kubernetes",
                "provider": self.name,
                "parser_version": self.parser_version,
                "evidence": self.evidence_url,
                "evidence_title": "kube-rbac-proxy project status",
                "evidence_basis": "project-status",
                "evidence_confidence": "high",
                "entries": [
                    {
                        "subject_constraints": [">=0.0"],
                        "dependency_constraints": [">=0.0"],
                        "status": "unknown",
                        "reason": "The upstream project identifies kube-rbac-proxy as alpha and publishes no Kubernetes compatibility matrix; this deployment cannot be marked verified.",
                    }
                ],
            }
        ]


class KubernetesCSISidecarsProvider(Provider):
    name = "kubernetes-csi-sidecar-support"
    source_url = "https://kubernetes-csi.github.io/docs/"
    evidence_url = source_url
    pages = {
        "csi-provisioner": "external-provisioner",
        "csi-attacher": "external-attacher",
        "csi-node-driver-registrar": "node-driver-registrar",
        "csi-resizer": "external-resizer",
        "csi-snapshotter": "external-snapshotter",
    }

    def __init__(self):
        self.observed_names: set[str] = set()

    def prepare(self, components: list[Component]) -> None:
        self.observed_names = {component.name for component in components}

    def fetch(self, client: TextClient, now: datetime) -> Snapshot:
        documents = []
        rules = []
        for component, page in self.pages.items():
            if component not in self.observed_names:
                continue
            url = f"{self.source_url}{page}.html"
            content = client.get_text(url)
            documents.append(content)
            rules.extend(self._parse_page(component, page, content))
        combined = "\n".join(documents) or "no-observed-csi-sidecars"
        return Snapshot(
            provider=self.name,
            source_url=self.source_url,
            retrieved_at=now.astimezone(UTC).isoformat().replace("+00:00", "Z"),
            checksum=hashlib.sha256(combined.encode()).hexdigest(),
            rules=rules,
        )

    def parse(self, content: str) -> list[dict]:
        raise NotImplementedError("CSI pages require a component identity")

    def _parse_page(self, component: str, page: str, content: str) -> list[dict]:
        section = re.search(
            r'id="supported-versions".*?<table>(.*?)</table>.*?id="unsupported-versions"',
            content,
            re.I | re.S,
        )
        if not section:
            raise ValueError(f"CSI {page} supported-version table format changed")
        rows = _html_table_rows(section.group(1))
        if len(rows) < 2:
            raise ValueError(f"CSI {page} supported-version table is empty")
        header = rows[0]
        try:
            release_index = header.index("Latest stable release")
            min_index = header.index("Min K8s Version")
            max_index = header.index("Max K8s Version")
        except ValueError as error:
            raise ValueError(f"CSI {page} table headers changed") from error
        entries = []
        for row in rows[1:]:
            if len(row) <= max(release_index, min_index, max_index):
                continue
            release = re.search(r"v(\d+\.\d+\.\d+)", row[release_index])
            minimum = re.search(r"v?(\d+\.\d+(?:\.\d+)?)", row[min_index])
            maximum = re.search(r"v?(\d+\.\d+(?:\.\d+)?)", row[max_index])
            if not release or not minimum:
                continue
            release_version = release.group(1)
            release_parts = release_version.split(".")
            dependency_constraint = f">={minimum.group(1)}"
            if maximum:
                dependency_constraint += f" <={maximum.group(1)}"
            entries.append(
                {
                    "subject_constraints": [".".join(release_parts[:2])],
                    "dependency_constraints": [dependency_constraint],
                    "status": "supported",
                    "reason": f"This CSI sidecar release series supports Kubernetes {dependency_constraint}.",
                }
            )
        if not entries:
            raise ValueError(f"CSI {page} table contains no supported releases")
        evidence = f"{self.source_url}{page}.html"
        return [
            {
                "id": f"{component}-kubernetes-support",
                "type": "constraint_matrix",
                "subject": component,
                "dependency": "kubernetes",
                "provider": self.name,
                "parser_version": self.parser_version,
                "evidence": evidence,
                "evidence_title": f"Kubernetes CSI {page} supported versions",
                "evidence_basis": "supported",
                "evidence_confidence": "high",
                "outside_status": "unknown",
                "outside_reason": "The deployed Kubernetes version is outside this CSI sidecar's documented support range.",
                "entries": entries,
            }
        ]


class CephCSICompatibilityProvider(Provider):
    name = "ceph-csi-support"
    source_url = "https://raw.githubusercontent.com/ceph/ceph-csi/devel/README.md"
    evidence_url = "https://github.com/ceph/ceph-csi#known-to-work-co-platforms"

    def parse(self, content: str) -> list[dict]:
        entries = []
        for cells in _table_after(content, "| Ceph CSI Version | Container Orchestrator Name"):
            if len(cells) < 3:
                continue
            version = re.fullmatch(r"v?(\d+\.\d+\.\d+)", cells[0])
            kubernetes = _version_list(cells[2])
            if version and "kubernetes" in cells[1].lower() and kubernetes:
                entries.append(
                    {
                        "subject_constraints": [version.group(1)],
                        "dependency_constraints": kubernetes,
                        "status": "supported",
                        "reason": "This Ceph CSI release is listed as tested with the deployed Kubernetes series.",
                    }
                )
        deprecated = content.split("Deprecated Ceph CSI Release/Branch", 1)
        if len(deprecated) == 2:
            section = deprecated[1].split("### Alternative images", 1)[0]
            for version in sorted(set(re.findall(r"\bv(\d+\.\d+\.\d+)\b", section))):
                entries.append(
                    {
                        "subject_constraints": [version],
                        "dependency_constraints": [">=0.0"],
                        "status": "unsupported",
                        "reason": "This Ceph CSI release is listed upstream as deprecated and outside the supported release window.",
                    }
                )
        if not entries:
            raise ValueError("Ceph CSI support document contains no tested or deprecated releases")
        return [
            {
                "id": "ceph-csi-kubernetes-support",
                "type": "constraint_matrix",
                "subject": "cephcsi",
                "dependency": "kubernetes",
                "provider": self.name,
                "parser_version": self.parser_version,
                "evidence": self.evidence_url,
                "evidence_title": "Ceph CSI support and tested-platform matrix",
                "evidence_basis": "supported",
                "evidence_confidence": "high",
                "outside_status": "unknown",
                "outside_reason": "This Ceph CSI/Kubernetes combination is not listed among upstream-tested platforms.",
                "entries": entries,
            }
        ]


class MarkdownVersionMatrixProvider(Provider):
    subject = ""
    dependency = "kubernetes"
    rule_id = ""
    table_header = ""
    supported_reason = "Combination is listed in the official upstream compatibility table."
    outside_reason = "Combination is not listed in the official upstream compatibility table."
    outside_status = "unknown"

    def parse(self, content: str) -> list[dict]:
        entries = []
        for cells in _table_after(content, self.table_header):
            if len(cells) < 2:
                continue
            subject = re.fullmatch(r"v?(\d+\.\d+)(?:\.x)?", cells[0])
            dependencies = _version_list(cells[1])
            if subject and dependencies:
                entries.append(
                    {
                        "subject_series": subject.group(1),
                        "supported_dependency_series": dependencies,
                        "tested_dependency_series": [],
                    }
                )
        if not entries:
            raise ValueError(f"{self.name} official table contains no version relationships")
        return [
            {
                "id": self.rule_id,
                "type": "matrix",
                "subject": self.subject,
                "dependency": self.dependency,
                "provider": self.name,
                "parser_version": self.parser_version,
                "evidence": self.evidence_url,
                "supported_reason": self.supported_reason,
                "unsupported_reason": self.outside_reason,
                "outside_status": self.outside_status,
                "entries": entries,
            }
        ]


class ArgoCDTestedVersionsProvider(MarkdownVersionMatrixProvider):
    name = "argocd-tested-kubernetes-versions"
    source_url = "https://raw.githubusercontent.com/argoproj/argo-cd/stable/docs/operator-manual/tested-kubernetes-versions.md"
    evidence_url = "https://argo-cd.readthedocs.io/en/stable/operator-manual/installation/#tested-versions"
    subject = "argocd"
    rule_id = "argocd-kubernetes-tested-versions"
    table_header = "| Argo CD version | Kubernetes versions |"
    supported_reason = "Combination is listed in the official Argo CD tested Kubernetes versions."
    outside_reason = "Kubernetes version is not listed among the versions tested upstream for this Argo CD series."


class PrometheusOperatorCompatibilityProvider(Provider):
    name = "prometheus-operator-kubernetes-requirements"
    source_url = "https://raw.githubusercontent.com/prometheus-operator/prometheus-operator/main/Documentation/getting-started/compatibility.md"
    evidence_url = "https://prometheus-operator.dev/docs/getting-started/compatibility/#kubernetes"

    def parse(self, content: str) -> list[dict]:
        current = re.search(
            r"prometheus-operator\s*>=\s*v?(\d+\.\d+\.\d+) requires Kubernetes\s*>=\s*v?(\d+\.\d+\.\d+)",
            content,
            re.I,
        )
        legacy = re.search(
            r"Releases before v?(\d+\.\d+\.\d+) require Kubernetes\s*>=\s*v?(\d+\.\d+\.\d+)",
            content,
            re.I,
        )
        exception = re.search(
            r"or\s*v?(\d+\.\d+\.\d+) with the `([^`]+)` feature gate enabled",
            content,
            re.I,
        )
        if not current or not legacy or not exception or current.group(1) != legacy.group(1):
            raise ValueError("Prometheus Operator Kubernetes requirement format changed")
        prometheus = re.search(
            r"supports all Prometheus versions\s*>=\s*v?(\d+\.\d+\.\d+)",
            content,
            re.I,
        )
        alertmanager = re.search(
            r"compatible with Alertmanager v?(\d+\.\d+)(?:\.\d+)? and above",
            content,
            re.I,
        )
        if not prometheus or not alertmanager:
            raise ValueError("Prometheus Operator component compatibility format changed")
        return [
            {
                "id": "prometheus-operator-kubernetes-minimum",
                "type": "minimum_version",
                "subject": "prometheus-operator",
                "dependency": "kubernetes",
                "provider": self.name,
                "parser_version": self.parser_version,
                "evidence": self.evidence_url,
                "entries": [
                    {
                        "subject_min_version": current.group(1),
                        "minimum_dependency_version": current.group(2),
                        "conditional_minimum_dependency_version": exception.group(1),
                        "condition": f"{exception.group(2)} feature gate enabled",
                    },
                    {
                        "subject_max_exclusive": legacy.group(1),
                        "minimum_dependency_version": legacy.group(2),
                    },
                ],
            },
            {
                "id": "prometheus-operator-prometheus-minimum",
                "type": "subject_minimum",
                "subject": "prometheus",
                "dependency": "prometheus-operator",
                "provider": self.name,
                "parser_version": self.parser_version,
                "evidence": self.evidence_url,
                "minimum_subject_version": prometheus.group(1),
            },
            {
                "id": "prometheus-operator-alertmanager-minimum",
                "type": "subject_minimum",
                "subject": "alertmanager",
                "dependency": "prometheus-operator",
                "provider": self.name,
                "parser_version": self.parser_version,
                "evidence": self.evidence_url,
                "minimum_subject_version": f"{alertmanager.group(1)}.0",
            },
        ]


class TalosReleaseProvider(Provider):
    name = "talos-kubernetes-releases"
    source_url = "https://github.com/siderolabs/talos/releases.atom"
    evidence_url = "https://github.com/siderolabs/talos/releases"

    def parse(self, content: str) -> list[dict]:
        if re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", content, re.IGNORECASE):
            raise ValueError("Talos release feed contains forbidden XML declarations")
        try:
            # The client bounds the document to 2 MiB and declarations/entities are rejected above.
            feed = ET.fromstring(content)  # nosec B314
        except ET.ParseError as error:
            raise ValueError("Talos release feed is not valid Atom XML") from error

        combinations: dict[str, set[str]] = {}
        bundled: dict[str, dict[str, set[str]]] = {"coredns": {}, "flannel": {}}
        namespace = {"atom": "http://www.w3.org/2005/Atom"}
        for release in feed.findall("atom:entry", namespace):
            talos_version = parse_release_tag(release.findtext("atom:title", "", namespace))
            body = release.findtext("atom:content", "", namespace)
            kubernetes_match = re.search(
                r"(?:registry\.k8s\.io|ghcr\.io/siderolabs)/(?:kube-apiserver|kubelet):v?(\d+\.\d+)(?:\.\d+)?\b",
                body,
                re.I,
            )
            if not talos_version or not kubernetes_match:
                continue
            kubernetes_series = kubernetes_match.group(1)
            combinations.setdefault(talos_version, set()).add(kubernetes_series)
            component_patterns = {
                "coredns": r"registry\.k8s\.io/coredns/coredns:v?(\d+\.\d+\.\d+)",
                "flannel": r"ghcr\.io/siderolabs/flannel:v?(\d+\.\d+\.\d+)",
            }
            for component, pattern in component_patterns.items():
                match = re.search(pattern, body, re.I)
                if match:
                    bundled[component].setdefault(match.group(1), set()).add(kubernetes_series)

        if not combinations:
            raise ValueError("Talos release feed contains no stable Talos/Kubernetes combinations")
        entries = [
            {
                "subject_series": talos_series,
                "supported_dependency_series": sorted(kubernetes_series),
                "tested_dependency_series": [],
            }
            for talos_series, kubernetes_series in sorted(combinations.items())
        ]
        rules = [
            {
                "id": "talos-kubernetes-release-matrix",
                "type": "matrix",
                "subject": "talos",
                "dependency": "kubernetes",
                "provider": self.name,
                "parser_version": self.parser_version,
                "evidence": self.evidence_url,
                "supported_reason": "Kubernetes minor series is shipped by an official Talos release in this Talos series.",
                "unsupported_reason": "Kubernetes minor series is not shipped by an official stable Talos release in this Talos series.",
                "missing_entry_reason": "Observed Talos series is not present in the current official stable release feed.",
                "entries": entries,
            }
        ]
        for component, versions in bundled.items():
            if not versions:
                continue
            rules.append(
                {
                    "id": f"talos-{component}-kubernetes-bundle",
                    "type": "constraint_matrix",
                    "subject": component,
                    "dependency": "kubernetes",
                    "provider": self.name,
                    "parser_version": self.parser_version,
                    "evidence": self.evidence_url,
                    "evidence_title": f"Talos stable release {component} images",
                    "evidence_basis": "bundled",
                    "evidence_confidence": "high",
                    "outside_status": "unknown",
                    "outside_reason": f"This {component}/Kubernetes combination is not shipped in the observed Talos stable release feed.",
                    "entries": [
                        {
                            "subject_constraints": [version],
                            "dependency_constraints": sorted(kubernetes),
                            "status": "supported",
                            "reason": f"This exact {component} version is shipped with the Kubernetes series in an official stable Talos release.",
                        }
                        for version, kubernetes in sorted(versions.items())
                    ],
                }
            )
        return rules


class DataHubHelmCompatibilityProvider(Provider):
    """Read the exact official DataHub chart observed in the cluster."""

    name = "datahub-official-helm-chart"
    source_url = "https://github.com/acryldata/datahub-helm"
    evidence_url = source_url
    parser_version = "1"

    def __init__(self):
        self.chart_version = ""
        self.observed_app_version = ""

    def prepare(self, components: list[Component]) -> None:
        application = next(
            (
                component
                for component in components
                if component.name == "datahub" and component.metadata.get("application_group")
            ),
            None,
        )
        self.chart_version = application.metadata.get("chart_version", "") if application else ""
        self.observed_app_version = application.version if application else ""
        if self.chart_version:
            tag = f"datahub-{self.chart_version}"
            self.source_url = (
                "https://raw.githubusercontent.com/acryldata/datahub-helm/"
                f"{tag}/charts/datahub/Chart.yaml"
            )
            self.evidence_url = (
                "https://github.com/acryldata/datahub-helm/blob/"
                f"{tag}/charts/datahub/Chart.yaml"
            )
        else:
            self.source_url = "https://github.com/acryldata/datahub-helm"
            self.evidence_url = self.source_url

    def fetch(self, client: TextClient, now: datetime) -> Snapshot:
        if not self.chart_version:
            content = "no-observed-datahub-chart"
            rules: list[dict] = []
        else:
            content = client.get_text(self.source_url)
            rules = self.parse(content)
        return Snapshot(
            provider=self.name,
            source_url=self.source_url,
            retrieved_at=now.astimezone(UTC).isoformat().replace("+00:00", "Z"),
            checksum=hashlib.sha256(content.encode()).hexdigest(),
            rules=rules,
        )

    def parse(self, content: str) -> list[dict]:
        chart_version = _yaml_scalar(content, "version")
        app_version = _yaml_scalar(content, "appVersion")
        kube_version = _yaml_scalar(content, "kubeVersion", required=False)
        if chart_version != self.chart_version:
            raise ValueError(
                f"DataHub chart identity changed: expected {self.chart_version}, received {chart_version}"
            )
        if self.observed_app_version.removeprefix("v") != app_version.removeprefix("v"):
            raise ValueError(
                "DataHub chart appVersion does not match the version observed across primary workloads"
            )

        entry = {
            "subject_exact": app_version,
            "subject_constraints": [],
            "dependency_constraints": [kube_version] if kube_version else [],
            "status": "supported" if kube_version else "unknown",
            "reason": (
                f"The official DataHub chart {chart_version} declares Kubernetes {kube_version}."
                if kube_version
                else f"The official DataHub chart {chart_version} declares appVersion {app_version} but no kubeVersion; Kubernetes compatibility is not documented."
            ),
            "outside_reason": (
                f"Kubernetes is outside the kubeVersion declared by official DataHub chart {chart_version}."
                if kube_version
                else f"Official DataHub chart {chart_version} does not declare kubeVersion, so this combination cannot be marked supported."
            ),
        }
        return [
            {
                "id": "datahub-chart-kubernetes-compatibility",
                "type": "constraint_matrix",
                "subject": "datahub",
                "dependency": "kubernetes",
                "provider": self.name,
                "parser_version": self.parser_version,
                "evidence": self.evidence_url,
                "evidence_title": f"DataHub Helm chart {chart_version} Chart.yaml",
                "missing_entry_reason": "The observed DataHub version is not the appVersion declared by the discovered chart.",
                "outside_status": "unknown" if not kube_version else "incompatible",
                "entries": [entry],
            }
        ]


class MetalLBHelmCompatibilityProvider(Provider):
    """Read kubeVersion from the exact upstream MetalLB release chart."""

    name = "metallb-official-helm-chart"
    source_url = "https://github.com/metallb/metallb"
    evidence_url = source_url
    parser_version = "1"

    def __init__(self):
        self.observed_version = ""

    def prepare(self, components: list[Component]) -> None:
        application = next(
            (
                component
                for component in components
                if component.name == "metallb" and component.metadata.get("application_group")
            ),
            None,
        )
        self.observed_version = application.version if application else ""
        if self.observed_version:
            tag = self.observed_version if self.observed_version.startswith("v") else f"v{self.observed_version}"
            self.source_url = f"https://raw.githubusercontent.com/metallb/metallb/{tag}/charts/metallb/Chart.yaml"
            self.evidence_url = f"https://github.com/metallb/metallb/blob/{tag}/charts/metallb/Chart.yaml"
        else:
            self.source_url = "https://github.com/metallb/metallb"
            self.evidence_url = self.source_url

    def fetch(self, client: TextClient, now: datetime) -> Snapshot:
        if not self.observed_version:
            content = "no-observed-metallb-release"
            rules: list[dict] = []
        else:
            content = client.get_text(self.source_url)
            rules = self.parse(content)
        return Snapshot(
            provider=self.name,
            source_url=self.source_url,
            retrieved_at=now.astimezone(UTC).isoformat().replace("+00:00", "Z"),
            checksum=hashlib.sha256(content.encode()).hexdigest(),
            rules=rules,
        )

    def parse(self, content: str) -> list[dict]:
        name = _yaml_scalar(content, "name")
        chart_version = _yaml_scalar(content, "version")
        app_version = _yaml_scalar(content, "appVersion")
        kube_version = _yaml_scalar(content, "kubeVersion")
        if name != "metallb":
            raise ValueError("official MetalLB chart identity changed")
        if self.observed_version.removeprefix("v") != app_version.removeprefix("v"):
            raise ValueError("MetalLB chart appVersion does not match the observed release")
        return [
            {
                "id": "metallb-kubernetes-compatibility",
                "type": "constraint_matrix",
                "subject": "metallb",
                "dependency": "kubernetes",
                "provider": self.name,
                "parser_version": self.parser_version,
                "evidence": self.evidence_url,
                "evidence_title": f"MetalLB {chart_version} official Chart.yaml",
                "evidence_basis": "supported",
                "evidence_confidence": "high",
                "outside_status": "incompatible",
                "entries": [
                    {
                        "subject_exact": app_version,
                        "subject_constraints": [],
                        "dependency_constraints": [kube_version],
                        "status": "supported",
                        "reason": f"The official MetalLB {chart_version} chart declares Kubernetes {kube_version}.",
                        "outside_reason": f"Kubernetes is outside the kubeVersion declared by official MetalLB chart {chart_version}.",
                    }
                ],
            }
        ]


class OpenTelemetryOperatorCompatibilityProvider(Provider):
    name = "opentelemetry-operator-compatibility"
    source_url = "https://raw.githubusercontent.com/open-telemetry/opentelemetry-operator/main/docs/getting-started/compatibility.md"
    evidence_url = "https://github.com/open-telemetry/opentelemetry-operator/blob/main/docs/getting-started/compatibility.md"

    def parse(self, content: str) -> list[dict]:
        entries = []
        for cells in _table_after(content, "| OpenTelemetry Operator | Kubernetes"):
            if len(cells) < 2:
                continue
            release = re.fullmatch(r"v?(\d+\.\d+\.\d+)", cells[0])
            supported = re.fullmatch(r"v?(\d+\.\d+)\s+to\s+v?(\d+\.\d+)", cells[1], re.I)
            if not release or not supported:
                continue
            constraint = f">={supported.group(1)} <={supported.group(2)}"
            entries.append(
                {
                    "subject_constraints": [release.group(1)],
                    "dependency_constraints": [constraint],
                    "status": "supported",
                    "reason": f"The official OpenTelemetry Operator matrix supports Kubernetes {supported.group(1)} through {supported.group(2)} for this release.",
                    "outside_reason": f"Kubernetes is outside the {supported.group(1)} through {supported.group(2)} range supported for this OpenTelemetry Operator release.",
                }
            )
        if not entries:
            raise ValueError("OpenTelemetry Operator compatibility matrix contains no version ranges")
        return [
            {
                "id": "opentelemetry-operator-kubernetes-compatibility",
                "type": "constraint_matrix",
                "subject": "opentelemetry-operator",
                "dependency": "kubernetes",
                "provider": self.name,
                "parser_version": self.parser_version,
                "evidence": self.evidence_url,
                "evidence_title": "OpenTelemetry Operator compatibility matrix",
                "evidence_basis": "supported",
                "evidence_confidence": "high",
                "outside_status": "unsupported",
                "entries": entries,
            }
        ]


class ClickHouseOperatorCompatibilityProvider(Provider):
    name = "clickhouse-operator-kubernetes-requirements"
    source_url = "https://raw.githubusercontent.com/Altinity/clickhouse-operator/master/docs/operator_installation_details.md"
    evidence_url = "https://github.com/Altinity/clickhouse-operator/blob/master/docs/operator_installation_details.md"

    def parse(self, content: str) -> list[dict]:
        plain = re.sub(r"[*_`\[\]]", "", content)
        requirement = re.search(
            r"clickhouse-operator versions\s+(\d+\.\d+\.\d+)\s+and after is compatible\s+Kubernetes version\s+(\d+\.\d+)\s+and after",
            plain,
            re.I,
        )
        if not requirement:
            raise ValueError("ClickHouse Operator Kubernetes requirement format changed")
        operator_minimum, kubernetes_minimum = requirement.groups()
        return [
            {
                "id": "clickhouse-operator-kubernetes-compatibility",
                "type": "constraint_matrix",
                "subject": "clickhouse-operator",
                "dependency": "kubernetes",
                "provider": self.name,
                "parser_version": self.parser_version,
                "evidence": self.evidence_url,
                "evidence_title": "Altinity ClickHouse Operator Kubernetes requirements",
                "evidence_basis": "supported",
                "evidence_confidence": "high",
                "outside_status": "incompatible",
                "entries": [
                    {
                        "subject_constraints": [f">={operator_minimum}"],
                        "dependency_constraints": [f">={kubernetes_minimum}"],
                        "status": "supported",
                        "reason": f"Altinity documents ClickHouse Operator {operator_minimum}+ as compatible with Kubernetes {kubernetes_minimum}+.",
                        "outside_reason": f"Kubernetes is below the documented minimum {kubernetes_minimum} for this ClickHouse Operator release.",
                    }
                ],
            }
        ]


class MendRenovateCEHelmEvidenceProvider(Provider):
    """Attach exact chart identity without inventing Kubernetes support."""

    name = "mend-renovate-ce-official-chart"
    source_url = "https://github.com/mend/renovate-ce-ee"
    evidence_url = source_url

    def __init__(self):
        self.chart_version = ""
        self.subjects: set[str] = set()

    def prepare(self, components: list[Component]) -> None:
        matching = [
            component
            for component in components
            if component.name in {"renovate", "mend-renovate-ce"}
            or component.metadata.get("chart_name") == "mend-renovate-ce"
        ]
        chart_versions = {
            component.metadata.get("chart_version", "")
            for component in matching
            if component.metadata.get("chart_version")
        }
        self.chart_version = sorted(chart_versions)[-1] if chart_versions else ""
        self.subjects = {component.name for component in matching}
        if self.chart_version:
            path = f"{self.chart_version}/helm-charts/mend-renovate-ce/Chart.yaml"
            self.source_url = f"https://raw.githubusercontent.com/mend/renovate-ce-ee/{path}"
            self.evidence_url = f"https://github.com/mend/renovate-ce-ee/blob/{path}"
        else:
            self.source_url = "https://github.com/mend/renovate-ce-ee"
            self.evidence_url = self.source_url

    def fetch(self, client: TextClient, now: datetime) -> Snapshot:
        if not self.chart_version:
            content = "no-observed-mend-renovate-chart"
            rules: list[dict] = []
        else:
            content = client.get_text(self.source_url)
            rules = self.parse(content)
        return Snapshot(
            provider=self.name,
            source_url=self.source_url,
            retrieved_at=now.astimezone(UTC).isoformat().replace("+00:00", "Z"),
            checksum=hashlib.sha256(content.encode()).hexdigest(),
            rules=rules,
        )

    def parse(self, content: str) -> list[dict]:
        name = _yaml_scalar(content, "name")
        chart_version = _yaml_scalar(content, "version")
        app_version = _yaml_scalar(content, "appVersion")
        kube_version = _yaml_scalar(content, "kubeVersion", required=False)
        if name != "mend-renovate-ce" or chart_version != self.chart_version:
            raise ValueError("Mend Renovate CE chart identity changed")
        entries = [
            {
                "subject_constraints": [app_version],
                "dependency_constraints": [kube_version or ">=0.0"],
                "status": "supported" if kube_version else "unknown",
                "reason": (
                    f"The official Mend Renovate CE chart {chart_version} declares Kubernetes {kube_version}."
                    if kube_version
                    else f"The official Mend Renovate CE chart {chart_version} confirms appVersion {app_version} but publishes no kubeVersion or Kubernetes compatibility matrix."
                ),
                "outside_reason": f"Kubernetes is outside the kubeVersion declared by Mend Renovate CE chart {chart_version}.",
            }
        ]
        return [
            {
                "id": f"{subject}-kubernetes-evidence",
                "type": "constraint_matrix",
                "subject": subject,
                "dependency": "kubernetes",
                "provider": self.name,
                "parser_version": self.parser_version,
                "evidence": self.evidence_url,
                "evidence_title": f"Mend Renovate CE {chart_version} official Chart.yaml",
                "evidence_basis": "release-identity" if not kube_version else "supported",
                "evidence_confidence": "high",
                "outside_status": "incompatible" if kube_version else "unknown",
                "entries": entries,
            }
            for subject in sorted(self.subjects)
        ]


class OpenTelemetryCollectorReleaseEvidenceProvider(Provider):
    """Verify observed Collector releases while keeping Kubernetes support unknown."""

    name = "opentelemetry-collector-official-releases"
    source_url = "https://github.com/open-telemetry/opentelemetry-collector-releases/releases"
    evidence_url = source_url

    def __init__(self):
        self.observed: dict[str, set[str]] = {}

    def prepare(self, components: list[Component]) -> None:
        self.observed = {}
        for component in components:
            if component.name not in {"otel-agent", "otel-collector", "opentelemetry-collector"}:
                continue
            parsed = re.search(r"\d+\.\d+\.\d+", component.version)
            if parsed:
                self.observed.setdefault(component.name, set()).add(parsed.group(0))

    def fetch(self, client: TextClient, now: datetime) -> Snapshot:
        versions = sorted({version for observed in self.observed.values() for version in observed})
        documents = []
        verified = set()
        for version in versions:
            url = f"https://api.github.com/repos/open-telemetry/opentelemetry-collector-releases/releases/tags/v{version}"
            content = client.get_text(url)
            document = json.loads(content)
            if document.get("tag_name") != f"v{version}":
                raise ValueError(f"OpenTelemetry Collector release identity changed for {version}")
            if not str(document.get("html_url", "")).startswith(
                "https://github.com/open-telemetry/opentelemetry-collector-releases/releases/tag/"
            ):
                raise ValueError(f"OpenTelemetry Collector release URL is invalid for {version}")
            documents.append(content)
            verified.add(version)
        rules = []
        for subject, observed_versions in sorted(self.observed.items()):
            entries = [
                {
                    "subject_constraints": [version],
                    "dependency_constraints": [">=0.0"],
                    "status": "unknown",
                    "reason": f"The official release registry confirms OpenTelemetry Collector {version}, but upstream publishes no Collector-to-Kubernetes compatibility matrix.",
                }
                for version in sorted(observed_versions & verified)
            ]
            if entries:
                rules.append(
                    {
                        "id": f"{subject}-kubernetes-release-evidence",
                        "type": "constraint_matrix",
                        "subject": subject,
                        "dependency": "kubernetes",
                        "provider": self.name,
                        "parser_version": self.parser_version,
                        "evidence": self.evidence_url,
                        "evidence_title": "OpenTelemetry Collector official releases",
                        "evidence_basis": "release-identity",
                        "evidence_confidence": "high",
                        "outside_status": "unknown",
                        "entries": entries,
                    }
                )
        content = "\n".join(documents) if documents else "no-observed-opentelemetry-collector"
        return Snapshot(
            provider=self.name,
            source_url=self.source_url,
            retrieved_at=now.astimezone(UTC).isoformat().replace("+00:00", "Z"),
            checksum=hashlib.sha256(content.encode()).hexdigest(),
            rules=rules,
        )

    def parse(self, content: str) -> list[dict]:
        raise NotImplementedError("OpenTelemetry Collector releases are fetched per observed version")


class CompatibilityFyiProvider(Provider):
    """Source-backed catalog fallback for observed project/Kubernetes pairs."""

    name = "compatibility-fyi"
    source_url = "https://compatibility.fyi/api/v1/projects"
    evidence_url = "https://compatibility.fyi/"
    parser_version = "1"
    fallback = True

    def __init__(self, max_evidence_age_days: int = 180):
        self.max_evidence_age_days = max_evidence_age_days
        self.observed_names: set[str] = set()

    def prepare(self, components: list[Component]) -> None:
        self.observed_names = {component.name for component in components}

    def fetch(self, client: TextClient, now: datetime) -> Snapshot:
        index_content = client.get_text(self.source_url)
        try:
            index = json.loads(index_content)
            projects = index["projects"]
        except (json.JSONDecodeError, KeyError, TypeError) as error:
            raise ValueError("compatibility.fyi project index is invalid") from error
        if not isinstance(projects, list):
            raise ValueError("compatibility.fyi project index has no project list")

        project_ids = sorted(
            project["id"]
            for project in projects
            if isinstance(project, dict)
            and isinstance(project.get("id"), str)
            and project["id"] in self.observed_names
        )
        documents = [index_content]
        rules: list[dict] = []
        for project_id in project_ids:
            content = client.get_text(f"{self.source_url}/{quote(project_id, safe='')}")
            documents.append(content)
            rules.extend(self.parse(content))
        combined = "\n".join(documents)
        return Snapshot(
            provider=self.name,
            source_url=self.source_url,
            retrieved_at=now.astimezone(UTC).isoformat().replace("+00:00", "Z"),
            checksum=hashlib.sha256(combined.encode()).hexdigest(),
            rules=rules,
        )

    def parse(self, content: str) -> list[dict]:
        try:
            document = json.loads(content)
            project_id = document["id"]
            versions = document["versions"]
        except (json.JSONDecodeError, KeyError, TypeError) as error:
            raise ValueError("compatibility.fyi project document is invalid") from error
        if not isinstance(project_id, str) or not isinstance(versions, dict):
            raise ValueError("compatibility.fyi project identity or versions are invalid")

        entries = []
        for subject_constraint, version_data in versions.items():
            if not isinstance(subject_constraint, str) or not isinstance(version_data, dict):
                continue
            dependency = version_data.get("dependencies", {}).get("kubernetes", {})
            if not isinstance(dependency, dict):
                continue
            sources = [
                source
                for source in dependency.get("sources", [])
                if isinstance(source, dict) and _primary_https_url(source.get("url", ""))
            ]
            ranges = dependency.get("ranges", [])
            if not sources or not isinstance(ranges, list) or not all(isinstance(item, str) for item in ranges):
                continue
            entries.append(
                {
                    "subject_constraint": subject_constraint,
                    "dependency_ranges": ranges,
                    "same_version": dependency.get("sameVersion") is True,
                    "basis": dependency.get("basis", "supported"),
                    "confidence": dependency.get("confidence", "low"),
                    "catalog_status": dependency.get("status", "unknown"),
                    "last_verified": dependency.get("lastVerified", ""),
                    "notes": [note for note in dependency.get("notes", []) if isinstance(note, str)],
                    "source_title": sources[0].get("title", "Primary upstream evidence"),
                    "source_url": sources[0]["url"],
                }
            )
        if not entries:
            return []
        return [
            {
                "id": f"compatibility-fyi-{project_id}-kubernetes",
                "type": "catalog_matrix",
                "subject": project_id,
                "dependency": "kubernetes",
                "provider": self.name,
                "parser_version": self.parser_version,
                "evidence": f"https://compatibility.fyi/projects/{quote(project_id, safe='')}/",
                "evidence_title": f"compatibility.fyi — {document.get('name', project_id)}",
                "max_evidence_age_days": self.max_evidence_age_days,
                "entries": entries,
            }
        ]


class ProviderManager:
    def __init__(
        self,
        providers: list[Provider],
        cache: EvidenceCache,
        client: TextClient | None = None,
        refresh_interval_seconds: int = 21600,
        stale_after_seconds: int = 604800,
    ):
        self.providers = providers
        self.cache = cache
        self.client = client or TextClient()
        self.refresh_interval_seconds = refresh_interval_seconds
        self.stale_after_seconds = stale_after_seconds
        self.next_refresh_at = 0.0
        self.last_document: dict | None = None
        self.last_states: list[ProviderState] = []

    def rules(
        self,
        force: bool = False,
        now: datetime | None = None,
        components: list[Component] | None = None,
    ) -> tuple[dict, list[ProviderState]]:
        now = now or datetime.now(UTC)
        if not force and self.last_document and now.timestamp() < self.next_refresh_at:
            return self.last_document, self.last_states

        rules: list[dict] = []
        states: list[ProviderState] = []
        claimed_relationships: set[tuple[str, str]] = set()
        for provider in self.providers:
            provider.prepare(components or [])
            snapshot, state = self._refresh_provider(provider, now)
            states.append(state)
            if snapshot:
                for rule in snapshot.rules:
                    relationship = (rule.get("subject", ""), rule.get("dependency", ""))
                    if provider.fallback and relationship in claimed_relationships:
                        continue
                    rules.append(
                        {
                            **rule,
                            "evidence_status": state.status,
                            "evidence_retrieved_at": state.retrieved_at,
                            "evidence_checksum": state.checksum,
                        }
                    )
                    claimed_relationships.add(relationship)
        self.last_document = {"schema_version": 1, "generated_at": now.isoformat(), "rules": rules}
        self.last_states = states
        self.next_refresh_at = now.timestamp() + self.refresh_interval_seconds
        return self.last_document, self.last_states

    def _refresh_provider(self, provider: Provider, now: datetime) -> tuple[Snapshot | None, ProviderState]:
        try:
            snapshot = provider.fetch(self.client, now)
            self.cache.save(snapshot)
            return snapshot, self._state(provider, snapshot, now, "fresh")
        except Exception as error:
            try:
                snapshot = self.cache.load(provider.name)
            except Exception as cache_error:
                return None, ProviderState(provider.name, provider.source_url, "unavailable", error=f"{error}; cache: {cache_error}")
            if not snapshot:
                return None, ProviderState(provider.name, provider.source_url, "unavailable", error=str(error))
            retrieved = datetime.fromisoformat(snapshot.retrieved_at.replace("Z", "+00:00"))
            age = max(0.0, (now - retrieved).total_seconds())
            status = "cached" if age <= self.stale_after_seconds else "stale"
            return snapshot, self._state(provider, snapshot, now, status, str(error))

    @staticmethod
    def _state(
        provider: Provider,
        snapshot: Snapshot,
        now: datetime,
        status: str,
        error: str = "",
    ) -> ProviderState:
        retrieved = datetime.fromisoformat(snapshot.retrieved_at.replace("Z", "+00:00"))
        return ProviderState(
            provider.name,
            provider.source_url,
            status,
            snapshot.retrieved_at,
            snapshot.checksum,
            max(0.0, (now - retrieved).total_seconds()),
            error,
        )


def default_manager(cache_dir: str, refresh_interval_seconds: int, stale_after_seconds: int) -> ProviderManager:
    return ProviderManager(
        [
            KubernetesSkewProvider(),
            CloudNativePGProvider(),
            ContainerdCompatibilityProvider(),
            KubeStateMetricsCompatibilityProvider(),
            KubeRbacProxyAdvisoryProvider(),
            TalosReleaseProvider(),
            KubernetesCSISidecarsProvider(),
            CephCSICompatibilityProvider(),
            ArgoCDTestedVersionsProvider(),
            PrometheusOperatorCompatibilityProvider(),
            DataHubHelmCompatibilityProvider(),
            MetalLBHelmCompatibilityProvider(),
            OpenTelemetryOperatorCompatibilityProvider(),
            ClickHouseOperatorCompatibilityProvider(),
            MendRenovateCEHelmEvidenceProvider(),
            OpenTelemetryCollectorReleaseEvidenceProvider(),
            CompatibilityFyiProvider(
                max_evidence_age_days=int(os.getenv("CATALOG_EVIDENCE_MAX_AGE_DAYS", "180"))
            ),
        ],
        EvidenceCache(cache_dir),
        refresh_interval_seconds=refresh_interval_seconds,
        stale_after_seconds=stale_after_seconds,
    )


def _primary_https_url(value: str) -> bool:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and bool(parsed.hostname)
        and parsed.hostname != "compatibility.fyi"
        and not parsed.hostname.endswith(".compatibility.fyi")
    )


def _yaml_scalar(content: str, key: str, required: bool = True) -> str:
    match = re.search(rf"^\s*{re.escape(key)}\s*:\s*(.*?)\s*$", content, re.M)
    if match:
        value = match.group(1).strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            return value[1:-1]
        return value.split(" #", 1)[0].strip()
    if required:
        raise ValueError(f"official chart is missing {key}")
    return ""


def _html_table_rows(content: str) -> list[list[str]]:
    rows = []
    for row in re.findall(r"<tr[^>]*>(.*?)</tr>", content, re.I | re.S):
        cells = []
        for cell in re.findall(r"<t[dh][^>]*>(.*?)</t[dh]>", row, re.I | re.S):
            text = re.sub(r"<[^>]+>", " ", cell)
            cells.append(re.sub(r"\s+", " ", html.unescape(text)).strip())
        if cells:
            rows.append(cells)
    return rows


def _markdown_section(content: str, start: str, end: str) -> str:
    start_index = content.find(start)
    end_index = content.find(end, start_index + len(start))
    if start_index < 0 or end_index < 0:
        raise ValueError(f"missing Markdown section {start}")
    return content[start_index:end_index]


def _require(content: str, pattern: str) -> str:
    match = re.search(pattern, content, re.I)
    if not match:
        raise ValueError(f"official policy format changed: {pattern}")
    return match.group(1)


def _word_number(value: str) -> int:
    numbers = {"one": 1, "two": 2, "three": 3, "four": 4}
    if value.lower() not in numbers:
        raise ValueError(f"unsupported word number: {value}")
    return numbers[value.lower()]


def _legacy_skew(content: str, component: str) -> tuple[str, int]:
    match = re.search(
        rf"`{re.escape(component)}` < (\d+\.\d+) may only be up to ([a-z]+) minor versions",
        content,
        re.I,
    )
    if not match:
        raise ValueError(f"official legacy skew marker changed for {component}")
    return match.group(1), _word_number(match.group(2))


def _table_after(content: str, header_prefix: str, after: str = "") -> list[list[str]]:
    lines = content.splitlines()
    offset = 0
    if after:
        try:
            offset = next(index for index, line in enumerate(lines) if line.startswith(after))
        except StopIteration as error:
            raise ValueError(f"missing official section: {after}") from error
    try:
        start = next(index for index, line in enumerate(lines[offset:], offset) if line.startswith(header_prefix))
    except StopIteration as error:
        raise ValueError(f"missing official table: {header_prefix}") from error
    rows: list[list[str]] = []
    for line in lines[start + 2 :]:
        if not line.startswith("|"):
            break
        rows.append([cell.strip() for cell in line.strip().strip("|").split("|")])
    return rows


def _version_list(value: str) -> list[str]:
    return re.findall(r"(?<!\d)v?(\d+\.\d+)\b", value)


def _exact_date(value: str) -> str | None:
    if not value or value.lstrip().startswith("~"):
        return None
    normalized = re.sub(r"\s+", " ", value.replace(",", " ")).strip()
    for pattern in ("%d %b %Y", "%d %B %Y", "%b %d %Y", "%B %d %Y"):
        try:
            return datetime.strptime(normalized, pattern).date().isoformat()
        except ValueError:
            pass
    raise ValueError(f"unrecognized exact date in official table: {value}")


def parse_release_tag(value: str) -> str | None:
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.\d+", value)
    return f"{match.group(1)}.{match.group(2)}" if match else None
