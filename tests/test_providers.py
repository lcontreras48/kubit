import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from kubit.providers import (
    ArgoCDTestedVersionsProvider,
    CloudNativePGProvider,
    ClickHouseOperatorCompatibilityProvider,
    CompatibilityFyiProvider,
    ContainerdCompatibilityProvider,
    DataHubHelmCompatibilityProvider,
    CephCSICompatibilityProvider,
    EvidenceCache,
    KubernetesSkewProvider,
    KubernetesCSISidecarsProvider,
    KubeRbacProxyAdvisoryProvider,
    KubeStateMetricsCompatibilityProvider,
    MendRenovateCEHelmEvidenceProvider,
    MetalLBHelmCompatibilityProvider,
    OpenTelemetryCollectorReleaseEvidenceProvider,
    OpenTelemetryOperatorCompatibilityProvider,
    ProviderManager,
    PrometheusOperatorCompatibilityProvider,
    Provider,
    TalosReleaseProvider,
    TextClient,
)
from kubit.models import Component


FIXTURES = Path(__file__).parent / "fixtures"
UTC = timezone.utc


class FakeClient:
    def __init__(self, content=None, error=None):
        self.content = content
        self.error = error
        self.calls = []

    def get_text(self, url):
        self.calls.append(url)
        if self.error:
            raise self.error
        if isinstance(self.content, dict):
            return self.content[url]
        return self.content


class ProviderInputSecurityTest(unittest.TestCase):
    def test_evidence_client_rejects_non_https_and_credentialed_urls(self):
        client = TextClient()
        unsafe = (
            "file:///tmp/evidence",
            "http://example.org/matrix",
            "https://user:pass@example.org/matrix",  # pragma: allowlist secret
        )
        for value in unsafe:
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "must use HTTPS"):
                client.get_text(value)

    def test_talos_parser_rejects_xml_declarations_and_entities(self):
        malicious = '<!DOCTYPE feed [<!ENTITY payload "expanded">]><feed>&payload;</feed>'
        with self.assertRaisesRegex(ValueError, "forbidden XML declarations"):
            TalosReleaseProvider().parse(malicious)


CATALOG_INDEX = json.dumps(
    {"projects": [{"id": "cilium", "name": "Cilium"}, {"id": "grafana", "name": "Grafana"}]}
)
CATALOG_CILIUM = json.dumps(
    {
        "id": "cilium",
        "name": "Cilium",
        "versions": {
            "1.20": {
                "dependencies": {
                    "kubernetes": {
                        "ranges": [">=1.33 <1.37"],
                        "basis": "tested",
                        "confidence": "high",
                        "status": "compatible",
                        "lastVerified": "2026-10-15",
                        "notes": ["Cilium 1.20 is tested with Kubernetes 1.33 through 1.36."],
                        "sources": [
                            {
                                "title": "Cilium Kubernetes compatibility",
                                "url": "https://raw.githubusercontent.com/cilium/cilium/v1.20.3/Documentation/network/kubernetes/compatibility.rst",
                            }
                        ],
                    }
                }
            }
        },
    }
)


class ProviderParserTest(unittest.TestCase):
    def test_metallb_exact_chart_declares_kubernetes_requirement(self):
        provider = MetalLBHelmCompatibilityProvider()
        provider.prepare(
            [
                Component(
                    "metallb",
                    "v0.14.8",
                    "application-group/argocd",
                    metadata={"application_group": True},
                )
            ]
        )
        rule = provider.parse(
            """
name: metallb
version: 0.14.8
appVersion: v0.14.8
kubeVersion: ">= 1.19.0-0"
"""
        )[0]
        self.assertEqual(rule["subject"], "metallb")
        self.assertEqual(rule["entries"][0]["dependency_constraints"], [">= 1.19.0-0"])
        self.assertEqual(rule["outside_status"], "incompatible")
        self.assertIn("v0.14.8/charts/metallb/Chart.yaml", rule["evidence"])

    def test_opentelemetry_operator_parser_reads_official_matrix(self):
        rule = OpenTelemetryOperatorCompatibilityProvider().parse(
            """
| OpenTelemetry Operator | Kubernetes |
| --- | --- |
| v0.134.0 | v1.25 to v1.33 |
| v0.133.0 | v1.25 to v1.32 |
"""
        )[0]
        entry = rule["entries"][0]
        self.assertEqual(entry["subject_constraints"], ["0.134.0"])
        self.assertEqual(entry["dependency_constraints"], [">=1.25 <=1.33"])
        self.assertEqual(rule["outside_status"], "unsupported")

    def test_clickhouse_operator_parser_reads_current_minimums(self):
        rule = ClickHouseOperatorCompatibilityProvider().parse(
            "clickhouse-operator versions **0.16.0** and after is compatible "
            "Kubernetes version **1.25** and after"
        )[0]
        entry = rule["entries"][0]
        self.assertEqual(entry["subject_constraints"], [">=0.16.0"])
        self.assertEqual(entry["dependency_constraints"], [">=1.25"])

    def test_renovate_chart_identity_remains_unknown_without_kube_version(self):
        provider = MendRenovateCEHelmEvidenceProvider()
        provider.prepare(
            [
                Component(
                    "renovate",
                    "13.2.0-full",
                    "application-group/helm",
                    metadata={
                        "application_group": True,
                        "chart_name": "mend-renovate-ce",
                        "chart_version": "13.2.0",
                    },
                ),
                Component(
                    "mend-renovate-ce",
                    "13.2.0-full",
                    "deployment/renovate/mend-renovate-ce",
                    metadata={"chart_name": "mend-renovate-ce", "chart_version": "13.2.0"},
                ),
            ]
        )
        rules = provider.parse(
            """
name: mend-renovate-ce
version: 13.2.0
appVersion: 13.2.0-full
"""
        )
        self.assertEqual({rule["subject"] for rule in rules}, {"renovate", "mend-renovate-ce"})
        self.assertTrue(all(rule["entries"][0]["status"] == "unknown" for rule in rules))
        self.assertTrue(all(rule["evidence_basis"] == "release-identity" for rule in rules))

    def test_collector_release_identity_remains_unknown_without_matrix(self):
        provider = OpenTelemetryCollectorReleaseEvidenceProvider()
        provider.prepare(
            [
                Component("otel-agent", "0.161.0", "daemonset"),
                Component("otel-collector", "0.161.0", "deployment"),
                Component("opentelemetry-collector", "0.81.0", "application-group/helm"),
            ]
        )
        client = FakeClient(
            {
                "https://api.github.com/repos/open-telemetry/opentelemetry-collector-releases/releases/tags/v0.81.0": json.dumps(
                    {
                        "tag_name": "v0.81.0",
                        "html_url": "https://github.com/open-telemetry/opentelemetry-collector-releases/releases/tag/v0.81.0",
                    }
                ),
                "https://api.github.com/repos/open-telemetry/opentelemetry-collector-releases/releases/tags/v0.161.0": json.dumps(
                    {
                        "tag_name": "v0.161.0",
                        "html_url": "https://github.com/open-telemetry/opentelemetry-collector-releases/releases/tag/v0.161.0",
                    }
                ),
            }
        )
        snapshot = provider.fetch(client, datetime(2026, 10, 28, tzinfo=UTC))
        self.assertEqual(len(snapshot.rules), 3)
        self.assertTrue(
            all(entry["status"] == "unknown" for rule in snapshot.rules for entry in rule["entries"])
        )
        self.assertEqual(len(client.calls), 2)

    def test_kubernetes_policy_generates_internal_component_rules(self):
        content = (FIXTURES / "kubernetes-version-skew.md").read_text()
        rules = KubernetesSkewProvider().parse(content)
        ids = {rule["id"] for rule in rules}
        self.assertEqual(len(rules), 7)
        self.assertIn("kubernetes-apiserver-ha-skew", ids)
        self.assertIn("kubernetes-kube-proxy-kubelet-skew", ids)
        kubelet = next(rule for rule in rules if rule["subject"] == "kubelet")
        self.assertEqual(kubelet["max_older_minors"], 3)
        self.assertEqual(kubelet["legacy_max_older_minors"], 2)

    def test_cloudnativepg_parser_separates_supported_tested_and_old(self):
        content = (FIXTURES / "cloudnativepg-supported-releases.md").read_text()
        rule = CloudNativePGProvider().parse(content)[0]
        entries = {entry["subject_series"]: entry for entry in rule["entries"]}
        self.assertEqual(entries["1.30"]["supported_dependency_series"], ["1.34", "1.35", "1.36"])
        self.assertEqual(entries["1.30"]["tested_dependency_series"], ["1.37", "1.33"])
        self.assertEqual(entries["1.29"]["end_of_life"], "2026-09-29")
        self.assertFalse(entries["1.28"]["currently_supported"])

    def test_talos_release_parser_builds_kubernetes_series_matrix(self):
        content = (FIXTURES / "talos-releases.atom").read_text()
        rules = TalosReleaseProvider().parse(content)
        rule = rules[0]
        entries = {entry["subject_series"]: entry for entry in rule["entries"]}
        self.assertEqual(entries["1.14"]["supported_dependency_series"], ["1.37"])
        self.assertEqual(entries["1.13"]["supported_dependency_series"], ["1.36"])
        self.assertNotIn("1.15", entries)
        by_subject = {item["subject"]: item for item in rules}
        self.assertEqual(by_subject["coredns"]["entries"][1]["subject_constraints"], ["1.14.7"])
        self.assertEqual(by_subject["coredns"]["entries"][1]["dependency_constraints"], ["1.37"])
        self.assertEqual(by_subject["flannel"]["entries"][1]["subject_constraints"], ["0.28.9"])
        self.assertEqual(by_subject["flannel"]["entries"][1]["dependency_constraints"], ["1.37"])

    def test_containerd_parser_builds_recommended_release_ranges(self):
        content = """
| Kubernetes Version | containerd Version | CRI Version |
| --- | --- | --- |
| 1.36 | 2.3.0+, 2.2.0+ | v1 |
| 1.37 | 2.4.0+, 2.3.0+ | v1 |
"""
        rule = ContainerdCompatibilityProvider().parse(content)[0]
        entry = next(item for item in rule["entries"] if item["subject_constraints"] == [">=2.3.0 <2.4.0"])
        self.assertEqual(entry["dependency_constraints"], ["1.36", "1.37"])

    def test_csi_parser_extracts_supported_release_series_and_kubernetes_minimum(self):
        content = """
<h3><a id="supported-versions">Supported Versions</a></h3>
<table><thead><tr><th>Latest stable release</th><th>Branch</th><th>Min K8s Version</th><th>Max K8s Version</th></tr></thead><tbody>
<tr><td>external-resizer v1.13.0</td><td>release-1.13</td><td>v1.16</td><td>-</td></tr>
</tbody></table>
<h3><a id="unsupported-versions">Unsupported Versions</a></h3>
"""
        rule = KubernetesCSISidecarsProvider()._parse_page("csi-resizer", "external-resizer", content)[0]
        self.assertEqual(rule["entries"][0]["subject_constraints"], ["1.13"])
        self.assertEqual(rule["entries"][0]["dependency_constraints"], [">=1.16"])

    def test_kube_state_metrics_parser_maps_release_to_documented_client_go_series(self):
        content = """
| kube-state-metrics | Kubernetes client-go Version |
|--------------------|:----------------------------:|
| **v2.20.0** | v1.36 |
| **main** | v1.37 |
"""
        rule = KubeStateMetricsCompatibilityProvider().parse(content)[0]
        self.assertEqual(rule["entries"][0]["subject_constraints"], ["2.20.0"])
        self.assertEqual(rule["entries"][0]["dependency_constraints"], ["1.36"])
        self.assertIn("best-effort", rule["entries"][0]["outside_reason"])

    def test_kube_rbac_proxy_advisory_never_manufactures_supported_status(self):
        content = "> NOTE: This project is *alpha* stage. Flags may change."
        rule = KubeRbacProxyAdvisoryProvider().parse(content)[0]
        self.assertEqual(rule["entries"][0]["status"], "unknown")
        self.assertIn("no Kubernetes compatibility matrix", rule["entries"][0]["reason"])

    def test_ceph_csi_parser_marks_deprecated_release_unsupported(self):
        content = """
| Ceph CSI Version | Container Orchestrator Name | Version Tested |
| --- | --- | --- |
| v3.18.1 | Kubernetes | v1.34, v1.35, v1.36 |

Deprecated Ceph CSI Release/Branch | Container image name | Image Tag
--- | --- | ---
v3.15.1 | quay.io/cephcsi/cephcsi | v3.15.1

### Alternative images
"""
        rule = CephCSICompatibilityProvider().parse(content)[0]
        deprecated = next(item for item in rule["entries"] if item["subject_constraints"] == ["3.15.1"])
        self.assertEqual(deprecated["status"], "unsupported")

    def test_generic_markdown_matrix_parses_argocd_tested_versions(self):
        content = (FIXTURES / "argocd-tested-kubernetes-versions.md").read_text()
        rule = ArgoCDTestedVersionsProvider().parse(content)[0]
        entries = {entry["subject_series"]: entry for entry in rule["entries"]}
        self.assertEqual(entries["3.5"]["supported_dependency_series"], ["1.36", "1.35", "1.34", "1.33"])
        self.assertEqual(rule["outside_status"], "unknown")

    def test_datahub_chart_without_kube_version_remains_unknown(self):
        provider = DataHubHelmCompatibilityProvider()
        provider.chart_version = "0.8.12"
        provider.observed_app_version = "v1.4.0.3"
        provider.evidence_url = "https://github.com/acryldata/datahub-helm/blob/datahub-0.8.12/charts/datahub/Chart.yaml"
        rule = provider.parse(
            """apiVersion: v2
name: datahub
version: 0.8.12
appVersion: v1.4.0.3
"""
        )[0]
        self.assertEqual(rule["subject"], "datahub")
        self.assertEqual(rule["entries"][0]["subject_exact"], "v1.4.0.3")
        self.assertEqual(rule["entries"][0]["dependency_constraints"], [])
        self.assertEqual(rule["outside_status"], "unknown")
        self.assertIn("does not declare kubeVersion", rule["entries"][0]["outside_reason"])

        with_kube_version = """apiVersion: v2
name: datahub
version: 0.8.12
appVersion: v1.4.0.3
kubeVersion: ">=1.31.0-0 <1.38.0-0"
"""
        constrained = provider.parse(with_kube_version)[0]
        self.assertEqual(
            constrained["entries"][0]["dependency_constraints"],
            [">=1.31.0-0 <1.38.0-0"],
        )

    def test_prometheus_operator_parser_extracts_versioned_kubernetes_minimums(self):
        content = (FIXTURES / "prometheus-operator-compatibility.md").read_text()
        rules = PrometheusOperatorCompatibilityProvider().parse(content)
        rule = next(item for item in rules if item["id"] == "prometheus-operator-kubernetes-minimum")
        self.assertEqual(rule["type"], "minimum_version")
        self.assertEqual(
            rule["entries"],
            [
                {
                    "subject_min_version": "0.84.0",
                    "minimum_dependency_version": "1.25.0",
                    "conditional_minimum_dependency_version": "1.23.0",
                    "condition": "CustomResourceValidationExpressions feature gate enabled",
                },
                {"subject_max_exclusive": "0.84.0", "minimum_dependency_version": "1.16.0"},
            ],
        )
        by_id = {item["id"]: item for item in rules}
        self.assertEqual(by_id["prometheus-operator-prometheus-minimum"]["minimum_subject_version"], "2.0.0")
        self.assertEqual(by_id["prometheus-operator-alertmanager-minimum"]["minimum_subject_version"], "0.15.0")

    def test_compatibility_fyi_parses_only_source_backed_kubernetes_evidence(self):
        rule = CompatibilityFyiProvider().parse(CATALOG_CILIUM)[0]
        self.assertEqual((rule["subject"], rule["dependency"]), ("cilium", "kubernetes"))
        self.assertEqual(rule["entries"][0]["dependency_ranges"], [">=1.33 <1.37"])
        self.assertEqual(rule["entries"][0]["basis"], "tested")
        self.assertEqual(rule["entries"][0]["confidence"], "high")
        self.assertIn("raw.githubusercontent.com/cilium", rule["entries"][0]["source_url"])

        self_sourced = json.loads(CATALOG_CILIUM)
        self_sourced["versions"]["1.20"]["dependencies"]["kubernetes"]["sources"][0]["url"] = (
            "https://compatibility.fyi/projects/cilium/"
        )
        self.assertEqual(CompatibilityFyiProvider().parse(json.dumps(self_sourced)), [])

    def test_compatibility_fyi_fetches_only_observed_catalog_projects(self):
        provider = CompatibilityFyiProvider()
        provider.prepare([Component("cilium", "1.20.3", "daemonset")])
        client = FakeClient(
            content={
                provider.source_url: CATALOG_INDEX,
                f"{provider.source_url}/cilium": CATALOG_CILIUM,
            }
        )
        snapshot = provider.fetch(client, datetime(2026, 10, 27, tzinfo=UTC))
        self.assertEqual(len(snapshot.rules), 1)
        self.assertEqual(client.calls, [provider.source_url, f"{provider.source_url}/cilium"])

    def test_direct_provider_takes_precedence_over_catalog_fallback(self):
        class DirectCiliumProvider(Provider):
            name = "direct-cilium"
            source_url = "https://example.test/cilium"

            def parse(self, content):
                return [
                    {
                        "id": "direct-cilium-kubernetes",
                        "type": "matrix",
                        "subject": "cilium",
                        "dependency": "kubernetes",
                        "provider": self.name,
                        "evidence": self.source_url,
                        "entries": [{"subject_series": "1.20", "supported_dependency_series": ["1.36"]}],
                    }
                ]

        catalog = CompatibilityFyiProvider()
        client = FakeClient(
            content={
                DirectCiliumProvider.source_url: "direct evidence",
                catalog.source_url: CATALOG_INDEX,
                f"{catalog.source_url}/cilium": CATALOG_CILIUM,
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            manager = ProviderManager(
                [DirectCiliumProvider(), catalog],
                EvidenceCache(directory),
                client,
            )
            document, states = manager.rules(
                now=datetime(2026, 10, 27, tzinfo=UTC),
                components=[Component("cilium", "1.20.3", "daemonset")],
            )
        self.assertEqual([rule["id"] for rule in document["rules"]], ["direct-cilium-kubernetes"])
        self.assertEqual([state.status for state in states], ["fresh", "fresh"])

    def test_provider_uses_cache_then_marks_it_stale(self):
        content = (FIXTURES / "kubernetes-version-skew.md").read_text()
        now = datetime(2026, 10, 27, tzinfo=UTC)
        with tempfile.TemporaryDirectory() as directory:
            manager = ProviderManager(
                [KubernetesSkewProvider()],
                EvidenceCache(directory),
                FakeClient(content=content),
                refresh_interval_seconds=0,
                stale_after_seconds=3600,
            )
            document, states = manager.rules(now=now)
            self.assertEqual(states[0].status, "fresh")
            self.assertTrue(document["rules"])

            manager.client = FakeClient(error=RuntimeError("offline"))
            document, states = manager.rules(now=now + timedelta(minutes=30))
            self.assertEqual(states[0].status, "cached")
            self.assertEqual(document["rules"][0]["evidence_status"], "cached")

            document, states = manager.rules(now=now + timedelta(hours=2))
            self.assertEqual(states[0].status, "stale")
            self.assertEqual(document["rules"][0]["evidence_status"], "stale")

    def test_no_source_and_no_cache_returns_no_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            manager = ProviderManager(
                [KubernetesSkewProvider()],
                EvidenceCache(directory),
                FakeClient(error=RuntimeError("offline")),
            )
            document, states = manager.rules(now=datetime(2026, 10, 27, tzinfo=UTC))
            self.assertEqual(states[0].status, "unavailable")
            self.assertEqual(document["rules"], [])


if __name__ == "__main__":
    unittest.main()
