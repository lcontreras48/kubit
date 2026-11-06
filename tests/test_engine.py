import unittest
from datetime import date

from kubit.engine import Engine
from kubit.models import Component
from kubit.providers import (
    ClickHouseOperatorCompatibilityProvider,
    MendRenovateCEHelmEvidenceProvider,
    MetalLBHelmCompatibilityProvider,
    OpenTelemetryOperatorCompatibilityProvider,
)


RULES = {
    "schema_version": 1,
    "rules": [
        {
            "id": "skew",
            "type": "version_skew",
            "subject": "kubelet",
            "dependency": "kubernetes",
            "never_newer": True,
            "max_older_minors": 3,
            "evidence": "https://example.test/skew",
        },
        {
            "id": "cnpg",
            "type": "matrix",
            "subject": "cloudnativepg",
            "dependency": "kubernetes",
            "evidence": "https://example.test/matrix",
            "entries": [
                {"subject_series": "1.30", "supported_dependency_series": ["1.34", "1.35", "1.36"]},
                {"subject_series": "1.29", "supported_dependency_series": ["1.35"], "end_of_life": "2026-09-29"},
            ],
        },
    ],
}


class EngineTest(unittest.TestCase):
    def setUp(self):
        self.engine = Engine(RULES, today=date(2026, 10, 27))

    def test_supported_kubelet_skew_and_cnpg_matrix(self):
        results = self.engine.evaluate(
            [
                Component("kubernetes", "v1.35.4", "api"),
                Component("kubelet", "v1.34.2", "node", "worker-1"),
                Component("cloudnativepg", "1.30.1", "deployment"),
            ]
        )
        self.assertEqual({result.status for result in results}, {"supported"})

    def test_sandbox_application_sources_preserve_supported_unsupported_and_unknown(self):
        metallb = MetalLBHelmCompatibilityProvider()
        metallb.prepare(
            [Component("metallb", "v0.14.8", "application", metadata={"application_group": True})]
        )
        renovate = MendRenovateCEHelmEvidenceProvider()
        renovate.prepare(
            [
                Component(
                    "renovate",
                    "13.2.0-full",
                    "application",
                    metadata={"chart_name": "mend-renovate-ce", "chart_version": "13.2.0"},
                )
            ]
        )
        rules = [
            *metallb.parse(
                "name: metallb\nversion: 0.14.8\nappVersion: v0.14.8\nkubeVersion: '>= 1.19.0-0'\n"
            ),
            *OpenTelemetryOperatorCompatibilityProvider().parse(
                "| OpenTelemetry Operator | Kubernetes |\n"
                "| --- | --- |\n"
                "| v0.134.0 | v1.25 to v1.33 |\n"
            ),
            *ClickHouseOperatorCompatibilityProvider().parse(
                "clickhouse-operator versions 0.16.0 and after is compatible "
                "Kubernetes version 1.25 and after"
            ),
            *renovate.parse(
                "name: mend-renovate-ce\nversion: 13.2.0\nappVersion: 13.2.0-full\n"
            ),
        ]
        results = Engine({"schema_version": 1, "rules": rules}).evaluate(
            [
                Component("kubernetes", "v1.37.1", "api"),
                Component("metallb", "v0.14.8", "application"),
                Component("opentelemetry-operator", "0.134.0", "deployment"),
                Component("clickhouse-operator", "0.26.0", "deployment"),
                Component("renovate", "13.2.0-full", "application"),
            ]
        )
        by_subject = {result.component: result for result in results}
        self.assertEqual(by_subject["metallb"].status, "supported")
        self.assertEqual(by_subject["opentelemetry-operator"].status, "unsupported")
        self.assertEqual(by_subject["clickhouse-operator"].status, "supported")
        self.assertEqual(by_subject["renovate"].status, "unknown")

    def test_newer_kubelet_is_incompatible(self):
        results = self.engine.evaluate(
            [Component("kubernetes", "v1.35.4", "api"), Component("kubelet", "v1.36.0", "node")]
        )
        self.assertEqual(results[0].status, "incompatible")

    def test_eol_takes_precedence_over_valid_matrix(self):
        results = self.engine.evaluate(
            [Component("kubernetes", "v1.35.4", "api"), Component("cloudnativepg", "1.29.3", "deployment")]
        )
        self.assertEqual(results[0].status, "unsupported")

    def test_component_without_rule_is_unknown(self):
        results = self.engine.evaluate([Component("cilium", "1.18.0", "daemonset")])
        self.assertEqual(results[0].status, "unknown")

    def test_matrix_can_explain_an_officially_shipped_combination(self):
        rules = {
            "schema_version": 1,
            "rules": [
                {
                    "id": "talos-release",
                    "type": "matrix",
                    "subject": "talos",
                    "dependency": "kubernetes",
                    "evidence": "https://example.test/releases",
                    "supported_reason": "Kubernetes series is shipped by this Talos series.",
                    "entries": [{"subject_series": "1.14", "supported_dependency_series": ["1.37"]}],
                }
            ],
        }
        result = Engine(rules).evaluate(
            [Component("kubernetes", "v1.37.1", "api"), Component("talos", "1.14.1", "node", "node-1")]
        )[0]
        self.assertEqual(result.status, "supported")
        self.assertEqual(result.reason, "Kubernetes series is shipped by this Talos series.")

        rules["rules"][0]["unsupported_reason"] = "Kubernetes series is not shipped by this Talos series."
        result = Engine(rules).evaluate(
            [Component("kubernetes", "v1.38.0", "api"), Component("talos", "1.14.1", "node", "node-1")]
        )[0]
        self.assertEqual(result.status, "unsupported")
        self.assertEqual(result.reason, "Kubernetes series is not shipped by this Talos series.")

    def test_tested_matrix_keeps_unlisted_combination_unknown(self):
        rules = {
            "schema_version": 1,
            "rules": [
                {
                    "id": "argocd-tested",
                    "type": "matrix",
                    "subject": "argocd",
                    "dependency": "kubernetes",
                    "evidence": "https://example.test/argocd",
                    "outside_status": "unknown",
                    "unsupported_reason": "Not listed as tested upstream.",
                    "supported_reason": "Listed as tested upstream.",
                    "entries": [{"subject_series": "3.5", "supported_dependency_series": ["1.36"]}],
                }
            ],
        }
        supported = Engine(rules).evaluate(
            [Component("kubernetes", "v1.36.4", "api"), Component("argocd", "v3.5.6", "statefulset")]
        )[0]
        unlisted = Engine(rules).evaluate(
            [Component("kubernetes", "v1.37.1", "api"), Component("argocd", "v3.5.6", "statefulset")]
        )[0]
        self.assertEqual((supported.status, supported.reason), ("supported", "Listed as tested upstream."))
        self.assertEqual((unlisted.status, unlisted.reason), ("unknown", "Not listed as tested upstream."))

    def test_minimum_dependency_rule(self):
        rules = {
            "schema_version": 1,
            "rules": [
                {
                    "id": "operator-minimum",
                    "type": "minimum_version",
                    "subject": "prometheus-operator",
                    "dependency": "kubernetes",
                    "evidence": "https://example.test/operator",
                    "entries": [
                        {
                            "subject_min_version": "0.84.0",
                            "minimum_dependency_version": "1.25.0",
                            "conditional_minimum_dependency_version": "1.23.0",
                            "condition": "ExampleFeature feature gate enabled",
                        },
                        {"subject_max_exclusive": "0.84.0", "minimum_dependency_version": "1.16.0"},
                    ],
                }
            ],
        }
        supported = Engine(rules).evaluate(
            [Component("kubernetes", "v1.37.1", "api"), Component("prometheus-operator", "v0.94.1", "deployment")]
        )[0]
        incompatible = Engine(rules).evaluate(
            [Component("kubernetes", "v1.22.9", "api"), Component("prometheus-operator", "v0.94.1", "deployment")]
        )[0]
        conditional = Engine(rules).evaluate(
            [Component("kubernetes", "v1.24.9", "api"), Component("prometheus-operator", "v0.94.1", "deployment")]
        )[0]
        self.assertEqual(supported.status, "supported")
        self.assertIn("documented minimum 1.25.0", supported.reason)
        self.assertEqual(incompatible.status, "incompatible")
        self.assertEqual(conditional.status, "unknown")
        self.assertIn("ExampleFeature feature gate enabled", conditional.reason)

    def test_subject_minimum_rule_builds_operator_dependency_chain(self):
        rules = {
            "schema_version": 1,
            "rules": [
                {
                    "id": "prometheus-minimum",
                    "type": "subject_minimum",
                    "subject": "prometheus",
                    "dependency": "prometheus-operator",
                    "minimum_subject_version": "2.0.0",
                    "evidence": "https://example.test/prometheus",
                }
            ],
        }
        supported = Engine(rules).evaluate(
            [
                Component("prometheus-operator", "v0.94.1", "deployment"),
                Component("prometheus", "v3.15.0-distroless", "statefulset"),
            ]
        )[0]
        incompatible = Engine(rules).evaluate(
            [
                Component("prometheus-operator", "v0.94.1", "deployment"),
                Component("prometheus", "v1.8.2", "statefulset"),
            ]
        )[0]
        self.assertEqual(supported.status, "supported")
        self.assertIn("supported by prometheus-operator", supported.reason)
        self.assertEqual(incompatible.status, "incompatible")

    def test_catalog_matrix_requires_high_fresh_source_backed_coverage(self):
        rules = {
            "schema_version": 1,
            "rules": [
                {
                    "id": "compatibility-fyi-cilium-kubernetes",
                    "type": "catalog_matrix",
                    "subject": "cilium",
                    "dependency": "kubernetes",
                    "provider": "compatibility-fyi",
                    "evidence": "https://compatibility.fyi/projects/cilium/",
                    "max_evidence_age_days": 180,
                    "entries": [
                        {
                            "subject_constraint": "1.20",
                            "dependency_ranges": [">=1.33 <1.37"],
                            "same_version": False,
                            "basis": "tested",
                            "confidence": "high",
                            "catalog_status": "compatible",
                            "last_verified": "2026-10-15",
                            "notes": ["Cilium 1.20 is tested with Kubernetes 1.33 through 1.36."],
                            "source_title": "Cilium Kubernetes compatibility",
                            "source_url": "https://raw.githubusercontent.com/cilium/cilium/v1.20.3/compatibility.rst",
                        }
                    ],
                }
            ],
        }
        engine = Engine(rules, today=date(2026, 10, 27))
        supported = engine.evaluate(
            [Component("kubernetes", "v1.36.4", "api"), Component("cilium", "v1.20.3", "daemonset")]
        )[0]
        uncovered = engine.evaluate(
            [Component("kubernetes", "v1.37.1", "api"), Component("cilium", "v1.20.3", "daemonset")]
        )[0]
        self.assertEqual(supported.status, "supported")
        self.assertEqual(supported.evidence_provider, "compatibility-fyi")
        self.assertEqual(supported.evidence_basis, "tested")
        self.assertEqual(supported.evidence_confidence, "high")
        self.assertEqual(supported.evidence_verified_at, "2026-10-15")
        self.assertEqual(uncovered.status, "unknown")
        self.assertIn("does not cover", uncovered.reason)

        rules["rules"][0]["entries"][0]["confidence"] = "medium"
        lower_confidence = Engine(rules, today=date(2026, 10, 27)).evaluate(
            [Component("kubernetes", "v1.36.4", "api"), Component("cilium", "v1.20.3", "daemonset")]
        )[0]
        self.assertEqual(lower_confidence.status, "unknown")

        rules["rules"][0]["entries"][0]["confidence"] = "high"
        rules["rules"][0]["entries"][0]["basis"] = "recommended"
        recommendation = Engine(rules, today=date(2026, 10, 27)).evaluate(
            [Component("kubernetes", "v1.36.4", "api"), Component("cilium", "v1.20.3", "daemonset")]
        )[0]
        self.assertEqual(recommendation.status, "unknown")

        rules["rules"][0]["entries"][0]["basis"] = "tested"
        rules["rules"][0]["entries"][0]["last_verified"] = "2025-01-01"
        stale = Engine(rules, today=date(2026, 10, 27)).evaluate(
            [Component("kubernetes", "v1.36.4", "api"), Component("cilium", "v1.20.3", "daemonset")]
        )[0]
        self.assertEqual(stale.status, "stale")

    def test_catalog_constraint_supports_ranges_or_groups_and_exact_patches(self):
        rule = {
            "id": "catalog-range",
            "type": "catalog_matrix",
            "subject": "example",
            "dependency": "kubernetes",
            "provider": "compatibility-fyi",
            "evidence": "https://compatibility.fyi/projects/example/",
            "entries": [
                {
                    "subject_constraint": ">=2.5.302 <2.6 || 3.1.4",
                    "dependency_ranges": [">=1.34 <1.38"],
                    "same_version": False,
                    "basis": "supported",
                    "confidence": "high",
                    "catalog_status": "compatible",
                    "last_verified": "2026-10-15",
                    "notes": [],
                    "source_title": "Example support matrix",
                    "source_url": "https://example.test/support",
                }
            ],
        }
        engine = Engine({"schema_version": 1, "rules": [rule]}, today=date(2026, 10, 27))
        for version in ("2.5.315", "3.1.4"):
            with self.subTest(version=version):
                result = engine.evaluate(
                    [Component("kubernetes", "1.37.1", "api"), Component("example", version, "deployment")]
                )[0]
                self.assertEqual(result.status, "supported")

    def test_constraint_matrix_supports_ranges_and_explicit_release_status(self):
        rule = {
            "id": "containerd",
            "type": "constraint_matrix",
            "subject": "containerd",
            "dependency": "kubernetes",
            "provider": "containerd",
            "evidence": "https://example.test/containerd",
            "outside_status": "unknown",
            "entries": [
                {
                    "subject_constraints": [">=2.3.0 <2.4.0"],
                    "dependency_constraints": ["1.36", "1.37"],
                    "status": "supported",
                    "reason": "Recommended combination.",
                    "outside_reason": "This release has a different documented dependency series.",
                }
            ],
        }
        engine = Engine({"schema_version": 1, "rules": [rule]})
        supported = engine.evaluate(
            [Component("kubernetes", "1.37.1", "api"), Component("containerd", "2.3.5", "node")]
        )[0]
        uncovered = engine.evaluate(
            [Component("kubernetes", "1.38.0", "api"), Component("containerd", "2.3.5", "node")]
        )[0]
        self.assertEqual((supported.status, supported.reason), ("supported", "Recommended combination."))
        self.assertEqual(
            (uncovered.status, uncovered.reason),
            ("unknown", "This release has a different documented dependency series."),
        )

        rule["entries"][0].update(
            {"subject_constraints": ["3.15.1"], "dependency_constraints": [">=0.0"], "status": "unsupported"}
        )
        rule["subject"] = "cephcsi"
        unsupported = Engine({"schema_version": 1, "rules": [rule]}).evaluate(
            [Component("kubernetes", "1.37.1", "api"), Component("cephcsi", "3.15.1", "daemonset")]
        )[0]
        self.assertEqual(unsupported.status, "unsupported")

    def test_constraint_matrix_matches_four_part_application_version_exactly(self):
        rule = {
            "id": "datahub-chart",
            "type": "constraint_matrix",
            "subject": "datahub",
            "dependency": "kubernetes",
            "evidence": "https://example.test/Chart.yaml",
            "outside_status": "unknown",
            "entries": [
                {
                    "subject_exact": "v1.4.0.3",
                    "subject_constraints": [],
                    "dependency_constraints": [],
                    "outside_reason": "Official chart does not declare kubeVersion.",
                }
            ],
        }
        result = Engine({"schema_version": 1, "rules": [rule]}).evaluate(
            [Component("kubernetes", "v1.37.1", "api"), Component("datahub", "v1.4.0.3", "application")]
        )[0]
        self.assertEqual(result.status, "unknown")
        self.assertEqual(result.reason, "Official chart does not declare kubeVersion.")

    def test_ha_apiserver_spread_is_evaluated_once(self):
        rules = {
            "schema_version": 1,
            "rules": [
                {
                    "id": "api-spread",
                    "type": "version_spread",
                    "subject": "kube-apiserver",
                    "max_minor_spread": 1,
                    "evidence": "https://example.test/skew",
                    "evidence_status": "fresh",
                }
            ],
        }
        results = Engine(rules).evaluate(
            [
                Component("kube-apiserver", "v1.35.4", "pod", "cp-1"),
                Component("kube-apiserver", "v1.33.8", "pod", "cp-2"),
            ]
        )
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, "incompatible")

    def test_stale_evidence_never_reports_supported(self):
        rules = {
            "schema_version": 1,
            "rules": [
                {
                    "id": "stale-skew",
                    "type": "version_skew",
                    "subject": "kubelet",
                    "dependency": "kube-apiserver",
                    "never_newer": True,
                    "max_older_minors": 3,
                    "evidence": "https://example.test/skew",
                    "evidence_status": "stale",
                }
            ],
        }
        results = Engine(rules).evaluate(
            [Component("kubelet", "v1.35.4", "node", "node-1"), Component("kube-apiserver", "v1.35.4", "pod", "cp-1")]
        )
        self.assertEqual(results[0].status, "stale")

    def test_multiple_api_servers_are_aggregated_per_subject(self):
        rules = {
            "schema_version": 1,
            "rules": [
                {
                    "id": "skew",
                    "type": "version_skew",
                    "subject": "kubelet",
                    "dependency": "kube-apiserver",
                    "never_newer": True,
                    "max_older_minors": 3,
                    "evidence": "https://example.test/skew",
                }
            ],
        }
        results = Engine(rules).evaluate(
            [
                Component("kubelet", "v1.35.4", "node", "worker-1"),
                Component("kube-apiserver", "v1.35.4", "pod", "cp-1"),
                Component("kube-apiserver", "v1.34.9", "pod", "cp-2"),
            ]
        )
        kubelet_results = [result for result in results if result.component == "kubelet"]
        self.assertEqual(len(kubelet_results), 1)
        self.assertEqual(kubelet_results[0].status, "incompatible")


if __name__ == "__main__":
    unittest.main()
