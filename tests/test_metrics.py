import unittest

from kubit.metrics import render
from kubit.models import Component, ProviderState, Result


class MetricsTest(unittest.TestCase):
    def test_exports_evidence_state_and_stale_result(self):
        output = render(
            [
                Component("kubernetes", "v1.37.1", "api"),
                Component("cloudnativepg", "1.30.1", "deployment/cloudnative-pg/operator", "cloudnative-pg", {"namespace": "cloudnative-pg", "application": "cloudnative-pg", "application_role": "core", "pod_total": 1, "pod_ready": 1}),
            ],
            [
                Result(
                    "cloudnativepg",
                    "1.30.1",
                    "kubernetes",
                    "v1.37.1",
                    "stale",
                    "evidence expired",
                    "cnpg",
                    "https://example.test",
                    instance="cloudnative-pg",
                    evidence_status="stale",
                    evidence_provider="cnpg",
                    evidence_title="CloudNativePG support matrix",
                )
            ],
            True,
            0.25,
            100,
            [ProviderState("cnpg", "https://example.test", "stale", age_seconds=700000)],
            {
                "available": True,
                "summary": {"vulnerabilities": 3, "fixable": 1, "eligible_containers": 2, "covered_containers": 1},
                "reports": [
                    {
                        "report_type": "vulnerability",
                        "namespace": "cloudnative-pg",
                        "workload_kind": "Deployment",
                        "workload_name": "operator",
                        "container": "manager",
                        "component": "cloudnativepg",
                        "application": "cloudnative-pg",
                        "status": "fresh",
                        "scanner": {"name": "Trivy", "version": "0.76.1"},
                        "summary": {"critical": 1, "high": 2, "medium": 0, "low": 0, "unknown": 0},
                        "fixable": 1,
                        "age_seconds": 60,
                    }
                ],
            },
        )
        self.assertIn('kubit_compatibility_results{status="stale"} 1', output)
        self.assertIn('evidence_status="stale"', output)
        self.assertIn('reason="evidence expired"', output)
        self.assertIn('evidence_provider="cnpg"', output)
        self.assertIn('evidence_title="CloudNativePG support matrix"', output)
        self.assertIn('evidence_url="https://example.test"', output)
        self.assertIn('component_namespace="cloudnative-pg"', output)
        self.assertIn('component_instance="cloudnative-pg"', output)
        self.assertIn('application="cloudnative-pg"', output)
        self.assertIn('application_role="core"', output)
        self.assertIn('kubit_component_runtime_pods{component="cloudnativepg"', output)
        self.assertIn('kubit_evidence_provider_info{provider="cnpg"', output)
        self.assertIn("kubit_security_collector_available 1", output)
        self.assertIn('kubit_security_summary{finding_type="vulnerabilities"} 3', output)
        self.assertIn('kubit_security_coverage_containers{state="covered"} 1', output)
        self.assertIn('kubit_security_report_findings{report_type="vulnerability"', output)
        self.assertNotIn("vulnerability_id=", output)


if __name__ == "__main__":
    unittest.main()
