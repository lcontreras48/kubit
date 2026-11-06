import unittest

from kubit.models import Component
from kubit.upgrade import evaluate_kubernetes_target


class UpgradeReadinessTest(unittest.TestCase):
    def test_replaces_only_kubernetes_and_apiserver_versions(self):
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
        current = [
            Component("kubernetes", "v1.37.1", "api"),
            Component("kube-apiserver", "v1.37.1", "pod", "cp-1"),
            Component("kubelet", "v1.37.1", "node", "worker-1"),
        ]
        hypothetical, results = evaluate_kubernetes_target(current, rules, "1.38.0")
        versions = {item.name: item.version for item in hypothetical}
        self.assertEqual(versions["kubernetes"], "v1.38.0")
        self.assertEqual(versions["kube-apiserver"], "v1.38.0")
        self.assertEqual(versions["kubelet"], "v1.37.1")
        self.assertEqual(next(item for item in results if item.component == "kubelet").status, "supported")

    def test_rejects_invalid_target(self):
        with self.assertRaises(ValueError):
            evaluate_kubernetes_target([], {"schema_version": 1, "rules": []}, "latest")


if __name__ == "__main__":
    unittest.main()
