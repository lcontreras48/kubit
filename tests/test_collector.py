import unittest

from kubit.applications import build_application_components
from kubit.collector import Collector, KubernetesAPI, _application_role
from kubit.models import Component


class FakeAPI:
    def get_optional(self, path):
        return self.get(path)

    def get(self, path):
        responses = {
            "/version": {"gitVersion": "v1.35.4"},
            "/api/v1/nodes": {
                "items": [
                    {
                        "metadata": {"name": "worker-1"},
                        "status": {
                            "nodeInfo": {
                                "kubeletVersion": "v1.35.4",
                                "containerRuntimeVersion": "containerd://2.1.4",
                                "osImage": "Talos (v1.12.1)",
                            }
                        },
                    }
                ]
            },
            "/api/v1/pods": {
                "items": [
                    {
                        "metadata": {"name": "kube-apiserver-cp-1", "namespace": "kube-system"},
                        "spec": {"nodeName": "cp-1", "containers": [{"image": "registry.k8s.io/kube-apiserver:v1.35.4"}]},
                    },
                    {
                        "metadata": {"name": "kube-proxy-worker-1", "namespace": "kube-system"},
                        "spec": {"nodeName": "worker-1", "containers": [{"image": "registry.k8s.io/kube-proxy:v1.35.4"}]},
                    },
                    {
                        "metadata": {"name": "kube-flannel-worker-1", "namespace": "kube-system"},
                        "spec": {"nodeName": "worker-1", "containers": [{"image": "ghcr.io/siderolabs/flannel:0.28.9"}]},
                    },
                    {
                        "metadata": {"name": "user-scheduler", "namespace": "application"},
                        "spec": {"nodeName": "worker-1", "containers": [{"image": "registry.k8s.io/kube-scheduler:v1.30.0"}]},
                    },
                ]
            },
            "/apis/apps/v1/replicasets": {"items": []},
            "/apis/argoproj.io/v1alpha1/applications": {
                "items": [
                    {
                        "metadata": {"name": "datahub", "namespace": "argocd"},
                        "spec": {
                            "destination": {"namespace": "datahub"},
                            "source": {"repoURL": "https://example.test/datahub.git"},
                        },
                        "status": {
                            "sync": {"status": "Synced", "revision": "abc123"},
                            "health": {"status": "Healthy"},
                            "resources": [],
                        },
                    }
                ]
            },
            "/apis/apps/v1/deployments": {
                "items": [
                    {
                        "metadata": {"name": "cnpg-controller-manager", "namespace": "cloudnative-pg"},
                        "spec": {"template": {"spec": {"containers": [{"image": "ghcr.io/cloudnative-pg/cloudnative-pg:1.30.1"}]}}},
                    },
                    {
                        "metadata": {"name": "catalog-svc", "namespace": "kasten-io"},
                        "spec": {"template": {"spec": {"containers": [{"image": "gcr.io/kasten-images/catalog:9.0.7"}]}}},
                    },
                    {
                        "metadata": {"name": "auth-svc", "namespace": "kasten-io"},
                        "spec": {"template": {"spec": {"containers": [{"image": "gcr.io/kasten-images/auth:9.0.7"}]}}},
                    },
                    {
                        "metadata": {"name": "example", "namespace": "example", "labels": {"app.kubernetes.io/name": "example-app"}},
                        "spec": {"template": {"spec": {"containers": [{"image": "registry.example/example:2.4.1"}]}}},
                    },
                    {
                        "metadata": {
                            "name": "prometheus-operator",
                            "namespace": "prometheus",
                            "labels": {
                                "app.kubernetes.io/name": "kube-prometheus-stack-prometheus-operator",
                                "app.kubernetes.io/version": "91.8.2",
                            },
                        },
                        "spec": {"template": {"spec": {"containers": [{"image": "quay.io/prometheus-operator/prometheus-operator:v0.94.1"}]}}},
                    },
                    {
                        "metadata": {
                            "name": "datahub-datahub-gms",
                            "namespace": "datahub",
                            "labels": {
                                "app.kubernetes.io/name": "datahub-gms",
                                "app.kubernetes.io/managed-by": "Helm",
                                "app.kubernetes.io/version": "0.1.1",
                                "helm.sh/chart": "datahub-gms-0.3.4",
                            },
                            "annotations": {
                                "argocd.argoproj.io/tracking-id": "datahub:apps/Deployment:datahub/datahub-datahub-gms"
                            },
                        },
                        "spec": {"template": {"spec": {"containers": [{"image": "acryldata/datahub-gms:v1.4.0.3"}]}}},
                    },
                ]
            },
            "/apis/apps/v1/daemonsets": {
                "items": [
                    {
                        "metadata": {"name": "kube-proxy", "namespace": "kube-system"},
                        "spec": {"template": {"spec": {"containers": [{"image": "registry.k8s.io/kube-proxy:v1.35.4"}]}}},
                    },
                    {
                        "metadata": {"name": "kube-flannel", "namespace": "kube-system"},
                        "spec": {"template": {"spec": {"containers": [{"image": "ghcr.io/siderolabs/flannel:0.28.9"}]}}},
                    },
                ]
            },
            "/apis/apps/v1/statefulsets": {
                "items": [
                    {
                        "metadata": {
                            "name": "prometheus-main",
                            "namespace": "prometheus",
                            "labels": {
                                "app.kubernetes.io/name": "prometheus",
                                "app.kubernetes.io/version": "91.8.2",
                            },
                        },
                        "spec": {
                            "template": {
                                "spec": {
                                    "containers": [
                                        {"image": "quay.io/prometheus/prometheus:v3.15.0-distroless"},
                                        {"image": "quay.io/prometheus-operator/prometheus-config-reloader:v0.94.1"},
                                    ]
                                }
                            }
                        },
                    }
                ]
            },
            "/apis/batch/v1/jobs": {
                "items": [
                    {
                        "metadata": {
                            "name": "datahub-system-update",
                            "namespace": "datahub",
                            "labels": {
                                "app.kubernetes.io/managed-by": "Helm",
                                "helm.sh/chart": "datahub-0.8.12",
                            },
                            "annotations": {
                                "argocd.argoproj.io/tracking-id": "datahub:batch/Job:datahub/datahub-system-update"
                            },
                        },
                        "spec": {"template": {"spec": {"containers": [{"image": "acryldata/datahub-upgrade:v1.4.0.3"}]}}},
                    }
                ]
            },
            "/apis/apiextensions.k8s.io/v1/customresourcedefinitions": {"items": [{}, {}]},
        }
        return responses[path]


class CollectorSecurityTest(unittest.TestCase):
    def test_kubernetes_api_rejects_non_https_origin_before_reading_token(self):
        with self.assertRaisesRegex(ValueError, "HTTPS origin"):
            KubernetesAPI(base_url="file:///tmp/fake-api", token_path="/does/not/exist")


class CollectorTest(unittest.TestCase):
    def test_collects_core_and_known_workload_components(self):
        components = Collector(FakeAPI()).collect()
        versions = {(item.name, item.version) for item in components}
        self.assertIn(("kubernetes", "v1.35.4"), versions)
        self.assertIn(("talos", "1.12.1"), versions)
        self.assertIn(("cloudnativepg", "1.30.1"), versions)
        self.assertIn(("kube-apiserver", "v1.35.4"), versions)
        self.assertIn(("kube-proxy", "v1.35.4"), versions)
        self.assertEqual(sum(item.name == "kube-proxy" for item in components), 1)
        self.assertIn(("flannel", "0.28.9"), versions)
        self.assertEqual(sum(item.name == "flannel" for item in components), 1)
        self.assertNotIn(("kube-scheduler", "v1.30.0"), versions)
        self.assertIn(("kasten-k10", "9.0.7"), versions)
        self.assertEqual(sum(item.name == "kasten-k10" for item in components), 1)
        self.assertIn(("example-app", "2.4.1"), versions)
        self.assertIn(("prometheus-operator", "v0.94.1"), versions)
        self.assertIn(("prometheus", "v3.15.0-distroless"), versions)
        self.assertIn(("prometheus-config-reloader", "v0.94.1"), versions)
        self.assertNotIn(("prometheus", "91.8.2"), versions)
        self.assertIn(("datahub", "v1.4.0.3"), versions)
        self.assertIn(("datahub-gms", "v1.4.0.3"), versions)
        self.assertIn(("crds", "2"), versions)
        cnpg = next(item for item in components if item.name == "cloudnativepg")
        apiserver = next(item for item in components if item.name == "kube-apiserver")
        self.assertEqual(cnpg.metadata["namespace"], "cloudnative-pg")
        self.assertEqual(apiserver.metadata["namespace"], "kube-system")
        datahub = next(item for item in components if item.name == "datahub")
        self.assertTrue(datahub.metadata["application_group"])
        self.assertEqual(datahub.metadata["application_id"], "argocd:datahub")
        self.assertEqual(datahub.metadata["chart_version"], "0.8.12")
        self.assertEqual(datahub.metadata["deployment_method"], "argocd-helm")
        self.assertEqual(datahub.metadata["version_mode"], "uniform")
        self.assertEqual(datahub.metadata["sync_status"], "Synced")
        self.assertIn("datahub-gms", datahub.metadata["members"])
        datahub_gms = next(item for item in components if item.name == "datahub-gms")
        self.assertEqual(datahub_gms.metadata["application_id"], "argocd:datahub")

    def test_keeps_node_agent_daemonset_when_no_pod_was_observed(self):
        workloads = [
            {
                "metadata": {"name": "kube-proxy", "namespace": "kube-system"},
                "spec": {
                    "template": {
                        "spec": {"containers": [{"image": "registry.k8s.io/kube-proxy:v1.35.4"}]}
                    }
                },
            }
        ]
        components = Collector(FakeAPI())._workloads("daemonset", workloads, set())
        self.assertEqual(len(components), 1)
        self.assertEqual(components[0].name, "kube-proxy")

    def test_correlates_deployment_pod_image_digest_through_replicaset(self):
        replicasets = [
            {
                "metadata": {
                    "name": "example-abc",
                    "namespace": "example",
                    "ownerReferences": [
                        {"kind": "Deployment", "name": "example", "controller": True}
                    ],
                }
            }
        ]
        pods = [
            {
                "metadata": {
                    "name": "example-abc-123",
                    "namespace": "example",
                    "ownerReferences": [
                        {"kind": "ReplicaSet", "name": "example-abc", "controller": True}
                    ],
                },
                "spec": {"containers": [{"name": "app", "image": "example:1.2.3"}]},
                "status": {
                    "phase": "Running",
                    "containerStatuses": [
                        {
                            "name": "app",
                            "image": "example:1.2.3",
                            "imageID": "example@sha256:abc",
                            "ready": True,
                        }
                    ],
                },
            }
        ]
        runtime = Collector(FakeAPI())._pod_runtime(pods, replicasets)
        observed = runtime[("deployment", "example", "example")][0]
        self.assertTrue(observed["ready"])
        self.assertEqual(observed["image_id"], "example@sha256:abc")

    def test_application_version_modes_distinguish_composite_from_skew(self):
        def member(name, version):
            return Component(
                name,
                version,
                "deployment/example/member",
                "example",
                {
                    "namespace": "example",
                    "application": "example",
                    "application_role": "core",
                },
            )

        uniform = build_application_components([member("api", "1.2.3"), member("web", "1.2.3")])[0]
        composite = build_application_components([member("api", "1.2.3"), member("web", "4.5.6")])[0]
        skew = build_application_components([member("api", "1.2.3"), member("api", "1.2.4")])[0]
        self.assertEqual((uniform.version, uniform.metadata["version_mode"]), ("1.2.3", "uniform"))
        self.assertEqual((composite.version, composite.metadata["version_mode"]), ("multiple", "composite"))
        self.assertEqual((skew.version, skew.metadata["version_mode"]), ("mixed", "skew"))

        dependency = Component(
            "database",
            "9.9.9",
            "statefulset/example/database",
            "example",
            {
                "namespace": "example",
                "application": "example",
                "application_role": "component",
            },
        )
        core_with_dependency = build_application_components(
            [member("api", "1.2.3"), member("web", "1.2.3"), dependency]
        )[0]
        self.assertEqual(
            (core_with_dependency.version, core_with_dependency.metadata["version_mode"]),
            ("1.2.3", "uniform"),
        )

    def test_argocd_application_groups_members_across_namespaces(self):
        member = Component(
            "example-worker",
            "1.2.3",
            "deployment/other/example-worker",
            "other",
            {
                "namespace": "other",
                "application": "example",
                "application_id": "argocd:example",
                "application_role": "core",
                "pod_total": 2,
                "pod_ready": 2,
            },
        )
        discovered = {
            "example": {
                "destination_namespace": "default",
                "health_status": "Healthy",
                "sync_status": "Synced",
            }
        }

        applications = build_application_components([member], discovered)

        self.assertEqual(len(applications), 1)
        self.assertEqual(applications[0].metadata["application_id"], "argocd:example")
        self.assertEqual(applications[0].metadata["namespace"], "default")
        self.assertEqual(applications[0].metadata["pod_ready"], 2)

    def test_registry_organization_does_not_define_core_product_identity(self):
        role = _application_role(
            "prometheus",
            "quay.io/prometheuscommunity/json-exporter:v0.8.0",
            {"app.kubernetes.io/instance": "prometheus"},
            "deployment",
            0,
        )
        self.assertEqual(role, "component")


if __name__ == "__main__":
    unittest.main()
