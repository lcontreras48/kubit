# Data sources, integrations, and RBAC

Kubit combines cluster inventory with official upstream compatibility evidence.
It does not infer support from the presence of a component, and it does not use
Prometheus or Trivy as compatibility authorities.

## Information flow

| Capability | Producer or source | How Kubit receives it | Required setup |
| --- | --- | --- | --- |
| Kubernetes and workload inventory | Kubernetes API | ServiceAccount HTTPS requests to cluster-wide list endpoints | Kubit ClusterRole and ServiceAccount |
| Argo CD application grouping | Argo CD `Application` CRs | Optional Kubernetes API list of `argoproj.io` applications | Argo CD CRDs plus `integrations.argocd.enabled=true` |
| Vulnerabilities, configuration audits, exposed secrets, and SBOMs | Trivy Operator | Optional Kubernetes API lists of `aquasecurity.github.io/v1alpha1` report CRs | Trivy Operator plus `integrations.trivyOperator.enabled=true` |
| Compatibility rules and support matrices | Official upstream HTTPS documentation and release metadata | Kubit providers fetch, checksum, and cache the evidence | Outbound HTTPS and writable evidence cache |
| Metrics | Kubit `/metrics` | Prometheus scrapes Kubit; Kubit never queries Prometheus | Prometheus Operator and `serviceMonitor.enabled=true`, or another scraper |
| Grafana dashboard | Kubit dashboard ConfigMap | Grafana sidecar discovers the ConfigMap | `grafanaDashboard.enabled=true` and compatible sidecar labels |
| Users, sessions, proposals, and scan history | PostgreSQL | Optional direct PostgreSQL connection | Existing PostgreSQL Secret or CloudNativePG settings |

Official project locations:

- Trivy Operator: <https://github.com/aquasecurity/trivy-operator>
- Trivy Operator Helm repository: <https://aquasecurity.github.io/helm-charts/>
- Prometheus community Helm charts: <https://github.com/prometheus-community/helm-charts>
- `kube-prometheus-stack` OCI chart: `oci://ghcr.io/prometheus-community/charts/kube-prometheus-stack`
- Prometheus Operator: <https://github.com/prometheus-operator/prometheus-operator>

Kubit exposes every fetched compatibility provider's URL, freshness, and
checksum in `/api/v1/report`, `/metrics`, and the **Sources of Truth** dashboard
view. Trivy's report payload also identifies the scanner name and version.

## Configuring optional readers

Helm values control whether Kubit queries the optional APIs and whether their
RBAC rules are rendered:

```yaml
integrations:
  argocd:
    enabled: true
  trivyOperator:
    enabled: true
```

Set either integration to `false` when its CRDs are absent or the permission is
not acceptable. Raw Kustomize installations use the corresponding
`ARGOCD_APPLICATIONS_ENABLED` and `TRIVY_REPORTS_ENABLED` keys in
`base/configmap.yaml`. The Kustomize base includes read permissions for both by
default; a least-privilege environment that disables an integration should also
remove its API group rule from the ClusterRole in its overlay.

## Exact Kubit RBAC

Kubit does not create, update, patch, or delete discovered cluster resources.
Its generated ClusterRole grants:

| API group | Resource | Verb | Purpose |
| --- | --- | --- | --- |
| non-resource | `/version` | `get` | Kubernetes server version |
| core | `nodes`, `pods` | `list` | node/runtime and running image inventory |
| `apps` | `deployments`, `daemonsets`, `statefulsets`, `replicasets` | `list` | workload, ownership, and runtime correlation |
| `batch` | `jobs` | `list` | batch workload inventory |
| `apiextensions.k8s.io` | `customresourcedefinitions` | `list` | CRD inventory |
| `argoproj.io` | `applications` | `list` | optional Argo CD grouping |
| `aquasecurity.github.io` | four report kinds | `list` | optional Trivy security data |

The optional PostgreSQL connection uses a Kubernetes Secret but the Pod reads
that Secret through a mounted volume or environment reference; the Kubit
ServiceAccount does not receive Secret API permissions.

## Installing information producers

Kubit deliberately does not install third-party operators. Review and pin their
versions independently before production use. Typical upstream installation
commands are:

```bash
helm repo add aqua https://aquasecurity.github.io/helm-charts/
helm repo update
helm upgrade --install trivy-operator aqua/trivy-operator \
  --namespace trivy-system --create-namespace

helm upgrade --install kube-prometheus-stack \
  oci://ghcr.io/prometheus-community/charts/kube-prometheus-stack \
  --namespace monitoring --create-namespace
```

To make Prometheus select Kubit's `ServiceMonitor`, set labels that match the
target Prometheus selector. A common kube-prometheus-stack installation uses:

```yaml
serviceMonitor:
  enabled: true
  labels:
    release: kube-prometheus-stack
prometheusRule:
  enabled: true
  labels:
    release: kube-prometheus-stack
grafanaDashboard:
  enabled: true
```

Release names and selectors are environment-specific; inspect the target
Prometheus custom resource rather than assuming a label.
