# Kustomize installation

Helm is the recommended configurable installation path. This base remains a
neutral alternative for Kustomize consumers and installs directly into the
`kubit` namespace:

```bash
kubectl apply -k base
```

Application defaults are centralized in `configmap.yaml`; the Deployment reads
them through `envFrom`. Environment repositories should own their differences
in a small overlay. For example:

```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

namespace: kubit

resources:
  - github.com/lcontreras48/kubit//base?ref=v1.4.0

images:
  - name: ghcr.io/lcontreras48/kubit
    newTag: 1.4.0

patches:
  - target:
      kind: ConfigMap
      name: kubit-config
    patch: |-
      apiVersion: v1
      kind: ConfigMap
      metadata:
        name: kubit-config
      data:
        CLUSTER_NAME: my-cluster
        SCAN_INTERVAL_SECONDS: "600"
```

`ARGOCD_APPLICATIONS_ENABLED` and `TRIVY_REPORTS_ENABLED` disable optional API
queries. The base ClusterRole grants read-only access to both integrations; an
overlay enforcing minimum permissions can also remove the disabled API group's
rule. Helm performs that RBAC pruning automatically.

Pin remote bases to a release tag. Do not use `main` for deployments. Keep
database credentials and other secrets outside this repository and reference
Secrets managed by the target environment.

Prometheus Operator and Grafana resources are deliberately excluded from the
base. Environments that provide those operators can include the optional
`components/monitoring` component; see its README for the required overlay.
