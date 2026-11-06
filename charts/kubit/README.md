# Kubit Helm chart

This chart installs Kubit with cluster-wide, read-only discovery permissions.
The default installation creates only native Kubernetes resources. Prometheus
Operator, Grafana sidecar discovery, Ingress, and CloudNativePG resources are
opt-in so the chart does not assume which operators exist in the cluster.

## Install

The chart defaults to the matching release image published by this repository:

```bash
helm upgrade --install kubit ./charts/kubit \
  --namespace kubit --create-namespace \
  --set config.clusterName=my-cluster
```

Inspect all generated resources before applying them:

```bash
helm template kubit ./charts/kubit --namespace kubit \
  --set config.clusterName=my-cluster
```

## Common configurations

Optional API readers and their RBAC rules can be disabled together:

```yaml
integrations:
  argocd:
    enabled: false
  trivyOperator:
    enabled: false
```

Prometheus is an output integration: it scrapes Kubit. Enable the following
resources only when the Prometheus Operator CRDs exist in the target cluster.

Enable resources consumed by Prometheus Operator and a Grafana dashboard
sidecar:

```yaml
serviceMonitor:
  enabled: true
  labels:
    release: prometheus
prometheusRule:
  enabled: true
  labels:
    release: prometheus
grafanaDashboard:
  enabled: true
```

Use an existing PostgreSQL connection Secret:

```yaml
database:
  enabled: true
  existingSecret: kubit-database
  existingSecretKey: database-url
  bootstrapAdmin:
    username: admin
    existingSecret: kubit-bootstrap-admin
```

The `database-url` value must be a PostgreSQL connection URI. The bootstrap
Secret must contain `bootstrap-admin-password` with at least 12 characters.
Credentials should never be committed to a values file.

To create a database through an already-installed CloudNativePG operator, use
`examples/values-cnpg.yaml`. CloudNativePG, backup policy, recovery tests, and
the required Secrets remain the cluster operator's responsibility.

## Upgrade and validation

```bash
helm lint ./charts/kubit
helm upgrade kubit ./charts/kubit --namespace kubit --reuse-values
helm test kubit --namespace kubit
```

Kubit releases use SemVer tags in the form `vMAJOR.MINOR.PATCH`. The application
and chart versions remain aligned. Pushing a release tag validates the project
and publishes the packaged chart as a GitHub Release asset.

Important defaults and all application environment controls are documented in
`values.yaml`. Arbitrary Kubernetes `EnvVar` entries can be appended with
`extraEnv`, and `values.schema.json` catches common type and range errors before
an install.

The default cache volume is `ReadWriteOnce`, so keep `replicaCount: 1` unless
you disable persistence or supply a storage class/access mode that supports all
replicas.

