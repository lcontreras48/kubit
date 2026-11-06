# Optional monitoring component

This Kustomize component adds a `ServiceMonitor`, `PrometheusRule`, and Grafana
dashboard ConfigMap. It requires the Prometheus Operator CRDs and a Grafana
sidecar configured to discover dashboard ConfigMaps.

Include it only from an environment overlay that owns those dependencies:

```yaml
resources:
  - ../../base

components:
  - ../../components/monitoring
```

Patch `serviceMonitor.labels` or `prometheusRule.labels` in the overlay when the
target Prometheus installation requires release-specific selector labels. Helm
users can instead enable `serviceMonitor`, `prometheusRule`, and
`grafanaDashboard` independently in their values file.
