# Kubit

**Kubernetes Unified Baseline & Interoperability Tracker**

Open-source Kubernetes compatibility intelligence that automatically inventories
your cluster and validates components against official upstream evidence.

Kubit treats Kubernetes as the central compatibility axis. It first evaluates
the control plane, nodes, runtimes, and networking components, then checks every
detected platform application against the observed or proposed Kubernetes
version. Missing or unverifiable compatibility evidence remains `unknown`; it
is never inferred as supported.

## Highlights

- Automatic discovery of Kubernetes control-plane and node components, Talos,
  containerd, CNIs, workload images, operators, and platform applications.
- Evidence-backed checks retrieved from official upstream sources, with
  provenance, checksums, caching, refresh timestamps, and stale-state handling.
- Upgrade-readiness simulation without changing the cluster.
- Built-in dashboard, JSON API, Prometheus metrics, Grafana dashboard,
  ServiceMonitor, and PrometheusRule resources.
- Optional CloudNativePG-backed authentication and persistence.
- Read-only Trivy Operator integration with bounded, sanitized security details.

## Project status

Kubit is currently a sandbox-stage project. The source version is `1.3.0`.
Production use requires an explicit review of high availability, database
recovery, provider coverage, resource sizing, and cluster security policy.

## Repository layout

```text
src/kubit/                 collector, compatibility engine, API, and web UI
base/                      reusable Kubernetes and monitoring resources
base/monitoring/           ServiceMonitor, PrometheusRule, and Grafana dashboard
components/postgres/       optional CloudNativePG database component
envs/sandbox/              example sandbox Kustomize overlay
charts/kubit/               configurable Helm chart and example values
tests/                     unit and regression tests
```

## Development

Kubit requires Python 3.11 or newer.

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 -m json.tool base/monitoring/dashboard.json >/dev/null
kubectl kustomize envs/sandbox >/dev/null
```

The public manifests and Helm chart use `kubit:1.3.0` as a placeholder image.
Build or publish the application with your preferred container pipeline and
override that image before deployment.

## Helm installation

The Helm chart is the recommended configurable installation path. It supports
custom image, scheduling, storage, Ingress, application intervals, existing
Secrets, Prometheus Operator resources, Grafana dashboard discovery, and an
optional CloudNativePG cluster.

```bash
helm upgrade --install kubit ./charts/kubit \
  --namespace kubit --create-namespace \
  --set image.repository=ghcr.io/your-org/kubit \
  --set config.clusterName=my-cluster
```

See [`charts/kubit/README.md`](charts/kubit/README.md) and the example values
under [`charts/kubit/examples`](charts/kubit/examples). The existing Kustomize
base remains available for consumers that prefer overlays.

## HTTP endpoints

- `GET /`: operational dashboard
- `GET /metrics`: Prometheus metrics
- `GET /healthz` and `GET /readyz`: health endpoints
- `GET /api/v1/report`: inventory, compatibility, and sanitized security report
- `GET /api/v1/upgrade-readiness?kubernetes=v1.38.0`: upgrade simulation
- `POST /api/v1/auth/login` and `POST /api/v1/auth/logout`: optional local auth
- `GET|POST /api/v1/admin/users`: administrator-only user management
- `GET|POST /api/v1/source-proposals`: evidence-source proposals

## Compatibility evidence

Providers retrieve compatibility information from official documentation and
release metadata. If evidence cannot be verified or becomes stale, Kubit
returns `unknown` or `stale` instead of manufacturing a green result.

Direct providers include Kubernetes version skew, CloudNativePG, Talos,
containerd, CoreDNS, Flannel, Kubernetes CSI sidecars, CephCSI,
kube-state-metrics, Argo CD, Prometheus Operator, MetalLB, OpenTelemetry
Operator, DataHub, and ClickHouse Operator. A guarded compatibility.fyi adapter
can supply source-backed fallback evidence when no direct provider exists.

Parser fixtures under `tests/fixtures` are test inputs only and are never used
as runtime compatibility data.

## Optional PostgreSQL

The component in `components/postgres` stores users, sessions, source proposals,
audit events, and scan history. It requires CloudNativePG and independently
generated Kubernetes Secrets. No default credentials are included. See
[`components/postgres/README.md`](components/postgres/README.md) before use.

## Community and security

Contributions are welcome. Read [`CONTRIBUTING.md`](CONTRIBUTING.md),
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md), and [`SECURITY.md`](SECURITY.md).
Do not report vulnerabilities through public issues.

## License

Kubit is licensed under the [Apache License 2.0](LICENSE).
