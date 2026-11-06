# Contributing to Kubit

Thank you for helping improve Kubit.

## Before you start

- Search existing issues and pull requests before opening a duplicate.
- Discuss large API or architecture changes in an issue first.
- Never add credentials, private cluster exports, or proprietary compatibility
  matrices.
- Compatibility claims must link to official upstream evidence. Missing or
  unverifiable evidence must remain `unknown`.
- Runtime inventory and evidence must be discovered automatically. Parser
  fixtures are for tests only.

## Development checks

Kubit requires Python 3.11 or newer. Run:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 scripts/set_version.py --check
python3 -m json.tool components/monitoring/dashboard.json >/dev/null
kubectl kustomize base >/dev/null
helm lint charts/kubit
docker build -t kubit:dev .
git diff --check
```

Keep pull requests focused and add tests for behavior changes. Describe the
official evidence used by every new provider and how failures or stale evidence
are prevented from producing a supported result.

By contributing, you agree that your contribution is licensed under the
Apache License 2.0.
