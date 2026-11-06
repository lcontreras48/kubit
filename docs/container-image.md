# Container image and release ownership

The application source, container build, Kubernetes resources, Helm chart, and
release automation live in this repository. The former `ics-docker/kubit`
repository is no longer required for new releases.

## Local build

```bash
version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' pyproject.toml)"
docker build \
  --build-arg "KUBIT_COMMIT=$(git rev-parse HEAD)" \
  --build-arg "KUBIT_VERSION=${version}" \
  --tag "kubit:${version}" .
docker run --rm --entrypoint python "kubit:${version}" -c \
  'from importlib.metadata import version; print(version("kubit"))'
```

The runtime image runs as UID/GID `65532`, installs dependencies from wheels
built in the first stage, and contains OCI source, revision, version, and
license labels.

## Release flow

Application and chart versions are kept equal. For a new release:

1. Run `python3 scripts/set_version.py MAJOR.MINOR.PATCH`; this updates the
   application, chart, manifests, Kustomize overlay, and documentation together.
2. Run the test, Helm, Kustomize, and container checks from `CONTRIBUTING.md`.
3. Merge the release commit, then push the matching tag, for example `v1.3.0`.

The `Release Kubit` workflow verifies these versions, publishes multi-platform
`linux/amd64` and `linux/arm64` images to GHCR, attaches SBOM/provenance
attestations, packages the Helm chart, and creates a GitHub Release. It publishes
the exact version, major/minor, and `latest` image tags. Deployments and charts
use the exact version tag.

## One-time GitHub configuration

- GitHub Actions must be enabled for the repository.
- Repository or organization policy must allow the workflow's declared
  `contents: write` and `packages: write` permissions.
- After the first image is published, set the `lcontreras48/kubit` container
  package visibility to public if anonymous cluster pulls are required.
  Otherwise configure the chart's `imagePullSecrets` with registry credentials.
- Protect release tags from deletion or force updates if the repository policy
  supports tag rulesets.

No GitLab deploy token, cross-project `CI_JOB_TOKEN`, source clone, or downstream
pipeline is needed. Once the first GHCR image and GitHub Release are verified,
the old `ics-docker/kubit` pipeline can be disabled and that repository can be
archived. Keep it read-only until the migration has been observed successfully
in at least one release.
