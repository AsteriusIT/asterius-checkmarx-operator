# Unofficial Kubernetes operator for Checkmarx One

[![Tests](https://github.com/AsteriusIT/asterius-checkmarx-operator/actions/workflows/tests.yml/badge.svg)](https://github.com/AsteriusIT/asterius-checkmarx-operator/actions/workflows/tests.yml)
[![Security](https://github.com/AsteriusIT/asterius-checkmarx-operator/actions/workflows/security.yml/badge.svg)](https://github.com/AsteriusIT/asterius-checkmarx-operator/actions/workflows/security.yml)

This is an independent project, not affiliated with, endorsed by, or supported by
Checkmarx. Checkmarx product names are used to describe compatibility.

A Kubernetes operator that runs Checkmarx One scans through CLI Jobs in a dedicated namespace.

- **Public Git repositories:** SAST, SCA and IaC scans.
- **Kubernetes workloads:** IaC scans of Deployment, StatefulSet, DaemonSet, Job and CronJob configuration in the same namespace.
- **Cluster images:** automatic discovery and container security scans of images used by running Pods across namespaces.

Workload scans inspect deployment configuration; cluster image scans inspect image contents. This is an initial MVP; real Checkmarx integration still needs validation.

## Quick start

Requires Docker, kubectl and a development Kubernetes cluster. Run commands from the repository root.

Build the operator and mock CLI images, then load them into your cluster or push them to a registry it can access:

```sh
docker build -t checkmarx-operator:dev .
docker build -t checkmarx-mock:dev mock/
```

Set `CX_CLI_IMAGE` to `checkmarx-mock:dev` in `config/install.yaml`. Adjust the operator image if using a registry. Then deploy and submit the example scans:

```sh
kubectl apply -f config/crd.yaml -f config/cluster-crd.yaml -f config/image-crd.yaml
kubectl apply -f config/install.yaml
kubectl -n checkmarx-operator create secret generic checkmarx-auth --from-literal=CX_MOCK_EXIT_CODE=0
kubectl apply -f examples/workload-target.yaml
kubectl apply -f examples/workload.yaml
kubectl apply -f examples/repository.yaml
kubectl -n checkmarx-operator get cxscan -w
```

The mock CLI performs no analysis. For testing the real CLI against a local API mock without an account, follow the [API mock guide](api-mock/README.md).

For `kind-asterius-local` with the API mock already running, use the local configuration instead. It runs the real CLI with dummy credentials:

```sh
docker build -t checkmarx-operator:dev .
kind load docker-image --name asterius-local checkmarx-operator:dev
kubectl --context kind-asterius-local apply -k overlays/local
kubectl --context kind-asterius-local -n checkmarx-operator rollout status deployment/checkmarx-operator
```

## Use Checkmarx One

The installation manifest uses the official [`checkmarx/ast-cli`](https://hub.docker.com/r/checkmarx/ast-cli)
image at version `2.3.67`, pinned by digest. No custom runner build or push is needed.
Scan Jobs use the image entrypoint, run as UID 10001 with a read-only root filesystem,
and use `/tmp` for their working directory and home.

1. Keep the default `CX_CLI_IMAGE` in `config/install.yaml`, or set it to another
   tested version and digest. Reapply the installation manifest after changes.
2. Replace the mock Secret with your integration credentials: `CX_APIKEY`,
   `CX_BASE_URI`, `CX_BASE_AUTH_URI` and `CX_TENANT`. OAuth client credentials
   (`CX_CLIENT_ID`, `CX_CLIENT_SECRET`) are also supported. Keep credentials out of Git.
3. Verify network access, project permissions and scanner licensing, then submit
   an example scan and inspect its Job logs and results in Checkmarx.

The `runner/` Dockerfile is optional for deployments requiring a customized CLI
image (for example, additional CA certificates). Custom images must expose the CLI
through their entrypoint. The downloader remains available for host-based API mock tests.

## Scan behavior

The operator checks scans every 30 seconds. Read `status.jobName` to find the scanner Job:

```sh
kubectl -n checkmarx-operator get cxscan NAME -o yaml
kubectl -n checkmarx-operator logs job/JOB_NAME
```

`Completed` means the CLI exited successfully; review Checkmarx results for findings. Change `spec.rerunToken` to retry or rescan a repository. Remote branch changes and credential updates do not automatically trigger another scan; workload configuration changes do.

Keep completed Jobs while their scan resources exist: deleting a Job can trigger another submission. Deleting a scan resource removes its Kubernetes Jobs and snapshots, but does not cancel or delete remote Checkmarx scans.

Individual scan resources and scanner Jobs stay in `checkmarx-operator`. Cluster discovery has read access to Pods across namespaces. To change the execution namespace, update the manifests, credential references and Kopf namespace argument together.

Workload snapshots redact literal environment values, commands, arguments,
probe HTTP header values, and annotations, including nested Pod templates and
init containers. Structural security settings and Secret references are retained
for IaC analysis. Redacted command text cannot be analyzed. Other inline fields
can still contain sensitive data; use Secret references and review manifests
before scanning.

## Automatic cluster image scans

Enable discovery of existing and newly observed images:

```sh
kubectl apply -f examples/cluster-images.yaml
kubectl get cxcluster
kubectl -n checkmarx-operator get cximage
```

The operator inventories running Pods every 30 seconds, including init containers and ephemeral containers. Images are deduplicated by runtime SHA-256 digest within each cluster scan. Short-lived Pods that disappear between checks may be missed. Scanning uses Checkmarx's cloud container-security engine; no Docker socket is needed.

Use `discovery.includeNamespaces` and `discovery.excludeNamespaces` to limit coverage. `scanExisting` controls the first inventory; `scanNewImages` controls subsequently discovered digests. Disabled images remain `Skipped` for that policy. The example excludes the operator namespace to avoid scanning scanner Jobs.

`maxConcurrentScans` limits active Jobs per policy. Set `rescanIntervalSeconds: 86400` for daily rescans of present images; the default `0` scans each digest once. Change `rerunToken` for an explicit retry. `suspend: true` pauses submissions while discovery continues. Completed scans are CLI success, not a guarantee of no vulnerabilities.

Each `CheckmarxImageScan` records its Job, phase and Pod references. Local image IDs without a pullable digest report `Unavailable`. Keep image records and Jobs to preserve scan history; a missing image Job reports `Lost` until explicitly retried. Deleting the cluster scan removes its records and Jobs through owner references, without cancelling remote scans.

### Private registries (including Nexus)

Create a `kubernetes.io/dockerconfigjson` Secret in the execution namespace
(`checkmarx-operator` by default). Use a Docker configuration containing inline
registry authentication; `credsStore` and `credHelpers` require external helpers
that are not included in the runner. The registry hostname and port must match
the image references used by your Pods.

```sh
# Use a dedicated Docker configuration and a Nexus account with pull access.
# docker login prompts for the password; do not commit the resulting file.
docker --config ./nexus-auth login nexus.example.com:5000
kubectl -n checkmarx-operator create secret generic nexus-registry-auth \
  --type=kubernetes.io/dockerconfigjson \
  --from-file=.dockerconfigjson=./nexus-auth/config.json
```

Add the optional reference to your `CheckmarxClusterScan`:

```yaml
spec:
  registryCredentialsSecretRef:
    namespace: checkmarx-operator
    name: nexus-registry-auth
```

Reapply `config/cluster-crd.yaml` when upgrading, then apply your cluster scan.
The operator mounts `.dockerconfigjson` as read-only `/registry-auth/config.json`,
sets `DOCKER_CONFIG=/registry-auth`, and adds `--containers-local-resolution`.
The resolver retrieves image contents directly from the registry without a
Docker daemon or socket. The operator does not read or copy Secret contents,
and it rejects references outside the execution namespace. Missing Secrets or
missing `.dockerconfigjson` keys prevent the scanner Pod from starting.

The scanner Job needs network access to Nexus and Checkmarx, trusted registry
TLS certificates, and enough temporary space and memory for image resolution.
The default runner trusts public certificate authorities; add your internal CA
to a custom runner when needed. Jobs currently have 2 GiB of temporary storage
and a 1 GiB memory limit; larger images may require adjusting the Job template.

The Secret can hold authentication for multiple registries. Setting the reference
enables local resolution for all images in that policy. Without it, scans continue
using cloud resolution. Changing or removing the reference triggers rescans of
present, enabled images once active Jobs finish. Updating Secret contents alone
does not trigger a rescan; change `spec.rerunToken` to retry after credential rotation.

Real private-registry scans still need validation against your Nexus and Checkmarx
environment. Local image export and findings storage are not implemented. Local
mock scans use synthetic results.

## Development

Run the offline tests with Python 3; no additional dependencies are needed:

```sh
make test
```

Build and scan the operator with Docker and Trivy installed:

```sh
make scan
# Include findings for which the vulnerability database has no fix:
trivy image --image-src docker --scanners vuln checkmarx-operator:dev
```

`make scan` fails if any vulnerability has an available fix, at any severity.
It does not gate vulnerabilities without an available fix. Override the local
image tag with `IMAGE=checkmarx-operator:my-tag`. To refresh OS updates even when
the base image is unchanged, first rebuild with
`docker build --pull --no-cache -t checkmarx-operator:dev .`.
The runtime image omits pip and ensurepip after installing dependencies.
Runner images need separate scans; the operator scan does not cover the CLI.

### GitHub CI security reports

The dynamic badges above link to the latest GitHub Actions runs. Tests run on
pushes and pull requests; security scans also run weekly and can be started
manually from the Actions tab. Badges become active after these workflows are
pushed to GitHub and run.

The Security workflow scans first-party Python with Bandit, declared dependencies
and repository configuration with Trivy, and the working tree and fetched Git
history with Gitleaks. It also builds the operator image, tests it as a non-root
user with a read-only filesystem, scans its complete runtime dependencies, and
generates a CycloneDX SBOM. Vendored Go snippets are not included in Python SAST;
their integrity is checked against the upstream manifest by the Tests workflow.
The CLI runner images are outside the operator image scan.

Each run publishes a security summary in its job summary and downloadable
`repository-security-reports`, `container-security-reports`, and `test-reports`
artifacts, retained for 30 days. Reports include all severities; Gitleaks output
redacts detected secret values. No images are published by CI.

Security fails on any HIGH/CRITICAL Trivy finding (including findings without
fixes), HIGH Bandit finding, detected secret, scanner error, or missing required
report. Lower-severity findings remain visible without blocking. One exact
KSV-0109 false positive is reviewed in `scripts/security-report.py`: the embedded
sample's `automountServiceAccountToken: false` setting is not a secret. Its raw
finding remains in JSON and the review appears in the summary; additional
suspected secrets still block CI. `.trivy/registries.json` explicitly trusts
Docker Hub, the registry used by the digest-pinned vendor images. Remaining
medium findings cover required namespace-local Job/ConfigMap creation; remaining
low findings concern Docker HEALTHCHECK instructions. Kubernetes
manifests control health probes for deployed services. These checks do not detect
every application-level risk, including the documented limits of snapshot
redaction.

## License and permitted use

Original project code is licensed under [Apache 2.0](LICENSE). Vendored Checkmarx
files retain their upstream license and notices; see
[third-party notices](THIRD_PARTY_NOTICES.md).

The local mock returns synthetic results and grants no access to Checkmarx One.
Real scans require appropriate Checkmarx subscriptions and API permissions under
the user's applicable agreement. Publishing this integration grants no right to
resell Checkmarx services, share credentials, or scan third-party material.
Users must have permission to process and upload the repositories, workload
configuration and images they submit, including any confidential or personal data.
