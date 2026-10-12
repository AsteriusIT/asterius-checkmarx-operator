# Unofficial Kubernetes operator for Checkmarx One

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
kind load docker-image --name asterius-local checkmarx-operator:dev checkmarx-real-cli:2.3.67
kubectl --context kind-asterius-local apply -k overlays/local
kubectl --context kind-asterius-local -n checkmarx-operator rollout status deployment/checkmarx-operator
```

## Use Checkmarx One

1. Download the pinned official Linux x64 CLI and prepare its license notices:

   ```sh
   python3 api-mock/scripts/download-cli.py --output-dir runner
   ```

   The downloader verifies the archive and accompanying notices against recorded
   checksums. Both runner images include the notices at
   `/usr/share/licenses/checkmarx-cli/`. When upgrading the CLI, update the pinned
   release, checksums and applicable notices together.
2. Build and push a runner image:

   ```sh
   docker build -t YOUR_REGISTRY/checkmarx-runner:YOUR_VERSION runner/
   docker push YOUR_REGISTRY/checkmarx-runner:YOUR_VERSION
   ```

3. Set `CX_CLI_IMAGE` in the installation manifest to the runner image, preferably pinned by digest, and reapply it.
4. Replace the mock Secret with your integration credentials: `CX_APIKEY`, `CX_BASE_URI`, `CX_BASE_AUTH_URI` and `CX_TENANT`. OAuth client credentials (`CX_CLIENT_ID`, `CX_CLIENT_SECRET`) are also supported. Keep credentials out of Git.
5. Verify network access, project permissions and scanner licensing, then submit an example scan and inspect its Job logs and results in Checkmarx.

## Scan behavior

The operator checks scans every 30 seconds. Read `status.jobName` to find the scanner Job:

```sh
kubectl -n checkmarx-operator get cxscan NAME -o yaml
kubectl -n checkmarx-operator logs job/JOB_NAME
```

`Completed` means the CLI exited successfully; review Checkmarx results for findings. Change `spec.rerunToken` to retry or rescan a repository. Remote branch changes and credential updates do not automatically trigger another scan; workload configuration changes do.

Keep completed Jobs while their scan resources exist: deleting a Job can trigger another submission. Deleting a scan resource removes its Kubernetes Jobs and snapshots, but does not cancel or delete remote Checkmarx scans.

Individual scan resources and scanner Jobs stay in `checkmarx-operator`. Cluster discovery has read access to Pods across namespaces. To change the execution namespace, update the manifests, credential references and Kopf namespace argument together.

Workload snapshots redact literal container environment values, but other inline fields can still contain sensitive data. Use Secret references and review manifests before scanning.

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

Private registry authentication, local image export and findings storage are not implemented. Local mock scans use synthetic results.

## Development

Run the offline tests with Python 3; no additional dependencies are needed:

```sh
make test
```

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
