# Kubernetes Checkmarx Operator — initial MVP

A namespace-scoped Python/Kopf operator for **Checkmarx One**. This is an initial implementation built against public CLI documentation; no account, Kubernetes cluster, image build or real Checkmarx scan was available for integration validation. It does not target legacy CxSAST/CxSCA APIs.

## MVP scope and product model

| Target | Implemented analysis | Source submitted |
|---|---|---|
| Public HTTPS Git repository | SAST, SCA, IaC (licensed engines required) | Repository URL and branch |
| Deployment, StatefulSet, DaemonSet, Job, CronJob in the same namespace | IaC misconfiguration analysis | Kubernetes resource identity and spec snapshot |

A workload is not source code. SAST cannot recover the application source from its running Pod. This first workload adapter checks deployment configuration; it does **not** scan image packages, live processes, network behavior or exploitability. Container image scanning is the next adapter, using resolved image digests and Checkmarx's documented container-security workflow.

One namespaced `CheckmarxScan` expresses one desired scan target. The operator polls every 30 seconds and creates a CLI Job. Owner references let Kubernetes remove child Jobs and snapshot ConfigMaps when the CR is deleted. CR status exposes `phase`, `jobName`, `inputDigest` and `observedGeneration`. `Completed` means the CLI Job exited successfully, not that the target has no vulnerabilities. `Failed` includes scanner, policy, authentication, image and execution failures; inspect Job/Pod diagnostics to distinguish them.

## Repository layout

| Path | Responsibility |
|---|---|
| `operator_src/planner.py` | Validation, snapshot redaction, input hashing, Job/ConfigMap construction |
| `operator_src/handlers.py` | Kopf timer, Kubernetes reads, idempotent child creation, status reconciliation |
| `config/crd.yaml` | Structural v1alpha1 CRD, target validation and status subresource |
| `config/install.yaml` | Namespace, ServiceAccount, namespace RBAC, single-replica Deployment |
| `examples/` | Repository scan, workload scan and demo Deployment |
| `runner/Dockerfile` | Runtime image for a supplied, verified official Linux CLI binary |
| `mock/` | Account-free mock CLI image; performs no analysis |
| `api-mock/` | Official CLI API contracts and a WireMock HTTP backend; runs the real CLI without an account |
| `tests/test_operator.py` | Offline planning and reconciliation tests using dependency doubles |
| `Dockerfile`, `requirements.txt`, `Makefile` | Operator packaging and development commands |

## Run the offline tests

```sh
cd checkmarx-operator
make test
```

Tests use only Python's standard library. They check stable identity, changed workload inputs, secret redaction, target validation, terminal states, conflict races, ownership collision protection and serialization of active runs. They do not validate Kopf, CRD admission, Kubernetes RBAC or CLI behavior. Controller dependencies are pinned to explicit starting versions and require installation/container smoke testing before deployment.

## Account-free cluster smoke test

To exercise the **real Checkmarx CLI** against a local HTTP API mock, see
[`api-mock/README.md`](api-mock/README.md). It includes copied official CLI API
contracts, a pinned WireMock server, Kubernetes manifests and a deployment script
for the dedicated `checkmarx-mock` namespace on `asterius-local`.
The following older smoke test substitutes the CLI executable itself.

The API mock runs the official WireMock image with ConfigMap-mounted mappings.
Its Swagger UI is exposed through the local nginx ingress at
[Checkmarx mock API UI](https://checkmarx-mock.asterius.local/).

Requires Docker, kubectl and a development cluster. Build/load or push these images so your cluster can pull them:

```sh
docker build -t checkmarx-operator:dev .
docker build -t checkmarx-mock:dev mock/
```

Change `CX_CLI_IMAGE` in `config/install.yaml` to `checkmarx-mock:dev`. Update the operator image to your registry if necessary. The mock is intentionally explicit: it prints `MOCK ONLY` and submits nothing. Then:

```sh
kubectl apply -f config/crd.yaml
kubectl apply -f config/install.yaml
kubectl -n checkmarx-system create secret generic checkmarx-auth --from-literal=CX_MOCK_EXIT_CODE=0
kubectl apply -f examples/workload-target.yaml
kubectl apply -f examples/workload.yaml
kubectl apply -f examples/repository.yaml
kubectl -n checkmarx-system get cxscan -w
```

Find `status.jobName` with `kubectl get cxscan NAME -n checkmarx-system -o yaml`, then run `kubectl logs job/JOB_NAME -n checkmarx-system`. Change the mock Secret's `CX_MOCK_EXIT_CODE` to `1` and change `spec.rerunToken` to exercise failure handling.

The supplied installation watches only `checkmarx-system`. For a different namespace, change the namespace fields, RoleBinding subject, and Dockerfile's Kopf `--namespace` argument (or override Deployment args). Use one operator per namespace for this MVP; no cluster-wide discovery permissions are granted.

## Connect Checkmarx One when account access returns

1. Download a specific official Linux CLI release, verify its checksum and place the executable at `runner/cx`. The executable is intentionally not bundled. Build `docker build -t YOUR_REGISTRY/checkmarx-runner:YOUR_VERSION runner/`, push it and configure `CX_CLI_IMAGE` with its immutable digest. The runner must expose `cx` on PATH and work as UID 10001 with `/tmp` as its writable home. The Dockerfiles' base image tags are starting points; pin their digests for release builds.
2. Replace the mock Secret with a dedicated Checkmarx integration Secret containing `CX_APIKEY`, `CX_BASE_URI`, `CX_BASE_AUTH_URI` and `CX_TENANT`, using the actual tenant-specific values from Checkmarx documentation. `CX_BASE_AUTH_URI` is the IAM variable bound by the pinned CLI 2.3.67; verify configuration for other releases. OAuth client credentials (`CX_CLIENT_ID`, `CX_CLIENT_SECRET`) are an alternative. Do not commit real Secret YAML. The operator references the Secret; it has no Secret read permission. Kubernetes injects it directly into the scanner Pod.
3. Confirm network access to Checkmarx authentication, API/upload endpoints and repository host; configure environment-specific egress restrictions. Ensure the integration identity can create/read projects and execute the selected licensed scanners.
4. Run the official CLI against a tiny public repository outside Kubernetes first; verify authentication, synchronous completion, expected exit codes and project permissions for the exact pinned version. Repeat with one Kubernetes manifest directory and `--scan-types iac-security`.
5. Apply one scan CR, inspect CLI logs and Checkmarx UI, and correlate the real remote scan to the Job. Confirm success and deliberate authentication/policy failure before broader rollout.

The command is `cx scan create --project-name PROJECT --branch BRANCH -s SOURCE --scan-types TYPES`; arguments are passed directly, without a shell. No `--async` is used. The operator intentionally does not guess a JSON response schema or parse human CLI output for scan IDs.

## Reconciliation and retry semantics

Job names hash CR UID, generation, spec, CLI image and sanitized workload contents. Repeated reconciliation reuses the existing Job; a workload spec change produces a new input. A new target waits while the previous Job is pending/running. Repository branches are mutable: remote commit changes are **not** discovered automatically. Change `spec.rerunToken` to trigger a new submission, including retries after a failed scan. Changing credentials alone does not retry a failed Job.

Jobs use `backoffLimit: 0` to reduce accidental duplicate remote scans and `activeDeadlineSeconds` to bound cluster execution. There is no Job TTL: completed Jobs are the reconciliation record and remain until the CR is deleted. Do not delete them while the CR remains; the initial controller can recreate a missing Job and submit again. Kubernetes node loss, network ambiguity or operator restart around a remote submission cannot provide exactly-once execution. A durable remote scan ID and API reconciliation are required before production use.

Snapshots are immutable ConfigMaps limited to 800 KB. The snapshot retains spec plus resource name/namespace; it excludes top-level annotations, status and transient metadata, and redacts literal container environment values. It does **not** implement general-purpose secret detection: commands, args, nested annotations, labels and other inline spec fields may contain sensitive data. Use Kubernetes Secret references and review submitted manifests. No Secret resource contents are fetched. Redaction also means literal env-value changes alone do not trigger scans and some IaC checks may lose context.

Jobs run without a service-account token, as non-root, with dropped capabilities, a read-only root filesystem and bounded resources. The operator is single replica with Recreate deployment strategy and Kopf standalone mode; it has no leader election. Resource naming is checked against owner UID. Restrict who can create Scan CRs, Jobs and referenced credentials in this dedicated namespace. Multiple CRs can submit concurrently: global quotas/concurrency limits are not implemented.

## Next implementation milestones

1. **Live contract verification:** pinned CLI/image, real tenant authentication, repository and manifest scans, failure cases; kind-based CRD/RBAC/restart tests.
2. **Durable remote lifecycle:** API adapter with scan ID, remote status polling, bounded rate-limit retries and cancellation; recover after ambiguous submissions without blindly retrying.
3. **Findings:** normalize documented JSON/SARIF output; persist reports externally and keep bounded severity counts, scan URL and policy decision in status. Never infer a clean scan from Job success.
4. **Container workloads:** resolve running image digests, deduplicate by digest, submit container-security scans, add registry auth and map image results back to workloads. No privileged Docker socket in the operator.
5. **Repository automation:** authenticated clone with scoped Secrets, commit SHA provenance, schedules/webhooks, concurrency budget, retention and Helm packaging.

Deletion currently removes cluster artifacts; it does not cancel or delete remote Checkmarx scans/projects. Private Git authentication, result storage, schedules, admission blocking and direct REST implementation are outside this first slice.

## Official references

- [Checkmarx One CLI quick start](https://docs.checkmarx.com/en/34965-68621-checkmarx-one-cli-quick-start-guide.html)
- [Scan command and engine flags](https://docs.checkmarx.com/en/34965-68643-scan.html)
- [CLI configuration and environment variables](https://docs.checkmarx.com/en/34965-68624-checkmarx-one-cli-config-and-environment-variables.html)
- [CLI authentication](https://docs.checkmarx.com/en/34965-118315-authentication-for-checkmarx-one-cli.html)
- [Running scans, including container images](https://docs.checkmarx.com/en/34965-350124-running-scans-via-the-cli.html)

Public documentation checked 2026-10-12. Licensing, tenant endpoint configuration and the exact release's behavior remain live-validation gates.
