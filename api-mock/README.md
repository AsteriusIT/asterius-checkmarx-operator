# Checkmarx One API mock for the real CLI

This folder provides an account-free HTTP test backend for the application's
`cx scan create --project-name PROJECT --branch BRANCH -s SOURCE --scan-types TYPES`
workflow. It runs **WireMock's official standalone image**, pinned by version
and digest, with mappings mounted from a Kubernetes ConfigMap. No custom mock image
or Docker build is needed. Swagger UI uses its official image with an OpenAPI
ConfigMap. `scripts/generate-ui.py` packages both ConfigMaps in `k8s/configmaps.json`. It supports the unmodified official **Checkmarx CLI 2.3.67**.
All results are synthetic. No SAST, SCA or IaC analysis occurs, and no Checkmarx
account, license or service is contacted. Repository URLs are accepted as test
data; the mock does not clone them. Local sources are ZIP-uploaded to the mock.
Container-security submissions are also accepted for testing cluster image discovery;
the mock returns canned results and does not pull or inspect images.

## Copied official API contracts

`upstream/ast-cli/internal/wrappers/` contains **all** API wrapper sources, models,
upstream test doubles and supporting files from the official
[Checkmarx CLI repository](https://github.com/Checkmarx/ast-cli/tree/2.3.67/internal/wrappers).
`upstream/ast-cli/internal/params/` contains the CLI endpoint and environment
configuration. These cover considerably more APIs than this mock implements.
The copied sources remain unmodified, with Apache 2.0 license and third-party
notices. `upstream/manifest.json` records the immutable commit and every file's
SHA-256. The inventory is in `upstream/endpoints.json`.

The [official API documentation](https://docs.checkmarx.com/en/34965-68772-checkmarx-one-api-documentation.html)
points to a [Stoplight reference](https://checkmarx.stoplight.io/docs/checkmarx-one-api-reference-guide)
that returned HTTP 404 on 2026-10-12. No official OpenAPI export was retrievable
there. The vendored Go contracts are official; `scripts/generate.py` and its
generated WireMock mappings are locally authored fixtures, **not an official
Checkmarx simulator or a complete implementation of Checkmarx One**.

```sh
python3 api-mock/scripts/upstream.py           # offline checksum verification
python3 api-mock/scripts/upstream.py --restore # restore from the pinned official commit
python3 api-mock/scripts/generate.py           # regenerate WireMock fixtures
python3 api-mock/scripts/generate-ui.py        # regenerate OpenAPI and ConfigMaps
```

## Deploy and validate on asterius-local

Requirements: kubectl, Python 3, and the existing nginx ingress controller on
`kind-asterius-local`. Kubernetes pulls both official images directly. The script
creates the namespace, applies the ConfigMaps, Deployments, Services and Ingress,
and restarts the pods to load changed mappings/specifications.

```sh
bash api-mock/scripts/deploy-local.sh
```

Open **[the API UI](https://checkmarx-mock.asterius.local/)** on the machine
hosting the cluster. Resolve `checkmarx-mock.asterius.local` to `127.0.0.1` on that
machine. The existing HTTPS listener forwards port 443 to nginx ingress.

The Ingress uses `cert-manager.io/cluster-issuer: asterius-local-ca` and
`spec.tls[].secretName: checkmarx-mock-tls`. cert-manager creates the Certificate
and stores its key/certificate in that namespaced Secret, which nginx serves.
The browser must trust the Asterius local root CA. Without `secretName`,
cert-manager skips the TLS block and nginx serves its default certificate.

The UI and mock API share the same origin. No CORS settings or path rewrites are
needed. Returned upload URLs and token claims preserve HTTPS through the ingress.
This is a local development ingress; it also exposes WireMock's unauthenticated
admin API for inspection/reset. Use only the supplied dummy credentials.

1. Expand **Authentication**, click **Try it out**, then **Execute**. The dummy
   credentials are prefilled.
2. Copy `access_token` from the response. Click **Authorize** and paste it without
   the `Bearer` prefix.
3. Create a project, create a scan, then execute the scan GET twice to see
   `Running` and `Completed`. Examples contain the fixed fixture IDs.
4. **Mock control** exposes request inspection, mapping inspection and reset.

`ui/openapi.json` describes the implemented mock surface with request examples and
response schemas. It is generated from the local fixtures and is not an official
Checkmarx OpenAPI export. The other vendored API contracts remain reference files.

To also build/run the optional real CLI smoke Job (Linux amd64; Docker and kind
required for this runner only):

```sh
bash api-mock/scripts/deploy-local.sh --with-cli-smoke
kubectl --context kind-asterius-local -n checkmarx-mock get pods,jobs,svc,ingress
kubectl --context kind-asterius-local -n checkmarx-mock port-forward svc/checkmarx-api-mock 18080:8080
```

In another terminal, run the complete CLI regression smoke test against this
dedicated mock (it resets server state and the request journal):

```sh
python3 api-mock/scripts/smoke.py --evidence api-mock/evidence/kubernetes-smoke.json
```

For other clusters, create `checkmarx-mock` first, then apply `k8s/configmaps.json`,
`k8s/install.yaml`, `k8s/ui.yaml` and `k8s/ingress.yaml`. Adjust ingress hosts,
class and TLS to match that cluster. There are no mock/UI images to build or push.
`runner.Dockerfile` remains only for the optional real CLI Job: it packages the
verified executable separately from the mock server.

## Run locally with Docker

```sh
python3 api-mock/scripts/download-cli.py
docker run --rm --name checkmarx-api-mock -p 127.0.0.1:18080:8080 \
  --user 10001:10001 \
  -v "$PWD/api-mock/mappings:/home/wiremock/mappings:ro" \
  wiremock/wiremock:3.13.2@sha256:0d4ecb3e4dc8213fd7a4d37d6a78f6e6b553a6d2e15bd51b0999781282ac61b3 \
  --global-response-templating --disable-gzip --max-request-journal-entries 200
```

In another terminal:

```sh
python3 api-mock/scripts/smoke.py

export CX_BASE_URI=http://127.0.0.1:18080
export CX_BASE_AUTH_URI=http://127.0.0.1:18080
export CX_TENANT=mock
export CX_CLIENT_ID=mock-cli
export CX_CLIENT_SECRET=mock-secret
api-mock/.cache/cx scan create --project-name mock-project --branch main \
  -s api-mock/fixtures/source --scan-types iac-security --wait-delay 1
api-mock/.cache/cx scan create --project-name mock-project --branch main \
  -s https://github.com/Checkmarx/ast-cli --scan-types sast,sca,iac-security --wait-delay 1
```

Unset any existing `CX_APIKEY` before these manual commands. `CX_BASE_AUTH_URI`
is the correct IAM variable for this pinned CLI; it appends `/auth/realms/mock`
itself. `CX_BASE_IAM_URI` from the original MVP instructions is not bound by
this release. The issued dummy JWT embeds the caller's base URL so both
port-forward access and Kubernetes service DNS work without changing fixtures.

## Implemented HTTP surface and behavior

| API | Mock behavior |
| --- | --- |
| `POST /auth/realms/mock/protocol/openid-connect/token` | Dummy client credentials, JWT-shaped mock access token; incorrect credentials return 401 |
| `GET /api/healthcheck` | Readiness and liveness |
| `GET /api/flags`, `/api/flags/{name}` | Disabled feature flags |
| `GET /api/configuration/tenant`, `/api/configuration/project/{id}` | Empty configuration |
| `PATCH /api/configuration/project` | Accept configuration updates |
| `GET/POST /api/projects`, `GET /api/projects/{id}` | Initially empty; creation enables existing-project lookup |
| `POST /api/uploads`, `PUT /mock-upload/source.zip` | Local presigned upload simulation; uploaded bytes are not persisted |
| `POST /api/scans`, `GET /api/scans/{id}` | Queued → Running → Completed; each submission restarts this scenario |
| `GET /api/scans`, `/api/scans/{id}/workflow` | Fixed scan and empty workflow |
| `GET /api/results`, `/api/scan-summary` | Synthetic empty results and counters |
| `POST/GET /api/sca/export/requests`, export download | Empty SCA package/vulnerability export required by the CLI report flow |
| `GET /api/policy_management_service_uri/evaluation` | Completed evaluation without a build break |

This is a **single-project, single-scan fixture**. Use project `mock-project`,
branch `main`, and sequential scans. IDs, dates and reported engines are fixed
(SAST/SCA/KICS), including for an IaC-only submission. It does not implement
arbitrary project storage, parallel scans, tenant isolation, real OAuth signature
verification, findings, policy violations, multipart uploads, remote scan deletion,
cancellation, or every CLI command. API wrappers copied upstream are reference
material, not automatically enabled mock endpoints. Unsupported requests fail;
the smoke test checks for unmatched and fallback responses.

`scripts/smoke.py` verifies repository submission, an actual local ZIP upload,
project reuse, container image submission, Running/Completed polling, result retrieval,
failed-scan exits and invalid credentials with the real CLI. The optional `--evidence`
argument writes compact request traces locally; these reports are excluded from Git.

To inject a scan failure manually, then restore the default fixtures:

```sh
curl -fsS -X POST -H 'Content-Type: application/json' \
  --data-binary @api-mock/fixtures/failed-scan.json http://127.0.0.1:18080/__admin/mappings
# Run cx scan create: it should now exit nonzero.
curl -fsS -X POST http://127.0.0.1:18080/__admin/reset
```

## Connect this application's operator

For operator tests, build its runner using the verified CLI, set `CX_CLI_IMAGE`
to `checkmarx-real-cli:2.3.67`, and configure each CR's `spec.credentialsSecretRef` to a Secret
**in the operator's scan namespace** with the five dummy variables above.
For cross-namespace access, use
`http://checkmarx-api-mock.checkmarx-mock.svc.cluster.local:8080` for both base URIs.
The mock namespace's Secret is not automatically available in `checkmarx-operator`.
Use `projectName: mock-project` and sequential Scan CRs. This deployment validates
the CLI/backend boundary; the operator controller is not installed by this script.

Cleanup removes only this test environment:

```sh
kubectl --context kind-asterius-local delete namespace checkmarx-mock
```

Tool references: [WireMock official Docker image](https://wiremock.org/docs/standalone/docker/),
[response templating](https://wiremock.org/docs/response-templating/),
[stateful scenarios](https://wiremock.org/docs/stateful-behaviour/),
[Swagger UI official image](https://swagger.io/docs/open-source-tools/swagger-ui/usage/installation/).
