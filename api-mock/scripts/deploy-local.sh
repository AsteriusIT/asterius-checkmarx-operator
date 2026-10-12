#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
context=kind-asterius-local
cluster=asterius-local
python3 scripts/generate.py
python3 scripts/generate-ui.py
# Namespace first, then ConfigMaps before either Deployment starts.
kubectl --context "$context" apply -f <(python3 - <<'PY'
from pathlib import Path
print(Path('k8s/install.yaml').read_text().split('---', 1)[0])
PY
)
kubectl --context "$context" apply -f k8s/configmaps.json
kubectl --context "$context" apply -f k8s/install.yaml
kubectl --context "$context" apply -f k8s/ui.yaml -f k8s/ingress.yaml
# WireMock reads files at startup; Swagger UI mounts the spec with subPath.
kubectl --context "$context" -n checkmarx-mock rollout restart deployment/checkmarx-api-mock
kubectl --context "$context" -n checkmarx-mock rollout restart deployment/checkmarx-api-ui
kubectl --context "$context" -n checkmarx-mock rollout status deployment/checkmarx-api-mock --timeout=120s
kubectl --context "$context" -n checkmarx-mock rollout status deployment/checkmarx-api-ui --timeout=120s
printf '\nAPI UI: https://checkmarx-mock.asterius.local/\n'
if [[ "${1:-}" != "--with-cli-smoke" ]]; then
  exit 0
fi
# Optional real CLI test runner; the mock and UI need no custom image builds.
python3 scripts/download-cli.py
docker build -t checkmarx-real-cli:2.3.67 -f runner.Dockerfile .cache
kind load docker-image --name "$cluster" checkmarx-real-cli:2.3.67
kubectl --context "$context" apply -f <(python3 - <<'PY'
from pathlib import Path
s=Path('k8s/cli-smoke.yaml').read_text()
print(s.split('---', 1)[1])
PY
)
job=$(kubectl --context "$context" create -f <(python3 - <<'PY'
from pathlib import Path
print(Path('k8s/cli-smoke.yaml').read_text().split('---', 1)[0])
PY
) -o name)
if ! kubectl --context "$context" -n checkmarx-mock wait --for=condition=complete "$job" --timeout=120s; then
  kubectl --context "$context" -n checkmarx-mock logs "$job"
  exit 1
fi
kubectl --context "$context" -n checkmarx-mock logs "$job"
printf '\nMock endpoint: http://checkmarx-api-mock.checkmarx-mock.svc.cluster.local:8080\n'
