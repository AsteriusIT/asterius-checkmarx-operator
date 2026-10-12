#!/usr/bin/env python3
"""Generate deterministic WireMock mappings from locally authored CLI fixtures."""
import base64
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROJECT = "11111111-1111-4111-8111-111111111111"
SCAN = "22222222-2222-4222-8222-222222222222"
PUBLIC_BASE = ("{{#if request.headers.X-Forwarded-Proto}}{{request.headers.X-Forwarded-Proto}}"
    "://{{request.headers.Host}}{{else}}{{request.baseUrl}}{{/if}}")
def encode(value):
    return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")

CLAIMS = {
    "tenant_name": "mock", "tenant_id": "organization::mock", "sub": "mock-cli",
    "ast-base-url": PUBLIC_BASE, "exp": 4102444800, "iat": 1767225600,
    "ast-license": {"LicenseData": {"allowedEngines": ["sast", "sca", "kics"], "dastEnabled": False}},
    "roles_ast": ["view-projects", "create-projects", "create-scan", "view-scans"]
}
TOKEN = ("{{#assign 'claims'}}" + json.dumps(CLAIMS) + "{{/assign}}" +
    encode({"alg": "HS256", "typ": "JWT"}) +
    ".{{{replace (replace (base64 claims padding=false) '+' '-') '/' '_'}}}." +
    encode("MOCK-ONLY-NOT-A-REAL-SIGNATURE"))
mappings = []
def stub(name, method, path, body=None, status=200, *, regex=False, priority=5, auth=True, **extra):
    request = {"method": method, "urlPathPattern" if regex else "urlPath": path}
    if auth:
        request["headers"] = {"Authorization": {"matches": r"Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\." + encode("MOCK-ONLY-NOT-A-REAL-SIGNATURE")}}
    response = {"status": status, "headers": {"Content-Type": "application/json", "X-Mock-Only": "true"}}
    if body is not None:
        # body (rather than jsonBody) enables response-template helpers.
        response["body"] = json.dumps(body)
    mapping = {"name": name, "priority": priority, "request": request, "response": response}
    mapping.update(extra)
    mappings.append(mapping)
    return mapping

stub("health", "GET", "/api/healthcheck", {"status": "MOCK ONLY"}, auth=False)
token = stub("token", "POST", "/auth/realms/mock/protocol/openid-connect/token", {
    "access_token": "MOCK_TOKEN", "token_type": "Bearer", "expires_in": 3600,
    "refresh_token": "mock-refresh-token", "refresh_expires_in": 3600
}, auth=False)
token["response"]["body"] = token["response"]["body"].replace("MOCK_TOKEN", TOKEN)
token["request"]["bodyPatterns"] = [{"contains": "grant_type=client_credentials"},
    {"contains": "client_id=mock-cli"}, {"contains": "client_secret=mock-secret"}]
stub("invalid-credentials", "POST", "/auth/realms/[^/]+/protocol/openid-connect/token",
     {"error": "invalid_client", "error_description": "Use mock tenant and dummy client credentials"},
     401, regex=True, priority=50, auth=False)
stub("flags", "GET", "/api/flags", {"flags": []})
stub("flag", "GET", "/api/flags/[^/]+", {"name": "{{request.pathSegments.[2]}}", "status": False}, regex=True)
stub("tenant-configuration", "GET", "/api/configuration/tenant", [])
stub("project-configuration", "GET", "/api/configuration/project/" + PROJECT, [])
project = {"id": PROJECT, "name": "mock-project", "mainBranch": "main", "repoUrl": "",
    "createdAt": "2026-01-01T00:00:00Z", "updatedAt": "2026-01-01T00:00:00Z",
    "groups": [], "tags": {}, "applicationIds": []}
stub("project-search-empty", "GET", "/api/projects", {"totalCount": 0, "projects": []},
     scenarioName="project", requiredScenarioState="Started")
stub("project-create", "POST", "/api/projects", {
    **project, "name": "{{jsonPath request.body '$.name'}}"
}, 201, scenarioName="project", newScenarioState="Created")
stub("project-search-existing", "GET", "/api/projects", {"totalCount": 1, "projects": [project]},
     scenarioName="project", requiredScenarioState="Created")
stub("project-get", "GET", "/api/projects/" + PROJECT, project)
stub("project-configuration-update", "PATCH", "/api/configuration/project", [])
stub("upload-url", "POST", "/api/uploads", {"url": PUBLIC_BASE + "/mock-upload/source.zip"})
stub("upload", "PUT", "/mock-upload/source.zip", status=200, auth=False)
def scan(status):
    return {"id": SCAN, "projectId": PROJECT, "projectName": "mock-project", "branch": "main",
        "status": status, "createdAt": "2026-01-01T00:00:00Z", "updatedAt": "2026-01-01T00:01:00Z",
        "initiator": "MOCK ONLY", "tags": {}, "engines": ["sast", "sca", "kics"],
        "metadata": {"configs": [{"type": t} for t in ["sast", "sca", "kics"]]},
        "statusDetails": [{"name": t, "status": status} for t in ["sast", "sca", "kics"]]}
stub("scan-create", "POST", "/api/scans", scan("Queued"), 201,
     scenarioName="scan", newScenarioState="Queued")
stub("scan-running", "GET", "/api/scans/" + SCAN, scan("Running"),
     scenarioName="scan", requiredScenarioState="Queued", newScenarioState="Running")
stub("scan-completed", "GET", "/api/scans/" + SCAN, scan("Completed"),
     scenarioName="scan", requiredScenarioState="Running", newScenarioState="Completed")
stub("scan-terminal", "GET", "/api/scans/" + SCAN, scan("Completed"),
     scenarioName="scan", requiredScenarioState="Completed")
stub("scan-list", "GET", "/api/scans", {"totalCount": 1, "scans": [scan("Completed")]})
stub("scan-workflow", "GET", "/api/scans/" + SCAN + "/workflow", [])
stub("results", "GET", "/api/results", {"scanID": SCAN, "totalCount": 0, "results": []})
stub("sca-export-create", "POST", "/api/sca/export/requests", {"exportId": "mock-export"}, 202)
stub("sca-export-status", "GET", "/api/sca/export/requests", {
    "exportId": "mock-export", "exportStatus": "Completed",
    "fileUrl": PUBLIC_BASE + "/mock-export/report.json"})
for path in ["/mock-export/report.json", "/api/sca/export/requests/mock-export/download"]:
    stub("sca-export-download-" + str(len(mappings)), "GET", path, {"Packages": [], "Vulnerabilities": []})
stub("scan-summary", "GET", "/api/scan-summary", {"totalCount": 1, "scansSummaries": [{
    "scanId": SCAN, "tenantId": "mock", **{k: {"totalCounter": 0, "severityCounters": []}
    for k in ["sastCounters", "scaCounters", "kicsCounters", "scaPackagesCounters", "scaContainersCounters"]}
}]})
stub("policy", "GET", "/api/policy_management_service_uri/evaluation", {
    "status": "COMPLETED", "breakBuild": False, "policies": []})
stub("unauthorized-or-unimplemented", "ANY", "/api/.*", {
    "message": "MOCK ONLY: missing mock bearer token or endpoint not implemented", "code": 401
}, 401, regex=True, priority=99, auth=False)

def main():
    out = ROOT / "mappings"
    for old in out.glob("*.json"):
        old.unlink()
    for mapping in mappings:
        (out / (mapping["name"] + ".json")).write_text(json.dumps(mapping, indent=2) + "\n")
    (ROOT / "fixtures" / "failed-scan.json").write_text(json.dumps({
        "name": "injected-failed-scan", "priority": 1,
        "request": {"method": "GET", "urlPath": "/api/scans/" + SCAN},
        "response": {"status": 200, "jsonBody": scan("Failed"), "headers": {"Content-Type": "application/json"}}
    }, indent=2) + "\n")
    print(f"Generated {len(mappings)} WireMock mappings")

if __name__ == "__main__":
    main()
