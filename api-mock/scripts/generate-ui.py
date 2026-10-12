#!/usr/bin/env python3
"""Describe implemented fixtures as OpenAPI; package files in Kubernetes ConfigMaps.

This is a locally authored mock contract, not a vendor OpenAPI specification.
"""
import json
from pathlib import Path
import re
from generate import PROJECT, SCAN, PUBLIC_BASE

ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / "ui"
UI.mkdir(exist_ok=True)
spec = {
    "openapi": "3.0.3",
    "info": {"title": "Checkmarx One — local mock API", "version": "2.3.67-mock",
        "description": "Synthetic responses only; no security analysis. This locally authored specification "
        "describes the implemented WireMock fixtures, not the complete official Checkmarx API. "
        "Use project mock-project and branch main, one scan at a time. First execute the Authentication "
        "token request with the prefilled dummy credentials. Copy access_token, click Authorize, and paste "
        "the token (without Bearer). Then create a project and scan; poll twice to reach Completed. "
        "Mock control lets you reset scenarios or inspect requests."},
    "servers": [{"url": "/", "description": "This local mock (same origin)"}],
    "security": [{"MockBearer": []}],
    "components": {"securitySchemes": {"MockBearer": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}}},
    "paths": {},
}
def schema(value):
    if isinstance(value, dict):
        return {"type": "object", "properties": {k: schema(v) for k, v in value.items()}}
    if isinstance(value, list):
        return {"type": "array", "items": schema(value[0]) if value else {}}
    if isinstance(value, bool):
        return {"type": "boolean"}
    if isinstance(value, int):
        return {"type": "integer"}
    return {"type": "string"}

def example_body(body):
    # The token contains template code and raw JSON inside base64 blocks.
    if '"access_token"' in body:
        return {"access_token": "<copy the token returned by executing this request>", "token_type": "Bearer", "expires_in": 3600}
    def replace(match):
        text = match.group()
        if "$.name" in text:
            return "mock-project"
        if "baseUrl" in text:
            return "http://checkmarx-mock.asterius.local"
        return "PACKAGE_ENFORCEMENT_ENABLED"
    return json.loads(re.sub(r"\{\{.*?\}\}", replace, body.replace(PUBLIC_BASE, "https://checkmarx-mock.127.0.0.1.sslip.io")))

def body(operation, content_type, example):
    operation["requestBody"] = {"required": True, "content": {content_type: {
        "schema": schema(example), "example": example}}}
    if content_type == "application/x-www-form-urlencoded":
        form = operation["requestBody"]["content"][content_type]["schema"]
        form["required"] = list(example)
        for key, value in example.items():
            form["properties"][key]["default"] = value

for file in sorted((ROOT / "mappings").glob("*.json")):
    mapping = json.loads(file.read_text())
    request = mapping["request"]
    if request["method"] == "ANY" or mapping["name"] == "invalid-credentials":
        continue
    path = request.get("urlPath", request.get("urlPathPattern"))
    path = path.replace(PROJECT, "{projectId}").replace(SCAN, "{scanId}").replace("[^/]+", "{name}")
    method = request["method"].lower()
    tag = ("Authentication" if path.startswith("/auth/") else
           "Uploads" if "upload" in path else "SCA export" if "export" in path else
           "Projects" if "project" in path else "Scans" if "scan" in path else "Configuration and results")
    operation = spec["paths"].setdefault(path, {}).setdefault(method, {
        "operationId": mapping["name"], "summary": mapping["name"].replace("-", " "),
        "tags": [tag], "responses": {},
    })
    if "headers" not in request:
        operation["security"] = []
    parameters = []
    for parameter in re.findall(r"\{([^}]+)\}", path):
        value = {"projectId": PROJECT, "scanId": SCAN, "name": "PACKAGE_ENFORCEMENT_ENABLED"}[parameter]
        parameters.append({"name": parameter, "in": "path", "required": True,
                           "schema": {"type": "string", "default": value}, "example": value})
    if parameters:
        operation["parameters"] = parameters
    response = mapping["response"]
    entry = operation["responses"].setdefault(str(response["status"]), {
        "description": "Synthetic mock response", "content": {"application/json": {"examples": {}}}})
    if "body" in response:
        example = example_body(response["body"])
        entry["content"]["application/json"]["examples"][mapping["name"]] = {"value": example}
        entry["content"]["application/json"]["schema"] = schema(example)

token = spec["paths"]["/auth/realms/mock/protocol/openid-connect/token"]["post"]
spec["paths"]["/api/scans/{scanId}"]["get"]["summary"] = "Poll scan: Running, then Completed"
body(token, "application/x-www-form-urlencoded", {
    "grant_type": "client_credentials", "client_id": "mock-cli", "client_secret": "mock-secret"})
body(spec["paths"]["/api/projects"]["post"], "application/json", {"name": "mock-project", "mainBranch": "main", "tags": {}})
body(spec["paths"]["/api/scans"]["post"], "application/json", {
    "type": "git", "project": {"id": PROJECT},
    "handler": {"repoUrl": "https://github.com/Checkmarx/ast-cli", "branch": "main"},
    "config": [{"type": "sast"}, {"type": "sca"}, {"type": "kics"}]})
body(spec["paths"]["/api/sca/export/requests"]["post"], "application/json", {"ScanID": SCAN, "FileFormat": "Json"})
operation = spec["paths"]["/mock-upload/source.zip"]["put"]
operation["requestBody"] = {"required": True, "content": {"application/zip": {"schema": {"type": "string", "format": "binary"}}}}
operation = spec["paths"]["/api/configuration/project"]["patch"]
operation["requestBody"] = {"required": True, "content": {"application/json": {
    "schema": {"type": "array", "items": {"type": "object"}}, "example": []}}}
for path, method, fields in [
    ("/api/projects", "get", {"name": "mock-project"}),
    ("/api/results", "get", {"scan-id": SCAN}),
    ("/api/scan-summary", "get", {"scan-ids": SCAN}),
    ("/api/configuration/project", "patch", {"project-id": PROJECT}),
    ("/api/sca/export/requests", "get", {"exportId": "mock-export", "returnUrl": "true"}),
    ("/api/policy_management_service_uri/evaluation", "get", {"astProjectId": PROJECT, "scanId": SCAN}),
]:
    spec["paths"][path][method].setdefault("parameters", []).extend([
        {"name": k, "in": "query", "schema": {"type": "string", "default": v}} for k, v in fields.items()])
for path, method, summary in [("/__admin/reset", "post", "Reset all mock scenarios, mappings and requests"),
                               ("/__admin/requests", "get", "Inspect recent requests"),
                               ("/__admin/mappings", "get", "Inspect WireMock mappings")]:
    spec["paths"][path] = {method: {"operationId": path.rsplit("/", 1)[-1], "summary": summary,
        "tags": ["Mock control"], "security": [], "responses": {"200": {"description": "WireMock admin response"}}}}
(UI / "openapi.json").write_text(json.dumps(spec, indent=2) + "\n")
maps = {p.name: p.read_text() for p in sorted((ROOT / "mappings").glob("*.json"))}
configmaps = {"apiVersion": "v1", "kind": "List", "items": [
    {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name, "namespace": "checkmarx-mock"}, "data": data}
    for name, data in [("checkmarx-mock-mappings", maps), ("checkmarx-mock-openapi", {"openapi.json": (UI / "openapi.json").read_text()})]]}
(ROOT / "k8s/configmaps.json").write_text(json.dumps(configmaps, indent=2) + "\n")
print(f"Generated {len(spec['paths'])} OpenAPI paths and two ConfigMaps")
