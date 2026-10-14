"""Pure planning layer: no Kubernetes or Checkmarx connection required."""
import copy
import hashlib
import json
import re
from urllib.parse import urlsplit

GROUP = "security.asteriusit.fr"
APPS_VERSION = "apps/v1"
BATCH_VERSION = "batch/v1"
SOURCE_PATH = "/source"
SCRATCH_PATH = "/scratch"
IMAGE_DIGEST = re.compile(r"^([a-zA-Z0-9][a-zA-Z0-9._:/-]*)@sha256:([a-f0-9]{64})$")
KINDS = {"Deployment": (APPS_VERSION, "deployments"), "StatefulSet": (APPS_VERSION, "statefulsets"),
         "DaemonSet": (APPS_VERSION, "daemonsets"), "Job": (BATCH_VERSION, "jobs"),
         "CronJob": (BATCH_VERSION, "cronjobs")}


def validate_registry_secret_name(name):
    if not isinstance(name, str) or len(name) > 253 or not re.fullmatch(r"[a-z0-9]([-a-z0-9.]*[a-z0-9])?", name):
        raise ValueError("Registry credentials require a valid Secret name")


def validate_target(spec):
    if "repository" in spec:
        repo = spec["repository"]
        url = urlsplit(repo["url"])
        if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment:
            raise ValueError("Repository must be an HTTPS URL without embedded credentials, query or fragment")
        if not repo.get("branch"):
            raise ValueError("Repository branch is required")
    elif "imageRef" in spec:
        if not IMAGE_DIGEST.fullmatch(spec["imageRef"]):
            raise ValueError("Image scans require a repository@sha256 digest")
    elif spec["workloadRef"]["kind"] not in KINDS:
        raise ValueError("Unsupported workload kind")


def validate_scan_types(spec):
    types = spec.get("scanTypes", ["sast", "sca", "iac-security"])
    supported = {"container-security"} if "imageRef" in spec else {"sast", "sca", "iac-security"}
    if not types or any(t not in supported for t in types):
        raise ValueError("Unsupported scan type")
    if "workloadRef" in spec and types != ["iac-security"]:
        raise ValueError("Workload scans require scanTypes: [iac-security]")


def validate(spec):
    if sum(bool(spec.get(k)) for k in ("repository", "workloadRef", "imageRef")) != 1:
        raise ValueError("Specify exactly one scan target")
    for key in ("projectName", "credentialsSecretRef"):
        if not spec.get(key):
            raise ValueError(key + " is required")
    validate_target(spec)
    validate_scan_types(spec)
    if "registryCredentialsSecretRef" in spec:
        if "imageRef" not in spec:
            raise ValueError("Registry credentials require an image scan")
        validate_registry_secret_name(spec["registryCredentialsSecretRef"])


def redact_inline_values(entries):
    return [dict(entry, value="REDACTED") if isinstance(entry, dict) and "value" in entry
            else copy.deepcopy(entry) for entry in entries]


def redact_field(key, item):
    if key == "annotations" and isinstance(item, dict):
        return {}
    if key in ("command", "args") and isinstance(item, list):
        return ["REDACTED"] * len(item)
    if key in ("httpHeaders", "env") and isinstance(item, list):
        return redact_inline_values(item)
    return redact(item)


def redact(value):
    if isinstance(value, dict):
        return {key: redact_field(key, item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    return copy.deepcopy(value)


def snapshot(workload):
    # Deliberately retain only identity and spec; never status or annotations.
    # Free-form executable text and inline values can contain credentials.
    # Secret references and structural security settings remain available to IaC.
    obj = {"apiVersion": workload["apiVersion"], "kind": workload["kind"],
           "metadata": {k: workload["metadata"][k] for k in ("name", "namespace") if k in workload["metadata"]},
           "spec": redact(workload["spec"])}
    data = json.dumps(obj, sort_keys=True, indent=2)
    if len(data.encode()) > 800_000:
        raise ValueError("Manifest exceeds snapshot size limit")
    return data


def plan(body, image, workload=None):
    spec, meta = body["spec"], body["metadata"]
    validate(spec)
    if ":" not in image and "@sha256:" not in image:
        raise ValueError("Configure a versioned CLI image")
    if image.endswith(":latest"):
        raise ValueError("Do not use a latest CLI image")
    content = snapshot(workload) if workload is not None else None
    identity = json.dumps({"uid": meta["uid"], "generation": meta["generation"],
                           "spec": spec, "snapshot": content, "image": image}, sort_keys=True)
    digest = hashlib.sha256(identity.encode()).hexdigest()
    name = "cx-" + digest[:32]
    owner = {"apiVersion": body["apiVersion"], "kind": body["kind"], "name": meta["name"],
             "uid": meta["uid"], "controller": True, "blockOwnerDeletion": False}
    metadata = {"name": name, "namespace": meta["namespace"], "ownerReferences": [owner],
                "labels": {"app.kubernetes.io/managed-by": "checkmarx-operator"}}
    repo = spec.get("repository")
    image_ref = spec.get("imageRef")
    branch = meta["name"] if image_ref else "workload"
    if repo:
        branch = repo["branch"]
    args = ["scan", "create", "--project-name", spec["projectName"], "--branch",
            branch, "-s", repo["url"] if repo else SOURCE_PATH,
            "--scan-types", ",".join(spec["scanTypes"])]
    if image_ref:
        args.extend(["--container-images", image_ref])
    container = {"name": "scan", "image": image, "args": args, "workingDir": SCRATCH_PATH,
                 "envFrom": [{"secretRef": {"name": spec["credentialsSecretRef"]}}],
                 "env": [{"name": "HOME", "value": SCRATCH_PATH}, {"name": "USER", "value": "cx"},
                         {"name": "TMPDIR", "value": SCRATCH_PATH}],
                 "resources": {"requests": {"cpu": "100m", "memory": "256Mi", "ephemeral-storage": "256Mi"},
                               "limits": {"cpu": "1", "memory": "1Gi", "ephemeral-storage": "3Gi"}},
                 "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                     "capabilities": {"drop": ["ALL"]}},
                 "volumeMounts": [{"name": "tmp", "mountPath": SCRATCH_PATH}]}
    pod = {"restartPolicy": "Never", "automountServiceAccountToken": False,
           "securityContext": {"runAsNonRoot": True, "runAsUser": 10001, "runAsGroup": 10001, "fsGroup": 10001,
                               "seccompProfile": {"type": "RuntimeDefault"}},
           "containers": [container], "volumes": [{"name": "tmp", "emptyDir": {"sizeLimit": "2Gi"}}]}
    cm = None
    if spec.get("registryCredentialsSecretRef"):
        args.append("--containers-local-resolution")
        container["env"].append({"name": "DOCKER_CONFIG", "value": "/registry-auth"})
        container["volumeMounts"].append({"name": "registry-auth", "mountPath": "/registry-auth", "readOnly": True})
        pod["volumes"].append({"name": "registry-auth", "secret": {
            "secretName": spec["registryCredentialsSecretRef"], "defaultMode": 0o440,
            "items": [{"key": ".dockerconfigjson", "path": "config.json"}]}})
    if image_ref:
        # The CLI requires a source folder even for explicit images.
        pod["volumes"].append({"name": "source", "emptyDir": {"sizeLimit": "512Mi"}})
        # Local resolution writes its .checkmarx/containers report in this folder.
        container["volumeMounts"].append({"name": "source", "mountPath": SOURCE_PATH,
                                         "readOnly": not bool(spec.get("registryCredentialsSecretRef"))})
    if content is not None:
        cm = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": copy.deepcopy(metadata),
              "immutable": True, "data": {"workload.yaml": content}}
        pod["volumes"].append({"name": "source", "configMap": {"name": name}})
        container["volumeMounts"].append({"name": "source", "mountPath": SOURCE_PATH, "readOnly": True})
    job = {"apiVersion": BATCH_VERSION, "kind": "Job", "metadata": metadata,
           "spec": {"backoffLimit": 0, "activeDeadlineSeconds": spec.get("timeoutSeconds", 1800),
                    "template": {"spec": pod}}}
    # No TTL: retaining the Job prevents a restart from submitting the same scan again.
    return name, digest, cm, job


def phase(job):
    for condition in (job.status.conditions or []):
        if condition.status == "True" and condition.type in ("Complete", "Failed"):
            return "Completed" if condition.type == "Complete" else "Failed"
    return "Running" if job.status.active else "Pending"
