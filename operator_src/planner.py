"""Pure planning layer: no Kubernetes or Checkmarx connection required."""
import copy
import hashlib
import json
import re
from urllib.parse import urlsplit

GROUP = "security.example.io"
IMAGE_DIGEST = re.compile(r"^([a-zA-Z0-9][a-zA-Z0-9._:/-]*)@sha256:([a-f0-9]{64})$")
KINDS = {"Deployment": ("apps/v1", "deployments"), "StatefulSet": ("apps/v1", "statefulsets"),
         "DaemonSet": ("apps/v1", "daemonsets"), "Job": ("batch/v1", "jobs"),
         "CronJob": ("batch/v1", "cronjobs")}


def validate(spec):
    if sum(bool(spec.get(k)) for k in ("repository", "workloadRef", "imageRef")) != 1:
        raise ValueError("Specify exactly one scan target")
    for key in ("projectName", "credentialsSecretRef"):
        if not spec.get(key):
            raise ValueError(key + " is required")
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
    types = spec.get("scanTypes", ["sast", "sca", "iac-security"])
    supported = {"container-security"} if "imageRef" in spec else {"sast", "sca", "iac-security"}
    if not types or any(t not in supported for t in types):
        raise ValueError("Unsupported scan type")
    if "workloadRef" in spec and types != ["iac-security"]:
        raise ValueError("Workload scans require scanTypes: [iac-security]")


def snapshot(workload):
    # Deliberately retain only identity and spec; never status or annotations.
    # Literal environment values are redacted; Secret references remain references.
    obj = {"apiVersion": workload["apiVersion"], "kind": workload["kind"],
           "metadata": {k: workload["metadata"][k] for k in ("name", "namespace") if k in workload["metadata"]},
           "spec": copy.deepcopy(workload["spec"])}
    def redact(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key == "env" and isinstance(item, list):
                    for env in item:
                        if "value" in env:
                            env["value"] = "REDACTED"
                else:
                    redact(item)
        elif isinstance(value, list):
            for item in value:
                redact(item)
    redact(obj)
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
    args = ["scan", "create", "--project-name", spec["projectName"], "--branch",
            repo["branch"] if repo else (meta["name"] if image_ref else "workload"),
            "-s", repo["url"] if repo else "/source",
            "--scan-types", ",".join(spec["scanTypes"])]
    if image_ref:
        args.extend(["--container-images", image_ref])
    container = {"name": "scan", "image": image, "command": ["cx"], "args": args,
                 "envFrom": [{"secretRef": {"name": spec["credentialsSecretRef"]}}],
                 "env": [{"name": "HOME", "value": "/tmp"}],
                 "resources": {"requests": {"cpu": "100m", "memory": "256Mi"},
                               "limits": {"cpu": "1", "memory": "1Gi"}},
                 "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                     "capabilities": {"drop": ["ALL"]}},
                 "volumeMounts": [{"name": "tmp", "mountPath": "/tmp"}]}
    pod = {"restartPolicy": "Never", "automountServiceAccountToken": False,
           "securityContext": {"runAsNonRoot": True, "runAsUser": 10001, "fsGroup": 10001,
                               "seccompProfile": {"type": "RuntimeDefault"}},
           "containers": [container], "volumes": [{"name": "tmp", "emptyDir": {"sizeLimit": "2Gi"}}]}
    cm = None
    if image_ref:
        # The CLI requires a source folder even for explicit cloud-resolved images.
        pod["volumes"].append({"name": "source", "emptyDir": {}})
        container["volumeMounts"].append({"name": "source", "mountPath": "/source", "readOnly": True})
    if content is not None:
        cm = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": copy.deepcopy(metadata),
              "immutable": True, "data": {"workload.yaml": content}}
        pod["volumes"].append({"name": "source", "configMap": {"name": name}})
        container["volumeMounts"].append({"name": "source", "mountPath": "/source", "readOnly": True})
    job = {"apiVersion": "batch/v1", "kind": "Job", "metadata": metadata,
           "spec": {"backoffLimit": 0, "activeDeadlineSeconds": spec.get("timeoutSeconds", 1800),
                    "template": {"spec": pod}}}
    # No TTL: retaining the Job prevents a restart from submitting the same scan again.
    return name, digest, cm, job


def phase(job):
    for condition in (job.status.conditions or []):
        if condition.status == "True" and condition.type in ("Complete", "Failed"):
            return "Completed" if condition.type == "Complete" else "Failed"
    return "Running" if job.status.active else "Pending"
