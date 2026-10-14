"""Image inventory and scan planning, independent of Kubernetes clients."""
import copy
import hashlib
import json
from datetime import datetime, timedelta, timezone

from operator_src.planner import GROUP, IMAGE_DIGEST, plan

POLICY_LABEL = GROUP + "/cluster-scan-uid"


def utcnow():
    return datetime.now(timezone.utc)


def timestamp(value):
    return value.isoformat().replace("+00:00", "Z")


def observed_containers(pod):
    for containers, statuses in (("containers", "containerStatuses"),
                                     ("initContainers", "initContainerStatuses"),
                                     ("ephemeralContainers", "ephemeralContainerStatuses")):
        observed = {s["name"]: s for s in pod.get("status", {}).get(statuses, [])}
        for container in pod.get("spec", {}).get(containers, []):
            yield container, observed.get(container["name"], {})


def add_image_reference(result, pod, container, state):
    raw = state.get("imageID", "")
    resolved = raw.removeprefix("docker-pullable://")
    match = IMAGE_DIGEST.fullmatch(resolved)
    # A bare sha256 or containerd:// ID may be a local config hash.
    image = resolved if match else ""
    key = "sha256:" + match[2] if match else "unresolved:" + raw + ":" + container["image"]
    entry = result.setdefault(key, {"image": image, "references": [], "referenceCount": 0})
    if image and (not entry["image"] or image < entry["image"]):
        entry["image"] = image
    entry["referenceCount"] += 1
    if len(entry["references"]) < 100:
        entry["references"].append({"namespace": pod["metadata"]["namespace"], "pod": pod["metadata"]["name"],
                                   "container": container["name"], "image": container["image"]})


def inventory(pods, discovery):
    """Use runtime manifest digests, never mutable tags or local config hashes."""
    result = {}
    included = set(discovery.get("includeNamespaces", []))
    excluded = set(discovery.get("excludeNamespaces", []))
    for pod in pods:
        namespace = pod["metadata"]["namespace"]
        if namespace in excluded or (included and namespace not in included):
            continue
        if pod.get("status", {}).get("phase") == "Running":
            for container, state in observed_containers(pod):
                add_image_reference(result, pod, container, state)
    return result


def image_record(policy, namespace, key, entry, allowed):
    uid = policy["metadata"]["uid"]
    name = "image-" + hashlib.sha256((uid + ":" + key).encode()).hexdigest()[:32]
    return {"apiVersion": GROUP + "/v1alpha1", "kind": "CheckmarxImageScan",
        "metadata": {"name": name, "namespace": namespace, "labels": {POLICY_LABEL: uid},
            "ownerReferences": [{"apiVersion": policy["apiVersion"], "kind": policy["kind"],
                "name": policy["metadata"]["name"], "uid": uid, "controller": True,
                "blockOwnerDeletion": False}]},
        "spec": {"clusterScan": policy["metadata"]["name"], "imageKey": key,
                 "image": entry["image"], "scanAllowed": allowed}}


def run_key(policy, scanner_image):
    spec = policy["spec"]
    inputs = {k: spec.get(k) for k in ("projectName", "credentialsSecretRef", "timeoutSeconds", "rerunToken")}
    if "registryCredentialsSecretRef" in spec:
        inputs["registryCredentialsSecretRef"] = spec["registryCredentialsSecretRef"]
    inputs["scannerImage"] = scanner_image
    return hashlib.sha256(json.dumps(inputs, sort_keys=True).encode()).hexdigest()


def due(status, key, interval, now):
    if status.get("runKey") != key:
        return True
    if not interval or not status.get("finishedAt"):
        return False
    finished = datetime.fromisoformat(status["finishedAt"].replace("Z", "+00:00"))
    return now >= finished + timedelta(seconds=interval)


def image_job(record, policy, scanner_image, attempt):
    """Reuse the hardened CLI Job template; scan one immutable image per Job."""
    body = copy.deepcopy(record)
    body["metadata"]["generation"] = attempt
    spec = policy["spec"]
    body["spec"] = {"projectName": spec["projectName"],
        "credentialsSecretRef": spec["credentialsSecretRef"]["name"], "scanTypes": ["container-security"],
        "imageRef": record["spec"]["image"],
        "timeoutSeconds": spec.get("timeoutSeconds", 1800), "rerunToken": run_key(policy, scanner_image)}
    if "registryCredentialsSecretRef" in spec:
        body["spec"]["registryCredentialsSecretRef"] = spec["registryCredentialsSecretRef"]["name"]
    job = plan(body, scanner_image)[3]
    job["metadata"]["labels"][POLICY_LABEL] = policy["metadata"]["uid"]
    return job
