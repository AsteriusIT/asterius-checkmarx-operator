"""Single-replica Kopf controller with namespace-local scan execution."""
import os
import kopf
from kubernetes import client, config
from kubernetes.client.exceptions import ApiException
from operator_src.planner import GROUP, KINDS, plan, phase, validate


@kopf.on.startup()
def startup(settings, **_):
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()
    settings.posting.enabled = False
    settings.scanning.disabled = True


def ensure(read, create, namespace, name, obj, uid):
    try:
        existing = read(name, namespace)
    except ApiException as exc:
        if exc.status != 404:
            raise
        try:
            return create(namespace, obj)
        except ApiException as conflict:
            if conflict.status != 409:
                raise
            existing = read(name, namespace)
    if not any(o.uid == uid for o in (existing.metadata.owner_references or [])):
        raise ValueError("Child name collision with an unrelated resource")
    return existing


@kopf.timer(GROUP, "v1alpha1", "checkmarxscans", interval=30, initial_delay=0)
def reconcile(body, patch, **_):
    if body["metadata"].get("deletionTimestamp"):
        return
    spec, meta = body["spec"], body["metadata"]
    namespace = meta["namespace"]
    try:
        validate(spec)
        workload = None
        if "workloadRef" in spec:
            ref = spec["workloadRef"]
            api_version, plural = KINDS[ref["kind"]]
            group, version = api_version.split("/")
            workload = client.CustomObjectsApi().get_namespaced_custom_object(
                group, version, namespace, plural, ref["name"])
        name, digest, cm, job = plan(body, os.environ["CX_CLI_IMAGE"], workload)
        previous = body.get("status", {})
        # Serialize generations/snapshots to avoid overlapping remote submissions.
        if previous.get("jobName") and previous["jobName"] != name:
            old = client.BatchV1Api().read_namespaced_job(previous["jobName"], namespace)
            if phase(old) in ("Pending", "Running"):
                patch.status["phase"] = "WaitingForPreviousRun"
                return
        api = client.CoreV1Api()
        if cm:
            ensure(api.read_namespaced_config_map, api.create_namespaced_config_map,
                   namespace, name, cm, meta["uid"])
        batch = client.BatchV1Api()
        result = ensure(batch.read_namespaced_job, batch.create_namespaced_job,
                        namespace, name, job, meta["uid"])
        patch.status.update({"phase": phase(result), "jobName": name, "inputDigest": digest,
                             "observedGeneration": meta["generation"], "message": ""})
    except ValueError as exc:
        patch.status.update({"phase": "Invalid", "message": str(exc)})
    except ApiException as exc:
        # Avoid copying server bodies (potentially sensitive) into CR status.
        patch.status.update({"phase": "Blocked", "message": "Kubernetes API status " + str(exc.status)})
        raise kopf.TemporaryError("Kubernetes API operation failed", delay=30)


# Register the cluster inventory timer alongside the existing scan timer.
from operator_src import cluster  # noqa: E402,F401
