"""Cluster inventory and per-policy image queue; all execution stays local."""
import os
import threading
from collections import Counter

import kopf
from kubernetes import client
from kubernetes.client.exceptions import ApiException

from operator_src.images import (POLICY_LABEL, due, image_job, image_record,
                                 inventory, run_key, timestamp, utcnow)
from operator_src.planner import GROUP, phase, validate_registry_secret_name

VERSION = "v1alpha1"
RECORDS = "checkmarximagescans"
RECORD_LABEL = GROUP + "/image-scan-uid"
ATTEMPT_LABEL = GROUP + "/attempt"
RUN_ANNOTATION = GROUP + "/run-key"
# Kopf runs synchronous timers in threads. Keep admission serialized across policies.
QUEUE_LOCK = threading.Lock()


def owned(obj, uid):
    return any(o.get("uid") == uid and o.get("controller") for o in obj["metadata"].get("ownerReferences", []))


def record_status(api, namespace, record, values):
    if any(record.get("status", {}).get(k) != v for k, v in values.items()):
        api.patch_namespaced_custom_object_status(GROUP, VERSION, namespace, RECORDS,
            record["metadata"]["name"], {"status": values})


def validate_credentials(spec, namespace):
    if spec["credentialsSecretRef"]["namespace"] != namespace:
        return "Credentials must be in the operator namespace"
    registry = spec.get("registryCredentialsSecretRef")
    if registry is None:
        return ""
    if not isinstance(registry, dict) or registry.get("namespace") != namespace:
        return "Registry credentials must be in the operator namespace"
    validate_registry_secret_name(registry.get("name"))
    return ""


def ensure_record(custom, namespace, policy, obj):
    try:
        return custom.create_namespaced_custom_object(GROUP, VERSION, namespace, RECORDS, obj)
    except ApiException as exc:
        if exc.status != 409:
            raise
    record = custom.get_namespaced_custom_object(GROUP, VERSION, namespace, RECORDS,
                                                 obj["metadata"]["name"])
    if not owned(record, policy["metadata"]["uid"]):
        raise ValueError("Image record name collision")
    return record


def discover_records(body, custom, namespace, selector, found):
    records = custom.list_namespaced_custom_object(GROUP, VERSION, namespace, RECORDS,
                                                   label_selector=selector)["items"]
    records = [record for record in records if owned(record, body["metadata"]["uid"])]
    known = {record["spec"]["imageKey"] for record in records}
    initial = not body.get("status", {}).get("discoveryInitialized", False)
    option = "scanExisting" if initial else "scanNewImages"
    allowed = body["spec"].get("discovery", {}).get(option, True)
    for key, entry in sorted(found.items()):
        if key not in known:
            obj = image_record(body, namespace, key, entry, allowed)
            records.append(ensure_record(custom, namespace, body, obj))
    return records


def latest_jobs(jobs):
    latest = {}
    for job in jobs:
        labels = job.metadata.labels or {}
        uid = labels.get(RECORD_LABEL)
        if not uid or not labels.get(ATTEMPT_LABEL, "").isdigit():
            continue
        if not any(owner.uid == uid and owner.controller for owner in job.metadata.owner_references or []):
            continue
        previous = latest.get(uid)
        if previous is None or int(labels[ATTEMPT_LABEL]) > int(previous.metadata.labels[ATTEMPT_LABEL]):
            latest[uid] = job
    return latest


def finished_at(job, now):
    ended = job.status.completion_time
    if ended is None:
        ended = next((condition.last_transition_time for condition in job.status.conditions or []
                      if condition.type == "Failed" and condition.status == "True"), None)
    return timestamp(ended or now)


def job_status(record, job, entry, now):
    status = dict(record.get("status", {}))
    status.update(present=entry is not None, references=entry["references"] if entry else [],
                  referenceCount=entry["referenceCount"] if entry else 0)
    if job and status.get("attempt", 0) > int(job.metadata.labels[ATTEMPT_LABEL]):
        job = None
    if job:
        status.update(phase=phase(job), jobName=job.metadata.name,
            attempt=int(job.metadata.labels[ATTEMPT_LABEL]),
            runKey=job.metadata.annotations[RUN_ANNOTATION], message="")
        if status["phase"] in ("Completed", "Failed"):
            status["finishedAt"] = finished_at(job, now)
    elif status.get("jobName"):
        status.update(phase="Lost", message="Scanner Job was removed; change rerunToken to submit again")
    return status


class ImageQueue:
    """Admission state for one policy reconciliation, serialized by QUEUE_LOCK."""
    def __init__(self, body, batch, namespace, now, scanner_image, jobs):
        self.body = body
        self.spec = body["spec"]
        self.batch = batch
        self.namespace = namespace
        self.now = now
        self.scanner_image = scanner_image
        self.key = run_key(body, scanner_image)
        self.active = sum(phase(job) in ("Pending", "Running") for job in jobs)
        self.latest = latest_jobs(jobs)

    def create_job(self, obj, record):
        try:
            self.batch.create_namespaced_job(self.namespace, obj)
        except ApiException as exc:
            if exc.status != 409:
                raise
            existing = self.batch.read_namespaced_job(obj["metadata"]["name"], self.namespace)
            if not any(owner.uid == record["metadata"]["uid"] for owner in existing.metadata.owner_references or []):
                raise ValueError("Scanner Job name collision")

    def submit(self, record, status):
        attempt = status.get("attempt", 0) + 1
        obj = image_job(record, self.body, self.scanner_image, attempt)
        obj["metadata"]["labels"].update({RECORD_LABEL: record["metadata"]["uid"],
                                          ATTEMPT_LABEL: str(attempt)})
        obj["metadata"]["annotations"] = {RUN_ANNOTATION: self.key}
        self.create_job(obj, record)
        self.active += 1
        status.update(phase="Pending", jobName=obj["metadata"]["name"], attempt=attempt,
                      runKey=self.key, finishedAt=None, message="")

    def schedule(self, record, status):
        if not record["spec"]["image"]:
            status.update(phase="Unavailable", message="Runtime has no pullable repository@sha256 image ID")
            return
        if not record["spec"]["scanAllowed"]:
            status.update(phase="Skipped", message="Disabled by discovery policy at first observation")
            return
        if self.spec.get("suspend", False) or not due(status, self.key, self.spec.get("rescanIntervalSeconds", 0), self.now):
            if "phase" not in status:
                status.update(phase="Queued", message="Scanning suspended")
            return
        # Lost Jobs require an explicit configuration/rerun change, not a timed retry.
        if status.get("phase") == "Lost" and status.get("runKey") == self.key:
            return
        if self.active >= self.spec.get("maxConcurrentScans", 2):
            status.update(phase="Queued", message="Waiting for a scanner slot")
            return
        self.submit(record, status)

    def reconcile(self, record, entry):
        job = self.latest.get(record["metadata"]["uid"])
        status = job_status(record, job, entry, self.now)
        if status.get("phase") not in ("Pending", "Running") and entry:
            self.schedule(record, status)
        return status


def reconcile_policy(body, patch, custom, core, batch, now, scanner_image, namespace):
    spec, meta = body["spec"], body["metadata"]
    error = validate_credentials(spec, namespace)
    if error:
        patch.status.update(phase="Invalid", message=error)
        return
    selector = POLICY_LABEL + "=" + meta["uid"]
    # Polling also recovers Pod changes missed while the operator was stopped.
    pods = client.ApiClient().sanitize_for_serialization(core.list_pod_for_all_namespaces())
    found = inventory(pods["items"], spec.get("discovery", {}))
    records = discover_records(body, custom, namespace, selector, found)
    # Durable records preserve the initial baseline across restarts.
    patch.status["discoveryInitialized"] = True
    jobs = batch.list_namespaced_job(namespace, label_selector=selector).items
    queue = ImageQueue(body, batch, namespace, now, scanner_image, jobs)
    counts = Counter()
    for record in sorted(records, key=lambda item: item["metadata"]["name"]):
        entry = found.get(record["spec"]["imageKey"])
        status = queue.reconcile(record, entry)
        record_status(custom, namespace, record, status)
        if entry:
            counts[status.get("phase", "Queued")] += 1
    patch.status.update(phase="Suspended" if spec.get("suspend") else "Ready", message="",
        observedGeneration=meta["generation"], discoveredImages=len(found),
        activeScans=queue.active, imageCounts={name: counts[name] for name in
            ("Pending", "Running", "Queued", "Completed", "Failed", "Unavailable", "Skipped", "Lost")},
        lastDiscoveryTime=timestamp(now))


@kopf.timer(GROUP, VERSION, "checkmarxclusterscans", interval=30, initial_delay=0)
def reconcile_cluster(body, patch, **_):
    if body["metadata"].get("deletionTimestamp"):
        return
    try:
        with QUEUE_LOCK:
            reconcile_policy(body, patch, client.CustomObjectsApi(), client.CoreV1Api(),
                client.BatchV1Api(), utcnow(), os.environ["CX_CLI_IMAGE"],
                os.environ.get("OPERATOR_NAMESPACE", "checkmarx-operator"))
    except ValueError as exc:
        patch.status.update(phase="Invalid", message=str(exc))
    except ApiException as exc:
        patch.status.update(phase="Blocked", message="Kubernetes API status " + str(exc.status))
        raise kopf.TemporaryError("Cluster image reconciliation failed", delay=30)
