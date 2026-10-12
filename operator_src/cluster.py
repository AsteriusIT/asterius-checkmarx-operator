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


def reconcile_policy(body, patch, custom, core, batch, now, scanner_image, namespace):
    spec, meta = body["spec"], body["metadata"]
    if spec["credentialsSecretRef"]["namespace"] != namespace:
        patch.status.update(phase="Invalid", message="Credentials must be in the operator namespace")
        return
    registry = spec.get("registryCredentialsSecretRef")
    if registry is not None:
        if not isinstance(registry, dict) or registry.get("namespace") != namespace:
            patch.status.update(phase="Invalid", message="Registry credentials must be in the operator namespace")
            return
        # Validate before discovery or queue processing, including empty inventories.
        validate_registry_secret_name(registry.get("name"))
    selector = POLICY_LABEL + "=" + meta["uid"]
    discovery = spec.get("discovery", {})
    # Polling also recovers Pod changes missed while the operator was stopped.
    pods = client.ApiClient().sanitize_for_serialization(core.list_pod_for_all_namespaces())
    found = inventory(pods["items"], discovery)
    records = custom.list_namespaced_custom_object(GROUP, VERSION, namespace, RECORDS,
                                                   label_selector=selector)["items"]
    records = [r for r in records if owned(r, meta["uid"])]
    by_key = {r["spec"]["imageKey"]: r for r in records}
    initial = not body.get("status", {}).get("discoveryInitialized", False)
    allowed = discovery.get("scanExisting", True) if initial else discovery.get("scanNewImages", True)
    for key, entry in sorted(found.items()):
        if key in by_key:
            continue
        obj = image_record(body, namespace, key, entry, allowed)
        try:
            record = custom.create_namespaced_custom_object(GROUP, VERSION, namespace, RECORDS, obj)
        except ApiException as exc:
            if exc.status != 409:
                raise
            record = custom.get_namespaced_custom_object(GROUP, VERSION, namespace, RECORDS,
                                                         obj["metadata"]["name"])
            if not owned(record, meta["uid"]):
                raise ValueError("Image record name collision")
        records.append(record)
    # The baseline consists of durable records, so restart never scans excluded initial images.
    patch.status["discoveryInitialized"] = True
    jobs = batch.list_namespaced_job(namespace, label_selector=selector).items
    active = sum(phase(job) in ("Pending", "Running") for job in jobs)
    latest = {}
    for job in jobs:
        labels = job.metadata.labels or {}
        uid = labels.get(RECORD_LABEL)
        if not uid or not labels.get(ATTEMPT_LABEL, "").isdigit():
            continue
        if not any(o.uid == uid and o.controller for o in job.metadata.owner_references or []):
            continue
        if uid not in latest or int(labels[ATTEMPT_LABEL]) > int(latest[uid].metadata.labels[ATTEMPT_LABEL]):
            latest[uid] = job
    key = run_key(body, scanner_image)
    counts = Counter()
    for record in sorted(records, key=lambda r: r["metadata"]["name"]):
        entry = found.get(record["spec"]["imageKey"])
        status = dict(record.get("status", {}))
        status.update(present=entry is not None, references=entry["references"] if entry else [],
                      referenceCount=entry["referenceCount"] if entry else 0)
        job = latest.get(record["metadata"]["uid"])
        if job and status.get("attempt", 0) > int(job.metadata.labels[ATTEMPT_LABEL]):
            job = None
        if job:
            status.update(phase=phase(job), jobName=job.metadata.name,
                attempt=int(job.metadata.labels[ATTEMPT_LABEL]),
                runKey=job.metadata.annotations[RUN_ANNOTATION], message="")
            if status["phase"] in ("Completed", "Failed"):
                ended = job.status.completion_time
                if ended is None:
                    ended = next((c.last_transition_time for c in job.status.conditions or []
                                  if c.type == "Failed" and c.status == "True"), None)
                status["finishedAt"] = timestamp(ended or now)
        elif status.get("jobName"):
            status.update(phase="Lost", message="Scanner Job was removed; change rerunToken to submit again")
        if status.get("phase") not in ("Pending", "Running") and entry:
            if not record["spec"]["image"]:
                status.update(phase="Unavailable", message="Runtime has no pullable repository@sha256 image ID")
            elif not record["spec"]["scanAllowed"]:
                status.update(phase="Skipped", message="Disabled by discovery policy at first observation")
            elif not spec.get("suspend", False) and due(status, key, spec.get("rescanIntervalSeconds", 0), now):
                # Lost Jobs require an explicit configuration/rerun change, not a timed retry.
                if status.get("phase") != "Lost" or status.get("runKey") != key:
                    if active < spec.get("maxConcurrentScans", 2):
                        attempt = status.get("attempt", 0) + 1
                        obj = image_job(record, body, scanner_image, attempt)
                        obj["metadata"]["labels"].update({RECORD_LABEL: record["metadata"]["uid"],
                                                          ATTEMPT_LABEL: str(attempt)})
                        obj["metadata"]["annotations"] = {RUN_ANNOTATION: key}
                        try:
                            batch.create_namespaced_job(namespace, obj)
                        except ApiException as exc:
                            if exc.status != 409:
                                raise
                            existing = batch.read_namespaced_job(obj["metadata"]["name"], namespace)
                            if not any(o.uid == record["metadata"]["uid"] for o in existing.metadata.owner_references or []):
                                raise ValueError("Scanner Job name collision")
                        active += 1
                        status.update(phase="Pending", jobName=obj["metadata"]["name"],
                                      attempt=attempt, runKey=key, finishedAt=None, message="")
                    else:
                        status.update(phase="Queued", message="Waiting for a scanner slot")
            elif "phase" not in status:
                status.update(phase="Queued", message="Scanning suspended")
        record_status(custom, namespace, record, status)
        if entry:
            counts[status.get("phase", "Queued")] += 1
    patch.status.update(phase="Suspended" if spec.get("suspend") else "Ready", message="",
        observedGeneration=meta["generation"], discoveredImages=len(found),
        activeScans=active, imageCounts={name: counts[name] for name in
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
