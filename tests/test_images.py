import copy
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace as NS
from unittest.mock import Mock, patch

# Reuse the offline Kubernetes/Kopf doubles used by the existing controller tests.
from test_operator import ApiException
from operator_src import cluster
from operator_src.images import image_job, image_record, inventory
from operator_src.planner import validate_registry_secret_name

NOW = datetime(2026, 10, 12, tzinfo=timezone.utc)
POLICY = {"apiVersion": "security.asteriusit.fr/v1alpha1", "kind": "CheckmarxClusterScan",
    "metadata": {"name": "images", "uid": "policy-uid", "generation": 1},
    "spec": {"projectName": "images", "credentialsSecretRef": {"namespace": "operator", "name": "auth"},
             "maxConcurrentScans": 2}}


def pod(name="app", digest="a", namespace="apps", image="example/app:latest"):
    return {"metadata": {"name": name, "namespace": namespace},
        "spec": {"containers": [{"name": "app", "image": image}]},
        "status": {"phase": "Running", "containerStatuses": [{"name": "app",
            "imageID": "docker-pullable://example/app@sha256:" + digest * 64}]}}


class Harness:
    def __init__(self, pods):
        self.policy = copy.deepcopy(POLICY)
        self.pods = pods
        self.records = {}
        self.jobs = []
        self.custom = NS(list_namespaced_custom_object=Mock(side_effect=lambda *a, **k: {"items": copy.deepcopy(list(self.records.values()))}),
            create_namespaced_custom_object=Mock(side_effect=self.create_record),
            patch_namespaced_custom_object_status=Mock(side_effect=self.patch_record))
        self.core = NS(list_pod_for_all_namespaces=Mock(side_effect=lambda: {"items": self.pods}))
        self.batch = NS(list_namespaced_job=Mock(side_effect=lambda *a, **k: NS(items=list(self.jobs))),
                        create_namespaced_job=Mock(side_effect=self.create_job))

    def create_record(self, group, version, namespace, plural, obj):
        obj = copy.deepcopy(obj)
        obj["metadata"].update(uid=obj["metadata"]["name"], generation=1)
        self.records[obj["metadata"]["name"]] = obj
        return copy.deepcopy(obj)

    def patch_record(self, group, version, namespace, plural, name, body):
        self.records[name].setdefault("status", {}).update(body["status"])

    def create_job(self, namespace, obj):
        meta = obj["metadata"]
        job = NS(metadata=NS(name=meta["name"], labels=meta["labels"], annotations=meta["annotations"],
            owner_references=[NS(uid=o["uid"], controller=True) for o in meta["ownerReferences"]]),
            status=NS(conditions=[], active=1, completion_time=None))
        self.jobs.append(job)
        return job

    def finish(self, job, success=True):
        job.status = NS(active=0, completion_time=NOW if success else None,
            conditions=[NS(type="Complete" if success else "Failed", status="True", last_transition_time=NOW)])

    def run(self, now=NOW):
        patch_status = NS(status={})
        with patch.object(cluster.client, "ApiClient", return_value=NS(sanitize_for_serialization=lambda x: x), create=True):
            cluster.reconcile_policy(self.policy, patch_status, self.custom, self.core, self.batch,
                                     now, "scanner:1", "operator")
        self.last_patch = copy.deepcopy(patch_status.status)
        # Most assertions care about nonzero counts; the API also clears old counts.
        if "imageCounts" in patch_status.status:
            patch_status.status["imageCounts"] = {k:v for k,v in patch_status.status["imageCounts"].items() if v}
        self.policy.setdefault("status", {}).update(patch_status.status)
        return patch_status.status


class InventoryTests(unittest.TestCase):
    def test_deduplicate_replicas_tags_and_repository_aliases_by_digest(self):
        a, b = pod(), pod("replica", image="example/app:v2")
        b["status"]["containerStatuses"][0]["imageID"] = "mirror/app@sha256:" + "a" * 64
        found = inventory([a, b], {})
        self.assertEqual(len(found), 1)
        self.assertEqual(next(iter(found.values()))["referenceCount"], 2)
        self.assertEqual(len(inventory([a, pod("updated", "b")], {})), 2)

    def test_filters_phase_and_all_container_types(self):
        a = pod()
        for spec_key, status_key, digest in [("initContainers", "initContainerStatuses", "b"),
                                            ("ephemeralContainers", "ephemeralContainerStatuses", "c")]:
            a["spec"][spec_key] = [{"name": spec_key, "image": "example/helper:1"}]
            a["status"][status_key] = [{"name": spec_key, "imageID": "example/helper@sha256:" + digest * 64}]
        done = pod("done", "d"); done["status"]["phase"] = "Succeeded"
        self.assertEqual(len(inventory([a, done, pod("system", "e", "kube-system")],
            {"includeNamespaces": ["apps", "kube-system"], "excludeNamespaces": ["kube-system"]})), 3)

    def test_local_or_missing_runtime_ids_never_fall_back_to_tags(self):
        for raw in ("", "sha256:" + "a" * 64, "containerd://" + "a" * 64):
            a = pod(); a["status"]["containerStatuses"][0]["imageID"] = raw
            self.assertEqual(next(iter(inventory([a], {}).values()))["image"], "")

    def test_references_are_bounded_without_losing_count(self):
        value = next(iter(inventory([pod(str(i)) for i in range(150)], {}).values()))
        self.assertEqual(value["referenceCount"], 150)
        self.assertEqual(len(value["references"]), 100)

    def test_image_job_uses_digest_and_hardened_template(self):
        key, entry = next(iter(inventory([pod()], {}).items()))
        record = image_record(POLICY, "operator", key, entry, True)
        record["metadata"].update(uid="record-uid", generation=1)
        job = image_job(record, POLICY, "scanner:1", 1)
        container = job["spec"]["template"]["spec"]["containers"][0]
        self.assertIn("container-security", container["args"])
        self.assertIn(entry["image"], container["args"])
        self.assertNotIn("example/app:latest", container["args"])
        self.assertFalse(job["spec"]["template"]["spec"]["automountServiceAccountToken"])
        self.assertTrue(container["securityContext"]["readOnlyRootFilesystem"])
        self.assertEqual(container["envFrom"], [{"secretRef": {"name": "auth"}}])
        self.assertNotIn("--containers-local-resolution", container["args"])
        self.assertFalse(any("secret" in v for v in job["spec"]["template"]["spec"]["volumes"]))
        self.assertTrue(next(m for m in container["volumeMounts"] if m["name"] == "source")["readOnly"])
        self.assertEqual(job, image_job(record, POLICY, "scanner:1", 1))
        self.assertNotEqual(job["metadata"]["name"], image_job(record, POLICY, "scanner:1", 2)["metadata"]["name"])


class ClusterQueueTests(unittest.TestCase):
    def test_registry_credentials_mount_and_policy_changes_rescan(self):
        h = Harness([pod()])
        h.policy["spec"]["registryCredentialsSecretRef"] = {"namespace": "operator", "name": "nexus-auth"}
        h.run()
        job = h.batch.create_namespaced_job.call_args.args[1]
        template = job["spec"]["template"]["spec"]
        container = template["containers"][0]
        self.assertIn("--containers-local-resolution", container["args"])
        self.assertIn({"name": "DOCKER_CONFIG", "value": "/registry-auth"}, container["env"])
        self.assertIn({"name": "registry-auth", "mountPath": "/registry-auth", "readOnly": True}, container["volumeMounts"])
        self.assertFalse(next(m for m in container["volumeMounts"] if m["name"] == "source")["readOnly"])
        self.assertTrue(container["securityContext"]["readOnlyRootFilesystem"])
        volume = next(v for v in template["volumes"] if v["name"] == "registry-auth")
        self.assertEqual(volume["secret"], {"secretName": "nexus-auth", "defaultMode": 0o440,
                         "items": [{"key": ".dockerconfigjson", "path": "config.json"}]})
        self.assertEqual(template["securityContext"]["fsGroup"], 10001)
        self.assertFalse(template["automountServiceAccountToken"])
        self.assertEqual(container["envFrom"], [{"secretRef": {"name": "auth"}}])
        h.finish(h.jobs[-1]); h.run()
        self.assertEqual(len(h.jobs), 1)
        h.policy["spec"]["registryCredentialsSecretRef"]["name"] = "nexus-auth-v2"
        h.run()
        self.assertEqual(len(h.jobs), 2)
        self.assertNotEqual(job["metadata"]["name"], h.jobs[-1].metadata.name)
        h.finish(h.jobs[-1]); h.run()
        del h.policy["spec"]["registryCredentialsSecretRef"]
        h.run()
        self.assertEqual(len(h.jobs), 3)
        container = h.batch.create_namespaced_job.call_args.args[1]["spec"]["template"]["spec"]["containers"][0]
        self.assertNotIn("--containers-local-resolution", container["args"])

    def test_registry_secret_namespace_rejected_before_discovery(self):
        h = Harness([pod()])
        h.policy["spec"]["registryCredentialsSecretRef"] = {"namespace": "apps", "name": "nexus-auth"}
        self.assertEqual(h.run()["phase"], "Invalid")
        h.core.list_pod_for_all_namespaces.assert_not_called()
        h.batch.create_namespaced_job.assert_not_called()

    def test_invalid_registry_secret_names_rejected(self):
        for name in (None, "", "../auth", "UPPER", "-auth", "auth-", "a" * 254, {"name": "auth"}):
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate_registry_secret_name(name)
        h = Harness([])
        h.policy["spec"]["registryCredentialsSecretRef"] = {"namespace": "operator"}
        with self.assertRaisesRegex(ValueError, "valid Secret name"):
            h.run()
        h.core.list_pod_for_all_namespaces.assert_not_called()

    def test_queue_limit_restart_and_slot_release(self):
        h = Harness([pod(digest=d) for d in "abc"])
        status = h.run()
        self.assertEqual(status["activeScans"], 2)
        self.assertEqual(status["imageCounts"], {"Pending": 2, "Queued": 1})
        h.run(); self.assertEqual(len(h.jobs), 2)
        h.finish(h.jobs[0]); h.run()
        self.assertEqual(len(h.jobs), 3)
        self.assertEqual(h.policy["status"]["activeScans"], 2)

    def test_job_created_before_status_failure_is_recovered(self):
        h = Harness([pod()])
        h.custom.patch_namespaced_custom_object_status.side_effect = ApiException(500)
        with self.assertRaises(ApiException): h.run()
        h.custom.patch_namespaced_custom_object_status.side_effect = h.patch_record
        h.run()
        self.assertEqual(len(h.jobs), 1)
        self.assertEqual(next(iter(h.records.values()))["status"]["phase"], "Running")

    def test_failed_scan_retries_only_on_interval_or_rerun(self):
        h = Harness([pod()]); h.run(); h.finish(h.jobs[0], success=False)
        h.run(NOW + timedelta(hours=1)); self.assertEqual(len(h.jobs), 1)
        self.assertEqual(h.policy["status"]["imageCounts"], {"Failed": 1})
        h.policy["spec"]["rescanIntervalSeconds"] = 86400
        h.run(NOW + timedelta(hours=23)); self.assertEqual(len(h.jobs), 1)
        h.run(NOW + timedelta(days=1)); self.assertEqual(len(h.jobs), 2)
        h.finish(h.jobs[-1]); h.run()
        h.policy["spec"]["rerunToken"] = "retry"
        h.run(); self.assertEqual(len(h.jobs), 3)

    def test_baseline_skipped_and_new_digest_processed(self):
        h = Harness([pod()]); h.policy["spec"]["discovery"] = {"scanExisting": False}
        h.run(); self.assertEqual(len(h.jobs), 0)
        h.pods.append(pod("new", "b")); h.run()
        self.assertEqual(len(h.jobs), 1)
        self.assertEqual(h.policy["status"]["imageCounts"], {"Skipped": 1, "Pending": 1})
        h.run(); self.assertEqual(len(h.jobs), 1)

    def test_new_images_disabled(self):
        h = Harness([pod()]); h.policy["spec"]["discovery"] = {"scanNewImages": False}
        h.run(); h.pods.append(pod("new", "b")); h.run()
        self.assertEqual(len(h.jobs), 1)
        self.assertEqual(h.policy["status"]["imageCounts"], {"Running": 1, "Skipped": 1})

    def test_vanished_image_not_rescanned_and_suspension_still_discovers(self):
        h = Harness([pod()]); h.run(); h.finish(h.jobs[0]); h.run()
        h.pods.clear(); h.policy["spec"]["rerunToken"] = "new"
        h.run(); self.assertEqual(len(h.jobs), 1)
        self.assertEqual(h.policy["status"]["discoveredImages"], 0)
        self.assertFalse(next(iter(h.records.values()))["status"]["present"])
        h.policy["spec"]["suspend"] = True; h.pods.append(pod("new", "b")); h.run()
        self.assertEqual(len(h.records), 2)
        self.assertEqual(len(h.jobs), 1)
        self.assertEqual(h.policy["status"]["phase"], "Suspended")

    def test_deleted_job_requires_explicit_rerun(self):
        h = Harness([pod()]); h.run(); h.jobs.clear()
        h.run(); self.assertEqual(len(h.jobs), 0)
        self.assertEqual(h.policy["status"]["imageCounts"], {"Lost": 1})
        h.policy["spec"]["rerunToken"] = "recover"
        h.run(); self.assertEqual(len(h.jobs), 1)

    def test_removed_latest_attempt_does_not_revert_to_old_job(self):
        h = Harness([pod()]); h.run(); h.finish(h.jobs[0]); h.run()
        h.policy["spec"]["rerunToken"] = "new"; h.run()
        h.jobs.pop(); h.run()
        self.assertEqual(h.policy["status"]["imageCounts"], {"Lost": 1})
        self.assertEqual(len(h.jobs), 1)

    def test_old_summary_counts_are_cleared(self):
        h = Harness([pod()]); h.run(); h.finish(h.jobs[0]); h.run()
        self.assertEqual(h.last_patch["imageCounts"]["Pending"], 0)
        self.assertEqual(h.last_patch["imageCounts"]["Completed"], 1)

    def test_unavailable_and_invalid_secret_namespace(self):
        a = pod(); a["status"]["containerStatuses"][0]["imageID"] = "containerd://local"
        h = Harness([a]); h.run()
        self.assertEqual(h.policy["status"]["imageCounts"], {"Unavailable": 1})
        self.assertEqual(len(h.jobs), 0)
        h.policy["spec"]["credentialsSecretRef"]["namespace"] = "other"
        self.assertEqual(h.run()["phase"], "Invalid")


if __name__ == "__main__":
    unittest.main()
