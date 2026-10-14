import copy
import importlib
import sys
import types
import unittest
from types import SimpleNamespace as NS
from unittest.mock import Mock, patch
from operator_src.planner import plan, phase, snapshot, validate

BODY = {'apiVersion':'security.asteriusit.fr/v1alpha1','kind':'CheckmarxScan',
        'metadata':{'name':'demo','namespace':'checkmarx-system','uid':'uid-1','generation':1},
        'spec':{'projectName':'demo','credentialsSecretRef':'auth', 'scanTypes':['sast'],
                'repository':{'url':'https://github.com/example/repo.git','branch':'main'}}}
WORKLOAD = {'apiVersion':'apps/v1','kind':'Deployment','metadata':{'name':'demo','namespace':'checkmarx-system',
            'annotations':{'secret':'omit'},'resourceVersion':'1'},'spec':{'template':{'spec':{'containers':[
            {'name':'app','image':'example:1','env':[{'name':'TOKEN','value':'sensitive'},
            {'name':'KEY','valueFrom':{'secretKeyRef':{'name':'app-secret','key':'key'}}}]}]}}},'status':{'replicas':1}}
IMAGE='cx-runner:tested'

class PlannerTests(unittest.TestCase):
    def test_deterministic_and_generation_changes(self):
        a=plan(BODY,IMAGE)
        self.assertEqual(a,plan(BODY,IMAGE))
        b=copy.deepcopy(BODY); b['metadata']['generation']=2
        self.assertNotEqual(a[0],plan(b,IMAGE)[0])
        self.assertLessEqual(len(a[0]),63)
    def test_no_shell_or_secret_contents(self):
        b=copy.deepcopy(BODY); b['spec']['projectName']='demo; touch /tmp/attack'
        job=plan(b,IMAGE)[3]; c=job['spec']['template']['spec']['containers'][0]
        self.assertNotIn('command', c)
        self.assertEqual(c['workingDir'], '/tmp')
        self.assertIn({'name': 'HOME', 'value': '/tmp'}, c['env'])
        self.assertIn({'name': 'USER', 'value': 'cx'}, c['env'])
        self.assertIn(b['spec']['projectName'],c['args'])
        self.assertEqual(c['envFrom'][0]['secretRef']['name'],'auth')
        self.assertEqual(job['spec']['backoffLimit'],0)
        self.assertNotIn('ttlSecondsAfterFinished',job['spec'])
        self.assertFalse(job['spec']['template']['spec']['automountServiceAccountToken'])
    def test_invalid_targets(self):
        b=copy.deepcopy(BODY); b['spec']['workloadRef']={'kind':'Deployment','name':'demo'}
        with self.assertRaises(ValueError): validate(b['spec'])
        del b['spec']['repository']
        with self.assertRaises(ValueError): validate(b['spec'])
        b['spec']['scanTypes']=['iac-security']; validate(b['spec'])
    def test_repo_credentials_rejected(self):
        for url in ['http://host/repo','https://token@host/repo','https://host/repo?token=x']:
            b=copy.deepcopy(BODY); b['spec']['repository']['url']=url
            with self.assertRaises(ValueError): validate(b['spec'])
    def test_snapshot_redacts_and_does_not_mutate(self):
        result=snapshot(WORKLOAD)
        self.assertNotIn('sensitive',result); self.assertNotIn('annotations',result)
        self.assertNotIn('status',result); self.assertIn('app-secret',result)
        self.assertIn('sensitive',str(WORKLOAD))
    def test_workload_identity_tracks_spec_not_status(self):
        b=copy.deepcopy(BODY); del b['spec']['repository']
        b['spec'].update(workloadRef={'kind':'Deployment','name':'demo'},scanTypes=['iac-security'])
        a=plan(b,IMAGE,WORKLOAD)
        w=copy.deepcopy(WORKLOAD); w['status']['replicas']=3
        self.assertEqual(a[0],plan(b,IMAGE,w)[0])
        w['spec']['template']['spec']['containers'][0]['image']='example:2'
        self.assertNotEqual(a[0],plan(b,IMAGE,w)[0])
        self.assertTrue(a[2]['immutable']); self.assertIn('/source',a[3]['spec']['template']['spec']['containers'][0]['args'])
    def test_terminal_conditions(self):
        for condition,expected in [('Complete','Completed'),('Failed','Failed')]:
            self.assertEqual(phase(NS(status=NS(conditions=[NS(type=condition,status='True')],active=0))),expected)
        self.assertEqual(phase(NS(status=NS(conditions=[],active=0))),'Pending')

# Minimal dependency doubles let reconciliation run offline without pip or a cluster.
class ApiException(Exception):
    def __init__(self,status): self.status=status
class TemporaryError(Exception):
    def __init__(self,message,delay): super().__init__(message)
kopf=types.ModuleType('kopf')
kopf.on=NS(startup=lambda **_: lambda f:f)
kopf.timer=lambda *a,**k: lambda f:f
kopf.TemporaryError=TemporaryError
kube=types.ModuleType('kubernetes'); kube.client=NS(); kube.config=NS()
exceptions=types.ModuleType('kubernetes.client.exceptions'); exceptions.ApiException=ApiException
with patch.dict(sys.modules,{'kopf':kopf,'kubernetes':kube,'kubernetes.client.exceptions':exceptions}):
    handlers=importlib.import_module('operator_src.handlers')

class ControllerTests(unittest.TestCase):
    def child(self,state='Complete'):
        return NS(metadata=NS(owner_references=[NS(uid='uid-1')]),
                  status=NS(conditions=[NS(type=state,status='True')],active=0))
    def test_existing_job_never_resubmitted(self):
        read=Mock(return_value=self.child()); create=Mock()
        handlers.ensure(read,create,'ns','job',{},'uid-1')
        create.assert_not_called()
    def test_conflict_race_recovers(self):
        read=Mock(side_effect=[ApiException(404),self.child()])
        create=Mock(side_effect=ApiException(409))
        handlers.ensure(read,create,'ns','job',{},'uid-1')
        self.assertEqual(read.call_count,2)
    def test_unrelated_child_blocked(self):
        obj=self.child(); obj.metadata.owner_references=[]
        with self.assertRaises(ValueError):
            handlers.ensure(Mock(return_value=obj),Mock(),'ns','job',{},'uid-1')
    def test_api_failure_not_treated_as_missing(self):
        create=Mock()
        with self.assertRaises(ApiException):
            handlers.ensure(Mock(side_effect=ApiException(403)),create,'ns','job',{},'uid-1')
        create.assert_not_called()
    def test_reconcile_completed(self):
        batch=NS(read_namespaced_job=Mock(return_value=self.child()),create_namespaced_job=Mock())
        status=NS(status={})
        with patch.object(handlers.client,'BatchV1Api',return_value=batch,create=True), \
             patch.object(handlers.client,'CoreV1Api',return_value=NS(),create=True), \
             patch.dict('os.environ',{'CX_CLI_IMAGE':IMAGE}):
            handlers.reconcile(BODY,status)
        self.assertEqual(status.status['phase'],'Completed')
        self.assertEqual(status.status['observedGeneration'],1)
        batch.create_namespaced_job.assert_not_called()
    def test_new_generation_waits_for_old(self):
        b=copy.deepcopy(BODY); b['status']={'jobName':'old-job'}
        old=self.child(); old.status=NS(conditions=[],active=1)
        batch=NS(read_namespaced_job=Mock(return_value=old),create_namespaced_job=Mock())
        status=NS(status={})
        with patch.object(handlers.client,'BatchV1Api',return_value=batch,create=True), \
             patch.dict('os.environ',{'CX_CLI_IMAGE':IMAGE}):
            handlers.reconcile(b,status)
        self.assertEqual(status.status['phase'],'WaitingForPreviousRun')
        batch.create_namespaced_job.assert_not_called()

if __name__=='__main__': unittest.main()
