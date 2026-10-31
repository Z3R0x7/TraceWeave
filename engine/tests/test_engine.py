from pathlib import Path
import json,os,sys,tempfile,unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'.deps'));sys.path.insert(0,str(ROOT))
from killchain.resources import resolve_config
from killchain.pipeline import analyze
from killchain.results import incident_entries,get_incident,validate_run
from killchain.ai import validate_review,review_run
from killchain.common import load_json,sanitize
from killchain.ingest import stream_records

def event(eid,stamp='2026-10-31T10:00:00Z',category='process',action='process_created',entity=None):
    e={'@timestamp':stamp,'event':{'id':eid,'category':[category],'action':action},'host':{'name':'A','ip':['10.0.0.1']},'user':{'name':'alice','domain':'CORP'}}
    if category=='process':e['process']={'name':'powershell.exe','parent':{'name':'winword.exe'}}
    if entity:e.setdefault('process',{})['entity_id']=entity
    return e

class EngineTests(unittest.TestCase):
    def setUp(self):self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
    def tearDown(self):self.temp.cleanup()
    def run_events(self,files,overrides=None):
        source=self.root/'input';source.mkdir()
        for name,events in files.items():
            with (source/name).open('w') as f:
                for e in events:f.write(json.dumps(e)+'\n')
        run=self.root/'run';cfg=resolve_config(overrides={'batch_records':1,'memory_gb':.25,'threads':1,**(overrides or {})},workspace=run)
        return run,analyze(source,run,'test',cfg),cfg
    def test_cross_file_process_identity_and_contract(self):
        a=event('a',entity='stable');b=event('b',stamp='2026-10-31T10:01:00Z',category='registry',action='registry_value_set')
        b['process']={'name':'powershell.exe','entity_id':'stable'};b['registry']={'path':r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run\entry'}
        run,p,cfg=self.run_events({'z.log':[a],'a.log':[b]})
        self.assertEqual(p['incidents_found'],1)
        bundle=get_incident(run,next(incident_entries(run))['incident_id'])
        self.assertEqual(len(bundle['steps']),2);self.assertEqual(bundle['steps'][0]['rule_id'],'office_powershell')
        self.assertTrue(any(e['relationship']=='same_recorded_process' for e in bundle['edges']))
        self.assertTrue(validate_run(run)['valid'])
    def test_same_host_user_does_not_invent_chain(self):
        run,p,cfg=self.run_events({'x.log':[event('a'),event('b',stamp='2026-10-31T10:00:01Z')]})
        self.assertEqual(p['incidents_found'],2)
    def test_failure_sequence_cross_file_out_of_order(self):
        failed=[]
        for i in range(25):
            e=event('f'+str(i),stamp=f'2026-10-31T10:00:{i:02d}Z',category='authentication',action='user_logon')
            e['event']['outcome']='failure';e['source']={'ip':'192.0.2.1'};failed.append(e)
        success=event('s',stamp='2026-10-31T10:01:00Z',category='authentication',action='user_logon')
        success['event']['outcome']='success';success['source']={'ip':'192.0.2.1'}
        run,p,cfg=self.run_events({'a.log':[success],'z.log':list(reversed(failed))})
        self.assertEqual(p['incidents_found'],1);b=get_incident(run,next(incident_entries(run))['incident_id'])
        self.assertEqual(b['steps'][0]['supporting_count'],25);self.assertEqual(b['steps'][0]['evidence_count'],26)
        self.assertTrue(validate_run(run)['valid'])
    def test_upstream_labels_alone_do_not_trigger(self):
        e=event('normal');e['process']={'name':'notepad.exe','parent':{'name':'explorer.exe'}}
        e['event']['kind']='alert';e['threat']={'technique':{'id':['T1059.001']}}
        run,p,cfg=self.run_events({'x.log':[e]})
        self.assertEqual(p['incidents_found'],0);self.assertTrue(validate_run(run)['valid'])
    def test_duplicate_and_conflicting_ids(self):
        e=event('same');other=event('same',stamp='2026-10-31T10:01:00Z')
        run,p,cfg=self.run_events({'x.log':[e,e,other]})
        self.assertEqual(p['duplicate_records'],1);self.assertEqual(p['conflicting_event_ids'],1);self.assertEqual(p['incidents_found'],2)
    def test_missing_timestamp_accounting(self):
        bad=event('bad');del bad['@timestamp'];run,p,cfg=self.run_events({'x.log':[bad,event('good')]})
        self.assertEqual(p['malformed_records'],1);self.assertEqual(p['records_read'],2)
        self.assertEqual(load_json(run/'manifest.v1.json')['input_completeness'],'completed_with_exclusions')
    def test_empty_is_success(self):
        run,p,cfg=self.run_events({'empty.log':[]});self.assertEqual(p['status'],'completed');self.assertEqual(p['incidents_found'],0)
        self.assertTrue(validate_run(run)['valid'])
    def test_oversized_reader_keeps_next_record(self):
        p=self.root/'huge.log';p.write_bytes(b'x'*10000+b'\n{}\n');rows=list(stream_records(p,100))
        self.assertEqual(rows[0][4],'oversized_record');self.assertEqual(rows[0][2],10001);self.assertEqual(rows[1][3],b'{}\n')
    def test_no_key_preserves_baseline(self):
        run,p,cfg=self.run_events({'x.log':[event('a')]});cfg['ai_provider']='groq'
        with patch.dict(os.environ,{},clear=True):self.assertEqual(review_run(run,cfg)['status'],'unavailable')
        self.assertEqual(get_incident(run,next(incident_entries(run))['incident_id'])['ai_review']['status'],'not_requested')
    def test_ai_rejects_invented_evidence(self):
        value={'assessment':'suspicious','supporting_event_ids':['fake'],'suggested_technique_ids':[],'proposed_links':[],'missing_evidence':[],'explanation':'test'}
        with self.assertRaises(ValueError):validate_review(value,['real'])
    def test_ai_success_and_failure_do_not_change_facts(self):
        run,p,cfg=self.run_events({'x.log':[event('a')]});cfg['ai_provider']='groq'
        def fake(provider,model,key,packet,config):
            return {'assessment':'suspicious','supporting_event_ids':[packet['events'][0]['id']],'suggested_technique_ids':['T1059.001'],'proposed_links':[],'missing_evidence':['Authorization context'],'explanation':'Office child process is recorded.'}
        with patch.dict(os.environ,{'GROQ_API_KEY':'test-not-a-real-key'}):
            self.assertEqual(review_run(run,cfg,caller=fake)['reviewed'],1)
            iid=next(incident_entries(run))['incident_id'];before=get_incident(run,iid);self.assertEqual(before['ai_review']['status'],'completed')
            cfg['ai_model']='different-model'
            def invalid(*args):raise ValueError('bad')
            self.assertEqual(review_run(run,cfg,caller=invalid)['failed'],1)
            after=get_incident(run,iid);self.assertEqual(before['steps'],after['steps']);self.assertEqual(after['ai_review']['status'],'failed')
    def test_sanitize(self):
        self.assertEqual(sanitize({'api_key':'SECRET'})['api_key'],'[REDACTED]');self.assertNotIn('SECRET',sanitize('Bearer SECRET'))
    def test_reject_overwrite(self):
        run,p,cfg=self.run_events({'x.log':[event('a')]})
        with self.assertRaises(FileExistsError):analyze(self.root/'input',run,'test',cfg)
    def test_nested_output_rejected(self):
        source=self.root/'input';source.mkdir();(source/'x.log').write_text('');cfg=resolve_config(workspace=self.root)
        with self.assertRaises(ValueError):analyze(source,source/'output','test',cfg)

    def test_unknown_configuration_key_rejected(self):
        path=self.root/'bad-config.json';path.write_text('{"imaginary_option":1}')
        with self.assertRaises(ValueError):resolve_config(path,workspace=self.root)
    def test_utc_export_and_dangling_reference_rejected(self):
        run,p,cfg=self.run_events({'x.log':[event('a')]})
        entry=next(incident_entries(run));bundle=get_incident(run,entry['incident_id'])
        self.assertTrue(bundle['steps'][0]['timestamp'].endswith('Z'))
        bundle['steps'][0]['evidence_ids']=['invented']
        (run/entry['bundle_path']).write_text(json.dumps(bundle))
        with self.assertRaises(ValueError):validate_run(run)
    def test_empty_incident_cli(self):
        run,p,cfg=self.run_events({'empty.log':[]})
        from killchain.cli import main
        import io,contextlib
        output=io.StringIO()
        with contextlib.redirect_stdout(output):code=main(['incidents','--run',str(run),'--json'])
        self.assertEqual(code,0);self.assertEqual(json.loads(output.getvalue()),[])

if __name__=='__main__':unittest.main()
