import json,sys,tempfile,unittest,importlib.util
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from killchain.evaluate import evaluate
from killchain.pipeline import analyze
from killchain.resources import resolve_config
from killchain.common import load_json
from killchain.results import incident_entries,get_incident


class EvaluationTests(unittest.TestCase):
    def test_independent_truth_and_no_false_alarm_claim_for_partial_truth(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=root/'sample.log';run=root/'run'
            source.write_text(json.dumps({'@timestamp':'2026-01-01T00:00:00Z','event':{'category':'process','action':'start'},'host':{'name':'A'},'process':{'name':'pwsh','parent':{'name':'winword.exe'}}})+'\n')
            cfg=resolve_config(overrides={'parse_workers':1,'memory_gb':.25},workspace=root)
            analyze(source,run,'evaluation',cfg)
            incident=get_incident(run,next(incident_entries(run))['incident_id']);eid=incident['steps'][0]['primary_evidence_id']
            truth=root/'truth.json';truth.write_text(json.dumps({'complete':False,'incidents':[{'id':'ground-truth-one','steps':[{'evidence_id':eid,'technique_id':'T1059.001'}]}]}))
            result=evaluate(run,truth)
            self.assertEqual(result['detection_recall'],1)
            self.assertEqual(result['correct_technique_share'],1)
            self.assertEqual(result['reconstructed_attack_share'],1)
            self.assertIsNone(result['false_incident_share'])
    def test_stix_conversion_filters_revoked_records(self):
        path=Path(__file__).resolve().parents[1]/'tools/import_intelligence.py'
        spec=importlib.util.spec_from_file_location('import_intelligence',path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        data={'objects':[
            {'id':'attack-pattern--a','type':'attack-pattern','external_references':[{'source_name':'mitre-attack','external_id':'T1110'}]},
            {'id':'course-of-action--b','type':'course-of-action','name':'Test mitigation','description':'Fixture only','external_references':[{'source_name':'mitre-attack','external_id':'M0000'}]},
            {'id':'relationship--one','type':'relationship','relationship_type':'mitigates','source_ref':'course-of-action--b','target_ref':'attack-pattern--a'},
            {'id':'relationship--revoked','type':'relationship','relationship_type':'mitigates','source_ref':'course-of-action--b','target_ref':'attack-pattern--a','revoked':True}]}
        output=module.stix_playbooks(data,'fixture','2026-01-01T00:00:00Z')
        self.assertEqual(len(output['techniques']['T1110']),1)
