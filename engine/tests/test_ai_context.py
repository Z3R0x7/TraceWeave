import unittest
import duckdb
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from killchain.ai import validate_review,build_packet
from killchain.presentation import brief


def review(**changes):
    result=dict(assessment='suspicious',supporting_event_ids=['a'],suggested_technique_ids=[],
        proposed_links=[],missing_evidence=[],explanation='Recorded activity needs investigation.')
    result.update(changes)
    return result


class AIContextTests(unittest.TestCase):
    def test_mapping_must_cite_known_evidence(self):
        with self.assertRaises(ValueError):
            validate_review(review(technique_mappings=[dict(technique_id='T1059.001',evidence_ids=['invented'],reason='test',confidence='low')]),['a'])

    def test_mapping_must_use_reference(self):
        with self.assertRaises(ValueError):
            validate_review(review(technique_mappings=[dict(technique_id='T9999',evidence_ids=['a'],reason='test',confidence='high')]),['a'])

    def test_reject_self_connection(self):
        with self.assertRaises(ValueError):
            validate_review(review(proposed_links=[dict(source_evidence_id='a',target_evidence_id='a',explanation='test')]),['a'])

    def test_accept_evidence_backed_mapping(self):
        result=validate_review(review(technique_mappings=[dict(technique_id='T1059.001',evidence_ids=['a'],reason='PowerShell execution recorded',confidence='medium')]),['a'])
        self.assertEqual(result['technique_mappings'][0]['evidence_ids'],['a'])

    def test_context_is_related_and_bounded(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);con=duckdb.connect()
            con.execute('CREATE TABLE e(incident_id VARCHAR,evidence_id VARCHAR,timestamp TIMESTAMPTZ,host_name VARCHAR,account_id VARCHAR,source_ip VARCHAR,destination_ip VARCHAR,evidence_excerpt VARCHAR)')
            con.executemany('INSERT INTO e VALUES (?,?,?,?,?,?,?,?)',[
                ('one','a','2026-01-01T00:00:00Z',None,None,'1','2','alert'),
                ('two','b','2026-01-01T00:01:00Z',None,None,'1','2','candidate'),
                ('three','c','2026-01-01T00:01:00Z',None,None,'3','4','unrelated'),
                ('four','d','2026-01-01T01:00:00Z',None,None,'1','2','too late')])
            con.execute('COPY e TO ? (FORMAT PARQUET)',[str(root/'e.parquet')])
            packet=build_packet(con,root,{'evidence_path':'e.parquet'},{'uncertainties':[]},{'incident_id':'one'},{'ai_max_input_chars':12000})
            self.assertEqual({e['id'] for e in packet['events']},{'a','b'})
            self.assertEqual(packet['events'][1]['role'],'candidate_context')
            small=build_packet(con,root,{'evidence_path':'e.parquet'},{'uncertainties':[]},{'incident_id':'one'},{'ai_max_input_chars':1})
            self.assertEqual(small['events'],[])
            con.close()

    def test_clean_output_keeps_partial_coverage(self):
        value=brief({'incident_id':'one','title':'Alert','steps':[],'edges':[],
            'ai_review':{'status':'not_requested'}},{'input_completeness':'partial_recovery'})
        self.assertEqual(value['coverage'],'partial_recovery')
        self.assertIsNone(value['ai_summary'])
