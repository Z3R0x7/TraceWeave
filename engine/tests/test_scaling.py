from pathlib import Path
import json,sys,tempfile,unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from killchain.resources import resolve_config
from killchain.pipeline import analyze
from killchain.parallel import ranges,RunCancelled
from killchain.results import validate_run,incident_entries,get_incident,raw_evidence
from killchain.common import load_json
import killchain.parallel as parallel


def auth(i,outcome='failure'):
    return {'@timestamp':f'2026-01-01T10:{i//60:02d}:{i%60:02d}Z','event':{'id':str(i),'category':'authentication','action':'login','outcome':outcome},
        'host':{'name':'HOST'},'user':{'name':'alice'},'source':{'ip':'192.0.2.1'}}


class ScalingTests(unittest.TestCase):
    def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
    def tearDown(self):self.tmp.cleanup()
    def config(self,**changes):
        return resolve_config(overrides={'parse_workers':1,'chunk_mb':.001,'memory_gb':.25,'total_memory_gb':2,**changes},workspace=self.root)
    def write(self,events):
        source=self.root/'events.log';source.write_text(''.join(json.dumps(e)+'\n' for e in events));return source
    def test_ranges_have_no_loss_with_oversized_and_unterminated_lines(self):
        path=self.root/'raw.log';data=b'a\n'+b'x'*10000+b'\nend';path.write_bytes(data)
        pieces=list(ranges(path,10));self.assertEqual(pieces[0][0],0);self.assertEqual(pieces[-1][1],len(data))
        self.assertEqual(b''.join(data[a:b] for a,b in pieces),data)
        for a,b in pieces:
            if a:self.assertEqual(data[a-1:a],b'\n')
    def test_parallel_equals_serial_across_auth_window(self):
        source=self.write([auth(i) for i in range(25)]+[auth(60,'success')])
        first=self.root/'one';second=self.root/'two'
        a=analyze(source,first,'one',self.config());b=analyze(source,second,'two',self.config(parse_workers=2))
        for key in ['records_read','records_parsed','processed_bytes','duplicate_records','detections_found','incidents_found','out_of_order_records']:
            self.assertEqual(a[key],b[key],key)
        ids=lambda r:{x['incident_id'] for x in incident_entries(r)}
        self.assertEqual(ids(first),ids(second));self.assertEqual(a['processed_bytes'],source.stat().st_size)
        self.assertGreater(a['parse_partitions_completed'],1)
        for iid in ids(first):self.assertEqual(get_incident(first,iid)['steps'],get_incident(second,iid)['steps'])
        self.assertTrue(validate_run(second)['valid'])
    def test_binary_skip_resumes_at_next_line(self):
        source=self.root/'mixed.log';good=json.dumps(auth(0)).encode()+b'\n';bad=b'broken=\xff\x00\n'
        source.write_bytes(good+bad+json.dumps(auth(1)).encode()+b'\n');run=self.root/'skip'
        result=analyze(source,run,'skip',self.config(fail_on_binary=False))
        summary=load_json(run/'summary.v1.json')
        self.assertEqual(result['records_parsed'],2);self.assertEqual(result['malformed_records'],1)
        self.assertEqual(summary['skipped_bytes'],len(bad));self.assertEqual(summary['scanned_bytes'],source.stat().st_size)
        self.assertEqual(summary['coverage'],'completed_with_exclusions')
        reject=json.loads((run/'diagnostics/rejected.jsonl').read_text())
        self.assertEqual(reject['byte_offset'],len(good));self.assertEqual(reject['byte_length'],len(bad))
    def test_cancel_resume_reuses_only_complete_partitions(self):
        source=self.write([auth(i) for i in range(30)]);run=self.root/'resumable';cfg=self.config()
        original=parallel.parse_partition
        def cancel_after_partition(job):
            value=original(job);(run/'CANCEL').touch();return value
        with patch.object(parallel,'parse_partition',cancel_after_partition):
            with self.assertRaises(RunCancelled):analyze(source,run,'resume',cfg)
        self.assertFalse((run/'manifest.v1.json').exists());self.assertTrue((run/'partial.v1.json').exists())
        result=analyze(source,run,'resume',cfg,resume=True)
        self.assertGreater(result['reused_parse_bytes'],0);self.assertEqual(result['records_parsed'],30)
        self.assertEqual(result['processed_bytes'],source.stat().st_size);self.assertTrue(validate_run(run)['valid'])
    def test_resume_rejects_changed_input(self):
        source=self.write([auth(i) for i in range(10)]);run=self.root/'change';cfg=self.config()
        with patch('killchain.pipeline.prepare',side_effect=ValueError('synthetic crash')):
            with self.assertRaises(ValueError):analyze(source,run,'change',cfg)
        source.write_text(source.read_text()+json.dumps(auth(20))+'\n')
        with self.assertRaisesRegex(ValueError,'input changed'):analyze(source,run,'change',cfg,resume=True)
    def test_disk_estimate_fails_before_parse(self):
        source=self.write([auth(0)]);run=self.root/'disk'
        with self.assertRaisesRegex(ValueError,'working/output space'):analyze(source,run,'disk',self.config(disk_estimate_multiplier=10**12))
        self.assertFalse((run/'staging').exists())
    def test_raw_reader_allows_only_registered_file_and_line_boundary(self):
        source=self.write([auth(0)]);run=self.root/'raw';analyze(source,run,'raw',self.config())
        manifest=load_json(run/'manifest.v1.json');file_id=manifest['sources'][0]['source_file_id']
        value=raw_evidence(run,file_id,0);self.assertEqual(json.loads(value['records'][0]['text'])['event']['id'],'0')
        with self.assertRaises(ValueError):raw_evidence(run,'../../etc/passwd',0)
        with self.assertRaises(ValueError):raw_evidence(run,file_id,1)
    def test_invalid_snapshot_fails_early(self):
        file=self.root/'feed.json';file.write_text('{"source":"test"}')
        with self.assertRaises(ValueError):self.config(indicator_snapshot=str(file))
    def test_offline_feed_and_playbook_are_attributed(self):
        feed=self.root/'feed.json';feed.write_text(json.dumps({'source':'team test fixture','retrieved_at':'2026-01-01T00:00:00Z','indicators':[{'type':'ip','value':'192.0.2.1'}]}))
        book=self.root/'playbooks.json';book.write_text(json.dumps({'source':'team test fixture','retrieved_at':'2026-01-01T00:00:00Z','techniques':{'T1110':[{'id':'test-only','name':'Investigate','description':'Review authentication evidence.'}]}}))
        events=[auth(i) for i in range(25)];events[0]['event']['category']='network'
        source=self.write(events+[auth(60,'success')]);run=self.root/'feed'
        result=analyze(source,run,'feed',self.config(indicator_snapshot=str(feed),playbook_snapshot=str(book),failure_threshold=20,
            asset_map=[{'host':'CANONICAL','aliases':['HOST'],'ips':[],'criticality':90}],
            allowlist=[{'field':'source_ip','value':'192.0.2.1','reason':'Known test generator'}]))
        bundles=[get_incident(run,row['incident_id']) for row in incident_entries(run)]
        self.assertTrue(any(b['enrichments'] for b in bundles));self.assertTrue(any(b['response_playbook'] for b in bundles))
        self.assertTrue(all(any(e['label']=='CANONICAL' for e in b['entities']) for b in bundles))
        self.assertTrue(all('priority_score' in b for b in bundles));self.assertEqual(result['allowlisted_records'],26)
