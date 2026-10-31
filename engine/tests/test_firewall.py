from pathlib import Path
import sys,tempfile,unittest,json
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'.deps'),str(ROOT)]
from killchain.log_formats import decode_record,parse_key_values
from killchain.ingest import normalize,inputs
from killchain.resources import resolve_config
from killchain.pipeline import analyze
from killchain.results import incident_entries,get_incident,validate_run

BASE='date=2026-10-23 time=08:48:26 eventtime=1792745306000000000 tz="+0530" devname="FGT-DEMO" devid="observer-1" '

class FirewallTests(unittest.TestCase):
    def test_quoted_values(self):
        d=parse_key_values('msg="Login failed for user" user="a=b" action=login')
        self.assertEqual(d['msg'],'Login failed for user');self.assertEqual(d['user'],'a=b')
    def test_duplicate_keys_rejected(self):
        with self.assertRaises(ValueError):parse_key_values('action=pass action=deny')
    def test_observer_not_source_and_time_conflict_preserved(self):
        raw=(BASE+'type=traffic subtype=forward action=accept srcip=10.0.0.1 dstip=10.0.0.2 sentbyte=10 rcvdbyte=20').encode()
        e,fmt=decode_record(raw);r=normalize(e,raw,Path('sample.log'),'test',1,0,fmt)
        self.assertIsNone(r['host_name']);self.assertEqual(r['source_ip'],'10.0.0.1')
        self.assertEqual(r['observer_id'],'observer-1');self.assertEqual(r['network_bytes'],30)
        self.assertEqual(r['timestamp_conflict_seconds'],19800)
    def test_authentication_outcome(self):
        e,fmt=decode_record((BASE+'type=event subtype=system action=login user=admin status=failed srcip=192.0.2.1').encode())
        self.assertEqual(e['event']['outcome'],'failure');self.assertEqual(e['host']['name'],'FGT-DEMO')
    def test_binary_never_silently_accepted(self):
        with self.assertRaisesRegex(ValueError,'unsupported_binary_record'):decode_record(b'\xff\x00invalid')
    def test_reference_manifest_not_an_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'a.log').write_text('');(root/'a.log.manifest.json').write_text('{"incidents":[]}')
            self.assertEqual([p.name for p in inputs(root)],['a.log'])
    def test_ips_fixture_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=root/'firewall.log'
            source.write_text(BASE+'type=utm subtype=ips action=dropped srcip=10.0.0.1 dstip=10.0.0.2 attack="Test.Signature" severity=high\n')
            run=root/'run';cfg=resolve_config(overrides={'memory_gb':.25,'threads':1},workspace=run)
            result=analyze(source,run,'test',cfg);self.assertEqual(result['records_parsed'],1)
            b=get_incident(run,next(incident_entries(run))['incident_id'])
            self.assertEqual(b['steps'][0]['rule_id'],'firewall_ips_alert');self.assertIsNone(b['steps'][0]['technique_id'])
            edge=b['edges'][0];self.assertEqual(edge['source_id'],'ip:10.0.0.1');self.assertEqual(edge['target_id'],'ip:10.0.0.2')
            self.assertTrue(validate_run(run)['valid'])
    def test_session_correlation_requires_matching_recorded_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=root/'sessions.log';run=root/'run'
            records=[]
            for sid,signature in [('42','Sig.A'),('42','Sig.B'),('99','Sig.C')]:
                records.append(BASE+'type=utm subtype=ips action=dropped srcip=10.0.0.1 dstip=10.0.0.2 srcport=1234 dstport=443 proto=6 sessionid='+sid+' attack='+signature+' severity=high')
            source.write_text('\n'.join(records)+'\n')
            cfg=resolve_config(overrides={'memory_gb':.25,'threads':1},workspace=run)
            result=analyze(source,run,'test',cfg)
            self.assertEqual(result['incidents_found'],2)
            groups=[get_incident(run,e['incident_id']) for e in incident_entries(run)]
            linked=next(b for b in groups if len(b['steps'])==2)
            self.assertTrue(any(e['relationship']=='same_recorded_network_session' for e in linked['edges']))
            self.assertTrue(validate_run(run)['valid'])

    def test_explicit_recovery_accounts_for_excluded_tail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=root/'partial.log'
            good=(BASE+'type=traffic subtype=forward action=accept srcip=10.0.0.1 dstip=10.0.0.2\n').encode()
            tail=b'partial field=\xff\x00binary'
            source.write_bytes(good+tail);run=root/'run'
            cfg=resolve_config(overrides={'memory_gb':.25,'threads':1,'recover_valid_prefix':True},workspace=run)
            result=analyze(source,run,'test',cfg)
            manifest=json.loads((run/'manifest.v1.json').read_text())
            self.assertEqual(result['records_parsed'],1)
            self.assertEqual(manifest['input_completeness'],'partial_recovery')
            self.assertEqual(manifest['analysis_bytes'],len(good))
            self.assertEqual(manifest['excluded_tail_bytes'],len(tail))
            self.assertTrue(validate_run(run)['valid'])

    def test_binary_run_fails_explicitly(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=root/'bad.log';source.write_bytes(b'\xff\x00not-a-text-record\n');run=root/'run'
            cfg=resolve_config(overrides={'memory_gb':.25,'threads':1},workspace=run)
            with self.assertRaisesRegex(ValueError,'unsupported binary bytes'):analyze(source,run,'test',cfg)
            self.assertEqual(json.loads((run/'progress.v1.json').read_text())['status'],'failed')
            self.assertFalse((run/'manifest.v1.json').exists())

if __name__=='__main__':unittest.main()
