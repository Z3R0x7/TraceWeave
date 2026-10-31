"""Exercise the actual engine-to-application contract, including empty access history."""
import json
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'engine'))
from killchain.pipeline import analyze
from killchain.resources import resolve_config
from scripts.adapt_engine import adapt
from api.contracts import Manifest,Incident
import pyarrow.parquet as pq


def test_firewall_engine_handoff(tmp_path):
    source=tmp_path/'official-format.log'
    source.write_text('date=2026-10-23 time=08:48:26 eventtime=1792745306000000000 tz="+0530" devname="FGT" devid="test" type=utm subtype=ips action=dropped srcip=10.0.0.1 dstip=10.0.0.2 attack="Test.Signature" severity=high\n')
    run=tmp_path/'engine-run';target=tmp_path/'handoff'
    cfg=resolve_config(overrides={'memory_gb':.25,'threads':1},workspace=tmp_path)
    analyze(source,run,'official-format-test',cfg)
    adapt(run,target)
    manifest=Manifest.model_validate_json((target/'manifest.json').read_text())
    assert manifest.run_id=='official-format-test'
    assert manifest.source_dataset.source_size_bytes==source.stat().st_size
    access=pq.read_table(target/'access_history.parquet')
    assert access.num_rows==0
    assert 'relationship_type' in access.column_names
    for item in (target/'incidents').glob('*.json'):
        incident=Incident.model_validate_json(item.read_text())
        assert incident.engine_review['status']=='not_requested'
        assert incident.kill_chain==[]
        assert incident.steps_truncated is False
        assert incident.total_step_count==1
        assert any(e.type=='ip' for e in incident.entities)
    assert len((run/'briefs.v1.jsonl').read_text().splitlines())==1
