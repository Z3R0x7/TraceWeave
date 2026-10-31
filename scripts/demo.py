"""Generate a small synthetic engine handoff, without implying detection accuracy."""

import hashlib
import json
import sys
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq


def create_demo(root: Path, count=1, access_rows=None):
    root.mkdir(parents=True, exist_ok=True)
    (root / "incidents").mkdir(exist_ok=True)
    incident = {
        "incident_id": "inc_01", "revision": 1, "title": "Suspicious scripting activity",
        "severity": "high", "risk_score": 80, "analysis_reference_time": "2026-10-31T12:00:00Z",
        "entities": [{"entity_id": "host:HR-07", "type": "host", "label": "HR-07"},
                     {"entity_id": "account:alice", "type": "account", "label": "alice"}],
        "timeline": [{"step_id": "step_01", "observed_at": "2026-10-31T10:00:00Z",
                      "display_order": 1, "ordering_basis": "event timestamp",
                      "ordering_confidence": "medium", "summary": "Office launched PowerShell",
                      "entity_ids": ["host:HR-07", "account:alice"], "evidence_ids": ["evt_01"],
                      "interpretation_status": "observed", "maliciousness": "suspicious",
                      "technique_id": "T1059.001"}],
        "relationships": [{"relationship_id": "rel_01", "source_id": "account:alice",
                           "target_id": "host:HR-07", "relationship_type": "executed_on",
                           "evidence_ids": ["evt_01"], "interpretation_status": "observed"}],
        "techniques": [{"id": "T1059.001", "name": "PowerShell", "tactic": "Execution"}],
        "data_quality_impact": ["Earlier authentication logs were not supplied."],
        "engine_review": {"version": "1", "assessment": "Suspicious; requires investigation"}
    }
    bundle_path = root / "incidents" / "inc_01.json"
    bundle_path.write_text(json.dumps(incident))
    def artifact(path):
        return {"location": str(path.relative_to(root)),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "size_bytes": path.stat().st_size}
    summary = {key: incident[key] for key in [
        "incident_id", "revision", "title", "severity", "risk_score"
    ]}
    summary["bundle"] = artifact(bundle_path)
    (root / "incidents.ndjson").write_text(json.dumps(summary) + "\n" if count else "")
    pq.write_table(pa.Table.from_pylist([{
        "incident_id": "inc_01", "evidence_id": "evt_01", "source_file_id": "edr_01",
        "record_locator": "line:42", "evidence_excerpt": "WINWORD.EXE launched powershell.exe"
    }]), root / "evidence.parquet")
    row = {
        "relationship_id": "access_01", "principal_id": "account:alice",
        "source_host_id": "host:HR-07", "source_ip": "10.0.0.7", "target_host_id": "host:FS-02",
        "relationship_type": "successful_remote_auth", "access_level": "unknown",
        "observed_at": "2026-10-30T10:00:00Z", "valid_from": "2026-10-30T00:00:00Z",
        "valid_to": "2026-10-31T23:59:59Z", "evidence_id": "auth_99",
        "source_file_id": "auth_01", "record_locator": "line:99"
    }
    pq.write_table(pa.Table.from_pylist(access_rows if access_rows is not None else [row],
                                      schema=pa.schema([(k, pa.string()) for k in row])),
                   root / "access.parquet")
    (root / "quality.json").write_text(json.dumps({
        "total_records_read": 1000, "successfully_parsed_records": 990, "malformed_records": 10,
        "missing_critical_fields": 2, "unknown_event_types": 1, "duplicate_records": 3,
        "late_arriving_events": 4, "records_excluded_from_detection": 10
    }))
    manifest = {"contract_version": "1.0", "run_id": "demo_run", "status": "completed",
                "source_dataset": {"name": "synthetic-demo", "source_size_bytes": 10000},
                "incident_count": count, "artifacts": {
                    name: artifact(root / file) for name, file in {
                        "incident_summaries": "incidents.ndjson", "evidence": "evidence.parquet",
                        "access_history": "access.parquet", "quality": "quality.json"
                    }.items()
                }}
    manifest["artifacts"]["incident_bundles"] = {"location": "incidents/", "format": "json"}
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2))
    return root / "manifest.json"


if __name__ == "__main__":
    print(create_demo(Path(sys.argv[1] if len(sys.argv) > 1 else "data/input/demo")))
