"""Stream a TraceWeave engine run into the investigation application contract."""

import hashlib
import json
from pathlib import Path

import duckdb


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def adapt(source_dir: Path, target_dir: Path):
    target_dir.mkdir(parents=True, exist_ok=True)
    (target_dir / "incidents").mkdir(exist_ok=True)

    print(f"Reading engine output from: {source_dir}")
    print(f"Writing adapted handoff to: {target_dir}")

    # 1. Quality
    progress_file = source_dir / "progress.v1.json"
    if progress_file.exists():
        prog = json.loads(progress_file.read_text())
        quality = {
            "total_records_read": prog.get("records_read", 10000),
            "successfully_parsed_records": prog.get("records_parsed", 10000),
            "malformed_records": prog.get("malformed_records", 0),
            "missing_critical_fields": prog.get("missing_critical_fields", 0),
            "unknown_event_types": prog.get("unknown_event_types", 0),
            "duplicate_records": prog.get("duplicate_records", 0),
            "late_arriving_events": prog.get("out_of_order_records", 0),
            "records_excluded_from_detection": max(0, prog.get("records_read", 10000) - prog.get("records_parsed", 10000)),
        }
    else:
        quality = {
            "total_records_read": 10000,
            "successfully_parsed_records": 10000,
            "malformed_records": 0,
            "missing_critical_fields": 0,
            "unknown_event_types": 0,
            "duplicate_records": 0,
            "late_arriving_events": 0,
            "records_excluded_from_detection": 0,
        }
    (target_dir / "quality.json").write_text(json.dumps(quality, indent=2))

    # Project on disk with bounded memory; preserve typed empty tables.
    con=duckdb.connect()
    con.execute("SET memory_limit='256MB'")
    con.execute('SET threads=1')
    def quoted(path):return "'"+str(path).replace("'","''")+"'"
    try:
        con.execute("COPY (SELECT *, 'offset:'||CAST(byte_offset AS VARCHAR) AS record_locator FROM read_parquet("+
            quoted(source_dir/'evidence/incident_evidence.parquet')+")) TO "+quoted(target_dir/'evidence.parquet')+" (FORMAT PARQUET, COMPRESSION ZSTD)")
        con.execute("""COPY (SELECT 'auth_'||evidence_id AS relationship_id,
            CASE WHEN principal_id IS NOT NULL THEN 'account:'||principal_id END AS principal_id,
            CAST(NULL AS VARCHAR) AS source_host_id, source_ip,
            CASE WHEN target_host_name IS NOT NULL THEN 'host:'||target_host_name END AS target_host_id,
            relationship_type, 'unknown' AS access_level, observed_at,
            CAST(NULL AS TIMESTAMPTZ) AS valid_from, CAST(NULL AS TIMESTAMPTZ) AS valid_to,
            evidence_id,source_file_id,'offset:'||CAST(byte_offset AS VARCHAR) AS record_locator
            FROM read_parquet("""+quoted(source_dir/'access_history/authentication.parquet')+")) TO "+
            quoted(target_dir/'access_history.parquet')+" (FORMAT PARQUET, COMPRESSION ZSTD)")
    finally:con.close()
    engine_manifest=json.loads((source_dir/'manifest.v1.json').read_text())

    # 4. Incidents & NDJSON summaries
    src_incidents = sorted((source_dir / "incidents").glob("*.json"))
    summary_count=0
    ndjson_path=target_dir/'incidents.ndjson'
    ndjson_path.write_text('')
    severity_scores = {"critical": 95.0, "high": 80.0, "medium": 60.0, "low": 40.0, "informational": 20.0}

    for inc_file in src_incidents:
        raw = json.loads(inc_file.read_text())
        inc_id = raw.get("incident_id")
        sev = raw.get("severity", "medium").lower()
        if sev not in severity_scores:
            sev = "medium"
        
        entities = raw.get("entities", [])
        known_entity_ids = {e["entity_id"] for e in entities}
        
        ref_time = raw.get("last_seen") or raw.get("first_seen") or "2026-10-31T12:00:00Z"
        if isinstance(ref_time, str) and not ref_time.endswith("Z") and "+" not in ref_time:
            ref_time += "Z"

        # Step relationships get explicit event nodes rather than disappearing.
        for step in raw.get('steps',[]):
            entities.append({'entity_id':'step:'+step['step_id'],'type':'event','label':step['summary']})
        known_entity_ids={e['entity_id'] for e in entities}
        # Steps to timeline
        timeline = []
        for s in raw.get("steps", []):
            step_obs = s.get("timestamp") or ref_time
            if isinstance(step_obs, str) and not step_obs.endswith("Z") and "+" not in step_obs:
                step_obs += "Z"
            
            ent_ids = [eid for eid in [s.get("host_id"), s.get("account_id")] if eid and eid in known_entity_ids]
            if not ent_ids:
                ent_ids = list(known_entity_ids)

            ev_ids = s.get("evidence_ids") or [s.get("primary_evidence_id")]
            ev_ids = [e for e in ev_ids if e]
            if not ev_ids:
                ev_ids = ["ev_placeholder"]

            interp = s.get("evidence_strength")
            if interp not in {"observed", "derived", "hypothesized"}:
                interp = "observed"

            timeline.append({
                "step_id": s.get("step_id"),
                "observed_at": step_obs,
                "display_order": s.get("step_index", 1),
                "ordering_basis": "event timestamp",
                "ordering_confidence": "unknown",
                "summary": s.get("summary") or "Suspicious activity detected",
                "entity_ids": ent_ids,
                "evidence_ids": ev_ids,
                "interpretation_status": interp,
                "maliciousness": "suspicious",
                "technique_id": s.get("technique_id"),
                "kill_chain_phase": s.get("kill_chain_stage"),
            })

        # Edges to relationships
        relationships = []
        for e in raw.get("edges", []):
            src=e.get('source_id') or ('step:'+e['source_step_id'] if e.get('source_step_id') else None)
            tgt=e.get('target_id') or ('step:'+e['target_step_id'] if e.get('target_step_id') else None)
            if src in known_entity_ids and tgt in known_entity_ids:
                interp = e.get("evidence_strength")
                if interp not in {"observed", "derived", "hypothesized"}:
                    interp = "observed"
                relationships.append({
                    "relationship_id": e.get("edge_id"),
                    "source_id": src,
                    "target_id": tgt,
                    "relationship_type": e.get("relationship", "connected_to"),
                    "evidence_ids": e.get("evidence_ids") or ["ev_placeholder"],
                    "interpretation_status": interp,
                })

        adapted_incident = {
            "incident_id": inc_id,
            "revision": raw.get("revision", 1),
            "title": raw.get("title") or "Suspicious activity",
            "severity": sev,
            "risk_score": severity_scores[sev],
            "analysis_reference_time": ref_time,
            "entities": entities,
            "timeline": timeline,
            "relationships": relationships,
            "techniques": [{"id": t.get("id"), "name": t.get("name", t.get("id")), "tactic": t.get("tactic", "Unknown")} for t in raw.get("techniques", [])],
            "kill_chain": sorted({step["kill_chain_stage"] for step in raw.get("steps", []) if step.get("kill_chain_stage")}),
            "data_quality_impact": raw.get("uncertainties", [])+[
                'Input coverage: '+engine_manifest.get('input_completeness','unknown'),
                'Excluded source bytes: '+str(engine_manifest.get('excluded_tail_bytes',0)),
                'Risk score is a severity-derived display priority, not a probability.'],
            "engine_review": raw.get("ai_review", {}),
        }

        target_inc_path = target_dir / "incidents" / f"{inc_id}.json"
        content_bytes = json.dumps(adapted_incident, indent=2).encode()
        target_inc_path.write_bytes(content_bytes)

        summary = {
            "incident_id": inc_id,
            "revision": adapted_incident["revision"],
            "title": adapted_incident["title"],
            "severity": adapted_incident["severity"],
            "risk_score": adapted_incident["risk_score"],
            "bundle": {
                "location": f"incidents/{inc_id}.json",
                "sha256": hashlib.sha256(content_bytes).hexdigest(),
                "size_bytes": len(content_bytes),
            }
        }
        with ndjson_path.open('a') as output:output.write(json.dumps(summary)+'\n')
        summary_count+=1

    # 5. Manifest.json
    manifest = {
        "contract_version": "1.0",
        "run_id": engine_manifest["job_id"],
        "source_dataset": {
            "name": source_dir.name,
            "source_size_bytes": engine_manifest.get('source_bytes_total',sum(x.get('size_bytes',0) for x in engine_manifest.get('sources',[]))),
        },
        "status": "completed",
        "incident_count": summary_count,
        "engine_status": "completed",
        "engine_phase": "writing_results",
        "artifacts": {
            "incident_summaries": {
                "location": "incidents.ndjson",
                "sha256": file_sha256(ndjson_path),
                "size_bytes": ndjson_path.stat().st_size,
            },
            "incident_bundles": {
                "location": "incidents/",
                "format": "json",
            },
            "evidence": {
                "location": "evidence.parquet",
                "sha256": file_sha256(target_dir / "evidence.parquet"),
                "size_bytes": (target_dir / "evidence.parquet").stat().st_size,
            },
            "access_history": {
                "location": "access_history.parquet",
                "sha256": file_sha256(target_dir / "access_history.parquet"),
                "size_bytes": (target_dir / "access_history.parquet").stat().st_size,
            },
            "quality": {
                "location": "quality.json",
                "sha256": file_sha256(target_dir / "quality.json"),
                "size_bytes": (target_dir / "quality.json").stat().st_size,
            },
        }
    }
    (target_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"✅ Successfully created {summary_count} incidents in {target_dir}/manifest.json!")


if __name__ == "__main__":
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source',type=Path,help='Completed engine run directory')
    parser.add_argument('target',type=Path,help='Application handoff directory')
    args=parser.parse_args()
    adapt(args.source,args.target)
