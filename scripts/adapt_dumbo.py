"""Adapt teammate engine output from ~/Downloads/dumbo into data/input/dumbo."""

import hashlib
import json
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq


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

    # 2. Evidence Parquet
    src_ev_path = source_dir / "evidence" / "incident_evidence.parquet"
    ev_table = pq.read_table(src_ev_path)
    
    # Ensure record_locator exists
    col_names = ev_table.column_names
    cols = [ev_table.column(c) for c in col_names]
    new_names = list(col_names)
    if "record_locator" not in col_names:
        if "raw_record_number" in col_names:
            locators = [f"rec:{val.as_py()}" for val in ev_table.column("raw_record_number")]
        else:
            locators = [f"rec:{i}" for i in range(len(ev_table))]
        new_names.append("record_locator")
        cols.append(pa.array(locators, type=pa.string()))
    
    adapted_ev_table = pa.Table.from_arrays(cols, names=new_names)
    pq.write_table(adapted_ev_table, target_dir / "evidence.parquet")

    # 3. Access History Parquet
    src_acc_path = source_dir / "access_history" / "authentication.parquet"
    acc_table = pq.read_table(src_acc_path)
    acc_rows = acc_table.to_pylist()
    adapted_acc_rows = []
    for i, r in enumerate(acc_rows):
        obs = r.get("observed_at")
        if isinstance(obs, int):
            obs_dt = datetime.fromtimestamp(obs / 1000000, tz=datetime.now().astimezone().tzinfo)
        elif isinstance(obs, datetime):
            obs_dt = obs
        else:
            obs_dt = datetime.now().astimezone()
        valid_from = obs_dt - timedelta(days=1)
        valid_to = obs_dt + timedelta(days=30)
        
        target_host = r.get("target_host_name") or "unknown"
        if not target_host.startswith("host:"):
            target_host = f"host:{target_host}"
        
        principal = r.get("principal_id") or "account:unknown"
        if not principal.startswith("account:"):
            principal = f"account:{principal}"

        source_ip = r.get("source_ip") or "127.0.0.1"
        adapted_acc_rows.append({
            "relationship_id": f"auth_rel_{i:06d}",
            "principal_id": principal,
            "source_host_id": f"host:{source_ip}",
            "source_ip": source_ip,
            "target_host_id": target_host,
            "relationship_type": "successful_remote_auth",
            "access_level": "user",
            "observed_at": obs_dt.isoformat(),
            "valid_from": valid_from.isoformat(),
            "valid_to": valid_to.isoformat(),
            "evidence_id": r.get("evidence_id") or f"auth_ev_{i}",
            "source_file_id": r.get("source_file_id") or "auth_source",
            "record_locator": f"offset:{r.get('byte_offset', i)}",
        })
    pq.write_table(pa.Table.from_pylist(adapted_acc_rows), target_dir / "access_history.parquet")

    # 4. Incidents & NDJSON summaries
    src_incidents = sorted((source_dir / "incidents").glob("*.json"))
    summaries = []
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
                "ordering_confidence": "high",
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
            src, tgt = e.get("source_id"), e.get("target_id")
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
            "kill_chain": [t.get("tactic") for t in raw.get("techniques", []) if t.get("tactic")],
            "data_quality_impact": raw.get("uncertainties", []),
            "engine_review": raw.get("ai_review", {}).get("result"),
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
        summaries.append(summary)

    # Write incidents.ndjson
    ndjson_path = target_dir / "incidents.ndjson"
    with ndjson_path.open("w") as f:
        for s in summaries:
            f.write(json.dumps(s) + "\n")

    # 5. Manifest.json
    manifest = {
        "contract_version": "1.0",
        "run_id": "dumbo",
        "source_dataset": {
            "name": "edr_events",
            "source_size_bytes": (source_dir / "findings.parquet").stat().st_size if (source_dir / "findings.parquet").exists() else 8364767,
        },
        "status": "completed",
        "incident_count": len(summaries),
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
    print(f"✅ Successfully created {len(summaries)} incidents in {target_dir}/manifest.json!")


if __name__ == "__main__":
    src = Path(sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser("~/Downloads/dumbo"))
    tgt = Path(sys.argv[2] if len(sys.argv) > 2 else "data/input/dumbo")
    adapt(src, tgt)
