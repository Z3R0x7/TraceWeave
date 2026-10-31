import json
from datetime import datetime
from pathlib import Path

import duckdb

from api.contracts import Incident
from api.imports import parquet


def evidence(directory: Path, incident_id: str, limit=100, offset=0, evidence_ids=None):
    with duckdb.connect(":memory:") as db:
        db.execute("SET memory_limit='512MB'")
        condition = " AND evidence_id IN (SELECT unnest(?))" if evidence_ids else ""
        params = [incident_id] + ([evidence_ids] if evidence_ids else []) + [limit, offset]
        cursor = db.execute(
            f"SELECT * FROM {parquet(directory / 'evidence')} WHERE incident_id=? "
            + condition + " ORDER BY evidence_id LIMIT ? OFFSET ?", params
        )
        columns = [c[0] for c in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]


def reachability(directory: Path, incident: Incident):
    implicated = {entity for step in incident.timeline
                  if step.maliciousness != "benign" and step.interpretation_status != "hypothesized"
                  for entity in step.entity_ids}
    accounts = [e.entity_id for e in incident.entities
                if e.type == "account" and e.entity_id in implicated]
    hosts = [e.entity_id for e in incident.entities if e.type == "host"]
    source_hosts = [host for host in hosts if host in implicated]
    reference = incident.analysis_reference_time
    candidates = {}
    with duckdb.connect(":memory:") as db:
        db.execute("SET memory_limit='512MB'")
        cursor = db.execute(
            f"SELECT * FROM {parquet(directory / 'access_history')} "
            "WHERE principal_id IN (SELECT unnest(?)) OR source_host_id IN (SELECT unnest(?))",
            [accounts, source_hosts]
        )
        columns = [c[0] for c in cursor.description]
        while rows := cursor.fetchmany(1000):
            for row in rows:
                item = dict(zip(columns, row))
                kind = item["relationship_type"]
                if kind not in {"permission", "admin_access", "allowed_network",
                                "successful_remote_auth", "observed_successful_authentication"}:
                    continue
                target = item["target_host_id"]
                if not target or target in hosts:
                    continue
                def timestamp(value):
                    if isinstance(value, datetime):
                        return value if value.tzinfo else None
                    if not value or str(value).lower() in ("none", "null", ""):
                        return None
                    try:
                        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
                        return result if result.tzinfo else None
                    except ValueError:
                        return None
                observed = timestamp(item["observed_at"])
                start, end = timestamp(item["valid_from"]), timestamp(item["valid_to"])
                if not observed or observed >= reference:
                    continue
                explicit = kind in {"permission", "admin_access", "allowed_network"}
                if explicit and (not start or not end or not start <= reference <= end):
                    continue
                # Host attribution must be time-qualified, even for historical logons.
                if item["principal_id"] not in accounts:
                    if not item.get("source_host_id") or item.get("source_host_id") == "unknown":
                        continue
                    if start and end and not (start <= observed <= end):
                        continue
                strength = "high" if explicit else "medium"
                score = (5 if explicit else 3) - int((reference - observed).days > 30)
                reason_text = "Explicit access valid at reference time" if explicit else "Historical authentication observation prior to reference time"
                assumptions_list = ["Evidence strength is not a probability of compromise."] + ([] if explicit else [
                    "Historical authentication observation is not granted permission or verified remote reachability."
                ])
                candidate = candidates.setdefault(target, {
                    "target_id": target, "evidence_strength": strength, "score": score,
                    "relationship": kind, "evidence_ids": [], "support": [],
                    "assumptions": assumptions_list,
                    "reason": reason_text
                })
                if score > candidate["score"]:
                    candidate.update(score=score, evidence_strength=strength, relationship=kind,
                                     reason=reason_text, assumptions=assumptions_list)
                if len(candidate["support"]) < 10:
                    candidate["evidence_ids"].append(item["evidence_id"])
                    candidate["support"].append(item)
                if len(candidates) > 10:
                    worst = sorted(candidates, key=lambda k: (-candidates[k]["score"], k))[-1]
                    del candidates[worst]
    values = sorted(candidates.values(), key=lambda c: (-c["score"], c["target_id"]))[:10]
    return {"candidates": values, "reference_time": reference.isoformat(), "message": (
        "Candidates reflect supplied access evidence and stated assumptions." if values else
        "No evidence-supported next target can be determined from the supplied access history."
    )}


def ordered_path(incident: Incident):
    value = json.loads(incident.model_dump_json())
    order = {s.step_id: (s.observed_at is None,
                         s.observed_at.timestamp() if s.observed_at else 0, s.display_order)
             for s in incident.timeline}
    value["timeline"] = sorted(value["timeline"], key=lambda s: order[s["step_id"]])
    return {k: value[k] for k in ["entities", "timeline", "relationships", "techniques"]}
