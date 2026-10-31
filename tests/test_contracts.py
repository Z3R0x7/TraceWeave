import pytest
from pydantic import ValidationError

from api.contracts import Manifest


def manifest():
    return {
        "contract_version": "1.0",
        "run_id": "empty_run",
        "source_dataset": {"name": "benign", "source_size_bytes": 0},
        "status": "completed",
        "incident_count": 0,
        "artifacts": {
            name: {"location": name, "sha256": "a" * 64}
            for name in [
                "incident_summaries", "incident_bundles", "evidence", "access_history", "quality"
            ]
        },
    }


def test_empty_result_is_valid():
    assert Manifest.model_validate(manifest()).incident_count == 0


def test_missing_access_history_is_rejected():
    value = manifest()
    del value["artifacts"]["access_history"]
    with pytest.raises(ValidationError, match="access_history"):
        Manifest.model_validate(value)


def test_unsupported_version_is_rejected():
    value = manifest()
    value["contract_version"] = "2.0"
    with pytest.raises(ValidationError):
        Manifest.model_validate(value)


def test_engine_metadata_and_kill_chain():
    from datetime import datetime, timezone

    from api.contracts import Entity, Incident, Step

    value = manifest()
    value["engine_status"] = "completed"
    value["engine_phase"] = "writing_results"
    m = Manifest.model_validate(value)
    assert m.engine_status == "completed"
    assert m.engine_phase == "writing_results"

    inc = Incident(
        incident_id="inc_kc",
        revision=1,
        title="Incident with kill chain",
        severity="medium",
        risk_score=50.0,
        analysis_reference_time=datetime(2026, 10, 31, 12, 0, tzinfo=timezone.utc),
        entities=[Entity(entity_id="host:srv1", type="host", label="srv1")],
        timeline=[
            Step(
                step_id="step_1",
                observed_at=datetime(2026, 10, 31, 10, 0, tzinfo=timezone.utc),
                display_order=1,
                ordering_basis="timestamp",
                ordering_confidence="high",
                summary="Initial access",
                entity_ids=["host:srv1"],
                evidence_ids=["ev_1"],
                interpretation_status="observed",
                kill_chain_phase="initial-access",
            )
        ],
        relationships=[],
        kill_chain=["initial-access"],
    )
    assert inc.kill_chain == ["initial-access"]
    assert inc.timeline[0].kill_chain_phase == "initial-access"
