import json

import pyarrow.parquet as pq
import pytest

from api.contracts import Incident
from api.investigation import ordered_path, reachability
from scripts.demo import create_demo


@pytest.mark.parametrize("change,expected", [
    ({}, 1),
    ({"observed_at": "2026-11-01T00:00:00Z"}, 0),
    ({"relationship_type": "network_connection"}, 0),
    ({"target_host_id": "host:HR-07"}, 0),
    ({"principal_id": "account:other", "valid_to": "2026-10-29T00:00:00Z"}, 0),
    ({"relationship_type": "admin_access", "valid_to": "2026-10-31T11:00:00Z"}, 0),
    ({"relationship_type": "admin_access"}, 1),
])
def test_access_conditions(tmp_path, change, expected):
    create_demo(tmp_path)
    rows = pq.read_table(tmp_path / "access.parquet").to_pylist()
    rows[0].update(change)
    create_demo(tmp_path, access_rows=rows)
    (tmp_path / "access_history").write_bytes((tmp_path / "access.parquet").read_bytes())
    incident = Incident.model_validate_json((tmp_path / "incidents/inc_01.json").read_text())
    result = reachability(tmp_path, incident)
    assert len(result["candidates"]) == expected
    if not expected:
        assert "No evidence-supported" in result["message"]


def test_timestamp_ties_do_not_become_causality(tmp_path):
    create_demo(tmp_path)
    value = json.loads((tmp_path / "incidents/inc_01.json").read_text())
    value["timeline"].append(dict(value["timeline"][0], step_id="step_02", display_order=0,
                                   ordering_confidence="unknown"))
    result = ordered_path(Incident.model_validate(value))
    assert result["timeline"][0]["step_id"] == "step_02"
    assert result["timeline"][0]["observed_at"] == result["timeline"][1]["observed_at"]
    assert result["timeline"][0]["ordering_confidence"] == "unknown"


def test_benign_account_does_not_seed_lookahead(tmp_path):
    create_demo(tmp_path)
    (tmp_path / "access_history").write_bytes((tmp_path / "access.parquet").read_bytes())
    incident = Incident.model_validate_json((tmp_path / "incidents/inc_01.json").read_text())
    incident.timeline[0].maliciousness = "benign"
    assert reachability(tmp_path, incident)["candidates"] == []
