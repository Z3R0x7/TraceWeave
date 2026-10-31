import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.config import Settings
from api.main import create_app
from scripts.demo import create_demo


@pytest.fixture
def setup(tmp_path):
    source = tmp_path / "input"
    manifest = create_demo(source)
    settings = Settings(import_root=source, data_root=tmp_path / "app", ai_provider="disabled")
    with TestClient(create_app(settings)) as client:
        yield client, manifest, settings


def perform(client, manifest):
    response = client.post("/api/v1/imports/local", json={"manifest_path": str(manifest)})
    assert response.status_code == 202
    return client.get("/api/v1/imports/" + response.json()["import_id"]).json()


def test_complete_investigation(setup):
    client, manifest, settings = setup
    state = perform(client, manifest)
    assert state["status"] == "completed"
    assert state["processed_bytes"] == state["total_bytes"]
    base = "/api/v1/runs/demo_run/incidents/inc_01"
    assert client.get("/api/v1/runs/demo_run/incidents").json()["total"] == 1
    assert client.get(base + "/path").json()["timeline"][0]["evidence_ids"] == ["evt_01"]
    assert client.get(base + "/evidence").json()["items"][0]["source_file_id"] == "edr_01"
    candidate = client.get(base + "/reachability").json()["candidates"][0]
    assert candidate["evidence_ids"] == ["auth_99"]
    assert candidate["target_id"] == "host:FS-02"
    assert client.post(base + "/report").json()["source"] == "deterministic"
    assert client.get(base + "/report").json()["source"] == "deterministic"
    assert client.get(base + "/report.html").status_code == 200
    assert client.get(base + "/report.md").status_code == 200
    assert client.get("/api/v1/runs/demo_run/quality").json()["scope"] == "dataset-wide"
    assert client.get("/api/v1/runs/demo_run/incidents?host=nope").json()["total"] == 0
    with TestClient(create_app(settings)) as restarted:
        assert len(restarted.get("/api/v1/runs").json()) == 1


def test_zero_incidents(setup):
    client, manifest, _ = setup
    create_demo(manifest.parent, count=0)
    assert perform(client, manifest)["status"] == "completed"
    assert client.get("/api/v1/runs/demo_run/incidents").json()["items"] == []


def test_checksum_failure_is_not_published(setup):
    client, manifest, _ = setup
    (manifest.parent / "quality.json").write_text("{}")
    result = perform(client, manifest)
    assert result["status"] == "failed"
    assert client.get("/api/v1/runs").json() == []


def test_path_escape(setup, tmp_path):
    client, _, _ = setup
    outside = tmp_path / "outside.json"
    outside.write_text("{}")
    assert perform(client, outside)["status"] == "failed"


def test_missing_evidence(setup):
    client, manifest, _ = setup
    data = json.loads(manifest.read_text())
    bundle = manifest.parent / "incidents/inc_01.json"
    value = json.loads(bundle.read_text())
    value["timeline"][0]["evidence_ids"] = ["missing"]
    bundle.write_text(json.dumps(value))
    import hashlib
    summary_path = manifest.parent / "incidents.ndjson"
    summary = json.loads(summary_path.read_text())
    summary["bundle"]["sha256"] = hashlib.sha256(bundle.read_bytes()).hexdigest()
    summary["bundle"]["size_bytes"] = bundle.stat().st_size
    summary_path.write_text(json.dumps(summary) + "\n")
    data["artifacts"]["incident_summaries"]["sha256"] = hashlib.sha256(
        summary_path.read_bytes()).hexdigest()
    data["artifacts"]["incident_summaries"]["size_bytes"] = summary_path.stat().st_size
    manifest.write_text(json.dumps(data))
    assert perform(client, manifest)["status"] == "failed"


def test_remote_unapproved_host(setup):
    client, _, _ = setup
    result = client.post("/api/v1/imports/remote", json={
        "manifest_url": "https://unapproved.example/manifest.json?secret=hidden"
    }).json()
    state = client.get("/api/v1/imports/" + result["import_id"]).json()
    assert state["status"] == "failed"
    assert "hidden" not in json.dumps(state)


def update_artifact(manifest, name, path):
    import hashlib
    data = json.loads(manifest.read_text())
    data["artifacts"][name] = {
        "location": str(path.relative_to(manifest.parent)),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "size_bytes": path.stat().st_size
    }
    manifest.write_text(json.dumps(data))


def test_external_engine_review_reused(setup):
    client, manifest, _ = setup
    review = manifest.parent / "review.ndjson"
    review.write_text(json.dumps({"incident_id": "inc_01", "revision": 1, "review": {
        "version": "1", "assessment": "Suspicious; requires investigation"
    }}) + "\n")
    update_artifact(manifest, "engine_review", review)
    assert perform(client, manifest)["status"] == "completed"
    assert client.get("/api/v1/runs/demo_run/incidents/inc_01").json()["engine_review"]["version"] == "1"


def test_revisions_and_rollback(setup):
    import hashlib
    client, manifest, _ = setup
    assert perform(client, manifest)["status"] == "completed"
    assert perform(client, manifest)["status"] == "failed"
    bundle = manifest.parent / "incidents/inc_01.json"
    value = json.loads(bundle.read_text())
    value["revision"] = 2
    bundle.write_text(json.dumps(value))
    summary_path = manifest.parent / "incidents.ndjson"
    summary = json.loads(summary_path.read_text())
    summary["revision"] = 2
    summary["bundle"].update(sha256=hashlib.sha256(bundle.read_bytes()).hexdigest(),
                             size_bytes=bundle.stat().st_size)
    summary_path.write_text(json.dumps(summary) + "\n")
    update_artifact(manifest, "incident_summaries", summary_path)
    assert perform(client, manifest)["status"] == "completed"
    assert client.get("/api/v1/runs/demo_run/incidents/inc_01").json()["revision"] == 2


def test_cached_report_avoids_provider_call(setup, monkeypatch):
    client, manifest, _ = setup
    assert perform(client, manifest)["status"] == "completed"
    route = "/api/v1/runs/demo_run/incidents/inc_01/report"
    result = client.post(route).json()
    monkeypatch.setattr("api.main.generate", lambda *args: pytest.fail("Cache missed"))
    assert client.post(route).json()["cache_key"] == result["cache_key"]


def test_health_missing_ids_and_filters(setup):
    client, manifest, _ = setup
    assert client.get("/health").json()["status"] == "ok"
    assert client.post("/api/v1/ai/health").json()["status"] == "unavailable"
    assert client.get("/api/v1/imports/missing").status_code == 404
    assert client.get("/api/v1/runs/missing/incidents").status_code == 404
    perform(client, manifest)
    assert client.get("/api/v1/runs/demo_run/incidents/missing").status_code == 404
    assert client.get("/api/v1/runs/demo_run/incidents?severity=high&technique=T1059.001").json()["total"] == 1


def test_invalid_contract_shows_field_without_input(setup):
    client, manifest, _ = setup
    value = json.loads(manifest.read_text())
    value["contract_version"] = "unsupported-private-value"
    manifest.write_text(json.dumps(value))
    result = perform(client, manifest)
    assert result["status"] == "failed"
    assert "contract_version" in result["error"]
    assert "unsupported-private-value" not in result["error"]


def test_transient_ai_fallback_can_recover(setup, monkeypatch):
    import api.main as main
    client, manifest, settings = setup
    perform(client, manifest)
    settings.ai_provider, settings.ai_model = "openai", "configured"
    calls = []
    original = main.generate
    def unavailable(*args):
        raise ValueError("Unavailable")
    def counted(*args):
        calls.append(1)
        return original(*args)
    monkeypatch.setattr("api.reports.Provider.request", unavailable)
    monkeypatch.setattr(main, "generate", counted)
    route = "/api/v1/runs/demo_run/incidents/inc_01/report"
    result = client.post(route).json()
    assert result["source"] == "deterministic"
    client.post(route)
    assert len(calls) == 1
    with main.Store(settings.data_root / "app.sqlite").connect() as db:
        result["cached_at"] = 0
        db.execute("UPDATE reports SET report=? WHERE cache_key=?",
                   (json.dumps(result), result["cache_key"]))
    client.post(route)
    assert len(calls) == 2


def test_streamed_summary_collection_and_pagination(setup, monkeypatch):
    import hashlib

    import pyarrow as pa
    import pyarrow.parquet as pq
    client, manifest, _ = setup
    root = manifest.parent
    template = json.loads((root / "incidents/inc_01.json").read_text())
    rows = []
    with (root / "incidents.ndjson").open("w") as stream:
        for number in range(300):
            incident = dict(template, incident_id=f"inc_{number:04d}")
            bundle = root / "incidents" / f"{incident['incident_id']}.json"
            bundle.write_text(json.dumps(incident))
            summary = {key: incident[key] for key in [
                "incident_id", "revision", "title", "severity", "risk_score"
            ]}
            summary["bundle"] = {
                "location": str(bundle.relative_to(root)), "size_bytes": bundle.stat().st_size,
                "sha256": hashlib.sha256(bundle.read_bytes()).hexdigest()
            }
            stream.write(json.dumps(summary) + "\n")
            rows.append({"incident_id": incident["incident_id"], "evidence_id": "evt_01",
                         "source_file_id": "edr_01", "record_locator": f"line:{number}",
                         "evidence_excerpt": "Office launched PowerShell"})
    pq.write_table(pa.Table.from_pylist(rows), root / "evidence.parquet")
    value = json.loads(manifest.read_text())
    value["incident_count"] = 300
    manifest.write_text(json.dumps(value))
    update_artifact(manifest, "evidence", root / "evidence.parquet")
    update_artifact(manifest, "incident_summaries", root / "incidents.ndjson")
    original = Path.read_text
    def guard(path, *args, **kwargs):
        assert path.name != "incidents.ndjson", "Summary collection must be streamed"
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "read_text", guard)
    assert perform(client, manifest)["status"] == "completed"
    result = client.get("/api/v1/runs/demo_run/incidents?offset=250&limit=25").json()
    assert result["total"] == 300
    assert len(result["items"]) == 25
    assert result["items"][0]["incident_id"] == "inc_0250"


def test_report_remains_usable_during_slow_import(setup, monkeypatch):
    import threading
    from concurrent.futures import ThreadPoolExecutor

    from api.transfer import Transfer
    client, manifest, _ = setup
    perform(client, manifest)
    value = json.loads(manifest.read_text())
    value["run_id"] = "second_run"
    manifest.write_text(json.dumps(value))
    entered, release = threading.Event(), threading.Event()
    original = Transfer.fetch
    def slow(self, location, *args, **kwargs):
        if location.startswith("incidents/"):
            entered.set()
            assert release.wait(5)
        return original(self, location, *args, **kwargs)
    monkeypatch.setattr(Transfer, "fetch", slow)
    with ThreadPoolExecutor(max_workers=2) as pool:
        importing = pool.submit(perform, client, manifest)
        assert entered.wait(5)
        try:
            reporting = pool.submit(client.post, "/api/v1/runs/demo_run/incidents/inc_01/report")
            assert reporting.result(timeout=2).status_code == 200
        finally:
            release.set()
        assert importing.result(timeout=5)["status"] == "completed"
