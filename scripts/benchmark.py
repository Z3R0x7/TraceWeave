"""Measure a supplied handoff, or an explicitly synthetic representative artifact set."""

import argparse
import hashlib
import json
import resource
import tempfile
import time
from pathlib import Path

import duckdb
from fastapi.testclient import TestClient

from api.config import Settings
from api.imports import parquet
from api.main import create_app
from scripts.demo import create_demo


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--rows", type=int, default=250000)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        manifest = args.manifest.resolve() if args.manifest else create_demo(root / "input")
        if not args.manifest:
            with duckdb.connect() as db:
                target = str(manifest.parent / "evidence.parquet").replace("'", "''")
                db.execute(f"COPY (SELECT 'inc_01' incident_id, CASE WHEN i=0 THEN 'evt_01' "
                           "ELSE 'evt_' || i END evidence_id, "
                           "'edr_01' source_file_id, 'line:' || i record_locator, "
                           "md5(i::VARCHAR) evidence_excerpt FROM range(?) t(i) "
                           f"ORDER BY evidence_id) TO '{target}' (FORMAT PARQUET, ROW_GROUP_SIZE 10000)",
                           [args.rows])
            value = json.loads(manifest.read_text())
            path = manifest.parent / "evidence.parquet"
            with path.open("rb") as handle:
                digest = hashlib.file_digest(handle, "sha256").hexdigest()
            value["artifacts"]["evidence"].update(sha256=digest, size_bytes=path.stat().st_size)
            manifest.write_text(json.dumps(value))
        settings = Settings(import_root=manifest.parent, data_root=root / "app", ai_provider="disabled")
        application = create_app(settings)
        with TestClient(application) as client:
            started = time.perf_counter()
            job = client.post("/api/v1/imports/local", json={"manifest_path": str(manifest)}).json()
            state = client.get("/api/v1/imports/" + job["import_id"]).json()
            elapsed = time.perf_counter() - started
            if state["status"] != "completed":
                raise RuntimeError(state)
            run = client.get("/api/v1/runs").json()[0]["manifest"]
            incidents = client.get(f"/api/v1/runs/{run['run_id']}/incidents").json()["items"]
            result = {"synthetic": not bool(args.manifest), "import_seconds": elapsed,
                      "source_size_metadata_bytes": run["source_dataset"]["source_size_bytes"]}
            if incidents:
                route = f"/api/v1/runs/{run['run_id']}/incidents/{incidents[0]['incident_id']}/path"
                durations = []
                for _ in range(11):
                    start = time.perf_counter()
                    assert client.get(route).status_code == 200
                    durations.append((time.perf_counter() - start) * 1000)
                result.update(cold_path_ms=durations[0], warm_path_max_ms=max(durations[1:]))
                with application.state.store.connect() as metadata:
                    directory = Path(metadata.execute("SELECT directory FROM runs").fetchone()[0])
                with duckdb.connect() as db:
                    profile = root / "query-profile.json"
                    db.execute("PRAGMA enable_profiling='json'")
                    db.execute("SET profiling_output=?", [str(profile)])
                    db.execute(f"SELECT evidence_id,evidence_excerpt FROM {parquet(directory / 'evidence')} "
                               "WHERE incident_id=? ORDER BY evidence_id LIMIT 100",
                               [incidents[0]["incident_id"]]).fetchall()
                query_profile = json.loads(profile.read_text())
                result["query_profile"] = query_profile
            # macOS reports ru_maxrss in bytes, Linux in KiB.
            import sys
            rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            result["process_peak_rss_bytes"] = rss if sys.platform == "darwin" else rss * 1024
            print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
