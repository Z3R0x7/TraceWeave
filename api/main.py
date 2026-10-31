import json
import threading
import time
from contextlib import asynccontextmanager
from functools import lru_cache
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel

from api.config import Settings
from api.contracts import Incident
from api.imports import Importer, read_json
from api.investigation import evidence, ordered_path, reachability
from api.reports import Provider, cache_key, generate, html_report, markdown, package
from api.storage import Store


class LocalImport(BaseModel):
    manifest_path: str


class RemoteImport(BaseModel):
    manifest_url: str


@lru_cache(maxsize=32)
def load_incident(path: str, modified_ns: int, limit: int):
    return Incident.model_validate(read_json(Path(path), limit))


def create_app(settings: Settings | None = None):
    settings = settings or Settings()
    settings.data_root = settings.data_root.resolve()
    settings.import_root = settings.import_root.resolve()
    store = Store(settings.data_root / "app.sqlite")
    importer = Importer(settings, store)
    lock = threading.Lock()

    @asynccontextmanager
    async def lifespan(app):
        with store.connect() as db:
            db.execute("UPDATE imports SET status='failed',error='Application restarted' "
                       "WHERE status IN ('queued','running')")
        yield

    app = FastAPI(title="Attack Investigation", version="1.0", lifespan=lifespan)
    app.state.store, app.state.settings = store, settings

    def run_record(run_id):
        with store.connect() as db:
            row = db.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Run not found")
        return dict(row)

    def incident_record(run_id, incident_id):
        with store.connect() as db:
            row = db.execute("SELECT bundle_path FROM incidents WHERE run_id=? AND incident_id=?",
                             (run_id, incident_id)).fetchone()
        if not row:
            raise HTTPException(404, "Incident not found")
        path = Path(row[0])
        return load_incident(str(path), path.stat().st_mtime_ns, settings.max_json_bytes)

    def start(source, remote, background):
        if not lock.acquire(blocking=False):
            raise HTTPException(409, "An import is already running")
        identifier = importer.create()
        def work():
            try:
                importer.run(identifier, source, remote)
            finally:
                lock.release()
        background.add_task(work)
        return {"import_id": identifier, "status": "queued"}

    @app.get("/health")
    def health():
        return {"status": "ok", "ai_provider": settings.ai_provider,
                "ai_model_configured": bool(settings.ai_model)}

    @app.post("/api/v1/ai/health")
    def ai_health():
        try:
            response = Provider(settings).request('Return JSON {"status":"ready"}.')
            if json.loads(response).get("status") != "ready":
                raise ValueError("Unexpected provider health response")
            return {"status": "verified", "provider": settings.ai_provider}
        except Exception:
            return {"status": "unavailable", "provider": settings.ai_provider}

    @app.post("/api/v1/imports/local", status_code=202)
    def local(body: LocalImport, background: BackgroundTasks):
        return start(body.manifest_path, False, background)

    @app.post("/api/v1/imports/remote", status_code=202)
    def remote(body: RemoteImport, background: BackgroundTasks):
        return start(body.manifest_url, True, background)

    @app.get("/api/v1/imports/{import_id}")
    def import_status(import_id: str):
        with store.connect() as db:
            row = db.execute("SELECT * FROM imports WHERE import_id=?", (import_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Import not found")
        return dict(row)

    @app.get("/api/v1/runs")
    def runs():
        with store.connect() as db:
            rows = db.execute("SELECT * FROM runs ORDER BY imported_at DESC LIMIT 100").fetchall()
        result = []
        for row in rows:
            manifest = json.loads(row["manifest"])
            manifest.pop("artifacts", None)  # Presigned URLs must stay inside the backend.
            result.append({"manifest": manifest, "imported_at": row["imported_at"]})
        return result

    @app.get("/api/v1/runs/{run_id}/quality")
    def quality(run_id: str):
        directory = Path(run_record(run_id)["directory"])
        return {"scope": "dataset-wide", "metrics": read_json(
            directory / "quality", settings.max_json_bytes
        )}

    @app.get("/api/v1/runs/{run_id}/incidents")
    def incidents(run_id: str, limit: int = Query(50, ge=1, le=100),
                  offset: int = Query(0, ge=0), severity: str | None = None,
                  min_risk: float = Query(0, ge=0, le=100),
                  host: str | None = None, account: str | None = None,
                  technique: str | None = None):
        run_record(run_id)
        clauses = ["run_id=?", "json_extract(summary,'$.risk_score')>=?"]
        params: list = [run_id, min_risk]
        if severity:
            clauses.append("json_extract(summary,'$.severity')=?")
            params.append(severity)
        for kind, value in [("host", host), ("account", account), ("technique", technique)]:
            if value:
                clauses.append("EXISTS (SELECT 1 FROM incident_filters f WHERE "
                               "f.run_id=incidents.run_id AND f.incident_id=incidents.incident_id "
                               "AND f.kind=? AND f.value=?)")
                params += [kind, value]
        with store.connect() as db:
            total = db.execute("SELECT count(*) FROM incidents WHERE " +
                               " AND ".join(clauses), params).fetchone()[0]
            rows = db.execute("SELECT summary FROM incidents WHERE " +
                              " AND ".join(clauses) +
                              " ORDER BY json_extract(summary,'$.risk_score') DESC,incident_id "
                              "LIMIT ? OFFSET ?", params + [limit, offset])
            result = []
            for row in rows:
                summary = json.loads(row["summary"])
                summary.pop("bundle", None)
                result.append(summary)
        return {"items": result, "total": total, "limit": limit, "offset": offset}

    @app.get("/api/v1/runs/{run_id}/incidents/{incident_id}")
    def detail(run_id: str, incident_id: str):
        return incident_record(run_id, incident_id)

    @app.get("/api/v1/runs/{run_id}/incidents/{incident_id}/path")
    def path(run_id: str, incident_id: str):
        return ordered_path(incident_record(run_id, incident_id))

    @app.get("/api/v1/runs/{run_id}/incidents/{incident_id}/evidence")
    def records(run_id: str, incident_id: str, limit: int = Query(100, ge=1, le=100),
                offset: int = Query(0, ge=0), evidence_id: str | None = None):
        incident_record(run_id, incident_id)
        return {"items": evidence(Path(run_record(run_id)["directory"]), incident_id,
                                  limit, offset, [evidence_id] if evidence_id else None),
                "offset": offset, "limit": limit}

    @app.get("/api/v1/runs/{run_id}/incidents/{incident_id}/reachability")
    def next_targets(run_id: str, incident_id: str):
        return reachability(Path(run_record(run_id)["directory"]),
                            incident_record(run_id, incident_id))

    def report(run_id, incident_id):
        incident = incident_record(run_id, incident_id)
        directory = Path(run_record(run_id)["directory"])
        sampled_ids = list(dict.fromkeys(e for step in incident.timeline
                                         for e in step.evidence_ids[:1]))[:30]
        payload = package(json.loads(incident.model_dump_json()), ordered_path(incident),
                          evidence(directory, incident_id, 30, evidence_ids=sampled_ids),
                          reachability(directory, incident), quality(run_id))
        with store.connect() as db:
            cached = db.execute("SELECT report FROM reports WHERE cache_key=?",
                                (cache_key(settings, payload),)).fetchone()
            if cached:
                value = json.loads(cached[0])
                if (settings.ai_provider == "disabled" or value["source"] == settings.ai_provider
                        or time.time() - value.get("cached_at", 0) < 60):
                    return value
        result = generate(settings, payload)
        result["cached_at"] = time.time()
        with store.connect() as db:
            db.execute("INSERT OR REPLACE INTO reports VALUES (?,?)",
                       (result["cache_key"], json.dumps(result, default=str)))
        return result

    @app.post("/api/v1/runs/{run_id}/incidents/{incident_id}/report")
    def create_report(run_id: str, incident_id: str):
        return report(run_id, incident_id)

    @app.get("/api/v1/runs/{run_id}/incidents/{incident_id}/report")
    def get_report(run_id: str, incident_id: str):
        return report(run_id, incident_id)

    @app.get("/api/v1/runs/{run_id}/incidents/{incident_id}/report.md",
             response_class=PlainTextResponse)
    def md(run_id: str, incident_id: str):
        return markdown(report(run_id, incident_id))

    @app.get("/api/v1/runs/{run_id}/incidents/{incident_id}/report.html",
             response_class=HTMLResponse)
    def html(run_id: str, incident_id: str):
        return html_report(report(run_id, incident_id))

    return app


app = create_app()
