import json
import shutil
import time
import uuid
from pathlib import Path

import duckdb
from pydantic import ValidationError

from api.config import Settings
from api.contracts import EngineReview, Incident, Manifest, Quality, Summary
from api.storage import Store
from api.transfer import ImportFailure, Transfer

EVIDENCE_COLUMNS = {
    "incident_id", "evidence_id", "source_file_id", "record_locator", "evidence_excerpt"
}
ACCESS_COLUMNS = {
    "relationship_id", "principal_id", "source_host_id", "source_ip", "target_host_id",
    "relationship_type", "access_level", "observed_at", "valid_from", "valid_to",
    "evidence_id", "source_file_id", "record_locator"
}


def parquet(path: Path):
    # Only internally generated paths are interpolated, and quotes are escaped.
    return "read_parquet('" + str(path).replace("'", "''") + "')"


def read_json(path: Path, limit: int):
    if path.stat().st_size > limit:
        raise ImportFailure("JSON artifact exceeds configured limit")
    with path.open() as handle:
        return json.load(handle)


class Importer:
    def __init__(self, settings: Settings, store: Store):
        self.settings, self.store = settings, store

    def create(self):
        identifier = uuid.uuid4().hex
        with self.store.connect() as db:
            db.execute("INSERT INTO imports(import_id,status,phase) VALUES (?,?,?)",
                       (identifier, "queued", "downloading"))
        return identifier

    def state(self, identifier, status, phase, error=None):
        with self.store.connect() as db:
            db.execute("UPDATE imports SET status=?,phase=?,error=? WHERE import_id=?",
                       (status, phase, error, identifier))

    def run(self, identifier: str, source: str, remote: bool):
        stage = self.settings.data_root / "staging" / identifier
        stage.mkdir(parents=True, exist_ok=False)
        promoted = None
        committed = False
        try:
            self.state(identifier, "running", "downloading")
            transferred, last_update = 0, 0.0
            def progress(size):
                nonlocal transferred, last_update
                transferred += size
                if time.monotonic() - last_update >= 0.25:
                    with self.store.connect() as db:
                        db.execute("UPDATE imports SET processed_bytes=? WHERE import_id=?",
                                   (transferred, identifier))
                    last_update = time.monotonic()
            transfer = Transfer(self.settings, source, remote, progress)
            manifest_path = stage / "manifest.json"
            transfer.fetch(source, manifest_path, limit=self.settings.max_json_bytes)
            manifest = Manifest.model_validate(read_json(
                manifest_path, self.settings.max_json_bytes
            ))
            with self.store.connect() as db:
                db.execute("UPDATE imports SET total_bytes=? WHERE import_id=?", (
                    manifest_path.stat().st_size + sum(
                        a.size_bytes or 0 for a in manifest.artifacts.values()
                    ), identifier
                ))
            for name in ["incident_summaries", "evidence", "access_history", "quality"]:
                artifact = manifest.artifacts[name]
                transfer.fetch(artifact.location, stage / name, artifact)
            if "engine_review" in manifest.artifacts:
                artifact = manifest.artifacts["engine_review"]
                if not artifact.sha256:
                    raise ImportFailure("Engine review requires a checksum when supplied")
                transfer.fetch(artifact.location, stage / "engine_review", artifact)
            self.state(identifier, "running", "validating")
            self.validate_parquet(stage)
            quality = read_json(stage / "quality", self.settings.max_json_bytes)
            Quality.model_validate(quality)
            self.state(identifier, "running", "importing")
            final = self.settings.data_root / "runs" / manifest.run_id / identifier
            final.parent.mkdir(parents=True, exist_ok=True)
            count = 0
            # Build indexes privately so downloads do not hold the application write lock.
            work = Store(stage / "index.sqlite")
            with work.connect() as db:
                db.execute("CREATE TEMP TABLE reviews(incident_id TEXT PRIMARY KEY,revision INT,review TEXT)")
                if (stage / "engine_review").exists():
                    with (stage / "engine_review").open("rb") as review_file:
                        while raw_review := review_file.readline(self.settings.max_json_bytes + 1):
                            if len(raw_review) > self.settings.max_json_bytes:
                                raise ImportFailure("Engine review record too large")
                            review = EngineReview.model_validate_json(raw_review)
                            db.execute("INSERT INTO reviews VALUES (?,?,?)", (
                                review.incident_id, review.revision, json.dumps(review.review)
                            ))
                db.execute("CREATE TEMP TABLE previous(incident_id TEXT,summary TEXT,bundle_path TEXT)")
                with self.store.connect() as current:
                    db.executemany("INSERT INTO previous VALUES (?,?,?)", current.execute(
                        "SELECT incident_id,summary,bundle_path FROM incidents WHERE run_id=?",
                        (manifest.run_id,)
                    ))
                db.execute("CREATE INDEX previous_id ON previous(incident_id)")
                previous_count = db.execute("SELECT count(*) FROM previous").fetchone()[0]
                changed = False
                db.execute("DELETE FROM incidents WHERE run_id=?", (manifest.run_id,))
                db.execute("DELETE FROM incident_filters WHERE run_id=?", (manifest.run_id,))
                with (stage / "incident_summaries").open("rb") as lines:
                    while raw := lines.readline(self.settings.max_json_bytes + 1):
                        if len(raw) > self.settings.max_json_bytes:
                            raise ImportFailure("Summary record too large")
                        summary = Summary.model_validate_json(raw)
                        bundle_path = stage / "incidents" / f"{summary.incident_id}.json"
                        if not summary.bundle.sha256:
                            raise ImportFailure("Every incident bundle requires a checksum")
                        transfer.fetch(summary.bundle.location, bundle_path, summary.bundle,
                                       self.settings.max_json_bytes)
                        incident = Incident.model_validate(read_json(
                            bundle_path, self.settings.max_json_bytes
                        ))
                        if any(getattr(incident, field) != getattr(summary, field) for field in
                               ["incident_id", "revision", "title", "severity", "risk_score"]):
                            raise ImportFailure("Summary and bundle metadata differ")
                        self.validate_evidence(stage, incident)
                        review = db.execute("SELECT revision,review FROM reviews WHERE incident_id=?",
                                            (incident.incident_id,)).fetchone()
                        if review:
                            if review[0] != incident.revision:
                                raise ImportFailure("Engine review revision mismatch")
                            external_review = json.loads(review[1])
                            if incident.engine_review and incident.engine_review != external_review:
                                raise ImportFailure("Conflicting engine reviews")
                            incident.engine_review = external_review
                            bundle_path.write_text(incident.model_dump_json())
                            db.execute("DELETE FROM reviews WHERE incident_id=?", (incident.incident_id,))
                        prior = db.execute("SELECT summary,bundle_path FROM previous WHERE incident_id=?",
                                           (incident.incident_id,)).fetchone()
                        if prior:
                            old_revision, old_path = json.loads(prior[0])["revision"], prior[1]
                            old = Incident.model_validate(read_json(Path(old_path), self.settings.max_json_bytes))
                            if incident.revision < old_revision or (
                                incident.revision == old_revision and incident != old
                            ):
                                raise ImportFailure("Changed incident must increase its revision")
                            changed |= incident.revision > old_revision
                        else:
                            changed = True
                        db.execute("INSERT INTO incidents VALUES (?,?,?,?)", (
                            manifest.run_id, summary.incident_id, summary.model_dump_json(),
                            str(final / "incidents" / bundle_path.name)
                        ))
                        filters = [(manifest.run_id, incident.incident_id, entity.type, value)
                                   for entity in incident.entities
                                   for value in {entity.entity_id, entity.label}]
                        filters += [(manifest.run_id, incident.incident_id, "technique", t["id"])
                                    for t in incident.techniques]
                        db.executemany("INSERT INTO incident_filters VALUES (?,?,?,?)", filters)
                        count += 1
                if count != manifest.incident_count:
                    raise ImportFailure("Incident count differs from manifest")
                if previous_count and not changed and count == previous_count:
                    raise ImportFailure("Unchanged run already imported")
                if db.execute("SELECT 1 FROM reviews LIMIT 1").fetchone():
                    raise ImportFailure("Engine review references unknown incident")
            self.state(identifier, "running", "indexing")
            stage.rename(final)
            promoted = final
            with self.store.connect() as db:
                db.execute("ATTACH DATABASE ? AS staged", (str(final / "index.sqlite"),))
                db.execute("DELETE FROM incidents WHERE run_id=?", (manifest.run_id,))
                db.execute("DELETE FROM incident_filters WHERE run_id=?", (manifest.run_id,))
                db.execute("INSERT INTO incidents SELECT * FROM staged.incidents")
                db.execute("INSERT INTO incident_filters SELECT * FROM staged.incident_filters")
                db.execute("INSERT OR REPLACE INTO runs(run_id,manifest,directory) VALUES (?,?,?)", (
                    manifest.run_id, manifest.model_dump_json(), str(final)
                ))
                db.execute("UPDATE imports SET processed_bytes=?,total_bytes=? WHERE import_id=?",
                           (transferred, transferred, identifier))
            committed = True
            self.state(identifier, "completed", "ready")
        except Exception as exc:
            # Do not expose URLs, remote credentials, log content or stack traces.
            message = str(exc) if isinstance(exc, ImportFailure) else type(exc).__name__
            if isinstance(exc, ValidationError):
                fields = [".".join(str(part) for part in error["loc"])
                          for error in exc.errors(include_input=False, include_context=False)[:5]]
                message = "Invalid contract fields: " + ", ".join(fields)
            with self.store.connect() as db:
                db.execute("UPDATE imports SET status='failed',error=? WHERE import_id=?",
                           (message, identifier))
        finally:
            if stage.exists():
                shutil.rmtree(stage)
            if promoted and not committed:
                shutil.rmtree(promoted)

    def validate_parquet(self, stage):
        with duckdb.connect(":memory:") as db:
            db.execute("SET memory_limit='512MB'")
            for name, required in [("evidence", EVIDENCE_COLUMNS),
                                   ("access_history", ACCESS_COLUMNS)]:
                table = parquet(stage / name)
                columns = {r[0] for r in db.execute(f"DESCRIBE SELECT * FROM {table}").fetchall()}
                if not required <= columns:
                    raise ImportFailure(f"{name} missing required columns")
                bad = db.execute(f"SELECT 1 FROM {table} WHERE evidence_id IS NULL OR "
                                 "source_file_id IS NULL OR record_locator IS NULL OR "
                                 "CAST(evidence_id AS VARCHAR)='' OR CAST(source_file_id AS VARCHAR)='' "
                                 "OR CAST(record_locator AS VARCHAR)='' LIMIT 1").fetchone()
                if bad:
                    raise ImportFailure(f"{name} has incomplete evidence locators")
                keys = "incident_id,evidence_id" if name == "evidence" else "relationship_id"
                if db.execute(f"SELECT 1 FROM {table} GROUP BY {keys} HAVING count(*)>1 LIMIT 1").fetchone():
                    raise ImportFailure(f"{name} contains duplicate identifiers")

    def validate_evidence(self, stage, incident):
        ids = {e for step in incident.timeline for e in step.evidence_ids}
        ids.update(e for edge in incident.relationships for e in edge.evidence_ids)
        if not ids:
            return
        with duckdb.connect(":memory:") as db:
            db.execute("SET memory_limit='512MB'")
            found = {r[0] for r in db.execute(
                f"SELECT evidence_id FROM {parquet(stage / 'evidence')} "
                "WHERE incident_id=? AND evidence_id IN (SELECT unnest(?))",
                [incident.incident_id, sorted(ids)]
            ).fetchall()}
        if found != ids:
            raise ImportFailure("Incident references missing evidence")
