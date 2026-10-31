"""Versioned engine handoff; no detection logic belongs here."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Artifact(Contract):
    location: str = Field(min_length=1)
    sha256: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")
    size_bytes: int | None = Field(default=None, ge=0)
    format: str | None = None
    optional: bool = False


class SourceDataset(Contract):
    name: str
    source_size_bytes: int = Field(ge=0)


class Manifest(Contract):
    contract_version: Literal["1.0"]
    run_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,120}$")
    source_dataset: SourceDataset
    status: Literal["completed"]
    incident_count: int = Field(ge=0)
    artifacts: dict[str, Artifact]
    engine_status: Literal["queued", "running", "completed", "failed"] = "completed"
    engine_phase: Literal["parsing", "detecting", "correlating", "writing_results"] = "writing_results"

    @model_validator(mode="after")
    def required_artifacts(self):
        required = {
            "incident_summaries", "incident_bundles", "evidence", "access_history", "quality"
        }
        missing = required - self.artifacts.keys()
        if missing:
            raise ValueError(f"Missing artifacts: {', '.join(sorted(missing))}")
        for name, artifact in self.artifacts.items():
            if name != "incident_bundles" and not artifact.sha256:
                raise ValueError(f"Checksum required for {name}")
        return self


class Entity(Contract):
    entity_id: str
    type: Literal["host", "account", "ip", "process", "file", "event"]
    label: str


class Step(Contract):
    step_id: str
    observed_at: datetime | None
    display_order: int
    ordering_basis: str
    ordering_confidence: Literal["high", "medium", "low", "unknown"]
    summary: str
    entity_ids: list[str]
    evidence_ids: list[str] = Field(min_length=1)
    interpretation_status: Literal["observed", "derived", "hypothesized"]
    maliciousness: Literal["suspicious", "malicious", "benign", "unknown"] = "unknown"
    technique_id: str | None = None
    kill_chain_phase: str | None = None
    source_sequence: int | None = None


class Relationship(Contract):
    relationship_id: str
    source_id: str
    target_id: str
    relationship_type: str
    evidence_ids: list[str] = Field(min_length=1)
    interpretation_status: Literal["observed", "derived", "hypothesized"]


class Incident(Contract):
    incident_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,120}$")
    revision: int = Field(ge=1)
    title: str
    severity: Literal["critical", "high", "medium", "low", "informational"]
    risk_score: float = Field(ge=0, le=100)
    analysis_reference_time: datetime
    entities: list[Entity]
    timeline: list[Step]
    relationships: list[Relationship]
    techniques: list[dict[str, str]] = Field(default_factory=list)
    kill_chain: list[str] | list[dict[str, str]] = Field(default_factory=list)
    data_quality_impact: list[str] = Field(default_factory=list)
    engine_review: dict | None = None

    @model_validator(mode="after")
    def references(self):
        ids = {e.entity_id for e in self.entities}
        if len(ids) != len(self.entities):
            raise ValueError("Duplicate entity IDs")
        for step in self.timeline:
            if not set(step.entity_ids) <= ids:
                raise ValueError("Timeline references unknown entity")
            if step.observed_at and step.observed_at.tzinfo is None:
                raise ValueError("Timestamps must include timezone")
            if step.technique_id and step.technique_id not in {
                t.get("id") for t in self.techniques
            }:
                raise ValueError("Timeline references unknown technique")
        for edge in self.relationships:
            if edge.source_id not in ids or edge.target_id not in ids:
                raise ValueError("Relationship references unknown entity")
        if self.analysis_reference_time.tzinfo is None:
            raise ValueError("Reference time must include timezone")
        for values, key in [(self.timeline, "step_id"),
                            (self.relationships, "relationship_id")]:
            identifiers = [getattr(v, key) for v in values]
            if len(set(identifiers)) != len(identifiers):
                raise ValueError(f"Duplicate {key}")
        return self


class Summary(Contract):
    incident_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,120}$")
    revision: int = Field(ge=1)
    title: str
    severity: str
    risk_score: float = Field(ge=0, le=100)
    bundle: Artifact


class Quality(Contract):
    total_records_read: int = Field(ge=0)
    successfully_parsed_records: int = Field(ge=0)
    malformed_records: int = Field(ge=0)
    missing_critical_fields: int = Field(ge=0)
    unknown_event_types: int = Field(ge=0)
    duplicate_records: int = Field(ge=0)
    late_arriving_events: int = Field(ge=0)
    records_excluded_from_detection: int = Field(ge=0)


class EngineReview(Contract):
    incident_id: str
    revision: int = Field(ge=1)
    review: dict
