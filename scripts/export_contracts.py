"""Regenerate machine-readable schemas from the authoritative Pydantic contract."""

import json
from pathlib import Path

from api.contracts import EngineReview, Incident, Manifest, Quality, Summary

if __name__ == "__main__":
    root = Path("contracts")
    root.mkdir(exist_ok=True)
    for model in [Manifest, Summary, Incident, EngineReview, Quality]:
        (root / f"{model.__name__.lower()}-v1.schema.json").write_text(
            json.dumps(model.model_json_schema(), indent=2) + "\n"
        )
