import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Settings:
    import_root: Path = field(default_factory=lambda: Path(os.getenv("IMPORT_ROOT", "data/input")))
    data_root: Path = field(default_factory=lambda: Path(os.getenv("DATA_ROOT", "data/app")))
    approved_hosts: tuple[str, ...] = field(default_factory=lambda: tuple(
        h.strip().lower() for h in os.getenv("APPROVED_REMOTE_HOSTS", "").split(",") if h.strip()
    ))
    max_json_bytes: int = 8 * 1024 * 1024
    max_artifact_bytes: int = 100 * 1024**3
    ai_provider: str = field(default_factory=lambda: os.getenv("AI_PROVIDER", "disabled"))
    ai_model: str = field(default_factory=lambda: os.getenv(
        f"{os.getenv('AI_PROVIDER', 'disabled').upper()}_MODEL", ""
    ))

