"""Configuration loading.

Settings come from a YAML file baked into the image, overridden by
environment variables at runtime.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import yaml

DEFAULT_PATH = Path(__file__).resolve().parents[2] / "config" / "settings.yaml"


@dataclass(frozen=True)
class Settings:
    bucket: str
    region: str
    database_url: str
    presign_ttl_seconds: int
    grades_service_url: str


def load_settings(path: str | os.PathLike | None = None) -> Settings:
    with open(path or os.environ.get("REPORTS_SETTINGS", DEFAULT_PATH), encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}

    return Settings(
        bucket=os.environ.get("REPORTS_BUCKET", raw.get("bucket", "")),
        region=os.environ.get("AWS_REGION", raw.get("region", "us-east-1")),
        database_url=os.environ.get("DATABASE_URL", ""),
        presign_ttl_seconds=int(raw.get("presign_ttl_seconds", 300)),
        grades_service_url=raw.get("grades_service_url", ""),
    )
