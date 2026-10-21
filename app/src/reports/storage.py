"""Report file storage on S3.

Clients never receive bucket credentials. They get short-lived presigned URLs.
"""

from __future__ import annotations

import re

import boto3

from .config import Settings

_KEY_PATTERN = re.compile(r"^[a-z0-9][a-z0-9/_\-]{2,120}\.pdf$")


class ReportStore:
    def __init__(self, settings: Settings):
        self._bucket = settings.bucket
        self._ttl = settings.presign_ttl_seconds
        self._s3 = boto3.client("s3", region_name=settings.region)

    def download_url(self, key: str) -> str:
        if not _KEY_PATTERN.match(key) or ".." in key:
            raise ValueError("invalid report key")
        return self._s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": self._bucket, "Key": key},
            ExpiresIn=self._ttl,
        )

    def list_reports(self, prefix: str, limit: int = 50) -> list[str]:
        response = self._s3.list_objects_v2(Bucket=self._bucket, Prefix=prefix, MaxKeys=limit)
        return [item["Key"] for item in response.get("Contents", [])]
