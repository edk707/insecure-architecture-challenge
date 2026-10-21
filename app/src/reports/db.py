"""Database access. All queries are parameterized."""

from __future__ import annotations

from contextlib import contextmanager

import psycopg

from .config import Settings


class ReportIndex:
    def __init__(self, settings: Settings):
        self._dsn = settings.database_url

    @contextmanager
    def _connect(self):
        with psycopg.connect(self._dsn, connect_timeout=5) as conn:
            yield conn

    def reports_for_student(self, student_id: str) -> list[dict]:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT report_key, term, created_at FROM reports "
                "WHERE student_id = %s ORDER BY created_at DESC LIMIT 50",
                (student_id,),
            )
            return [
                {"key": key, "term": term, "created_at": created.isoformat()}
                for key, term, created in cur.fetchall()
            ]

    def ping(self) -> bool:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT 1")
            return cur.fetchone() == (1,)
