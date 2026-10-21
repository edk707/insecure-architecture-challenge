"""HTTP API for the Student Reports service."""

from __future__ import annotations

import logging
import os

import requests
from flask import Flask, abort, jsonify, request

from . import __version__
from .config import load_settings
from .db import ReportIndex
from .storage import ReportStore

log = logging.getLogger("reports")


def create_app() -> Flask:
    settings = load_settings()
    store = ReportStore(settings)
    index = ReportIndex(settings)

    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024

    @app.get("/healthz")
    def healthz():
        return jsonify(status="ok", version=__version__)

    @app.get("/readyz")
    def readyz():
        try:
            return jsonify(database=index.ping())
        except Exception:  # readiness must never crash the pod
            log.exception("database ping failed")
            return jsonify(database=False), 503

    @app.get("/students/<student_id>/reports")
    def student_reports(student_id: str):
        if not student_id.isalnum() or len(student_id) > 16:
            abort(400)
        if request.headers.get("X-Student-Id") != student_id:
            abort(403)
        return jsonify(index.reports_for_student(student_id))

    @app.get("/reports/<path:key>/download")
    def download(key: str):
        try:
            return jsonify(url=store.download_url(key))
        except ValueError:
            abort(400)

    @app.get("/grades/status")
    def grades_status():
        upstream = requests.get(settings.grades_service_url, timeout=3)
        return jsonify(upstream=upstream.status_code)

    return app


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
