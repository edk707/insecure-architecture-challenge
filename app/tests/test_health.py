from unittest import mock

from reports.main import create_app


def test_healthz_reports_version(tmp_path, monkeypatch):
    settings = tmp_path / "settings.yaml"
    settings.write_text("bucket: test-bucket\nregion: us-east-1\n")
    monkeypatch.setenv("REPORTS_SETTINGS", str(settings))

    with mock.patch("reports.storage.boto3.client"):
        client = create_app().test_client()
        response = client.get("/healthz")

    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"
