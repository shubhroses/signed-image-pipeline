from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_healthz_reports_ok():
    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_version_reports_the_build_revision(monkeypatch):
    monkeypatch.setenv("APP_REVISION", "0123abc")

    response = client.get("/version")

    assert response.status_code == 200
    assert response.json() == {"revision": "0123abc"}


def test_version_is_unknown_when_no_revision_was_built_in(monkeypatch):
    monkeypatch.delenv("APP_REVISION", raising=False)

    assert client.get("/version").json() == {"revision": "unknown"}


def test_the_service_has_exactly_two_endpoints():
    assert {route.path for route in app.routes} == {"/healthz", "/version"}
