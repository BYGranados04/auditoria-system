from fastapi.testclient import TestClient

from app.api.main import create_app


def test_health_returns_ok() -> None:
    client = TestClient(create_app())

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "auditoria-system-api",
    }


def test_health_does_not_expose_unexpected_fields() -> None:
    client = TestClient(create_app())

    response = client.get("/health")

    assert set(response.json()) == {
        "status",
        "service",
    }
