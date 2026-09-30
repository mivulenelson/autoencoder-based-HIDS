import json
import pytest
from fastapi.testclient import TestClient
import api.main

EXPECTED_INPUT_DIM = 22  # Modellens faktiske dimension


def test_health_check():
    with TestClient(api.main.app) as client:
        response = client.get("/health")
        assert response.status_code == 200
        assert "status" in response.json()


def test_readiness_check():
    with TestClient(api.main.app) as client:
        response = client.get("/ready")
        assert response.status_code == 200


def test_predict_invalid_vector_length():
    """Sikrer at vektorer med forkert længde afvises med 422."""
    short_vector = [0.1] * (EXPECTED_INPUT_DIM - 2)
    with TestClient(api.main.app) as client:
        response = client.post("/detection/predict", json={"features": short_vector})
        assert response.status_code == 422


def test_predict_non_finite_values():
    """Sikrer at NaN eller uendelige værdier fejler valideringen."""
    invalid_vector = [0.1] * EXPECTED_INPUT_DIM
    invalid_vector[0] = float("nan")

    payload = json.dumps({"features": invalid_vector}, allow_nan=True)
    with TestClient(api.main.app) as client:
        response = client.post(
            "/detection/predict",
            content=payload,
            headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 422


def test_get_alerts_pagination():
    with TestClient(api.main.app) as client:
        response = client.get("/alerts/?limit=10&offset=0")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, dict)
        assert "total" in data
        assert "limit" in data
        # Find the list key holding the items (e.g., 'alerts')
        list_key = next((k for k, v in data.items() if isinstance(v, list)), None)
        assert list_key is not None
        assert isinstance(data[list_key], list)


def test_get_alert_stats():
    with TestClient(api.main.app) as client:
        response = client.get("/alerts/stats")
        assert response.status_code == 200


def test_get_nonexistent_alert():
    with TestClient(api.main.app) as client:
        response = client.get("/alerts/999999")
        assert response.status_code == 404