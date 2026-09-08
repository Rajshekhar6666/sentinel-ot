from fastapi.testclient import TestClient
from backend.api.main import app

client = TestClient(app)


def test_analyze_endpoint():

    response = client.post(
        "/analyze",
        json={
            "alert_id": "TEST-001",
            "anomalous_node": "PLC-02",
            "anomaly_type": "value_outside_historical_range",
            "anomaly_score": 0.85
        }
    )

    assert response.status_code == 200

    data = response.json()

    assert data["alert_id"] == "TEST-001"
    assert data["anomaly_score"] == 0.85
    assert data["attack_techniques"][0]["technique_id"] == "T0836"
    assert data["blast_radius"]["blast_radius_score"] == 1.0
    assert data["risk_score"] == 0.91


def test_invalid_anomaly_score():

    response = client.post(
        "/analyze",
        json={
            "alert_id": "TEST-002",
            "anomalous_node": "PLC-01",
            "anomaly_type": "new_write_to_read_only_register",
            "anomaly_score": 1.5
        }
    )

    assert response.status_code == 422