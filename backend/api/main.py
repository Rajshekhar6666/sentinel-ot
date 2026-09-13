from fastapi import FastAPI
from backend.attack_bridge.attack_mapper import map_attack_technique
from backend.blast_radius.blast_radius import calculate_blast_radius
from backend.risk.risk_scoring import calculate_risk_score
from backend.api.models import AlertInput
from backend.ptg.graph import PTG_GRAPH, CRITICAL_NODES
app = FastAPI(title="SENTINEL-OT Backend")


@app.get("/")
def home():
    return {
        "message": "SENTINEL-OT Backend is running"
    }

@app.post("/analyze")
def analyze_alert(alert: AlertInput):

    # ATT&CK mapping
    attack = map_attack_technique(alert.anomaly_type)

    blast_result = calculate_blast_radius(
    PTG_GRAPH,
    alert.anomalous_node,
    CRITICAL_NODES,
    max_hops=3
    )   

    # Risk Score
    risk_score = calculate_risk_score(
        alert.anomaly_score,
        blast_result["blast_radius_score"]
    )

    return {
        "alert_id": alert.alert_id,
        "anomalous_node": alert.anomalous_node,
        "anomaly_type": alert.anomaly_type,
        "anomaly_score": alert.anomaly_score,
        "blast_radius": blast_result,
        "risk_score": risk_score,
        "attack_techniques": [attack]
    }
@app.get("/alert")
def get_alert():

    anomaly_type = "new_write_to_read_only_register"

    # ATT&CK mapping
    attack = map_attack_technique(anomaly_type)


    # Calculate Blast Radius
    blast_result = calculate_blast_radius(
    PTG_GRAPH,
    "PLC-01",
    CRITICAL_NODES,
    max_hops=3
    )
    risk_score = calculate_risk_score(
    0.92,
    blast_result["blast_radius_score"]
    )

    return {
        "alert_id": "ALERT-001",
        "anomalous_node": "PLC-01",
        "anomaly_type": anomaly_type,
        "anomaly_score": 0.92,

        "blast_radius": blast_result,

        "risk_score": risk_score,

        "attack_techniques": [attack]
    }