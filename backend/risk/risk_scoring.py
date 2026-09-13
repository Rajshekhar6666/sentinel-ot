def calculate_risk_score(anomaly_score, blast_radius):
    """
    Calculate overall risk score using:
    Anomaly Score + Blast Radius
    """

    # MVP weights
    anomaly_weight = 0.6
    blast_weight = 0.4

    risk_score = (
        anomaly_weight * anomaly_score
        + blast_weight * blast_radius
    )

    return round(risk_score, 2)