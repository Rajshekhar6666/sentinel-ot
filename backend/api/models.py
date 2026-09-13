from pydantic import BaseModel, Field


class AlertInput(BaseModel):
    alert_id: str
    anomalous_node: str
    anomaly_type: str
    anomaly_score: float = Field(ge=0.0, le=1.0)