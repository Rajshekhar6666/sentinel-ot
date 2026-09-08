import json
from pathlib import Path


# rules.json ka path
RULES_FILE = Path(__file__).parent / "rules.json"


def load_rules():
    with open(RULES_FILE, "r") as file:
        data = json.load(file)

    return data["rules"]


def map_attack_technique(anomaly_type):
    rules = load_rules()

    for rule in rules:
        if rule["pattern"] == anomaly_type:
            return {
                "technique_id": rule["technique_id"],
                "technique_name": rule["technique_name"],
                "confidence": rule["confidence"]
            }

    return {
        "technique_id": None,
        "technique_name": "Unknown",
        "confidence": 0.0
    }


if __name__ == "__main__":
    result = map_attack_technique(
        "new_write_to_read_only_register"
    )

    print(result)