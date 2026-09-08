# Backend — Mansi

## Overview

This folder contains the backend components of SENTINEL-OT.

The backend is responsible for:

- ATT&CK technique mapping
- Blast Radius calculation
- Risk Score calculation
- FastAPI API endpoints
- Input validation
- Automated testing

---

## Project Structure

```text
backend/
├── api/
│   ├── main.py
│   ├── models.py
│   ├── test_api.py
│   └── __init__.py
│
├── attack_bridge/
│   ├── rules.json
│   ├── attack_mapper.py
│   └── test_attack_mapper.py
│
├── blast_radius/
│   ├── blast_radius.py
│   └── test_blast_radius.py
│
├── risk/
│   ├── risk_scoring.py
│   └── test_risk_scoring.py
│
└── ptg/
    └── graph.py
## 1. ATT&CK Bridge

The ATT&CK Bridge maps detected anomaly patterns to MITRE ATT&CK for ICS techniques.

Example mappings:

| Anomaly Pattern | Technique |
|---|---|
| new_write_to_read_only_register | T0855 — Unauthorized Command Message |
| value_outside_historical_range | T0836 — Modify Parameter |
| new_device_connection_across_subnet | T0840 — Network Connection Enumeration |
| burst_of_device_identification_requests | T0888 — Remote System Information Discovery |
| new_remote_service_connection | T0886 — Remote Services |

Unknown anomaly patterns are handled gracefully and return:

```text
Technique: Unknown
Confidence: 0.0