# Sample Process Topology Graph (PTG)

PTG_GRAPH = {
    "PLC-01": ["PLC-02"],
    "PLC-02": ["RTU-01"],
    "RTU-01": ["Pump-01"],
    "Pump-01": []
}


CRITICAL_NODES = [
    "Pump-01"
]