from blast_radius import calculate_blast_radius


def test_blast_radius_reaches_critical_node():

    graph = {
        "PLC-01": ["PLC-02"],
        "PLC-02": ["RTU-01"],
        "RTU-01": ["Pump-01"],
        "Pump-01": []
    }

    critical_nodes = ["Pump-01"]

    result = calculate_blast_radius(
        graph,
        "PLC-01",
        critical_nodes,
        max_hops=3
    )

    assert result["blast_radius_score"] == 1.0
    assert result["reachable_critical_nodes"][0]["node"] == "Pump-01"
    assert result["reachable_critical_nodes"][0]["hops"] == 3


def test_blast_radius_no_critical_node():

    graph = {
        "PLC-01": ["PLC-02"],
        "PLC-02": []
    }

    critical_nodes = ["Pump-01"]

    result = calculate_blast_radius(
        graph,
        "PLC-01",
        critical_nodes,
        max_hops=3
    )

    assert result["blast_radius_score"] == 0.0
    assert result["reachable_critical_nodes"] == []