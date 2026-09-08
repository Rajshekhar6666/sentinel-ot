from attack_mapper import map_attack_technique


def test_known_attack_pattern():
    result = map_attack_technique(
        "new_write_to_read_only_register"
    )

    assert result["technique_id"] == "T0855"
    assert result["technique_name"] == "Unauthorized Command Message"
    assert result["confidence"] == 0.90


def test_unknown_attack_pattern():
    result = map_attack_technique(
        "unknown_test_pattern"
    )

    assert result["technique_id"] is None
    assert result["technique_name"] == "Unknown"
    assert result["confidence"] == 0.0