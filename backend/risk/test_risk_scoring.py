from risk_scoring import calculate_risk_score


def test_high_risk_score():
    result = calculate_risk_score(0.92, 1.0)

    assert result == 0.95


def test_low_risk_score():
    result = calculate_risk_score(0.20, 0.0)

    assert result == 0.12