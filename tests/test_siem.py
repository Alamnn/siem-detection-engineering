from siem_engine import run_detection_engine


def test_all_six_custom_rules_fire_with_zero_fp():
    res = run_detection_engine()
    assert res["total_rules_loaded"] == 6
    assert res["total_alerts_fired"] == 6
    assert res["false_positives"] == 0
    rule_ids = [a["rule_id"] for a in res["alerts"]]
    assert rule_ids == ["100101", "100102", "100103", "100201", "100202", "100203"]
