from sat_sa.normalizer import normalize

def test_normalize():
    e = normalize({
        "timestamp": "2026-01-01T00:00:00Z",
        "asset_code": "TEST-01",
        "alert_id": "4625",
        "severity": "high",
        "message": "Failed login"
    })
    assert e["host"] == "TEST-01"
    assert e["event_code"] == "4625"
    assert e["level"] == "HIGH"
