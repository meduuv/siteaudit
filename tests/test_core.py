from siteaudit import audit_headers, audit_status

def test_headers():
    result = audit_headers({"Content-Security-Policy": "default-src 'self'"})
    assert result["score"] == 1
    assert "referrer-policy" in result["missing"]

def test_status():
    assert audit_status(200)["ok"] is True
    assert audit_status(500)["family"] == "5xx"
