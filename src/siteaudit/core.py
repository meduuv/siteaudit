SECURITY_HEADERS = ("content-security-policy", "strict-transport-security", "x-content-type-options", "referrer-policy", "permissions-policy")

def audit_headers(headers):
    keys = {str(k).lower() for k in headers}
    present = [h for h in SECURITY_HEADERS if h in keys]
    return {"present": present, "missing": [h for h in SECURITY_HEADERS if h not in keys], "score": len(present)}

def audit_status(status):
    status = int(status)
    return {"status": status, "ok": 200 <= status < 400, "family": f"{status // 100}xx" if 100 <= status < 600 else "unknown"}
