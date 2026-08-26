from app.services.url_service import analyze_url


def test_suspicious_url():
    result = analyze_url(
        "http://192.168.1.10/login",
        "en",
    )

    assert result["risk_level"] == "HIGH"
    assert result["category"] == "SUSPICIOUS_URL"
    assert result["features"]["uses_ip_address"] is True
    assert result["features"]["uses_https"] is False
    assert "login" in result["features"]["suspicious_keywords"]
    assert len(result["indicators"]) >= 3


def test_clean_url():
    result = analyze_url(
        "https://example.com",
        "en",
    )

    assert result["risk_level"] == "LOW"
    assert result["category"] == "NO_OBVIOUS_INDICATORS"
    assert result["features"]["uses_https"] is True


def test_hindi_url_response():
    result = analyze_url(
        "http://192.168.1.10/login",
        "hi",
    )

    assert result["language"] == "hi"
    assert result["risk_level"] == "HIGH"
    assert result["explanation"] != ""
    assert len(result["recommended_actions"]) > 0


def test_marathi_url_response():
    result = analyze_url(
        "http://192.168.1.10/login",
        "mr",
    )

    assert result["language"] == "mr"
    assert result["risk_level"] == "HIGH"
    assert result["explanation"] != ""
    assert len(result["recommended_actions"]) > 0


def test_url_without_scheme():
    result = analyze_url(
        "example.com",
        "en",
    )

    assert result["url"] == "https://example.com"
    assert result["risk_level"] == "LOW"