from app.main import _text_result
from app.scamshield.member5.cybersecurity import live_url_inspector
from app.scamshield.member5.cybersecurity.url_analyzer import analyze_url
from app.scamshield.workflow import run_scamshield_workflow


def test_text_result_passes_explicit_url_to_url_analyzer():
    result = _text_result(
        "http://sbi-kyc-update.verify9-secure.info",
        "en",
        ["http://sbi-kyc-update.verify9-secure.info"],
    )

    analysis = result["cybersecurity_analysis"]

    assert result["status"] == "ok"
    assert result["extracted_information"]["urls"] == ["http://sbi-kyc-update.verify9-secure.info"]
    assert analysis["url_analysis"]
    assert analysis["risk_level"] in {"MEDIUM", "HIGH", "VERY HIGH"}
    assert any(item["id"] == "suspicious_domain" for item in analysis["indicators"])


def test_static_url_analysis_flags_netflix_credential_phishing_domain():
    result = _text_result(
        "https://verify-netflix-login.com/",
        "en",
        ["https://verify-netflix-login.com/"],
    )

    analysis = result["cybersecurity_analysis"]
    indicator_ids = {item["id"] for item in analysis["indicators"]}

    assert analysis["risk_level"] in {"MEDIUM", "HIGH", "VERY HIGH"}
    assert "brand_action_link_mismatch" in indicator_ids
    assert any("Netflix" in item["evidence"] for item in analysis["indicators"])


def test_live_url_scan_flags_sensitive_landing_page(monkeypatch):
    def fake_private_check(_hostname):
        return False

    def fake_fetch(_url):
        return live_url_inspector.FetchResult(
            url="https://verify9-secure.info/login",
            status_code=200,
            headers={"Content-Type": "text/html; charset=utf-8"},
            body=b"""
                <html>
                  <head><title>SBI KYC Update</title></head>
                  <body>
                    <h1>SBI account verification</h1>
                    <form><input type="password" name="password"><input name="otp"></form>
                    Please enter OTP, card number, and net banking details.
                  </body>
                </html>
            """,
        )

    monkeypatch.setattr(live_url_inspector, "_is_private_host", fake_private_check)
    monkeypatch.setattr(live_url_inspector, "_fetch_once", fake_fetch)

    result = analyze_url("https://verify9-secure.info/login", live_scan=True)
    indicator_ids = {item["id"] for item in result["indicators"]}

    assert result["live_analysis"]["status"] == "fetched"
    assert result["live_analysis"]["title"] == "SBI KYC Update"
    assert "live_page_credential_form" in indicator_ids
    assert "live_page_sensitive_data_request" in indicator_ids
    assert "live_page_brand_mismatch" in indicator_ids
    assert result["risk_level"] in {"HIGH", "VERY HIGH"}


def test_text_result_can_request_live_url_scan(monkeypatch):
    def fake_live_scan(_url):
        return {
            "status": "fetched",
            "final_url": "https://example.com/login",
            "status_code": 200,
            "content_type": "text/html",
            "redirect_chain": [],
            "title": "Example Login",
            "bytes_read": 500,
            "indicators": [
                {
                    "id": "live_page_credential_form",
                    "label": "Landing page asks for a password",
                    "severity": "very_high",
                    "evidence": "Landing page contains a password field",
                }
            ],
        }

    monkeypatch.setattr("app.scamshield.member5.cybersecurity.url_analyzer.inspect_live_url", fake_live_scan)

    result = _text_result("https://example.com/login", "en", ["https://example.com/login"], live_url_scan=True)

    url_analysis = result["cybersecurity_analysis"]["url_analysis"][0]
    assert url_analysis["live_analysis"]["status"] == "fetched"
    assert any(item["id"] == "live_page_credential_form" for item in url_analysis["indicators"])


def test_workflow_runs_extraction_cybersecurity_and_ai():
    def fake_extractor(_image_path):
        return {
            "image_path": "sample.png",
            "text": "Please share your OTP now to verify refund.",
            "urls": [],
            "qr_data": [],
            "upi_ids": [],
            "qr_detected": False,
        }

    result = run_scamshield_workflow("sample.png", extraction_service=fake_extractor)

    assert result["status"] == "ok"
    assert result["extracted_information"]["text"].startswith("Please share")
    assert result["cybersecurity_analysis"]["scam_type"] == "OTP_SCAM"
    assert result["ai_response"]["risk_source"] == "member5_cybersecurity"


def test_workflow_returns_partial_result_when_ai_fails():
    def fake_extractor(_image_path):
        return {
            "image_path": "sample.png",
            "text": "Please share your OTP now.",
            "urls": [],
            "qr_data": [],
            "upi_ids": [],
            "qr_detected": False,
        }

    def broken_ai(*_args, **_kwargs):
        raise RuntimeError("AI unavailable")

    result = run_scamshield_workflow("sample.png", extraction_service=fake_extractor, ai_service=broken_ai)

    assert result["status"] == "partial"
    assert result["cybersecurity_analysis"]["scam_type"] == "OTP_SCAM"
    assert result["ai_response"]["available"] is False
    assert result["errors"][0]["stage"] == "member3_ai_nlp"
