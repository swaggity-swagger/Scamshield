from app.services.analyzer import analyze_text


def test_otp_and_payment_message_is_critical() -> None:
    result = analyze_text("Urgent! Your SBI account is blocked. Send your OTP and pay Rs 500 now at https://bit.ly/x")
    assert result["risk_level"] == "critical"
    assert result["risk_score"] >= 70
    assert "credential_theft" in result["scam_categories"]


def test_hindi_message_returns_hindi_copy() -> None:
    result = analyze_text("तुरंत OTP भेजें और पैसे भेजें", "hi")
    assert result["risk_level"] == "critical"
    assert "गंभीर" in result["summary"]


def test_benign_message_stays_low_risk() -> None:
    result = analyze_text("Hello, our meeting is at 4 PM tomorrow.")
    assert result["risk_level"] == "low"
    assert result["safe_to_interact"] is True
