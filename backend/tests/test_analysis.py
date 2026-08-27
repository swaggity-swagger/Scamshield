from app.services.analysis_service import analyze_message


def test_english_scam_message():
    result = analyze_message(
        "Your bank account will be blocked today. Send your OTP immediately.",
        "en",
    )

    assert result["risk_level"] in {"HIGH", "CRITICAL"}
    assert result["category"] != "NO_SPECIFIC_CATEGORY"
    assert result["confidence"] is not None
    assert len(result["indicators"]) > 0
    assert len(result["recommended_actions"]) > 0


def test_hindi_scam_message():
    result = analyze_message(
        "आपका बैंक खाता आज बंद हो जाएगा। तुरंत OTP भेजें।",
        "hi",
    )

    assert result["risk_level"] in {"HIGH", "CRITICAL"}
    assert result["language"] == "hi"
    assert len(result["indicators"]) > 0


def test_marathi_scam_message():
    result = analyze_message(
        "तुमचे बँक खाते आज बंद होईल. OTP पाठवा.",
        "mr",
    )

    assert result["risk_level"] in {"HIGH", "CRITICAL"}
    assert result["language"] == "mr"
    assert len(result["indicators"]) > 0


def test_normal_message():
    result = analyze_message(
        "Hi, let's meet tomorrow at 10 AM for our project discussion.",
        "en",
    )

    assert result["risk_level"] == "LOW"