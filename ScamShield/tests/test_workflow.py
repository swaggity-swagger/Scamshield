import json

from scamshield.workflow import run_scamshield_workflow


def fake_extractor(_: str) -> dict:
    return {
        "image_path": "sample.png",
        "text": "Urgent! Share your OTP and pay now.",
        "urls": ["http://sbi-verify-kyc.click/login"],
        "qr_data": [],
        "upi_ids": [],
        "qr_detected": False,
    }


def test_full_workflow_keeps_cybersecurity_result_authoritative() -> None:
    result = run_scamshield_workflow("sample.png", extraction_service=fake_extractor)
    assert result["status"] == "ok"
    assert result["cybersecurity_analysis"]["risk_score"] > 0
    assert result["ai_response"]["risk_source"] == "member5_cybersecurity"
    assert result["ai_response"]["cybersecurity_context"]["risk_score"] == result["cybersecurity_analysis"]["risk_score"]
    json.dumps(result)


def test_missing_input_returns_clean_error() -> None:
    result = run_scamshield_workflow(None)
    assert result["status"] == "invalid_input"
    assert result["cybersecurity_analysis"] is None


def test_ai_failure_keeps_cybersecurity_analysis() -> None:
    def unavailable_ai(*_args, **_kwargs):
        raise RuntimeError("AI service offline")

    result = run_scamshield_workflow("sample.png", extraction_service=fake_extractor, ai_service=unavailable_ai)
    assert result["status"] == "partial"
    assert result["cybersecurity_analysis"] is not None
    assert result["ai_response"]["available"] is False


def test_extraction_failure_stops_downstream_services() -> None:
    def broken_extractor(_: str) -> dict:
        raise ValueError("invalid image")

    result = run_scamshield_workflow("bad.png", extraction_service=broken_extractor)
    assert result["status"] == "failed"
    assert result["cybersecurity_analysis"] is None


def test_prize_qr_poster_is_high_risk_even_when_qr_is_undecodable() -> None:
    def giveaway_extractor(_: str) -> dict:
        return {
            "image_path": "giveaway.png",
            "text": "Congratulations! You could be the lucky winner of an Apple iPhone. Scan the QR code to claim your prize.",
            "urls": [],
            "qr_data": [],
            "upi_ids": [],
            "qr_detected": True,
        }

    result = run_scamshield_workflow("giveaway.png", extraction_service=giveaway_extractor)
    analysis = result["cybersecurity_analysis"]
    assert analysis["risk_level"] in {"HIGH", "VERY HIGH"}
    assert analysis["scam_type"] in {"PRIZE_SCAM", "QR_SCAM"}
    assert {"Unexpected prize or giveaway", "QR code used to claim or verify"} <= {
        item["label"] for item in analysis["indicators"]
    }


def test_benign_qr_examples_remain_low_risk() -> None:
    for text in (
        "Restaurant menu. Scan the QR code to view today's dishes.",
        "Guest Wi-Fi QR code for visitors.",
        "Scan this QR code to see the event schedule.",
        "Apple introduces a new phone. Details: https://www.apple.com/iphone/",
    ):
        result = run_scamshield_workflow(
            "benign.png",
            extraction_service=lambda _path, message=text: {
                "image_path": "benign.png", "text": message, "urls": [], "qr_data": [], "upi_ids": [], "qr_detected": True,
            },
        )
        assert result["cybersecurity_analysis"]["risk_level"] == "LOW"


def test_bank_threat_and_brand_giveaway_qr_are_high_risk() -> None:
    for text in (
        "Your bank account will be blocked. Scan the QR code immediately to verify your account.",
        "Amazon gift card giveaway! Congratulations, you are selected. Scan the QR code to claim your reward.",
    ):
        result = run_scamshield_workflow(
            "scam.png",
            extraction_service=lambda _path, message=text: {
                "image_path": "scam.png", "text": message, "urls": [], "qr_data": [], "upi_ids": [], "qr_detected": True,
            },
        )
        assert result["cybersecurity_analysis"]["risk_level"] in {"HIGH", "VERY HIGH"}


def test_bank_email_with_lookalike_sender_and_reset_link_is_high_risk() -> None:
    text = (
        "From: authenticationmail@trust.ameribank7.com\n"
        "Subject: A new login to your bank account\n"
        "Bank of America\n"
        "If this was not you, please reset your password immediately with this link: "
        "https://trust.ameribank7.com/reset-password"
    )
    result = run_scamshield_workflow(
        "email.png",
        extraction_service=lambda _path: {
            "image_path": "email.png", "text": text,
            "urls": ["https://trust.ameribank7.com/reset-password"],
            "qr_data": [], "upi_ids": [], "qr_detected": False,
        },
    )
    analysis = result["cybersecurity_analysis"]
    assert analysis["risk_level"] in {"HIGH", "VERY HIGH"}
    assert {"Brand claim and sender domain do not match", "Brand claim and account-action link do not match"} <= {
        item["label"] for item in analysis["indicators"]
    }


def test_official_brand_sender_and_link_are_not_flagged_as_mismatched() -> None:
    text = (
        "From: alerts@e.bankofamerica.com\nBank of America\n"
        "A new statement is available in your account. https://www.bankofamerica.com/"
    )
    result = run_scamshield_workflow(
        "legitimate-email.png",
        extraction_service=lambda _path: {
            "image_path": "legitimate-email.png", "text": text,
            "urls": ["https://www.bankofamerica.com/"],
            "qr_data": [], "upi_ids": [], "qr_detected": False,
        },
    )
    analysis = result["cybersecurity_analysis"]
    assert analysis["risk_level"] == "LOW"
    assert not {"brand_sender_domain_mismatch", "brand_action_link_mismatch"} & {
        item["id"] for item in analysis["indicators"]
    }
