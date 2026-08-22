"""Realistic fictional ScamShield test cases."""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from cybersecurity.analyzer import analyze_input


CASES = [
    {
        "name": "Banking phishing",
        "text": "SBI official alert: your account will be blocked today. Complete KYC immediately at http://sbi-verify-kyc.click/login",
    },
    {"name": "OTP scam", "text": "Please share your OTP now to verify your refund."},
    {
        "name": "UPI scam",
        "text": "Scan this QR to receive refund money immediately.",
        "upi_data": "upi://pay?pa=refund.agent934829@unknownpay&pn=Refund%20Team&am=14999&tn=Refund",
    },
    {
        "name": "Fake job offer",
        "text": "You are selected for work from home job. Pay 999 rupees  registration fee today to confirm.",
    },
    {
        "name": "Investment scam",
        "text": "Guaranteed 30% return every month. Transfer money now to double your investment.",
    },
    {"name": "Prize scam", "text": "Congratulations winner! Claim your lottery prize by paying processing charges Rs. 499."},
    {"name": "Impersonation", "text": "Police cyber crime notice: pay fine today or arrest warrant will be issued."},
    {"name": "Suspicious URL", "urls": ["http://192.168.1.4:8080/login-update"]},
    {"name": "QR malicious-looking URL", "qr_data": "https://paytm-secure-verify.xyz/claim?bonus=1&kyc=update"},
    {"name": "Normal meeting", "text": "Reminder: team meeting at 4 PM today. Please review the agenda."},
    {"name": "Normal bank info", "text": "Your bank statement for July is available in the official app."},
    {"name": "Normal UPI received", "upi_data": "upi://pay?pa=shop@upi&pn=Local%20Shop&am=120&tn=Tea"},
]


def run_cases() -> None:
    for case in CASES:
        result = analyze_input(
            text=case.get("text"),
            urls=case.get("urls"),
            qr_data=case.get("qr_data"),
            upi_data=case.get("upi_data"),
            use_ai=False,
        )
        print("=" * 80)
        print(case["name"])
        print("Input:", case.get("text") or case.get("urls") or case.get("qr_data") or case.get("upi_data"))
        print("Detected indicators:", [item["label"] for item in result["indicators"]])
        print("Scam type:", result["scam_type"])
        print("Risk score:", result["risk_score"])
        print("Risk level:", result["risk_level"])
        print("Recommendations:", json.dumps(result["recommendations"], indent=2))


if __name__ == "__main__":
    run_cases()
