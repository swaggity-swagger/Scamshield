"""Command-line demonstration for ScamShield cybersecurity analysis."""

from __future__ import annotations

import argparse
import json

from cybersecurity.analyzer import analyze_input


SAMPLES = [
    "SBI official alert: your account will be blocked today. Complete KYC immediately at http://sbi-verify-kyc.click/login",
    "Please share your OTP now to verify your refund.",
    "You are selected for work from home job. Pay ₹999 registration fee today to confirm.",
    "Reminder: dentist appointment tomorrow at 10 AM.",
]


def _print_result(title: str, result: dict) -> None:
    print("=" * 80)
    print(title)
    print(f"Risk: {result['risk_score']} ({result['risk_level']})")
    print(f"Scam type: {result['scam_type']}")
    print("Indicators:", ", ".join(item["label"] for item in result["indicators"]) or "None")
    print("Recommendations:")
    for recommendation in result["recommendations"]:
        print(f"- {recommendation}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run ScamShield cybersecurity analysis demos.")
    parser.add_argument("message", nargs="*", help="Optional custom message to analyze")
    parser.add_argument("--url", action="append", help="Optional URL to analyze; can be used multiple times")
    parser.add_argument("--qr", action="append", help="Optional decoded QR payload; can be used multiple times")
    parser.add_argument("--upi", help="Optional UPI payload or UPI ID")
    parser.add_argument("--json", action="store_true", help="Print full JSON result for a custom message")
    args = parser.parse_args()

    message = " ".join(args.message).strip() or None
    if message or args.url or args.qr or args.upi:
        result = analyze_input(text=message, urls=args.url, qr_data=args.qr, upi_data=args.upi)
        if args.json:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            _print_result("Custom analysis", result)
        return

    for index, sample in enumerate(SAMPLES, start=1):
        result = analyze_input(text=sample)
        _print_result(f"Sample {index}: {sample}", result)


if __name__ == "__main__":
    main()
