# ScamSense - AI/NLP Module

This repository currently contains the AI/NLP service for ScamSense. It accepts a message (or OCR-extracted text) and returns an explainable risk assessment in English, Hindi, or Marathi.

## Included

- Multilingual signal detection (English, Hindi, Marathi)
- Explainable evidence for every matched scam indicator
- Risk score, risk level, scam categories, and user-safe next steps
- FastAPI endpoint ready for React or OCR/QR integrations
- Automated tests with legitimate and scam-message examples

## Run locally

The ready-to-run local environment is already present. Easiest option: double-click `backend/run_backend.bat`, or open a terminal in `backend` and run:

```powershell
.\run_backend.bat
```

Keep that terminal open while testing. If the environment is ever deleted, recreate it with:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Open `http://127.0.0.1:8000/docs` to test the API interactively.

Example request body:

```json
{
  "text": "Urgent! Send your OTP and pay the processing fee now.",
  "preferred_language": "en"
}
```

## API contract

`POST /api/v1/analyze/text`

The response includes `risk_score`, `risk_level`, `confidence`, `scam_categories`, `evidence`, and `recommended_actions`. The frontend should display evidence directly so users understand *why* a warning was raised.

## Next integration points

- OCR service sends extracted screenshot text to this endpoint.
- QR/URL service sends decoded URLs or UPI-payment text to this endpoint.
- React uses the response to render the risk dashboard and incident guidance.
