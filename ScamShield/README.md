# ScamShield

ScamShield is a Smart India Hackathon prototype for checking suspicious messages, screenshots, links, and QR codes. The main image route uses the supplied OpenCV preprocessing, Tesseract OCR, OpenCV QR decoder, and existing cybersecurity risk engine. It does not store uploaded screenshots permanently.

## What is connected

`frontend/index.html` sends a selected image to `POST /api/analyze/image`. The FastAPI app saves it to a temporary file, calls `scamshield.workflow.run_scamshield_workflow`, then removes the temporary file. The workflow runs:

1. Member 4: OpenCV preprocessing, OCR, QR decoding, URL/UPI extraction.
2. Member 5: indicator detection, URL/UPI checks, risk score, category, and recommendations.
3. Member 3: language-aware plain-language explanation and safety guidance.

The web UI renders the returned threat level, category, OCR text, QR result/data, actual indicators, explanation, and recommendations. Typed messages and URLs use the existing Member 3 and Member 5 analysis modules directly.

## Requirements

- Python 3.10 or newer
- Tesseract OCR for Windows: install it from the [UB Mannheim build](https://github.com/UB-Mannheim/tesseract/wiki) and keep the default executable location: `C:\Program Files\Tesseract-OCR\tesseract.exe`

## Run locally (Windows PowerShell)

```powershell
cd path\to\ScamShield
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app:app --reload
```

Open `http://127.0.0.1:8000` in a browser. Do not open `frontend/index.html` directly—the API is served by FastAPI.

## Test

```powershell
pytest
```

The included workflow tests cover a Bank/KYC-style blocking message, QR prize/giveaway scam patterns, and suspicious/phishing link content without a QR. For a live UI check, upload a clear PNG/JPG screenshot for each scenario; confirm that the extracted text and QR payload shown on-screen match the uploaded image.

## Project layout

- `app.py` — FastAPI server, upload validation, temporary-file lifecycle, and frontend response adapter.
- `frontend/index.html` — existing interface, now wired to live API calls.
- `scamshield/member4/original_main.py` — supplied OCR/OpenCV/QR extraction.
- `scamshield/member5/cybersecurity/` — supplied risk, URL, QR, UPI, category, and recommendation logic.
- `scamshield/member3/` — supplied multilingual explanation logic.
