@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
  echo Python environment is missing. Please tell the team lead.
  pause
  exit /b 1
)

echo Starting ScamSense AI/NLP API...
echo Open http://127.0.0.1:8000/docs in your browser.
echo Keep this window open while testing.
.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
