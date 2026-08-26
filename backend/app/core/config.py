import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
JWT_SECRET = os.getenv("JWT_SECRET")
OPENAI_API_KEY = os.getenv(
    "OPENAI_API_KEY"
)

OPENAI_MODEL = os.getenv(
    "OPENAI_MODEL"
)

VIRUSTOTAL_API_KEY = os.getenv(
    "VIRUSTOTAL_API_KEY"
)

ABUSEIPDB_API_KEY = os.getenv(
    "ABUSEIPDB_API_KEY"
)

if not DATABASE_URL:
    raise ValueError("DATABASE_URL is not configured")

if not JWT_SECRET:
    raise ValueError("JWT_SECRET is not configured")
if not OPENAI_API_KEY:
    raise ValueError(
        "OPENAI_API_KEY is not configured"
    )

if not OPENAI_MODEL:
    raise ValueError(
        "OPENAI_MODEL is not configured"
    )