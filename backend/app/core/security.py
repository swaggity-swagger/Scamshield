import base64
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

import jwt

from app.core.config import JWT_SECRET


# ============================================================
# JWT CONFIGURATION
# ============================================================

ALGORITHM = "HS256"

# JWT lifetime: 60 minutes for the current project MVP.
ACCESS_TOKEN_EXPIRE_MINUTES = 60


# ============================================================
# PASSWORD HASHING
# ============================================================

# PBKDF2-HMAC-SHA256 avoids native Argon2 dependency issues
# on Windows and uses Python's standard library.
PBKDF2_ITERATIONS = 600_000
SALT_LENGTH = 16
KEY_LENGTH = 32


def hash_password(password: str) -> str:
    """
    Hash a password using PBKDF2-HMAC-SHA256.

    Stored format:
        pbkdf2_sha256$iterations$salt$key
    """

    if not password:
        raise ValueError("Password cannot be empty.")

    salt = secrets.token_bytes(SALT_LENGTH)

    derived_key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=KEY_LENGTH,
    )

    salt_b64 = base64.urlsafe_b64encode(
        salt
    ).decode("ascii")

    key_b64 = base64.urlsafe_b64encode(
        derived_key
    ).decode("ascii")

    return (
        f"pbkdf2_sha256${PBKDF2_ITERATIONS}"
        f"${salt_b64}${key_b64}"
    )


def verify_password(
    password: str,
    stored_hash: str,
) -> bool:
    """
    Verify a password against a stored PBKDF2-HMAC-SHA256 hash.
    """

    try:
        (
            algorithm,
            iterations,
            salt_b64,
            key_b64,
        ) = stored_hash.split("$")

        if algorithm != "pbkdf2_sha256":
            return False

        iterations = int(iterations)

        if iterations <= 0:
            return False

        salt = base64.urlsafe_b64decode(
            salt_b64.encode("ascii")
        )

        expected_key = base64.urlsafe_b64decode(
            key_b64.encode("ascii")
        )

        actual_key = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
            dklen=len(expected_key),
        )

        return hmac.compare_digest(
            actual_key,
            expected_key,
        )

    except (
        ValueError,
        TypeError,
        UnicodeError,
    ):
        return False


# ============================================================
# JWT TOKEN CREATION
# ============================================================

def create_access_token(
    user_id: int,
    expires_delta: timedelta | None = None,
) -> str:
    """
    Create a JWT access token for an authenticated user.

    The user ID is stored in the `sub` claim.
    """

    if expires_delta is None:
        expires_delta = timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES
        )

    now = datetime.now(timezone.utc)
    expire = now + expires_delta

    payload = {
        "sub": str(user_id),
        "iat": now,
        "exp": expire,
    }

    return jwt.encode(
        payload,
        JWT_SECRET,
        algorithm=ALGORITHM,
    )


# ============================================================
# JWT TOKEN DECODING
# ============================================================

def decode_access_token(
    token: str,
) -> dict:
    """
    Decode and validate a JWT access token.

    Raises:
        jwt.InvalidTokenError:
            When the token is invalid or expired.
    """

    return jwt.decode(
        token,
        JWT_SECRET,
        algorithms=[ALGORITHM],
    )