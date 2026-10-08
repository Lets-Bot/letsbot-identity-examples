"""LetsBot In-App Chat identity token using only the Python standard library."""
import base64
import hashlib
import hmac
import json
import time
from typing import Optional

MAX_TTL_SECONDS = 7 * 24 * 60 * 60


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def create_identity_token(user_id, secret: str, ttl_seconds: int = 24 * 60 * 60, *, name: Optional[str] = None,
                          email: Optional[str] = None, phone: Optional[str] = None, now: Optional[int] = None) -> str:
    """JWT, HS256, signed with the app's Identity Secret. Claims: sub, iat, exp (+ optional name, email, phone)."""
    if not isinstance(secret, str) or not secret:
        raise ValueError("Identity Secret is missing")
    sub = str(user_id if user_id is not None else "").strip()
    if not sub or len(sub) > 191:
        raise ValueError("user_id must be 1-191 characters")
    if not isinstance(ttl_seconds, int) or not 0 < ttl_seconds <= MAX_TTL_SECONDS:
        raise ValueError("ttl_seconds must be between 1 and 604800 (7 days)")

    iat = int(time.time()) if now is None else int(now)
    claims = {"sub": sub, "iat": iat, "exp": iat + ttl_seconds}
    for key, value in (("name", name), ("email", email), ("phone", phone)):
        if value:
            claims[key] = value

    def encode(value: dict) -> str:
        return _b64(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))

    signing_input = encode({"alg": "HS256", "typ": "JWT"}) + "." + encode(claims)
    signature = hmac.new(secret.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256).digest()
    return signing_input + "." + _b64(signature)
