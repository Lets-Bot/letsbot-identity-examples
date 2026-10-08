"""LetsBot In-App Chat identity token using PyJWT (pip install PyJWT)."""
import time
from typing import Optional

import jwt

MAX_TTL_SECONDS = 7 * 24 * 60 * 60


def create_identity_token(user_id, secret: str, ttl_seconds: int = 24 * 60 * 60, *, name: Optional[str] = None,
                          email: Optional[str] = None, phone: Optional[str] = None, now: Optional[int] = None) -> str:
    if not secret:
        raise ValueError("Identity Secret is missing")
    sub = str(user_id if user_id is not None else "").strip()
    if not sub or len(sub) > 191 or not 0 < ttl_seconds <= MAX_TTL_SECONDS:
        raise ValueError("user_id must be 1-191 characters and ttl_seconds at most 7 days")

    iat = int(time.time()) if now is None else int(now)
    claims = {"sub": sub, "iat": iat, "exp": iat + ttl_seconds}
    claims.update({k: v for k, v in (("name", name), ("email", email), ("phone", phone)) if v})
    return jwt.encode(claims, secret, algorithm="HS256")
