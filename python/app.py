"""Flask endpoint: GET /api/letsbot/identity-token (run: LETSBOT_IDENTITY_SECRET=... flask --app app run)."""
import os
import time
from typing import Optional

from flask import Flask, g, jsonify, request

from letsbot_identity_pyjwt import create_identity_token

# Placeholder authentication — replace with your own session / login_required.
DEMO_SESSIONS = {
    "demo-session": {"id": "user-42", "name": "Sara", "email": "sara@example.com", "phone": "+966501234567"},
}


def create_app(secret: Optional[str] = None) -> Flask:
    app = Flask(__name__)
    app.config["LETSBOT_IDENTITY_SECRET"] = secret or os.environ.get("LETSBOT_IDENTITY_SECRET", "")

    @app.get("/api/letsbot/identity-token")
    def identity_token():
        bearer = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        g.user = DEMO_SESSIONS.get(bearer)
        if g.user is None:
            return jsonify(error="unauthenticated"), 401

        ttl = 24 * 60 * 60  # 24 h recommended, 7 days max
        now = int(time.time())
        token = create_identity_token(g.user["id"], app.config["LETSBOT_IDENTITY_SECRET"], ttl,
                                      name=g.user["name"], email=g.user["email"], phone=g.user["phone"], now=now)
        response = jsonify(token=token, expires_at=now + ttl)
        response.headers["Cache-Control"] = "no-store"
        return response

    return app


app = create_app()
