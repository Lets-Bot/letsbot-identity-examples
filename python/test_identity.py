"""python -m unittest -v"""
import base64
import hashlib
import hmac
import importlib.util
import json
import unittest

import letsbot_identity_stdlib as stdlib_impl

SECRET = "letsbot-test-identity-secret-0123456789"
IAT = 1791446400
HAS_PYJWT = importlib.util.find_spec("jwt") is not None
HAS_FLASK = importlib.util.find_spec("flask") is not None


def verify_hs256(token: str, secret: str):
    """Independent HS256 check (no JWT library). Returns the claims or None."""
    h, p, s = token.split(".")
    unb64 = lambda v: base64.urlsafe_b64decode(v + "=" * (-len(v) % 4))  # noqa: E731
    if json.loads(unb64(h))["alg"] != "HS256":
        return None
    expected = hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return json.loads(unb64(p)) if hmac.compare_digest(expected, unb64(s)) else None


class StdlibTest(unittest.TestCase):
    def test_verifies_with_sub_iat_exp(self):
        token = stdlib_impl.create_identity_token(42, SECRET, name="سارة", phone="", now=IAT)
        self.assertEqual(verify_hs256(token, SECRET), {"sub": "42", "iat": IAT, "exp": IAT + 86400, "name": "سارة"})
        self.assertIsNone(verify_hs256(token, SECRET + "x"))

    def test_rejects_bad_input(self):
        for args in (("u", ""), ("", SECRET), ("x" * 192, SECRET), ("u", SECRET, 604801), ("u", SECRET, 0)):
            with self.assertRaises(ValueError):
                stdlib_impl.create_identity_token(*args)

    @unittest.skipUnless(HAS_PYJWT, "PyJWT not installed")
    def test_pyjwt_decodes_stdlib_token(self):
        import jwt
        claims = jwt.decode(stdlib_impl.create_identity_token("user-42", SECRET), SECRET, algorithms=["HS256"])
        self.assertEqual(claims["sub"], "user-42")
        self.assertEqual(claims["exp"] - claims["iat"], 86400)


@unittest.skipUnless(HAS_PYJWT, "PyJWT not installed")
class PyJwtTest(unittest.TestCase):
    def test_verifies_with_sub_iat_exp(self):
        import letsbot_identity_pyjwt as pyjwt_impl
        token = pyjwt_impl.create_identity_token("user-42", SECRET, 3600, email="sara@example.com", now=IAT)
        self.assertEqual(verify_hs256(token, SECRET),
                         {"sub": "user-42", "iat": IAT, "exp": IAT + 3600, "email": "sara@example.com"})
        # Both implementations produce byte-identical tokens for the same claims.
        self.assertEqual(token, stdlib_impl.create_identity_token("user-42", SECRET, 3600, email="sara@example.com", now=IAT))


@unittest.skipUnless(HAS_PYJWT and HAS_FLASK, "PyJWT/Flask not installed")
class EndpointTest(unittest.TestCase):
    def test_endpoint(self):
        from app import create_app
        client = create_app(SECRET).test_client()
        self.assertEqual(client.get("/api/letsbot/identity-token").status_code, 401)

        res = client.get("/api/letsbot/identity-token", headers={"Authorization": "Bearer demo-session"})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers["Cache-Control"], "no-store")
        claims = verify_hs256(res.json["token"], SECRET)
        self.assertEqual(claims["sub"], "user-42")
        self.assertEqual(claims["exp"] - claims["iat"], 86400)
        self.assertEqual(res.json["expires_at"], claims["exp"])


if __name__ == "__main__":
    unittest.main()
