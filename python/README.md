# Python

| File | What |
|---|---|
| `letsbot_identity_stdlib.py` | `create_identity_token()` with the standard library only (`hmac`, `hashlib`) |
| `letsbot_identity_pyjwt.py` | Same with [PyJWT](https://pyjwt.readthedocs.io/) |
| `app.py` | Flask `GET /api/letsbot/identity-token` (placeholder auth — replace with your own) |

```python
from letsbot_identity_stdlib import create_identity_token
token = create_identity_token(user.id, os.environ["LETSBOT_IDENTITY_SECRET"], 24 * 3600, name=user.name)
```

Django / FastAPI: call the same function inside a view that requires login and return
`{"token": token}` with `Cache-Control: no-store`.

## Run

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt     # the stdlib tests run without it
python -m unittest -v
LETSBOT_IDENTITY_SECRET=... flask --app app run
curl -H 'Authorization: Bearer demo-session' http://localhost:5000/api/letsbot/identity-token
```
