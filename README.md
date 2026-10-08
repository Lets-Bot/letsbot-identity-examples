# LetsBot In-App Chat — identity token examples

Server-side examples that mint the **identity token** a signed-in user's app passes to LetsBot In-App Chat
(`identify(identityToken)` in the iOS / Android / Flutter / React Native SDKs), and expose it from an authenticated
endpoint:

```
GET /api/letsbot/identity-token
Authorization: <your own app session>

200 {"token": "<JWT>", "expires_at": 1791532800}
```

| Folder | Stack | Token | Endpoint | Test |
|---|---|---|---|---|
| [`node/`](node) | Node 18+ | `node:crypto` (or `@letsbot/sdk`) | Express | `npm test` |
| [`php/`](php) | PHP 8.1+ | plain `hash_hmac` · `firebase/php-jwt` | plain PHP · Laravel route | `php tests/run.php` |
| [`python/`](python) | Python 3.9+ | stdlib `hmac` · PyJWT | Flask | `python -m unittest` |
| [`go/`](go) | Go 1.21+ | stdlib `crypto/hmac` | `net/http` | `go test ./...` |
| [`ruby/`](ruby) | Ruby 3.1+ | `jwt` gem | Rack | `ruby test/identity_test.rb` |
| [`dotnet/`](dotnet) | .NET 8+ (targets `net10.0`) | `System.IdentityModel.Tokens.Jwt` | ASP.NET Core minimal API | `dotnet test` |

## The token

A JWT signed with **HS256** using your app's **Identity Secret** (LetsBot panel → In-App Chat → your app).

| Claim | Required | Value |
|---|---|---|
| `sub` | yes | Your stable, never-reused user id, at most 191 characters |
| `iat` | yes | Issued-at, Unix seconds |
| `exp` | yes | Expiry, Unix seconds — at most `iat` + 7 days. **Recommended: 24 hours** |
| `name`, `email`, `phone` | no | Shown to your team in the LetsBot inbox. Claims win over the fields the app sends |

LetsBot allows 60 seconds of clock skew. Errors returned to the app by `identify`:

- `identity_expired` — `exp` has passed: fetch a fresh token from your endpoint and call `identify` again.
- `identity_invalid` — bad signature, malformed token, or no Identity Secret configured for the app.

## Rules for your endpoint

1. **Authenticate first.** Only return a token for the user who is signed in to *your* app — the token is what proves
   to LetsBot who the user is. Every example uses a placeholder `Bearer demo-session` lookup: replace it with your
   real session / auth middleware.
2. **Keep the secret on the server.** Read it from an environment variable (`LETSBOT_IDENTITY_SECRET` in these
   examples). Never ship it inside a mobile app, never commit it.
3. **Never log** the token or the secret. Send `Cache-Control: no-store`.
4. Use a `sub` that never changes for that user (database id, not e-mail) — a verified user on a new device joins
   their earlier conversation.

## Run the tests

Each folder's README lists its commands. Every test asserts that the token verifies with HS256 and carries `sub`,
`iat` and `exp`, and that the endpoint answers `401` without a session.

## Links

- Docs: https://letsbot.net/developers/in-app-chat
- Issues: https://github.com/Lets-Bot/letsbot-identity-examples/issues
- Contact: support@letsbot.net

MIT © 2026 LetsBot
