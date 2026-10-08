# .NET (`System.IdentityModel.Tokens.Jwt`)

- `LetsBot.IdentityExample/LetsBotIdentityToken.cs` — `LetsBotIdentityToken.Create(userId, secret, lifetime, name, email, phone)`
- `LetsBot.IdentityExample/Program.cs` — ASP.NET Core minimal API `GET /api/letsbot/identity-token`
  `.RequireAuthorization()`; `DemoAuthHandler` is a placeholder — use your own authentication scheme.
- `LetsBot.IdentityExample.Tests` — xUnit: verifies the token with plain `HMACSHA256` and calls the endpoint.

Targets `net10.0`; change `TargetFramework` to `net8.0` / `net9.0` if that is what you run — the code is the same.
`System.IdentityModel.Tokens.Jwt` requires an HS256 key of at least 32 bytes.

## Run

```bash
dotnet test LetsBot.IdentityExample.Tests
LETSBOT_IDENTITY_SECRET=... dotnet run --project LetsBot.IdentityExample
curl -H 'Authorization: Bearer demo-session' http://localhost:5000/api/letsbot/identity-token
```
