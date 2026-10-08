# Go (standard library only)

- `identity/identity.go` — `identity.Create(identity.Options{UserID, Secret, TTL, Name, Email, Phone})`
- `server/handler.go` — `GET /api/letsbot/identity-token` handler (`DemoAuth` is a placeholder — pass your own auth)

```go
token, err := identity.Create(identity.Options{UserID: user.ID, Secret: os.Getenv("LETSBOT_IDENTITY_SECRET")})
```

## Run

```bash
go test ./...
LETSBOT_IDENTITY_SECRET=... go run .
curl -H 'Authorization: Bearer demo-session' http://localhost:8080/api/letsbot/identity-token
```
