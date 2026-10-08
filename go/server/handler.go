// Package server exposes GET /api/letsbot/identity-token.
package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/Lets-Bot/letsbot-identity-examples/go/identity"
)

// User is whatever your auth layer returns.
type User struct{ ID, Name, Email, Phone string }

// DemoAuth is a placeholder — replace it with your own session / auth lookup.
func DemoAuth(r *http.Request) *User {
	if strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") == "demo-session" {
		return &User{ID: "user-42", Name: "Sara", Email: "sara@example.com", Phone: "+966501234567"}
	}
	return nil
}

// IdentityTokenHandler returns {"token": "...", "expires_at": <unix>} for the signed-in user.
func IdentityTokenHandler(secret string, auth func(*http.Request) *User) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		user := auth(r)
		if user == nil {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthenticated"}`))
			return
		}
		now := time.Now()
		token, err := identity.Create(identity.Options{
			UserID: user.ID, Secret: secret, TTL: identity.DefaultTTL, Now: now,
			Name: user.Name, Email: user.Email, Phone: user.Phone,
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError) // never echo the error: it may hint at the secret setup
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"token": token, "expires_at": now.Add(identity.DefaultTTL).Unix()})
	}
}
