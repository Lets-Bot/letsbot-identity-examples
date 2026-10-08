package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Lets-Bot/letsbot-identity-examples/go/identity"
)

const secret = "letsbot-test-identity-secret-0123456789"

func verifyHS256(t *testing.T, token, key string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT")
	}
	enc := base64.RawURLEncoding
	header, _ := enc.DecodeString(parts[0])
	var h map[string]string
	if err := json.Unmarshal(header, &h); err != nil || h["alg"] != "HS256" {
		t.Fatalf("bad header %s", header)
	}
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	sig, _ := enc.DecodeString(parts[2])
	if !hmac.Equal(sig, mac.Sum(nil)) {
		t.Fatalf("signature does not verify")
	}
	payload, _ := enc.DecodeString(parts[1])
	var claims map[string]any
	_ = json.Unmarshal(payload, &claims)
	return claims
}

func TestCreate(t *testing.T) {
	token, err := identity.Create(identity.Options{UserID: "42", Secret: secret, Now: time.Unix(1791446400, 0)})
	if err != nil {
		t.Fatal(err)
	}
	c := verifyHS256(t, token, secret)
	if c["sub"] != "42" || c["iat"] != float64(1791446400) || c["exp"] != float64(1791446400+86400) || c["name"] != nil {
		t.Fatalf("claims %v", c)
	}
}

func TestCreateRejectsBadInput(t *testing.T) {
	for _, o := range []identity.Options{
		{UserID: "u"},
		{UserID: " ", Secret: secret},
		{UserID: strings.Repeat("x", 192), Secret: secret},
		{UserID: "u", Secret: secret, TTL: 8 * 24 * time.Hour},
	} {
		if _, err := identity.Create(o); err == nil {
			t.Fatalf("expected error for %+v", o)
		}
	}
}

func TestHandler(t *testing.T) {
	h := IdentityTokenHandler(secret, DemoAuth)

	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/api/letsbot/identity-token", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/letsbot/identity-token", nil)
	req.Header.Set("Authorization", "Bearer demo-session")
	rec = httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("want 200 no-store, got %d", rec.Code)
	}
	var body struct {
		Token     string `json:"token"`
		ExpiresAt int64  `json:"expires_at"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	c := verifyHS256(t, body.Token, secret)
	if c["sub"] != "user-42" || c["exp"].(float64)-c["iat"].(float64) != 86400 || int64(c["exp"].(float64)) != body.ExpiresAt {
		t.Fatalf("claims %v", c)
	}
}
