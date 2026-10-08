// Package identity mints LetsBot In-App Chat identity tokens with the standard library only.
package identity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"
)

// MaxTTL is the longest lifetime LetsBot accepts. DefaultTTL is the recommended one.
const (
	MaxTTL     = 7 * 24 * time.Hour
	DefaultTTL = 24 * time.Hour
)

// Claims of a LetsBot identity token.
type Claims struct {
	Sub   string `json:"sub"`
	Iat   int64  `json:"iat"`
	Exp   int64  `json:"exp"`
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
	Phone string `json:"phone,omitempty"`
}

// Options for Create. Now defaults to time.Now(), TTL to DefaultTTL.
type Options struct {
	UserID string
	Secret string
	TTL    time.Duration
	Name   string
	Email  string
	Phone  string
	Now    time.Time
}

// Create returns a JWT (HS256) signed with the app's Identity Secret.
func Create(o Options) (string, error) {
	if o.Secret == "" {
		return "", errors.New("identity secret is missing")
	}
	sub := strings.TrimSpace(o.UserID)
	if sub == "" || utf8.RuneCountInString(sub) > 191 {
		return "", errors.New("user id must be 1-191 characters")
	}
	ttl := o.TTL
	if ttl == 0 {
		ttl = DefaultTTL
	}
	if ttl < time.Second || ttl > MaxTTL {
		return "", errors.New("ttl must be between 1s and 7 days")
	}
	now := o.Now
	if now.IsZero() {
		now = time.Now()
	}

	claims := Claims{Sub: sub, Iat: now.Unix(), Exp: now.Add(ttl).Unix(), Name: o.Name, Email: o.Email, Phone: o.Phone}
	header, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	input := enc.EncodeToString(header) + "." + enc.EncodeToString(payload)
	mac := hmac.New(sha256.New, []byte(o.Secret))
	mac.Write([]byte(input))
	return input + "." + enc.EncodeToString(mac.Sum(nil)), nil
}
