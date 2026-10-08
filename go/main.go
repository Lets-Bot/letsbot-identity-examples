package main

import (
	"log"
	"net/http"
	"os"

	"github.com/Lets-Bot/letsbot-identity-examples/go/server"
)

func main() {
	secret := os.Getenv("LETSBOT_IDENTITY_SECRET")
	if secret == "" {
		log.Fatal("set LETSBOT_IDENTITY_SECRET")
	}
	http.Handle("/api/letsbot/identity-token", server.IdentityTokenHandler(secret, server.DemoAuth))
	log.Println("listening on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
