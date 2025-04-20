package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	firebase "firebase.google.com/go"
	"firebase.google.com/go/auth"
	"google.golang.org/api/option"
)

var firebaseAuthClient *auth.Client

func initFirebase() {
	opt := option.WithCredentialsFile("path/to/serviceAccountKey.json")
	app, err := firebase.NewApp(context.Background(), nil, opt)
	if err != nil {
		log.Fatalf("error initializing firebase app: %v", err)
	}
	client, err := app.Auth(context.Background())
	if err != nil {
		log.Fatalf("error getting auth client: %v", err)
	}
	firebaseAuthClient = client
}

func googleAuthHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	token, err := firebaseAuthClient.VerifyIDToken(context.Background(), req.Token)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	userID := token.UID
	email := token.Claims["email"].(string)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "User authenticated successfully!",
		"uid":     userID,
		"email":   email,
	})
}

func main() {
	initFirebase()
	http.HandleFunc("/api/auth/google", googleAuthHandler)
	log.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
