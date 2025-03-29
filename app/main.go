package main

import (
	"log"
	"net/http"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/sessionmanager"
	"github.com/gimaevra94/auth/app/validator"
)

func main() {
	sessionmanager.SignUpRouter()
	http.HandleFunc("/", authentication)

	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal("Failed to start server: ", err)
	}
}

func authentication(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("Authorization")
	if err != nil {
		http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
	}

	err = validator.IsValidToken(r, cookie.Value)
	if err != nil {
		http.Redirect(w, r, consts.SignInURL, http.StatusFound)
	}

	w.Header().Set("Authorization", "Bearer"+cookie.Value)
	w.Write([]byte(cookie.Value))
	sessionmanager.Home(w, r)
}
