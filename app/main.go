package main

import (
	"log"
	"net/http"

	"github.com/gimaevra94/auth/app/auth"
	"github.com/gimaevra94/auth/app/constsandstructs"
	"github.com/gimaevra94/auth/app/validator"
)

func main() {
	auth.SignUpRouter()
	http.HandleFunc("/", authentication)

	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal("Failed to start server: ", err)
	}
}

func authentication(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("Authorization")
	if err != nil {
		http.Redirect(w, r, constsandstructs.SignUpURL, http.StatusFound)
	}

	err = validator.IsValidToken(r, cookie.Value)
	if err != nil {
		http.Redirect(w, r, constsandstructs.SignInURL, http.StatusFound)
	}

	w.Header().Set("Authorization", "Bearer"+cookie.Value)
	w.Write([]byte(cookie.Value))
	auth.Home(w, r)
}
