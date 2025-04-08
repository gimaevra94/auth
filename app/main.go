package main

import (
	"log"
	"net/http"

	"github.com/gimaevra94/auth/app/auth"
	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/database"
	"github.com/gimaevra94/auth/app/validator"
)

func main() {
	err := database.DBConn()
	if err != nil {
		log.Fatal("Failed to start database: ", err)
	}
	defer database.DB.Close()

	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal("Failed to start server: ", err)
	}

	auth.Router()
	http.HandleFunc("/", authentication)
}

func authentication(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("Authorization")
	if err != nil {
		http.Redirect(w, r, consts.SignUpLoginInputURL, http.StatusFound)
	}

	err = validator.IsValidToken(r, cookie.Value)
	if err != nil {
		http.Redirect(w, r, consts.SignInLoginInputURL, http.StatusFound)
	}

	w.Header().Set("Authorization", "Bearer"+cookie.Value)
	w.Write([]byte(cookie.Value))
	http.ServeFile(w, r, consts.HomeURL)
}
