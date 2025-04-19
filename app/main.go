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

	r := auth.Router()
	r.Get("/", authentication)

	err = http.ListenAndServe(":8080", r)
	if err != nil {
		log.Fatal("Failed to start server: ", err)
	}
}

func authentication(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("Authorization")
	if err != nil {
		http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
	}

	_, err = validator.IsValidToken(r)
	if err != nil {
		http.Redirect(w, r, consts.LoginInURL, http.StatusFound)
	}

	w.Header().Set("Authorization", "Bearer"+cookie.Value)
	w.Write([]byte(cookie.Value))
	http.ServeFile(w, r, consts.HomeURL)
}
