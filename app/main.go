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
		log.Fatal(consts.DBStartFailedErr, err)
	}
	defer database.DB.Close()

	r := auth.Router()
	r.Get(consts.SlashStr, authentication)

	err = http.ListenAndServe(consts.ServerPortStr, r)
	if err != nil {
		log.Fatal(consts.DBStartServerFailedErr, err)
	}
}

func authentication(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(consts.CookieNameStr)
	if err != nil {
		http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
	}

	_, err = validator.IsValidToken(r)
	if err != nil {
		http.Redirect(w, r, consts.LogInURL, http.StatusFound)
	}

	w.Header().Set(consts.CookieNameStr, consts.BearerStr+cookie.Value)
	w.Write([]byte(cookie.Value))
	http.Redirect(w, r, consts.HomeURL, http.StatusFound)
}
