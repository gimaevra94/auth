package main

import (
	"log"
	"net/http"
	"os"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/database"
	"github.com/gimaevra94/auth/app/htmlfiles"
	"github.com/gimaevra94/auth/app/logout"
	"github.com/gimaevra94/auth/app/signin"
	"github.com/gimaevra94/auth/app/signup"
	"github.com/gimaevra94/auth/app/validator"
	"github.com/go-chi/chi"
	"github.com/gorilla/sessions"
)

var store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET_KEY")))

func main() {
	err := database.DBConn()
	if err != nil {
		log.Fatal(consts.DBStartFailedErr, err)
	}
	defer database.DB.Close()

	r := Router()
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

	_, err = validator.IsValidToken(w, r)
	if err != nil {
		http.Redirect(w, r, consts.LogInURL, http.StatusFound)
	}

	w.Header().Set(consts.CookieNameStr, consts.BearerStr+cookie.Value)
	w.Write([]byte(cookie.Value))
	http.Redirect(w, r, consts.HomeURL, http.StatusFound)
}

func Router() *chi.Mux {
	r := chi.NewRouter()
	r.Use(logout.IsExpiredTokenMW(store))

	r.Get(consts.SignUpURL, htmlfiles.SignUpLoginInput)
	r.Post(consts.InputCheckURL, signup.InputCheck)
	r.Get(consts.CodeSendURL, signup.CodeSend)
	r.Post(consts.UserAddURL, signup.UserAdd)

	r.Get(consts.SignInURL, htmlfiles.SignInLoginInput)
	r.Post(consts.LogInURL, signin.LogIn)

	r.Get(consts.RequestErrorURL, htmlfiles.RequestError)

	r.With(logout.IsExpiredTokenMW(store)).Get(consts.HomeURL,
		htmlfiles.Home)
	r.With(logout.IsExpiredTokenMW(store)).Post(consts.LogoutURL,
		logout.Logout(store))

	return r
}
