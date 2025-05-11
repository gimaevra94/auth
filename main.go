package main

import (
	"log"
	"net/http"
	"os"

	"github.com/gimaevra94/auth/app"
	"github.com/gimaevra94/auth/app/auth"

	"github.com/gimaevra94/auth/app/templates"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/go-chi/chi"
	"github.com/gorilla/sessions"
)

var store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET_KEY")))

func main() {
	err := app.DBConn()
	if err != nil {
		log.Fatal(app.DBStartFailedErr, err)
	}
	defer app.DB.Close()

	r := Router()
	r.Get(app.SlashStr, authentication)

	err = http.ListenAndServe(app.ServerPortStr, r)
	if err != nil {
		log.Fatal(app.DBStartServerFailedErr, err)
	}
}

func authentication(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(app.CookieNameStr)
	if err != nil {
		http.Redirect(w, r, app.SignUpURL, http.StatusFound)
	}

	_, err = tools.IsValidToken(w, r)
	if err != nil {
		http.Redirect(w, r, app.LogInURL, http.StatusFound)
	}

	w.Header().Set(app.CookieNameStr, app.BearerStr+cookie.Value)
	w.Write([]byte(cookie.Value))
	http.Redirect(w, r, app.HomeURL, http.StatusFound)
}

func Router() *chi.Mux {
	r := chi.NewRouter()
	r.Use(auth.IsExpiredTokenMW(store))

	r.Get(app.SignUpURL, templates.SignUpLoginInput)
	r.Post(app.InputCheckURL, auth.InputCheck)
	r.Get(app.CodeSendURL, auth.CodeSend)
	r.Post(app.UserAddURL, auth.UserAdd)

	r.Get(app.SignInURL, templates.SignInLoginInput)
	r.Post(app.LogInURL, auth.LogIn)
	r.Get(app.BadSignInURL, templates.BadSignIn)

	r.Get(app.RequestErrorURL, templates.RequestError)

	r.With(auth.IsExpiredTokenMW(store)).Get(app.HomeURL,
		templates.Home)
	r.With(auth.IsExpiredTokenMW(store)).Post(app.LogoutURL,
		auth.Logout(store))

	return r
}
