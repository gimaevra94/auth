package main

import (
	"log"
	"net/http"
	"os"

	"github.com/gimaevra94/auth/app"
	"github.com/gimaevra94/auth/app/auth"
	"github.com/pkg/errors"

	"github.com/gimaevra94/auth/app/templates"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/go-chi/chi"
	"github.com/gorilla/sessions"
)

var store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET_KEY")))

func main() {
	err := app.DBConn()
	if err != nil {
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		log.Fatal(wrappedErr)
	}
	defer app.DB.Close()

	r := Router()
	r.Get(app.SlashStr, authentication)

	err = http.ListenAndServe(app.ServerPortStr, r)
	if err != nil {
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		log.Fatal(wrappedErr)
	}
}

func authentication(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(app.CookieNameStr)
	if err != nil {
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		http.Redirect(w, r, app.SignUpURL, http.StatusFound)
	}

	_, err = tools.IsValidToken(w, r)
	if err != nil {
		log.Printf("%+v", err)
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
	r.Post("/input_check", auth.InputCheck(store))
	r.Get(app.CodeSendURL, auth.CodeSend(store))
	r.Post("/user_add", auth.UserAdd(store))

	r.Get(app.BadSignUpURL, templates.BadSignUp)
	r.Get(app.WrongCodeURL, templates.WrongCode)
	r.Get(app.UserNotExistURL, templates.UserNotExist)

	r.Get(app.SignInURL, templates.SignInLoginInput)
	r.Post(app.LogInURL, auth.LogIn(store))
	r.Get(app.BadSignInURL, templates.BadSignIn)
	r.Get(app.AlreadyExistURL, templates.UserAllreadyExist)

	r.Get(app.RequestErrorURL, templates.RequestError)

	r.With(auth.IsExpiredTokenMW(store)).Get(app.HomeURL,
		templates.Home)
	r.With(auth.IsExpiredTokenMW(store)).Post(app.LogoutURL,
		auth.Logout(store))

	return r
}
