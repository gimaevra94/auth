package main

import (
	"log"
	"net/http"
	"os"

	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	"github.com/pkg/errors"

	"github.com/gimaevra94/auth/app/auth"
	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/tmpls"
	"github.com/go-chi/chi"
)

const (
	signUpURL = "/sign_up"
	logInURL  = "/log_in"
)

func main() {
	initEnv()
	initDB()
	s := data.InitStore()
	r := initRouter(s)
	serverStart(r)
	defer data.DBClose()
}

func initEnv() {
	err := godotenv.Load("../.env")
	if err != nil {
		log.Printf("%+v", errors.WithStack(err))
		return
	}

	envVars := []string{
		"SESSION_SECRET",
		"JWT_SECRET",
		"DB_PASSWORD",
		"MAIL_SENDER_EMAIL",
		"MAIL_PASSWORD",
	}

	for _, v := range envVars {
		if os.Getenv(v) == "" {
			log.Printf("%+v", errors.WithStack(errors.New(v+": "+tmpls.NotExistErr)))
			return
		}
	}
}

func initDB() {
	err := data.DBConn()
	if err != nil {
		log.Printf("%+v", errors.WithStack(err))
		return
	}
}

func initRouter(s *sessions.CookieStore) *chi.Mux {
	r := chi.NewRouter()

	r.Get("/", authStart)

	r.Get(signUpURL, tmpls.SignUp)
	r.Post(tmpls.InputCheckURL, auth.InputCheck(s))
	r.Get(tmpls.CodeSendURL, tmpls.CodeSend)
	r.Post(tmpls.UserAddURL, auth.UserAdd)

	r.Get(tmpls.BadSignUpURL, tmpls.BadSignUp)
	r.Get(tmpls.BadEmailURL, tmpls.BadEmail)
	r.Get(tmpls.WrongCodeURL, tmpls.WrongCode)
	r.Get(tmpls.UserNotExistURL, tmpls.UserNotExist)

	r.Get(tmpls.SignInURL, tmpls.SignIn)
	r.Post(logInURL, auth.LogIn)
	r.Get(tmpls.BadSignInURL, tmpls.BadSignIn)
	r.Get(tmpls.AlreadyExistURL, tmpls.UserAllreadyExist)

	r.Get("/yauth", auth.YandexAuthHandler)
	r.Get("/ya_callback", auth.YandexCallbackHandler)

	r.Get(tmpls.Err500URL, tmpls.RequestError)
	r.Get(tmpls.Err500URL, tmpls.Err500)

	r.With(auth.IsExpiredTokenMW).Get(tmpls.HomeURL,
		tmpls.Home)
	r.With(auth.IsExpiredTokenMW).Post(tmpls.LogoutURL, auth.Logout)

	return r
}

func serverStart(r *chi.Mux) {
	err := http.ListenAndServe(":8080", r)
	if err != nil {
		log.Printf("%+v", errors.WithStack(err))
		return
	}
}

func authStart(w http.ResponseWriter, r *http.Request) {
	httpCookie, err := r.Cookie("token")
	if err != nil {
		http.Redirect(w, r, signUpURL, http.StatusFound)
		return
	}

	if httpCookie.Value == "" {
		errors.WithStack(errors.New("token: " + tmpls.NotExistErr))
		http.Redirect(w, r, signUpURL, http.StatusFound)
		return
	}

	_, err = data.IsValidToken(w, r)
	if err != nil {
		log.Printf("%+v", errors.WithStack(err))
		http.Redirect(w, r, signUpURL, http.StatusFound)
		return
	}

	http.Redirect(w, r, tmpls.HomeURL, http.StatusFound)
}
