package main

import (
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
	"github.com/pkg/errors"

	"github.com/gimaevra94/auth/app/auth"
	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/go-chi/chi"
)

const (
	signUpURL = "/sign_up"
	logInURL  = "/log_in"
)

func main() {
	initEnv()
	initDB()
	data.InitStore()
	r := initRouter()
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
		"GOOGLE_CAPTCHA_SECRET",
	}

	for _, v := range envVars {
		if os.Getenv(v) == "" {
			log.Printf("%+v", errors.WithStack(errors.New(v+": "+consts.NotExistErr)))
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

func initRouter() *chi.Mux {
	r := chi.NewRouter()

	r.Get("/", authStart)

	r.Get(signUpURL, consts.SignUp)
	r.Post(consts.InputCheckURL, auth.InputCheck)
	r.Get(consts.CodeSendURL, consts.CodeSend)
	r.Post(consts.UserAddURL, auth.UserAdd)

	r.Get(consts.BadSignUpURL, consts.BadSignUp)
	r.Get(consts.BadEmailURL, consts.BadEmail)
	r.Get(consts.WrongCodeURL, consts.WrongCode)
	r.Get(consts.UserNotExistURL, consts.UserNotExist)

	r.Get(consts.SignInURL, consts.SignIn)
	r.Post(logInURL, auth.LogIn)
	r.Get(consts.BadSignInURL, consts.BadSignIn)
	r.Get(consts.AlreadyExistURL, consts.UserAllreadyExist)

	r.Get("/yauth", auth.YandexAuthHandler)
	r.Get("/ya_callback", auth.YandexCallbackHandler)

	r.Get(consts.Err500URL, consts.Err500)

	r.With(auth.IsExpiredTokenMW).Get(consts.HomeURL,
		consts.Home)
	r.With(auth.IsExpiredTokenMW).Post(consts.LogoutURL, auth.Logout)

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
		errors.WithStack(errors.New("token: " + consts.NotExistErr))
		http.Redirect(w, r, signUpURL, http.StatusFound)
		return
	}

	_, err = tools.IsValidToken(w, r)
	if err != nil {
		log.Printf("%+v", errors.WithStack(err))
		http.Redirect(w, r, signUpURL, http.StatusFound)
		return
	}

	http.Redirect(w, r, consts.HomeURL, http.StatusFound)
}
