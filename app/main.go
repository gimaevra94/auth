package main

import (
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
	"github.com/pkg/errors"

	"github.com/gimaevra94/auth/app/auth"
	"github.com/gimaevra94/auth/app/data"
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
	tools.InitStore()
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
	}

	for _, v := range envVars {
		if os.Getenv(v) == "" {
			log.Printf("%+v", errors.WithStack(errors.New(v+": "+data.NotExistErr)))
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

	r.Get(signUpURL, data.SignUp)
	r.Post("/input_check", auth.InputCheck)
	r.Get(data.CodeSendURL, data.CodeSend)
	r.Post(data.UserAddURL, auth.UserAdd)

	r.Get(data.BadSignUpURL, data.BadSignUp)
	r.Get(data.BadEmailURL, data.BadEmail)
	r.Get(data.WrongCodeURL, data.WrongCode)
	r.Get(data.UserNotExistURL, data.UserNotExist)

	r.Get(data.SignInURL, data.SignIn)
	r.Post(logInURL, auth.LogIn)
	r.Get(data.BadSignInURL, data.BadSignIn)
	r.Get(data.AlreadyExistURL, data.UserAllreadyExist)

	r.Get("/yauth", auth.YandexAuthHandler)
	r.Get("/ya_callback", auth.YandexCallbackHandler)

	r.Get(data.RequestErrorURL, data.RequestError)
	r.Get(data.Err500URL, data.Err500)

	r.With(auth.IsExpiredTokenMW).Get(data.HomeURL,
		data.Home)
	r.With(auth.IsExpiredTokenMW).Post(data.LogoutURL, auth.Logout)

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
	loginCounter := 3
	tools.SessionDataSet(w, r, loginCounter)

	httpCookie, err := r.Cookie("token")
	if err != nil {
		http.Redirect(w, r, signUpURL, http.StatusFound)
		return
	}

	if httpCookie.Value == "" {
		errors.WithStack(errors.New("token: " + data.NotExistErr))
		http.Redirect(w, r, signUpURL, http.StatusFound)
		return
	}

	_, err = tools.IsValidToken(w, r)
	if err != nil {
		log.Printf("%+v", errors.WithStack(err))
		http.Redirect(w, r, signUpURL, http.StatusFound)
		return
	}

	http.Redirect(w, r, data.HomeURL, http.StatusFound)
}
