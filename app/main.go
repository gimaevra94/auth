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
	"github.com/gorilla/sessions"
)

var store *sessions.CookieStore

const (
	signUpURL = "/sign_up"
	logInURL  = "/log_in"
)

func main() {
	initEnv()
	initStore()
	initDB()

	defer data.DB.Close()

	r := initRouter()

	serverStart(r)
}

func initEnv() {
	err := godotenv.Load("../.env")
	if err != nil {
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		return
	}

	envVars := []string{
		"SESSION_SECRET",
		"JWT_SECRET",
		"DB_PASSWORD",
		"MAIL_SENDER_EMAIL",
		"MAIL_PASSWORD_FILE",
	}

	for _, v := range envVars {
		if os.Getenv(v) == "" {
			newErr := errors.New(data.NotExistErr)
			wrappedErr := errors.Wrap(newErr, v)
			log.Printf("%+v", wrappedErr)
			return
		}
	}
}

func initStore() {
	store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET")))
}

func initDB() {
	err := data.DBConn()
	if err != nil {
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		return
	}
}

func initRouter() *chi.Mux {
	r := chi.NewRouter()

	r.Get("/", authStart)

	r.Get(signUpURL, data.SignUp)
	r.Post("/input_check", auth.InputCheck(store))
	r.Get(data.CodeSendURL, auth.CodeSend(store))
	r.Post("/user_add", auth.UserAdd(store))

	r.Get(data.BadSignUpURL, data.BadSignUp)
	r.Get(data.BadEmailURL, data.BadEmail)
	r.Get(data.WrongCodeURL, data.WrongCode)
	r.Get(data.UserNotExistURL, data.UserNotExist)

	r.Get(data.SignInURL, data.SignIn)
	r.Post(logInURL, auth.LogIn(store))
	r.Get(data.BadSignInURL, data.BadSignIn)
	r.Get(data.AlreadyExistURL, data.UserAllreadyExist)

	r.Get("/yauth", auth.YandexAuthHandler)
	r.Get("/ya_callback", auth.YandexCallbackHandler(store))

	r.Get(data.RequestErrorURL, data.RequestError)

	r.With(auth.IsExpiredTokenMW(store)).Get(data.HomeURL,
		data.Home)

	return r
}

func serverStart(r *chi.Mux) {
	err := http.ListenAndServe(":8080", r)
	if err != nil {
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		log.Fatal(wrappedErr)
	}
}

func authStart(w http.ResponseWriter, r *http.Request) {
	httpCookie, err := r.Cookie("auth")
	if err != nil {
		dataCookie := data.NewCookie()
		httpCookie := dataCookie.GetCookie()
		http.SetCookie(w, httpCookie)
		http.Redirect(w, r, signUpURL, http.StatusFound)
		return
	}

	if httpCookie.Value == "" {
		http.Redirect(w, r, signUpURL, http.StatusFound)
		return
	}

	token, err := tools.IsValidToken(w, r)
	if token == nil && err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, logInURL, http.StatusFound)
		return
	}

	w.Header().Set("auth", httpCookie.Value)

	http.Redirect(w, r, data.HomeURL, http.StatusFound)
}
