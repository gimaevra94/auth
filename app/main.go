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

var store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET_KEY")))

const (
	signUpURL = "/sign_up"
	logInURL  = "/log_in"
)

func main() {
	envStart()
	dbStart()
	r := routerStart()
	srvStart(r)
}

func envStart() {
	err := godotenv.Load(".env")
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

func dbStart() {
	err := data.DBConn()
	if err != nil {
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		return
	}
	defer data.DB.Close()
}

func routerStart() *chi.Mux {
	r := chi.NewRouter()
	r.Use(auth.IsExpiredTokenMW(store))

	r.Get("/", authStart)

	r.Get(signUpURL, data.SignUp)
	r.Post("/input_check", auth.InputCheck(store))
	r.Get(data.CodeSendURL, auth.CodeSend(store))
	r.Post("/user_add", auth.UserAdd(store))

	r.Get(data.BadSignUpURL, data.BadSignUp)
	r.Get(data.WrongCodeURL, data.WrongCode)
	r.Get(data.UserNotExistURL, data.UserNotExist)

	r.Get(data.SignInURL, data.SignIn)
	r.Post(logInURL, auth.LogIn(store))
	r.Get(data.BadSignInURL, data.BadSignIn)
	r.Get(data.AlreadyExistURL, data.UserAllreadyExist)

	r.Get("/yauth", auth.YandexAuthHandler)
	r.Get("/ya_callback", auth.YandexCallbackHandler)

	r.Get(data.RequestErrorURL, data.RequestError)

	r.With(auth.IsExpiredTokenMW(store)).Get(data.HomeURL,
		data.Home)

	return r
}

func srvStart(r *chi.Mux) {
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

	// проверить что все секреты есть убрать проверку секрета
	//убедиться что если куки есть то значение тоже есть

	token, err := tools.IsValidToken(w, r)
	if token == nil && err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, logInURL, http.StatusFound)
		return
	}
	if token == nil && err == nil {
		newErr := errors.New(data.NotExistErr)
		wrappedErr := errors.Wrap(newErr, "'tokenSecret'")
		log.Printf("%+v", wrappedErr)
		return
	}

	w.Header().Set("auth", httpCookie.Value)
	http.Redirect(w, r, data.HomeURL, http.StatusFound)
}
