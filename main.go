package main

import (
	"log"
	"net/http"
	"os"

	"github.com/gimaevra94/auth/app"
	"github.com/gimaevra94/auth/app/auth"
	"github.com/joho/godotenv"
	"github.com/pkg/errors"

	"github.com/gimaevra94/auth/app/templates"
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
	}

	for _, v := range envVars {
		if os.Getenv(v) == "" {
			newErr := errors.New(app.NotExistErr)
			wrappedErr := errors.Wrap(newErr, v)
			log.Printf("%+v", wrappedErr)
			return
		}
	}
}

func dbStart() {
	err := app.DBConn()
	if err != nil {
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		return
	}
	defer app.DB.Close()
}

func routerStart() *chi.Mux {
	r := chi.NewRouter()
	r.Use(auth.IsExpiredTokenMW(store))

	r.Get("/", authStart)

	r.Get(signUpURL, templates.SignUp)
	r.Post("/input_check", auth.InputCheck(store))
	r.Get(app.CodeSendURL, auth.CodeSend(store))
	r.Post("/user_add", auth.UserAdd(store))

	r.Get(app.BadSignUpURL, templates.BadSignUp)
	r.Get(app.WrongCodeURL, templates.WrongCode)
	r.Get(app.UserNotExistURL, templates.UserNotExist)

	r.Get(app.SignInURL, templates.SignIn)
	r.Post(logInURL, auth.LogIn(store))
	r.Get(app.BadSignInURL, templates.BadSignIn)
	r.Get(app.AlreadyExistURL, templates.UserAllreadyExist)

	r.Get("/yauth", auth.YandexAuthHandler)
	r.Get("/yacallback", auth.YandexCallbackHandler)

	r.Get(app.RequestErrorURL, templates.RequestError)

	r.With(auth.IsExpiredTokenMW(store)).Get(app.HomeURL,
		templates.Home)
	r.With(auth.IsExpiredTokenMW(store)).Post(app.LogoutURL,
		auth.Logout(store))

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
	cookie, err := r.Cookie("auth")
	if err != nil {
		cookie := http.Cookie{
			Name:     "auth",
			Path:     "/set-token",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			Value:    "",
		}
		http.SetCookie(w, &cookie)
		http.Redirect(w, r, signUpURL, http.StatusFound)
		return
	}
	// проверить что все секреты есть убрать проверку секрета
	//убедиться что если куки есть то значение тоже есть

	token, err := tools.IsValidToken(r)
	if token == nil && err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, logInURL, http.StatusFound)
		return
	}
	if token == nil && err == nil {
		newErr := errors.New(app.NotExistErr)
		wrappedErr := errors.Wrap(newErr, "'tokenSecret'")
		log.Printf("%+v", wrappedErr)
		return
	}

	w.Header().Set("auth", cookie.Value)
	w.Write([]byte(cookie.Value))
	http.Redirect(w, r, app.HomeURL, http.StatusFound)
}
