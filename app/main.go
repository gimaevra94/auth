package main

import (
	"log"
	"net/http"
	"os"

	"github.com/gimaevra94/auth/app/auth"
	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/tmpls"
	"github.com/go-chi/chi"
	"github.com/joho/godotenv"
	"github.com/pkg/errors"
)

const (
	validateSignUpInputURL       = "/validate-sign-up-input"
	setUserInDbURL               = "/set-user-in-db"
	validateSignInInputURL       = "/validate-sign-in-input"
	generatePasswordResetLinkURL = "/generate-password-reset-link"
	yandexCallbackURL            = "/ya_callback"
	setNewPasswordURL            = "/set-new-password"
	setFirstTimePasswordURL      = "/set-first-time-password"
	logoutURL                    = "/logout"
	simpleLogoutURL              = "/simple-logout"
)

func main() {
	initEnv()
	initDb()
	data.InitStore()
	r := initRouter()
	serverStart(r)
	defer data.DbClose()
}

func initEnv() {
	if err := godotenv.Load("../public/.env"); err != nil {
		log.Printf("%+v", errors.WithStack(err))
		return
	}

	envVars := []string{
		"CAPTCHA_STORE_SESSION_SECRET_KEY",
		"LOGIN_STORE_SESSION_AUTH_KEY",
		"LOGIN_STORE_SESSION_ENCRYPTION_KEY",
		"JWT_SECRET",
		"DB_PASSWORD",
		"SERVER_EMAIL",
		"SERVER_EMAIL_PASSWORD",
		"GOOGLE_CAPTCHA_SECRET",
		"clientId",
		"clientSecret",
	}

	for _, v := range envVars {
		if os.Getenv(v) == "" {
			err := errors.New(v + " not exist")
			log.Printf("%+v", errors.WithStack(err))
			return
		}
	}
}

func initDb() {
	if err := data.DbConn(); err != nil {
		log.Printf("%+v", errors.WithStack(err))
		return
	}
}

func initRouter() *chi.Mux {
	r := chi.NewRouter()

	r.Handle("/public/*", http.StripPrefix("/public/", http.FileServer(http.Dir("../public"))))

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
	})

	r.With(auth.AuthGuardForSignUpAndSignInPath).Get(consts.SignUpURL, tmpls.SignUp)
	r.Post(validateSignUpInputURL, auth.ValidateSignUpInput)
	r.With(auth.AuthGuardForServerAuthCodeSendPath).Get(consts.ServerAuthCodeSendURL, tmpls.ServerAuthCodeSend)
	r.Post(setUserInDbURL, auth.SetUserInDb)

	r.With(auth.AuthGuardForSignUpAndSignInPath).Get(consts.SignInURL, tmpls.SignIn)
	r.Post(validateSignInInputURL, auth.ValidateSignInInput)

	r.Get("/yauth", auth.YandexAuthHandler)
	r.Get(yandexCallbackURL, auth.YandexCallbackHandler)

	r.Get(consts.GeneratePasswordResetLinkURL, tmpls.GeneratePasswordResetLink)
	r.Post(generatePasswordResetLinkURL, auth.GeneratePasswordResetLink)
	r.With(auth.ResetTokenGuard).Get(setNewPasswordURL, tmpls.SetNewPassword)
	r.Post(setNewPasswordURL, auth.SetNewPassword)
	r.With(auth.AuthGuardForHomePath).Get(setFirstTimePasswordURL, tmpls.SetFirstTimePassword)
	r.Post(setFirstTimePasswordURL, auth.SetFirstTimePassword)

	r.With(auth.AuthGuardForHomePath).Get(consts.HomeURL, tmpls.Home)

	r.With(auth.AuthGuardForHomePath).Get(logoutURL, auth.Logout)
	r.With(auth.AuthGuardForHomePath).Get(simpleLogoutURL, auth.SimpleLogout)

	r.Get("/clear", data.ClearCookiesDev)

	r.Get(consts.Err500URL, tmpls.Err500)

	return r
}

func serverStart(r *chi.Mux) {
	if err := http.ListenAndServe(":8080", r); err != nil {
		log.Printf("%+v", errors.WithStack(err))
		return
	}
}
