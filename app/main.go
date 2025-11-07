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
	ValidateSignUpInputURL       = "/Validate-sign-up-input"
	SetUserInDbURL               = "/set-user-in-db"
	ValidateSignInInputURL       = "/Validate-sign-in-input"
	GeneratePasswordResetLinkURL = "/generate-password-reset-link"
	YandexCallbackURL            = "/ya_callback"
	SetNewPasswordURL            = "/set-new-password"
	SetFirstTimePasswordURL      = "/set-first-time-password"
	LogoutURL                    = "/logout"
	SimpleLogoutURL              = "/simple-logout"
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
		"Db_PASSWORD",
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

	r.With(auth.AuthGuardForSignInPath).Get(consts.SignUpURL, tmpls.SignUp)
	r.Post(ValidateSignUpInputURL, auth.ValidateSignUpInput)
	r.With(auth.AuthGuardForSignUpPath).Get(consts.CodeSendURL, tmpls.CodeSend)
	r.Post(SetUserInDbURL, auth.SetUserInDb)

	r.With(auth.AuthGuardForSignInPath).Get(consts.SignInURL, tmpls.SignIn)
	r.Post(ValidateSignInInputURL, auth.ValidateSignInInput)

	r.Get("/yauth", auth.YandexAuthHandler)
	r.Get(YandexCallbackURL, auth.YandexCallbackHandler)

	r.Get(consts.PasswordResetURL, tmpls.PasswordReset)
	r.Post(GeneratePasswordResetLinkURL, auth.GeneratePasswordResetLink)
	r.With(auth.ResetTokenGuard).Get(SetNewPasswordURL, tmpls.SetNewPassword)
	r.Post(SetNewPasswordURL, auth.SetNewPassword)
	r.With(auth.AuthGuardForHomePath).Get(SetFirstTimePasswordURL, tmpls.SetFirstTimePassword)
	r.Post(SetFirstTimePasswordURL, auth.SetFirstTimePassword)

	r.With(auth.AuthGuardForHomePath).Get(consts.HomeURL, tmpls.Home)

	r.With(auth.AuthGuardForHomePath).Get(LogoutURL, auth.Logout)
	r.With(auth.AuthGuardForHomePath).Get(SimpleLogoutURL, auth.SimpleLogout)

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
