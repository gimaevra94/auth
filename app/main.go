package main

import (
	"log"
	"net/http"
	"os"

	"github.com/gimaevra94/auth/app/auth"
	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/data"
	htmls "github.com/gimaevra94/auth/app/tmpls"
	"github.com/go-chi/chi"
	"github.com/joho/godotenv"
	"github.com/pkg/errors"
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
	err := godotenv.Load("../public/.env")
	if err != nil {
		log.Printf("%+v", errors.WithStack(err))
		return
	}
	envVars := []string{
		"SESSION_SECRET",
		"SESSION_AUTH_KEY",
		"SESSION_ENCRYPTION_KEY",
		"JWT_SECRET",
		"DB_PASSWORD",
		"MAIL_SENDER_EMAIL",
		"MAIL_PASSWORD",
		"GOOGLE_CAPTCHA_SECRET",
		"clientID",
		"clientSecret",
	}
	for _, v := range envVars {
		if os.Getenv(v) == "" {
			log.Printf("%+v", errors.WithStack(errors.New(v+" not exist")))
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

	// Serve static files
	r.Handle("/public/*", http.StripPrefix("/public/", http.FileServer(http.Dir("../public"))))

	// Default route
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
	})

	// Dev routes
	r.Get("/dev", func(w http.ResponseWriter, r *http.Request) {
		data.ClearCookiesDev(w, r)
		err := data.AuthSessionEnd(w, r)
		if err != nil {
			log.Printf("%+v", err)
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}
	})
	r.Get("/clear", data.ClearCookiesDev)

	// Public routes (redirect if already logged in)
	r.With(auth.AlreadyAuthedRedirectMW).Get(consts.SignUpURL, htmls.SignUp)
	r.Post(consts.SignUpInputCheckURL, auth.SignUpInputCheck)
	r.With(auth.SignUpFlowOnlyMW).Get(consts.CodeSendURL, htmls.CodeSend)
	r.Post(consts.UserAddURL, auth.UserAdd)
	r.With(auth.AlreadyAuthedRedirectMW).Get(consts.SignInURL, htmls.SignIn)
	r.Post(consts.SignInInputCheckURL, auth.SignInInputCheck)

	// OAuth routes
	r.Get("/yauth", auth.YandexAuthHandler)
	r.Get(consts.YandexCallbackURL, auth.YandexCallbackHandler)

	// Password reset routes
	r.Get(consts.PasswordResetURL, htmls.PasswordReset)
	r.Post(consts.PasswordResetEmailURL, auth.PasswordResetEmailCheck)
	r.With(auth.ResetTokenGuardMW).Get(consts.SetNewPasswordURL, htmls.SetNewPassword)
	r.Post(consts.SetNewPasswordURL, auth.SetNewPassword)

	// Protected routes (require valid token session)
	r.With(auth.IsExpiredTokenMW).Get(consts.HomeURL, htmls.Home)
	// Apply MW to set-password route
	r.With(auth.IsExpiredTokenMW).Get(consts.SetPasswordURL, htmls.SetPassword)
	r.Post(consts.SubmitPasswordURL, auth.SubmitPassword)

	// Logout routes
	r.With(auth.IsExpiredTokenMW).Get(consts.LogoutURL, auth.Logout)
	r.With(auth.IsExpiredTokenMW).Get(consts.SimpleLogoutURL, auth.SimpleLogout)

	// Error page
	r.Get(consts.Err500URL, htmls.Err500)

	return r
}

func serverStart(r *chi.Mux) {
	err := http.ListenAndServe(":8080", r)
	if err != nil {
		log.Printf("%+v", errors.WithStack(err))
		return
	}
}