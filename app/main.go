package main

import (
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
	"github.com/pkg/errors"

	"github.com/gimaevra94/auth/app/auth"
	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/htmls"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/go-chi/chi"
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
		"JWT_SECRET",
		"DB_PASSWORD",
		"MAIL_SENDER_EMAIL",
		"MAIL_PASSWORD",
		"GOOGLE_CAPTCHA_SECRET",
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

	r.Get("/", authStart)

	r.Handle("/public/*", http.StripPrefix("/public/", http.FileServer(http.Dir("../public"))))

	r.With(data.InitSessionVarsMW).Get(consts.SignUpURL, htmls.SignUp)
	r.Post(consts.SignUpInputCheckURL, auth.SignUpInputCheck)
	r.Get(consts.CodeSendURL, htmls.CodeSend)
	r.Post(consts.UserAddURL, auth.UserAdd)

	r.With(data.InitSessionVarsMW).Get(consts.SignInURL, htmls.SignIn)
	r.Post(consts.SignInInputCheckURL, auth.SignInInputCheck)

	r.Get("/yauth", auth.YandexAuthHandler)
	r.Get("/ya_callback", auth.YandexCallbackHandler)

	r.With(auth.IsExpiredTokenMW).Get(consts.HomeURL, htmls.Home)
	r.With(auth.IsExpiredTokenMW).Post(consts.LogoutURL, auth.Logout)

	r.Get(consts.Err500URL, htmls.Err500)

	r.Get(consts.PasswordResetURL, htmls.PasswordReset)
	r.Post(consts.PasswordResetURL, auth.PasswordReset)
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
	tokenValue, err := data.CookieIsExist(r)
	if err != nil {
		log.Printf("%+v", errors.WithStack(err))
		http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
	}

	_, err = tools.IsValidToken(w, r, tokenValue)
	if err != nil {
		log.Printf("%+v", errors.WithStack(err))
		http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
		return
	}

	http.Redirect(w, r, consts.HomeURL, http.StatusFound)
}
