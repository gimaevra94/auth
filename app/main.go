// Package main предоставляет точку входа для веб-приложения аутентификации.
//
// Файл содержит основные функции инициализации и запуска сервера:
//   - main: основная функция запуска приложения
//   - initEnv: инициализация переменных окружения
//   - initDb: инициализация подключения к базе данных
//   - initRouter: настройка маршрутизатора HTTP-запросов
//   - serverStart: запуск HTTP-сервера
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
	setUserInDbURL                         = "/set-user-in-db"
	codeValidateURL                        = "/code-validate"
	CheckInDbAndValidateSignUpUserInputURL = "/check-in-db-and-validate-sign-up-user-input"
	CheckInDbAndValidateSignInUserInputURL = "/check-in-db-and-validate-sign-in-user-input"
	generatePasswordResetLinkURL           = "/generate-password-reset-link"
	yandexCallbackURL                      = "/ya_callback"
	setNewPasswordURL                      = "/set-new-password"
	logoutURL                              = "/logout"
)

// main является точкой входа в приложение.
//
// Последовательно инициализирует окружение, базу данных, хранилище сессий
// и маршрутизатор, затем запускает HTTP-сервер.
func main() {
	initEnv()
	initDb()
	data.InitStore()
	r := initRouter()
	if err := serverStart(r); err != nil {
		log.Printf("%+v", err)
	}
	defer data.DbClose()
}

// initEnv загружает переменные окружения из .env файла
// и проверяет наличие всех необходимых переменных.
//
// В случае отсутствия переменных выводит предупреждение в лог.
func initEnv() {
	if err := godotenv.Load(".env"); err != nil {
		log.Printf("Could not load .env file: %+v", errors.WithStack(err))
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
		"DB_SSL_CA",
		"DB_SSL_CERT",
		"DB_SSL_KEY",
	}

	missingVars := []string{}
	for _, v := range envVars {
		if os.Getenv(v) == "" {
			missingVars = append(missingVars, v)
		}
	}

	if len(missingVars) > 0 {
		log.Printf("Missing environment variables: %v", missingVars)
	}
}

// initDb устанавливает соединение с базой данных.
//
// Использует параметры подключения из переменных окружения.
// В случае ошибки выводит стек ошибки в лог.
func initDb() {
	if err := data.DbConn(); err != nil {
		log.Printf("%+v", errors.WithStack(err))
		return
	}
}

// initRouter создает и настраивает HTTP-маршрутизатор.
//
// Регистрирует все обработчики маршрутов для аутентификации,
// авторизации, сброса пароля и других функций приложения.
// Возвращает настроенный маршрутизатор chi.Mux.
func initRouter() *chi.Mux {
	r := chi.NewRouter()

	r.Get("/public/styles.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		http.ServeFile(w, r, "/app/styles.css")
	})

	r.Get("/public/500", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		http.ServeFile(w, r, "/app/500.html")
	})

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
	})

	r.With(auth.AuthGuardForSignUpAndSignInPath).Get(consts.SignUpURL, tmpls.SignUp)
	r.Post(CheckInDbAndValidateSignUpUserInputURL, auth.CheckInDbAndValidateSignUpUserInput)
	r.With(auth.AuthGuardForServerAuthCodeSendPath).Get(consts.ServerAuthCodeSendURL, tmpls.ServerAuthCodeSend)
	r.With(auth.AuthGuardForServerAuthCodeSendPath).Get(consts.ServerAuthCodeSendAgainURL, auth.ServerAuthCodeSend)
	r.Post(codeValidateURL, auth.CodeValidate)
	r.Post(setUserInDbURL, auth.SetUserInDb)

	r.With(auth.AuthGuardForSignUpAndSignInPath).Get(consts.SignInURL, tmpls.SignIn)
	r.Post(CheckInDbAndValidateSignInUserInputURL, auth.CheckInDbAndValidateSignInUserInput)

	r.Get("/yauth", auth.YandexAuthHandler)
	r.Get(yandexCallbackURL, auth.YandexCallbackHandler)

	r.Get(generatePasswordResetLinkURL, tmpls.GeneratePasswordResetLink)
	r.Post(generatePasswordResetLinkURL, auth.GeneratePasswordResetLink)
	r.With(auth.ResetTokenGuard).Get(setNewPasswordURL, tmpls.SetNewPassword)
	r.Post(setNewPasswordURL, auth.SetNewPassword)

	r.With(auth.AuthGuardForHomePath).Get(consts.HomeURL, tmpls.Home)
	r.With(auth.AuthGuardForHomePath).Get(logoutURL, auth.Logout)
	r.Get("/clear", data.ClearCookiesDev)
	r.Get(consts.Err500URL, tmpls.Err500)

	return r
}

// serverStart запускает HTTPS сервер на указанном порту.
//
// Для HTTPS используются сертификаты из certs/app_cert/.
// Возвращает ошибку в случае неудачного запуска сервера.
func serverStart(r *chi.Mux) error {
	certFile := "/app/cert/app-cert.pem"
	keyFile := "/app/cert/app-key.pem"
	if err := http.ListenAndServeTLS(":443", certFile, keyFile, r); err != nil {
		return errors.WithStack(err)
	}
	return nil
}
