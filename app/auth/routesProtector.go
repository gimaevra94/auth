package auth

import (
	"database/sql"
	"log"
	"net/http"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/pkg/errors"
)

func IsExpiredTokenMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := data.TemporaryUserIDCookiesGet(r)
		if err != nil {
			log.Printf("%v", errors.WithStack(err))
			http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
			return
		}

		temporaryUserID := cookie.Value
		login, email, permanentUserID, temporaryCancelled, err := data.MWUserCheck(temporaryUserID)
		if err != nil {
			log.Printf("%v", errors.WithStack(err))
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}

		if temporaryCancelled {
			Revocate(w, r, true, false, false)
			http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
			return
		}

		refreshToken, deviceInfo, tokenCancelled, err := data.RefreshTokenCheck(permanentUserID, r.UserAgent())
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				if isNewSession {
					// Первый запрос новой сессии и ещё нет токена для этого UA — считаем это новым устройством
					log.Println("routesProtector: No refresh token for this UA on first request; treating as new device and allowing.")
					if mailErr := tools.SendNewDeviceLoginEmail(email, login, currentUA); mailErr != nil {
						log.Printf("%v", errors.WithStack(mailErr))
						http.Redirect(w, r, consts.Err500URL, http.StatusFound)
						return
					}
					// Сбрасываем маркер новой сессии и пропускаем запрос
					http.SetCookie(w, &http.Cookie{Name: "new_session", Path: "/", MaxAge: -1})
					next.ServeHTTP(w, r)
					return
				}
				log.Println("routesProtector: RefreshToken not found for permanentUserID or UserAgent. Sending new device login alert and allowing request.")
				if mailErr := tools.SendNewDeviceLoginEmail(email, login, r.UserAgent()); mailErr != nil {
					log.Printf("%v", errors.WithStack(mailErr))
					log.Println("routesProtector: Redirecting to Err500URL because SendNewDeviceLoginEmail failed.")
					http.Redirect(w, r, consts.Err500URL, http.StatusFound)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			log.Printf("%v", errors.WithStack(err))
			log.Println("routesProtector: Redirecting to Err500URL because RefreshTokenCheck failed.")
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}

		if deviceInfo != r.UserAgent() {
			if isNewSession {
				log.Println("routesProtector: UserAgent mismatch on first request. Treating as suspicious.")
				if mailErr := tools.SendSuspiciousLoginEmail(email, login, r.UserAgent()); mailErr != nil {
					log.Printf("%v", errors.WithStack(mailErr))
					log.Println("routesProtector: Redirecting to Err500URL because SendSuspiciousLoginEmail failed.")
					http.Redirect(w, r, consts.Err500URL, http.StatusFound)
					return
				}
				http.SetCookie(w, &http.Cookie{Name: "new_session", Path: "/", MaxAge: -1})
				Revocate(w, r, true, true, true)
				http.Redirect(w, r, consts.SignInURL, http.StatusFound)
				return
			}
			log.Println("routesProtector: UserAgent mismatch mid-session; allowing without notifications.")
			next.ServeHTTP(w, r)
			return
		}

		err = tools.RefreshTokenValidate(refreshToken)
		if err != nil {
			log.Println("routesProtector: Redirecting to SignInURL because RefreshToken is invalid or expired.")
			Revocate(w, r, true, true, true)
			http.Redirect(w, r, consts.SignInURL, http.StatusFound)
			return
		}

		if tokenCancelled {
			log.Println("routesProtector: Redirecting to SignInURL because RefreshToken is cancelled.")
			Revocate(w, r, true, true, false)
			err := tools.SendSuspiciousLoginEmail(email, login, deviceInfo)
			if err != nil {
				log.Printf("%v", errors.WithStack(err))
				log.Println("routesProtector: Redirecting to Err500URL because SendSuspiciousLoginEmail failed.")
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}
			http.Redirect(w, r, consts.SignInURL, http.StatusFound)
			return
		}

		// Успешная проверка — если это первый запрос новой сессии, сбрасываем маркер
		if isNewSession {
			http.SetCookie(w, &http.Cookie{Name: "new_session", Path: "/", MaxAge: -1})
		}
		next.ServeHTTP(w, r)
	})
}

func AlreadyAuthedRedirectMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := data.TemporaryUserIDCookiesGet(r)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		temporaryUserID := cookie.Value
		_, _, permanentUserID, temporaryCancelled, err := data.MWUserCheck(temporaryUserID)
		if err != nil || temporaryCancelled {
			next.ServeHTTP(w, r)
			return
		}

		_, _, tokenCancelled, err := data.RefreshTokenCheck(permanentUserID, r.UserAgent())
		if err != nil || tokenCancelled {
			next.ServeHTTP(w, r)
			return
		}

		http.Redirect(w, r, consts.HomeURL, http.StatusFound)
	})
}

func SignUpFlowOnlyMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := data.SessionUserGet(r)
		if err != nil {
			http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
			return
		}

		if user.ServerCode == "" {
			http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ResetTokenGuardMW обеспечивает доступ к установке нового пароля только через действительную ссылку сброса
func ResetTokenGuardMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if token == "" {
			http.Redirect(w, r, consts.PasswordResetURL, http.StatusFound)
			return
		}
		// Проверяем структуру JWT и срок действия
		if _, err := tools.ValidateResetToken(token); err != nil {
			http.Redirect(w, r, consts.PasswordResetURL, http.StatusFound)
			return
		}
		// Проверяем наличие токена и отсутствие отмены в БД
		cancelled, err := data.ResetTokenCheck(token)
		if err != nil || cancelled {
			http.Redirect(w, r, consts.PasswordResetURL, http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}
