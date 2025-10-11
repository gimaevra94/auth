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
		log.Printf("routesProtector: Request URL: %s", r.URL.Path)
		log.Printf("routesProtector: Received cookies: %+v", r.Cookies())
		cookie, err := data.TemporaryUserIDCookiesGet(r)
		if err != nil {
			log.Println("routesProtector: Redirecting to SignInURL because TemporaryUserID cookie not found or expired.")
			http.Redirect(w, r, consts.SignInURL, http.StatusFound)
			return
		}

		temporaryUserID := cookie.Value
		login, email, permanentUserID, temporaryCancelled, err := data.MWUserCheck(temporaryUserID)
		if err != nil {
			log.Printf("%v", errors.WithStack(err))
			log.Println("routesProtector: Redirecting to Err500URL because MWUserCheck failed.")
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}

		if temporaryCancelled {
			log.Println("routesProtector: Redirecting to SignInURL because temporaryUserID is cancelled.")
			Revocate(w, r, true, false, false)
			http.Redirect(w, r, consts.SignInURL, http.StatusFound)
			return
		}

		refreshToken, deviceInfo, tokenCancelled, err := data.RefreshTokenCheck(permanentUserID, r.UserAgent())
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				log.Println("routesProtector: Redirecting to SignInURL because RefreshToken not found for permanentUserID or UserAgent.")
				Revocate(w, r, true, true, false)
				http.Redirect(w, r, consts.SignInURL, http.StatusFound)
				return
			}

			log.Printf("%v", errors.WithStack(err))
			log.Println("routesProtector: Redirecting to Err500URL because RefreshTokenCheck failed.")
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}

		if deviceInfo != r.UserAgent() {
			log.Println("routesProtector: Redirecting to SignInURL because UserAgent mismatch.")
			Revocate(w, r, true, true, true)
			http.Redirect(w, r, consts.SignInURL, http.StatusFound)
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
			err := tools.SendSuspiciousLoginEmail(login, email, deviceInfo)
			if err != nil {
				log.Printf("%v", errors.WithStack(err))
				log.Println("routesProtector: Redirecting to Err500URL because SendSuspiciousLoginEmail failed.")
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}
			http.Redirect(w, r, consts.SignInURL, http.StatusFound)
			return
		}

		next.ServeHTTP(w, r)
	})
}
