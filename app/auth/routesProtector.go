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
			http.Redirect(w, r, consts.SignInURL, http.StatusFound)
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
			http.Redirect(w, r, consts.SignInURL, http.StatusFound)
			return
		}

		refreshToken, deviceInfo, tokenCancelled, err := data.RefreshTokenCheck(permanentUserID, r.UserAgent())
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				Revocate(w, r, true, true, false)
				http.Redirect(w, r, consts.SignInURL, http.StatusFound)
				return
			}

			log.Printf("%v", errors.WithStack(err))
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}

		if deviceInfo != r.UserAgent() {
			Revocate(w, r, true, true, true)
			http.Redirect(w, r, consts.SignInURL, http.StatusFound)
			return
		}

		err = tools.RefreshTokenValidate(refreshToken)
		if err != nil {
			Revocate(w, r, true, true, true)
			http.Redirect(w, r, consts.SignInURL, http.StatusFound)
			return
		}

		if tokenCancelled {
			Revocate(w, r, true, true, false)
			//алерт на почту
			http.Redirect(w, r, consts.SignInURL, http.StatusFound)
			return
		}

		next.ServeHTTP(w, r)
	})
}
