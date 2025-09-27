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
		user, err := data.SessionGetUser(r)
		if err != nil {
			http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
			return
		}

		var accessToken string
		cookie, err := data.CookieIsExist(r)
		if err == nil {
			accessToken = cookie.Value
		}

		_, err = tools.AccessTokenValidator(accessToken)
		if err != nil {
			signedRefreshToken, deviceInfo, err := data.RefreshTokenCheck(user.UserID)
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					http.Redirect(w, r, consts.SignInURL, http.StatusFound)
					return
				}
				log.Printf("%v", err)
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}

			_, err = tools.RefreshTokenValidator(signedRefreshToken)
			if err != nil {
				http.Redirect(w, r, consts.SignInURL, http.StatusFound)
				return
			}

			if deviceInfo != r.UserAgent() {
				http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
			}

			signedAccessToken, err := tools.GenerateAccessToken(consts.AccessTokenExp15Min, user.UserID)
			if err != nil {
				log.Printf("%v", err)
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}
			data.CookieAccessTokenSet(w, signedAccessToken)
		}
		next.ServeHTTP(w, r)
	})
}

func Logout(w http.ResponseWriter, r *http.Request) {
	err := data.SessionEnd(w, r)
	if err != nil {
		data.ClearCookie(w)
		http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
		return
	}
}
