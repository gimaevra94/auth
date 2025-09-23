package auth

import (
	"log"
	"net/http"
	"time"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/pkg/errors"
)

func IsExpiredTokenMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() != "sign-up/" {
			tokenValue, err := data.CookieIsExist(r)
			if err != nil {
				http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
				return
			}

			claims, err := tools.AccessTokenValidator(tokenValue)
			if err != nil {
				log.Printf("%+v", errors.WithStack(err))
				http.Redirect(w, r, consts.SignInURL, http.StatusFound)
				return
			}

			expiresAtUnix := claims.ExpiresAt
			expiresAtTime := time.Unix(expiresAtUnix, 0)

			if time.Now().After(expiresAtTime) {

				user, err := data.SessionUserDataGet(r, "user")
				if err != nil {
					log.Printf("%+v", errors.WithStack(err))
					http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				}

				signedAuthToken, err := tools.GenerateAccessToken(user)
				if err != nil {
					log.Printf("%+v", errors.WithStack(err))
					http.Redirect(w, r, consts.Err500URL, http.StatusFound)
					return
				}
				data.SetAccessTokenCookie(w, signedAuthToken)
			}

			err = data.SessionEnd(w, r)
			if err != nil {
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}
			next.ServeHTTP(w, r)
		}

		err := data.SessionEnd(w, r)
		if err != nil {
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func Logout(w http.ResponseWriter, r *http.Request) {
	err := data.SessionEnd(w, r)
	if err != nil {
		log.Printf("%+v", errors.WithStack(err))
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}
	data.ClearCookie(w)
	http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
}

func ClearCookies(w http.ResponseWriter, r *http.Request) {
	data.ClearCookie(w)
	http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
}
