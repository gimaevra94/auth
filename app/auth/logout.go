package auth

import (
	"log"
	"net/http"
	"time"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/tools"
)

func IsExpiredTokenMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := data.SessionGetUser(r)
		if err != nil {
			http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
			return
		}

		if user.AccessToken == "" {
			user, err := data.RefreshTokenCheck(user)
			if err != nil {
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}

			if time.Now().After(user.RefreshExpiresAt) {
				user, err := tools.GenerateRefreshToken(user)
				if err != nil {
					http.Redirect(w, r, consts.Err500URL, http.StatusFound)
					return
				}
			}

			user, err = tools.RefreshTokenValidator(user)
			if err != nil {
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}

		}

		err = data.SessionEnd(w, r)
		if err != nil {
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
		return

		err = data.SessionDataSet(w, r, "captcha", "captchaCounter", 3)
		if err != nil {
			log.Printf("%+v", err)
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}
	})
}

func Logout(w http.ResponseWriter, r *http.Request) {
	err := data.SessionEnd(w, r)
	if err != nil {
		data.ClearCookie(w)
		http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
	}
}

func ClearCookies(w http.ResponseWriter, r *http.Request) {
	data.ClearCookie(w)
	http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
}
