package auth

import (
	"log"
	"net/http"
	"time"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/golang-jwt/jwt"
	"github.com/pkg/errors"
)

func IsExpiredTokenMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenValue, err := data.CookieIsExist(r)
		if err != nil {
			log.Printf("%+v", errors.WithStack(err))
			http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
		}

		token, err := tools.IsValidToken(w, r, tokenValue)
		if err != nil {
			log.Printf("%+v", err)
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}

		claims := token.Claims.(jwt.MapClaims)
		exp := claims["exp"].(float64)

		if exp != consts.NoExpiration {
			expUnix := time.Unix(int64(exp), 0)

			if time.Now().After(expUnix) {
				lastActivity, err := data.SessionTimeDataGet(r, "lastActivity")

				if err != nil {
					log.Printf("%+v", err)
					http.Redirect(w, r, consts.Err500URL, http.StatusFound)
					return
				}

				if time.Since(lastActivity) > 3*time.Hour {
					Logout(w, r)
					return
				}

				user, err := data.SessionUserDataGet(r, "user")
				if err != nil {
					log.Printf("%+v", err)
					http.Redirect(w, r, consts.Err500URL, http.StatusFound)
					return
				}

				_, err = tools.TokenCreate(w, r, "3hours", user)
				if err != nil {
					log.Printf("%+v", err)
					http.Redirect(w, r, consts.Err500URL, http.StatusFound)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func Logout(w http.ResponseWriter, r *http.Request) {
	err := data.SessionEnd(w, r)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	data.ClearCookie(w)
	http.Redirect(w, r, consts.SignInURL, http.StatusFound)
}
