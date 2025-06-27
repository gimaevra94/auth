package auth

import (
	"log"
	"net/http"
	"time"

	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/golang-jwt/jwt"
)

func IsExpiredTokenMW() func(http.Handler) http.Handler {

	return func(next http.Handler) http.Handler {

		return http.HandlerFunc(func(w http.ResponseWriter,
			r *http.Request) {

			token, err := tools.IsValidToken(w, r)
			if err != nil {
				log.Printf("%+v", err)
				http.Redirect(w, r, data.RequestErrorURL, http.StatusFound)
				return
			}

			claims := token.Claims.(jwt.MapClaims)
			exp := claims["exp"].(float64)

			var noExpiration = 253402300799.0
			if exp != noExpiration {
				expUnix := time.Unix(int64(exp), 0)

				session, user, err := tools.SessionUserGet(r)
				if err != nil {
					log.Printf("%+v", err)
					http.Redirect(w, r, data.RequestErrorURL, http.StatusFound)
					return
				}

				if time.Now().After(expUnix) {
					lastActivity := session.Values["lastActivity"].(int64)
					if time.Since(time.Unix(lastActivity, 0)) > 3*time.Hour {
						Logout(w, r)
						return
					}

					err = tools.TokenCreate(w, r, "3hours", user)
					if err != nil {
						log.Printf("%+v", err)
						http.Redirect(w, r, data.RequestErrorURL, http.StatusFound)
						return
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func Logout(w http.ResponseWriter, r *http.Request) {
	err := tools.SessionEnd(w, r)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, data.Err500URL, http.StatusFound)
		return
	}

	tools.ClearCookie(w)
	http.Redirect(w, r, data.SignInURL, http.StatusFound)
}
