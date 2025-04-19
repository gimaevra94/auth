package logout

import (
	"log"
	"net/http"
	"time"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/tokenizer"
	"github.com/gimaevra94/auth/app/validator"
	"github.com/golang-jwt/jwt"
	"github.com/gorilla/sessions"
)

func IsExpiredTokenMW(store *sessions.CookieStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter,
			r *http.Request) {

			session, err := store.Get(r, "auth")
			if err != nil {
				http.ServeFile(w, r, consts.RequestErrorHTML)
				log.Println("Failed to get the session  from the store")
				return
			}

			token, err := validator.IsValidToken(r)
			if err != nil {
				http.ServeFile(w, r, consts.RequestErrorHTML)
				log.Println("Token validation is failed", err)
				return
			}

			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				log.Println("Failed to get the claims from the token")
				return
			}

			exp, ok := claims["exp"].(float64)
			if !ok {
				log.Println("Failed to get the expire from the claims")
				return
			}

			expUnix := time.Unix(int64(exp), 0)
			if time.Now().After(expUnix) {
				lastActivity := session.Values["lastActivity"].(time.Time)
				if time.Now().Sub(lastActivity) > 3*time.Hour {
					http.ServeFile(w, r, "logout.html")
					log.Println("session ended")
					return
				}
			}

			err = tokenizer.TokenCreate(w, r, "expire_3_hours", session)
			if err != nil {
				http.ServeFile(w, r, consts.RequestErrorHTML)
				log.Println("Failed to create a token", err)
			}
		})
	}
}
