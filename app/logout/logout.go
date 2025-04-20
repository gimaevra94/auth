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

			session, err := store.Get(r, consts.SessionNameStr)
			if err != nil {
				http.ServeFile(w, r, consts.RequestErrorHTML)
				log.Println(consts.SessionGetFailedErr)
				return
			}

			token, err := validator.IsValidToken(r)
			if err != nil {
				http.ServeFile(w, r, consts.RequestErrorHTML)
				log.Println(consts.TokenValidateFailedErr, err)
				return
			}

			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				log.Println(consts.ClaimsGetFromTokenFailedErr)
				return
			}

			exp, ok := claims[consts.ExpStr].(float64)
			if !ok {
				log.Println(consts.ExpireGetFromClaimsFailedErr)
				return
			}

			expUnix := time.Unix(int64(exp), 0)
			if time.Now().After(expUnix) {
				lastActivity := session.Values[consts.LastActivityStr].(time.Time)
				if time.Since(lastActivity) > consts.TokenLifetime3HoursInt {
					http.ServeFile(w, r, consts.LogoutURL)
					log.Println(consts.SessionEndedErr)
					return
				}
			}

			err = tokenizer.TokenCreate(w, r, consts.TokenCommand3HoursStr,
				session)
			if err != nil {
				http.ServeFile(w, r, consts.RequestErrorHTML)
				log.Println(consts.TokenCreateFailedErr, err)
			}
		})
	}
}
