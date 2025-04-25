package logout

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/structs"
	"github.com/gimaevra94/auth/app/tokenizer"
	"github.com/gimaevra94/auth/app/validator"
	"github.com/golang-jwt/jwt"
	"github.com/gorilla/sessions"
)

func IsExpiredTokenMW(store *sessions.CookieStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter,
			r *http.Request) {

			token, err := validator.IsValidToken(r)
			if err != nil {
				http.ServeFile(w, r, consts.RequestErrorHTML)
				log.Println(consts.TokenValidateFailedErr, err)
				return
			}

			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				log.Println(consts.ClaimsGetFailedErr)
				return
			}

			exp, ok := claims[consts.ExpStr].(float64)
			if !ok {
				log.Println(consts.ExpireGetFromClaimsFailedErr)
				return
			}

			session, user, err := sessionUserGetUnmarshal(r, store)
			if err != nil {
				http.ServeFile(w, r, consts.RequestErrorHTML)
				log.Println(consts.SessionGetFailedErr, err)
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
				user)
			if err != nil {
				http.ServeFile(w, r, consts.RequestErrorHTML)
				log.Println(consts.TokenCreateFailedErr, err)
			}

			//w.Header().Set(consts.CookieNameStr, consts.BearerStr+cookie.Value)
			//w.Write([]byte(cookie.Value))
		})

		// next
	}
}

func sessionUserGetUnmarshal(r *http.Request,
	store *sessions.CookieStore) (*sessions.Session, structs.User, error) {

	session, err := store.Get(r, consts.SessionNameStr)
	if err != nil {
		log.Println(consts.SessionGetFailedErr, err)
		return nil, nil, err
	}

	jsonData, ok := session.Values[consts.UserStr].([]byte)
	if !ok {
		log.Println(consts.UserNotExistInSessionErr)
		return nil, nil, err
	}

	var user structs.User
	err = json.Unmarshal([]byte(jsonData), &user)
	if err != nil {
		log.Println(consts.UserDeserializeFailedErr, err)
		return nil, nil, err
	}

	return session, user, nil
}
