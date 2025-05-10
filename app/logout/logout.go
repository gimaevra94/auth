package logout

import (
	"log"
	"net/http"
	"time"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/serializer"
	"github.com/gimaevra94/auth/app/tokenizer"
	"github.com/gimaevra94/auth/app/validator"
	"github.com/golang-jwt/jwt"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
)

func IsExpiredTokenMW(store *sessions.CookieStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter,
			r *http.Request) {

			token, err := validator.IsValidToken(w, r)
			if err != nil {
				log.Println("%+v", err)
				http.Redirect(w, r, consts.RequestErrorURL, http.StatusFound)
				return
			}

			claims := token.Claims.(jwt.MapClaims)
			exp := claims["exp"].(float64)

			session, user, err := serializer.SessionUserGetUnmarshal(r,
				store)
			if err != nil {
				log.Println("%+v", err)
				http.Redirect(w, r, consts.RequestErrorURL, http.StatusFound)
				return
			}

			expUnix := time.Unix(int64(exp), 0)
			if time.Now().After(expUnix) {
				lastActivity := session.Values["lastActivity"].(time.Time)
				if time.Since(lastActivity) > 3*time.Hour {
					newErr := errors.New("session ended")
					wrappedErr := errors.WithStack(newErr)
					log.Println("%+v", wrappedErr)
					http.Redirect(w, r, consts.LogoutURL, http.StatusFound)
					return
				}
			}

			err = tokenizer.TokenCreate(w, r, consts.TokenCommand3HoursStr,
				user)
			if err != nil {
				log.Println("%+v", err)
				http.Redirect(w, r, consts.RequestErrorURL, http.StatusFound)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func Logout(store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, consts.SessionNameStr)
		if err != nil {
			wrappedErr := errors.WithStack(err)
			log.Println("%+v", wrappedErr)
			http.Redirect(w, r, consts.RequestErrorURL, http.StatusFound)
			return
		}

		session.Options.MaxAge = -1
		err = session.Save(r, w)
		if err != nil {
			wrappedErr := errors.WithStack(err)
			log.Println("%+v", wrappedErr)
			http.Redirect(w, r, consts.RequestErrorURL, http.StatusFound)
			return
		}

		cookie := http.Cookie{
			Name:     "Authorization",
			Path:     "/set-token",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			Value:    "",
			MaxAge:   -1,
		}

		http.SetCookie(w, &cookie)
		http.Redirect(w, r, consts.LogoutURL, http.StatusFound)
	}
}
