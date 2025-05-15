package auth

import (
	"log"
	"net/http"
	"time"

	"github.com/gimaevra94/auth/app"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/golang-jwt/jwt"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
)

func IsExpiredTokenMW(store *sessions.CookieStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter,
			r *http.Request) {

			token, err := tools.IsValidToken(r)
			if err != nil {
				log.Printf("%+v", err)
				http.Redirect(w, r, app.RequestErrorURL, http.StatusFound)
				return
			}

			claims := token.Claims.(jwt.MapClaims)
			exp := claims["exp"].(float64)
			session, user, err := tools.SessionUserGetUnmarshal(r,
				store)
			if err != nil {
				log.Println("%+v", err)
				http.Redirect(w, r, app.RequestErrorURL, http.StatusFound)
				return
			}

			expUnix := time.Unix(int64(exp), 0)
			if time.Now().After(expUnix) {
				lastActivity := session.Values["lastActivity"].(time.Time)
				if time.Since(lastActivity) > 3*time.Hour {
					newErr := errors.New("session ended")
					wrappedErr := errors.WithStack(newErr)
					log.Println("%+v", wrappedErr)
					http.Redirect(w, r, app.LogoutURL, http.StatusFound)
					return
				}
			}

			err = tools.TokenCreate(w, r, "3hours",
				user)
			if err != nil {
				log.Println("%+v", err)
				http.Redirect(w, r, app.RequestErrorURL, http.StatusFound)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func Logout(store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "auth")
		if err != nil {
			wrappedErr := errors.WithStack(err)
			log.Println("%+v", wrappedErr)
			http.Redirect(w, r, app.RequestErrorURL, http.StatusFound)
			return
		}

		session.Options.MaxAge = -1
		err = session.Save(r, w)
		if err != nil {
			wrappedErr := errors.WithStack(err)
			log.Println("%+v", wrappedErr)
			http.Redirect(w, r, app.RequestErrorURL, http.StatusFound)
			return
		}

		cookie := http.Cookie{
			Name:     "auth",
			Path:     "/set-token",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			Value:    "",
			MaxAge:   -1,
		}

		http.SetCookie(w, &cookie)
		http.Redirect(w, r, app.SignInURL, http.StatusFound)
	}
}
