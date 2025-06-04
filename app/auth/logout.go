package auth

import (
	"net/http"
	"time"

	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/errs"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/golang-jwt/jwt"
	"github.com/gorilla/sessions"
)

func IsExpiredTokenMW(store *sessions.CookieStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter,
			r *http.Request) {
			token, err := tools.IsValidToken(w, r)
			if err != nil {
				errs.WrappedErrPrintRedir(w, r, data.RequestErrorURL, err)
				return
			}

			claims := token.Claims.(jwt.MapClaims)
			exp := claims["exp"].(float64)
			session, user, err := tools.SessionUserGetUnmarshal(w, r, store)
			if err != nil {
				errs.WrappedErrPrintRedir(w, r, data.RequestErrorURL, err)
				return
			}

			if exp != 253402300799 {
				expUnix := time.Unix(int64(exp), 0)
				if time.Now().After(expUnix) {
					lastActivity := session.Values["lastActivity"].(time.Time)
					if time.Since(lastActivity) > 3*time.Hour {
						errs.WrappingErrPrintRedir(w, r, data.LogoutURL, "session ended", "")
						return
					}
				}

				err = tools.TokenCreate(w, r, "3hours", user)
				if err != nil {
					errs.WrappedErrPrintRedir(w, r, data.RequestErrorURL, err)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

func Logout(store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "auth")
		if err != nil {
			errs.WithStackingErrPrintRedir(w, r, data.RequestErrorURL, err)
			return
		}

		session.Options.MaxAge = -1
		err = session.Save(r, w)
		if err != nil {
			errs.WithStackingErrPrintRedir(w, r, data.RequestErrorURL, err)
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
		http.Redirect(w, r, data.SignInURL, http.StatusFound)
	}
}
