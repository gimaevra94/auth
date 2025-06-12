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

			var noExpiration = 253402300799.0
			if exp != noExpiration {
				expUnix := time.Unix(int64(exp), 0)

				session, user, err := tools.SessionUserGet(w, r, store)
				if err != nil {
					errs.WrappedErrPrintRedir(w, r, data.RequestErrorURL, err)
					return
				}

				if time.Now().After(expUnix) {
					lastActivity := session.Values["lastActivity"].(time.Time)

					if time.Since(lastActivity) > 3*time.Hour {
						errs.NewErrWrapPrintRedir(w, r, "", "session ended", "")
						logout(w, r, store)
						return
					}

					err = tools.TokenCreate(w, r, "3hours", user)
					if err != nil {
						errs.WrappedErrPrintRedir(w, r, data.RequestErrorURL, err)
						return
					}
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

func logout(w http.ResponseWriter, r *http.Request, store *sessions.CookieStore) {
	session, err := store.Get(r, "auth")
	if err != nil {
		errs.OrigErrWrapPrintRedir(w, r, data.RequestErrorURL, err)
		return
	}

	session.Options.MaxAge = -1
	err = session.Save(r, w)
	if err != nil {
		errs.OrigErrWrapPrintRedir(w, r, data.RequestErrorURL, err)
		return
	}

	dataCookie := data.NewCookie()
	dataCookie.SetMaxAge(-1)
	httpCookie := dataCookie.GetCookie()
	http.SetCookie(w, httpCookie)
	http.Redirect(w, r, data.SignInURL, http.StatusFound)
}
