package auth

import (
	"database/sql"
	"log"
	"net/http"

	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/errs"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

func LogIn(store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rememberMe := r.FormValue("'rememberMe'")
		if rememberMe == "" {
			errs.WrappingErrPrintRedir(w, r, data.RequestErrorURL,
				data.NotExistErr, "'rememberMe'")
			return
		}

		session, err := store.Get(r, "auth")
		if err != nil {
			errs.WithStackingErrPrintRedir(w, r, data.RequestErrorURL, err)
			return
		}

		cookie, err := r.Cookie("auth")
		if err != nil {
			errs.WithStackingErrPrintRedir(w, r, data.RequestErrorURL, err)
			return
		}

		validatedLoginInput, err := tools.IsValidInput(w, r)
		if err != nil {
			errs.WrappedErrPrintRedir(w, r, data.BadSignInURL, err)
			return
		}

		err = data.UserCheck(w, r, validatedLoginInput)
		if err != nil {
			if err == sql.ErrNoRows {
				errs.WrappedErrPrintRedir(w, r, data.UserNotExistURL, err)
				return
			}

			if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
				errs.WrappedErrPrintRedir(w, r, data.BadSignInURL, err)
				return
			}

			errs.WrappedErrPrintRedir(w, r, data.RequestErrorURL, err)
			return
		}

		err = tools.TokenCreate(w, r, rememberMe, validatedLoginInput)
		if err != nil {
			log.Printf("%+v", err)
			http.Redirect(w, r, data.RequestErrorURL, http.StatusFound)
			return
		}

		if rememberMe == "false" {
			err := tools.SetlastActivityKeyForSession(w, r, session)
			if err != nil {
				errs.WrappedErrPrintRedir(w, r, data.RequestErrorURL, err)
				return
			}
		}

		w.Header().Set("auth", cookie.Value)	
		http.Redirect(w, r, data.HomeURL, http.StatusFound)
	}
}
