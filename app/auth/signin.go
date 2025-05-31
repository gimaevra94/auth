package auth

import (
	"database/sql"
	"log"
	"net/http"
	"time"

	"github.com/pkg/errors"

	"github.com/gimaevra94/auth/app"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

func LogIn(store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rememberMe := r.FormValue("'rememberMe'")
		if rememberMe == "" {
			tools.WrappingErrPrintRedir(w, r, app.RequestErrorURL,
				app.NotExistErr, "'rememberMe'")
			return
		}

		session, err := store.Get(r, "auth")
		if err != nil {
			tools.WithStackingErrPrintRedir(w, r, app.RequestErrorURL, err)
			return
		}

		cookie, err := r.Cookie("auth")
		if err != nil {
			tools.WithStackingErrPrintRedir(w, r, app.RequestErrorURL, err)
			return
		}

		validatedLoginInput, err := tools.IsValidInput(w, r)
		if err != nil {
			tools.WrappedErrPrintRedir(w, r, app.BadSignInURL, err)
			return
		}

		err = app.UserCheck(w, r, validatedLoginInput, true)
		if err != nil {
			if err == sql.ErrNoRows {
				tools.WrappedErrPrintRedir(w, r, app.UserNotExistURL, err)
				return
			}

			if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
				tools.WrappedErrPrintRedir(w, r, app.BadSignInURL, err)
				return
			}

			tools.WrappedErrPrintRedir(w, r, app.RequestErrorURL, err)
			return
		}

		err = tools.TokenCreate(w, r, rememberMe, validatedLoginInput)
		if err != nil {
			log.Printf("%+v", err)
			http.Redirect(w, r, app.RequestErrorURL, http.StatusFound)
		}

		if rememberMe == "false" {
			err := setlastActivityKeyForSession(w, r, session)
			if err != nil {
				tools.WithStackingErrPrintRedir(w, r, app.RequestErrorURL, err)
				return
			}
		}

		w.Header().Set("auth", cookie.Value)
		w.Write([]byte(cookie.Value))
		http.Redirect(w, r, app.HomeURL, http.StatusFound)
	}
}

func setlastActivityKeyForSession(w http.ResponseWriter, r *http.Request,
	session *sessions.Session) error {
	lastActivity := time.Now().Add(3 * time.Hour)
	session.Values["lastActivity"] = lastActivity
	err := session.Save(r, w)
	return err
}
