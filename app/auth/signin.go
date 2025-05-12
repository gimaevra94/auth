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
			newErr := errors.New(app.NotExistErr)
			wrappedErr := errors.Wrap(newErr, "'rememberMe'")
			log.Println("%+v", wrappedErr)
			http.Redirect(w, r, app.RequestErrorURL, http.StatusFound)
			return
		}

		session, err := store.Get(r, "auth")
		if err != nil {
			wrappedErr := errors.WithStack(err)
			log.Println("%+v", wrappedErr)
			http.Redirect(w, r, app.RequestErrorURL, http.StatusFound)
		}

		cookie, err := r.Cookie("auth")
		if err != nil {
			wrappedErr := errors.WithStack(err)
			log.Println("%+v", wrappedErr)
			http.Redirect(w, r, app.RequestErrorURL, http.StatusFound)
		}

		validatedLoginInput, err := tools.IsValidInput(w, r)
		if err != nil {
			log.Println("%+v", err)
			http.Redirect(w, r, app.BadSignInURL, http.StatusFound)
			return
		}

		err = app.UserCheck(w, r, validatedLoginInput, true)
		if err != nil {
			if err == sql.ErrNoRows {
				log.Println("%+v", err)
				http.Redirect(w, r, app.UserNotExistURL, http.StatusFound)
				return
			}

			if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
				log.Println("%+v", err)
				http.Redirect(w, r, app.BadSignInURL, http.StatusFound)
				return
			}

			log.Println("%+v", err)
			http.Redirect(w, r, app.RequestErrorURL, http.StatusFound)
		}

		err = tools.TokenCreate(w, r, rememberMe, validatedLoginInput)
		if err != nil {
			log.Println("%+v", err)
			http.Redirect(w, r, app.RequestErrorURL, http.StatusFound)
		}

		lastActivity := time.Now().Add(3 * time.Hour)
		session.Values["lastActivity"] = lastActivity
		err = session.Save(r, w)
		if err != nil {
			wrappedErr := errors.WithStack(err)
			log.Println("%+v", wrappedErr)
			http.Redirect(w, r, app.RequestErrorURL, http.StatusFound)
		}

		w.Header().Set("auth", cookie.Value)
		w.Write([]byte(cookie.Value))
		http.Redirect(w, r, app.HomeURL, http.StatusFound)
	}
}
