package auth

import (
	"database/sql"
	"log"
	"net/http"

	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

func LogIn(store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rememberMe := r.FormValue("rememberMe")
		if rememberMe == "" {
			log.Printf("%+v", errors.WithStack(errors.New("rememberMe: "+data.NotExistErr)))
			http.Redirect(w, r, data.RequestErrorURL, http.StatusFound)
			return
		}

		session, err := store.Get(r, "auth")
		if err != nil {
			log.Printf("%+v", errors.WithStack(err))
			http.Redirect(w, r, data.RequestErrorURL, http.StatusFound)
			return
		}

		validatedLoginInput, err := tools.IsValidInput(w, r)
		if err != nil {
			log.Printf("%+v", err)
			http.Redirect(w, r, data.BadSignInURL, http.StatusFound)
			return
		}

		err = data.UserCheck(w, r, validatedLoginInput)
		if err != nil {
			if err == sql.ErrNoRows {
				log.Printf("%+v", err)
				http.Redirect(w, r, data.UserNotExistURL, http.StatusFound)
				return
			}

			if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
				log.Printf("%+v", err)
				http.Redirect(w, r, data.BadSignInURL, http.StatusFound)
				return
			}

			log.Printf("%+v", err)
			http.Redirect(w, r, data.RequestErrorURL, http.StatusFound)
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
				log.Printf("%+v", err)
				http.Redirect(w, r, data.RequestErrorURL, http.StatusFound)
				return
			}
		}

		http.Redirect(w, r, data.HomeURL, http.StatusFound)
	}
}
