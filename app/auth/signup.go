package auth

import (
	"database/sql"
	"log"
	"net/http"
	"time"

	"github.com/gimaevra94/auth/app/tools"
	"github.com/gimaevra94/auth/app/dataspace"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
)

func InputCheck(store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		validatedLoginInput, err := tools.IsValidInput(w, r)
		if err != nil {
			log.Printf("%+v", err)
			http.Redirect(w, r, dataspace.BadSignUpURL, http.StatusFound)
		}

		err = dataspace.UserCheck(w, r, validatedLoginInput, false)
		if err != nil {
			if err == sql.ErrNoRows {
				err := tools.SessionUserSetMarshal(w, r, store, validatedLoginInput)
				if err != nil {
					log.Printf("%+v", err)
					http.Redirect(w, r, dataspace.RequestErrorURL, http.StatusFound)
				}
				http.Redirect(w, r, dataspace.CodeSendURL, http.StatusFound)
			}

			log.Printf("%+v", err)
			http.Redirect(w, r, dataspace.RequestErrorURL, http.StatusFound)
		}

		http.Redirect(w, r, dataspace.AlreadyExistURL, http.StatusFound)
	}
}

func CodeSend(store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "codeSend.html")
		session, user, err := tools.SessionUserGetUnmarshal(r, store)
		if err != nil {
			log.Printf("%+v", err)
			http.Redirect(w, r, dataspace.RequestErrorURL, http.StatusFound)
			return
		}

		email := user.GetEmail()
		msCode, err := tools.MailSendler(email)
		if err != nil {
			log.Printf("%+v", err)
			http.Redirect(w, r, dataspace.RequestErrorURL, http.StatusFound)
			return
		}

		session.Values["mscode"] = msCode
		err = session.Save(r, w)
		if err != nil {
			wrappedErr := errors.WithStack(err)
			log.Printf("%+v", wrappedErr)
			http.Redirect(w, r, dataspace.RequestErrorURL, http.StatusFound)
			return
		}
	}
}

func UserAdd(store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, user, err := tools.SessionUserGetUnmarshal(r, store)
		if err != nil {
			log.Printf("%+v", err)
			http.Redirect(w, r, dataspace.RequestErrorURL, http.StatusFound)
			return
		}

		rememberMe := r.FormValue("rememberMe")
		if rememberMe == "" {
			newErr := errors.New(dataspace.NotExistErr)
			wrappedErr := errors.Wrap(newErr, "'rememberMe'")
			log.Printf("%+v", wrappedErr)
			http.Redirect(w, r, dataspace.RequestErrorURL, http.StatusFound)
			return
		}

		cookie, err := r.Cookie("auth")
		if err != nil {
			wrappedErr := errors.WithStack(err)
			log.Printf("%+v", wrappedErr)
			http.Redirect(w, r, dataspace.RequestErrorURL, http.StatusFound)
			return
		}

		userCode := r.FormValue("user")
		msCode, ok := session.Values["mscode"].(string)
		if !ok {
			newErr := errors.New(dataspace.NotExistErr)
			wrappedErr := errors.Wrap(newErr, "'msCode'")
			log.Printf("%+v", wrappedErr)
			http.Redirect(w, r, dataspace.RequestErrorURL, http.StatusFound)
			return
		}

		if userCode != msCode {
			newErr := errors.New("not match 'userCode'")
			wrappedErr := errors.Wrap(newErr, "'msCode'")
			log.Printf("%+v", wrappedErr)
			http.Redirect(w, r, dataspace.WrongCodeURL, http.StatusFound)
			return
		}

		err = dataspace.UserAdd(w, r, user)
		if err != nil {
			log.Printf("%+v", err)
			http.Redirect(w, r, dataspace.RequestErrorURL, http.StatusFound)
			return
		}

		err = tools.TokenCreate(w, r, rememberMe, user)
		if err != nil {
			log.Printf("%+v", err)
			http.Redirect(w, r, dataspace.RequestErrorURL, http.StatusFound)
			return
		}

		if rememberMe == "false" {
			lastActivity := time.Now().Add(3 * time.Hour)
			session.Values["lastActivity"] = lastActivity
			err = session.Save(r, w)

			if err != nil {
				wrappedErr := errors.WithStack(err)
				log.Printf("%+v", wrappedErr)
				http.Redirect(w, r, dataspace.RequestErrorURL, http.StatusFound)
			}
		}

		w.Header().Set("auth", cookie.Value)
		w.Write([]byte(cookie.Value))
		http.Redirect(w, r, dataspace.HomeURL, http.StatusFound)
	}
}
