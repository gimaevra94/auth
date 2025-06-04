package auth

import (
	"database/sql"
	"log"
	"net/http"
	"time"

	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/errs"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
)

func InputCheck(store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		validatedLoginInput, err := tools.IsValidInput(w, r)
		if err != nil {
			errs.WrappedErrPrintRedir(w, r, "", err)
			return
		}

		err = data.UserCheck(w, r, validatedLoginInput, false)
		if err != nil {
			if err == sql.ErrNoRows {
				err := tools.SessionUserSetMarshal(w, r, store, validatedLoginInput)
				if err != nil {
					errs.WrappedErrPrintRedir(w, r, "", err)
					return
				}
				http.Redirect(w, r, data.CodeSendURL, http.StatusFound)
				return
			}

			errs.WrappedErrPrintRedir(w, r, "", err)
			return

		}

		http.Redirect(w, r, data.AlreadyExistURL, http.StatusFound)
		return
	}
}

func CodeSend(store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "codeSend.html")
		session, user, err := tools.SessionUserGetUnmarshal(w, r, store)
		if err != nil {
			errs.WrappedErrPrintRedir(w, r, "", err)
			return
		}

		email := user.GetEmail()
		msCode, err := tools.MailSendler(email)
		if err != nil {
			errs.WrappedErrPrintRedir(w, r, "", err)
			return
		}

		session.Values["mscode"] = msCode
		err = session.Save(r, w)
		if err != nil {
			wrappedErr := errors.WithStack(err)
			log.Printf("%+v", wrappedErr)
			http.Redirect(w, r, data.RequestErrorURL, http.StatusFound)
			errs.w(w, r, "", err)

			return
		}
	}
}

func UserAdd(store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, user, err := tools.SessionUserGetUnmarshal(w, r, store)
		if err != nil {
			log.Printf("%+v", err)
			http.Redirect(w, r, data.RequestErrorURL, http.StatusFound)
			return
		}

		rememberMe := r.FormValue("rememberMe")
		if rememberMe == "" {
			newErr := errors.New(data.NotExistErr)
			wrappedErr := errors.Wrap(newErr, "'rememberMe'")
			log.Printf("%+v", wrappedErr)
			http.Redirect(w, r, data.RequestErrorURL, http.StatusFound)
			return
		}

		cookie, err := r.Cookie("auth")
		if err != nil {
			wrappedErr := errors.WithStack(err)
			log.Printf("%+v", wrappedErr)
			http.Redirect(w, r, data.RequestErrorURL, http.StatusFound)
			return
		}

		userCode := r.FormValue("user")
		msCode, ok := session.Values["mscode"].(string)
		if !ok {
			newErr := errors.New(data.NotExistErr)
			wrappedErr := errors.Wrap(newErr, "'msCode'")
			log.Printf("%+v", wrappedErr)
			http.Redirect(w, r, data.RequestErrorURL, http.StatusFound)
			return
		}

		if userCode != msCode {
			newErr := errors.New("not match 'userCode'")
			wrappedErr := errors.Wrap(newErr, "'msCode'")
			log.Printf("%+v", wrappedErr)
			http.Redirect(w, r, data.WrongCodeURL, http.StatusFound)
			return
		}

		err = data.UserAdd(w, r, user)
		if err != nil {
			log.Printf("%+v", err)
			http.Redirect(w, r, data.RequestErrorURL, http.StatusFound)
			return
		}

		err = tools.TokenCreate(w, r, rememberMe, user)
		if err != nil {
			log.Printf("%+v", err)
			http.Redirect(w, r, data.RequestErrorURL, http.StatusFound)
			return
		}

		if rememberMe == "false" {
			lastActivity := time.Now().Add(3 * time.Hour)
			session.Values["lastActivity"] = lastActivity
			err = session.Save(r, w)

			if err != nil {
				wrappedErr := errors.WithStack(err)
				log.Printf("%+v", wrappedErr)
				http.Redirect(w, r, data.RequestErrorURL, http.StatusFound)
			}
		}

		w.Header().Set("auth", cookie.Value)
		w.Write([]byte(cookie.Value))
		http.Redirect(w, r, data.HomeURL, http.StatusFound)
	}
}
