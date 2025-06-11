package auth

import (
	"database/sql"
	"net/http"
	"strings"

	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/errs"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

func InputCheck(store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		validatedLoginInput, err := tools.IsValidInput(w, r)
		if err != nil {

			if strings.Contains(err.Error(),
				"login: "+data.InvalidErr) ||
				strings.Contains(err.Error(),
					"password: "+data.InvalidErr) {
				errs.WrappedErrPrintRedir(w, r, data.BadSignUpURL, err)
				return
			}

			if strings.Contains(err.Error(), "email: "+data.InvalidErr) {
				errs.WrappedErrPrintRedir(w, r, data.BadEmailURL, err)
				return
			}

			errs.WrappedErrPrintRedir(w, r, data.RequestErrorURL, err)
			return
		}

		err = data.UserCheck(w, r, validatedLoginInput)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				err := tools.SessionUserSetMarshal(w, r, store, validatedLoginInput)
				if err != nil {
					errs.WrappedErrPrintRedir(w, r, data.RequestErrorURL, err)
					return
				}
				http.Redirect(w, r, data.CodeSendURL, http.StatusFound)
				return
			}

			if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
				errs.WrappedErrPrintRedir(w, r, data.BadSignUpURL, err)
				return
			}

			errs.WrappedErrPrintRedir(w, r, data.RequestErrorURL, err)
			return
		}

		http.Redirect(w, r, data.AlreadyExistURL, http.StatusFound)
	}
}

func CodeSend(store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "codeSend.html")
		session, user, err := tools.SessionUserGetUnmarshal(w, r, store)
		if err != nil {
			errs.WrappedErrPrintRedir(w, r, data.RequestErrorURL, err)
			return
		}

		email := user.GetEmail()
		msCode, err := tools.MailSendler(w, r, email)
		if err != nil {
			errs.WrappedErrPrintRedir(w, r, data.RequestErrorURL, err)
			return
		}

		session.Values["mscode"] = msCode
		err = session.Save(r, w)
		if err != nil {
			errs.WrappedErrPrintRedir(w, r, data.RequestErrorURL, err)
		}
	}
}

func UserAdd(store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, user, err := tools.SessionUserGetUnmarshal(w, r, store)
		if err != nil {
			errs.WrappedErrPrintRedir(w, r, data.RequestErrorURL, err)
			return
		}

		rememberMe := r.FormValue("rememberMe")
		if rememberMe == "" {
			errs.NewErrWrapPrintRedir(w, r, data.RequestErrorURL, data.NotExistErr, "rememberMe")
			return
		}

		cookie, err := r.Cookie("auth")
		if err != nil {
			errs.OrigErrWrapPrintRedir(w, r, data.RequestErrorURL, err)
			return
		}

		userCode := r.FormValue("user")
		msCode, ok := session.Values["mscode"].(string)
		if !ok {
			errs.NewErrWrapPrintRedir(w, r, data.RequestErrorURL, data.NotExistErr, "msCode")
			return
		}

		if userCode != msCode {
			errs.NewErrWrapPrintRedir(w, r, data.WrongCodeURL, "not match 'userCode'", "msCode")
			return
		}

		err = data.UserAdd(w, r, user)
		if err != nil {
			errs.WrappedErrPrintRedir(w, r, data.RequestErrorURL, err)
			return
		}

		err = tools.TokenCreate(w, r, rememberMe, user)
		if err != nil {
			errs.WrappedErrPrintRedir(w, r, data.RequestErrorURL, err)
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
