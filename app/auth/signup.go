package auth

import (
	"database/sql"
	"log"
	"net/http"
	"strings"

	"github.com/gimaevra94/auth/app/data"
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
				log.Printf("%+v", err)
				http.Redirect(w, r, data.BadSignUpURL, http.StatusFound)
				return
			}

			if strings.Contains(err.Error(), "email: "+data.InvalidErr) {
				log.Printf("%+v", err)
				http.Redirect(w, r, data.BadEmailURL, http.StatusFound)
				return
			}

			log.Printf("%+v", err)
			http.Redirect(w, r, data.RequestErrorURL, http.StatusFound)
			return
		}

		err = data.UserCheck(validatedLoginInput)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {

				err := tools.SessionUserSet(w, r, store, validatedLoginInput)
				if err != nil {
					log.Printf("%+v", err)
					http.Redirect(w, r, data.RequestErrorURL, http.StatusFound)
					return
				}

				CodeSend(w, r, store)
				return
			}

			if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
				log.Printf("%+v", err)
				http.Redirect(w, r, data.BadSignUpURL, http.StatusFound)
				return
			}

			log.Printf("%+v", err)
			http.Redirect(w, r, data.RequestErrorURL, http.StatusFound)
			return
		}

		http.Redirect(w, r, data.AlreadyExistURL, http.StatusFound)
	}
}

func CodeSend(w http.ResponseWriter, r *http.Request, store *sessions.CookieStore) {
	session, user, err := tools.SessionUserGet(r, store)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, data.RequestErrorURL, http.StatusFound)
		return
	}

	msCode, err := tools.MailSendler(user.Email)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, data.RequestErrorURL, http.StatusFound)
		return
	}

	session.Values["msCode"] = msCode
	err = session.Save(r, w)
	if err != nil {
		log.Printf("%+v", errors.WithStack(err))
		http.Redirect(w, r, data.RequestErrorURL, http.StatusFound)
	}

	http.Redirect(w, r, data.CodeSendURL, http.StatusFound)
}

func UserAdd(store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, user, err := tools.SessionUserGet(r, store)
		if err != nil {
			log.Printf("%+v", err)
			http.Redirect(w, r, data.RequestErrorURL, http.StatusFound)
			return
		}

		rememberMe := r.FormValue("rememberMe")
		if rememberMe == "" {
			log.Printf("%+v", errors.WithStack(errors.New("rememberMe: "+data.NotExistErr)))
			http.Redirect(w, r, data.RequestErrorURL, http.StatusFound)
			return
		}

		userCode := r.FormValue("userCode")
		msCode, ok := session.Values["msCode"].(string)
		if !ok {
			log.Printf("%+v", errors.WithStack(errors.New("msCode: "+data.NotExistErr)))
			http.Redirect(w, r, data.RequestErrorURL, http.StatusFound)
			return
		}

		if userCode != msCode {
			log.Printf("%+v", errors.WithStack(errors.New("msCode not match userCode")))
			http.Redirect(w, r, data.WrongCodeURL, http.StatusFound)
			return
		}

		err = data.UserAdd(user)
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
