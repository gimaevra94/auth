package auth

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/tmpls"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
)

func InputCheck(store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		validatedLoginInput, err := tools.IsValidInput(r, false)
		if err != nil {


			if strings.Contains(err.Error(), "login") {
				err := tmpls.ErrRenderer(w, tmpls.BaseTmpl, tmpls.LoginMsg, tmpls.LoginReqs)
				if err != nil {
					http.Redirect(w, r, data.Err500URL, http.StatusFound)
					return
				}
				return
			}

			if strings.Contains(err.Error(), "email") {
				err := tmpls.ErrRenderer(w, tmpls.BaseTmpl, tmpls.EmailMsg, tmpls.EmailReqs)
				if err != nil {
					http.Redirect(w, r, data.Err500URL, http.StatusFound)
					return
				}
				return
			}

			if strings.Contains(err.Error(), "password") {
				err := tmpls.ErrRenderer(w, tmpls.BaseTmpl, tmpls.PasswrdMsg, tmpls.PswrdReqs)
				if err != nil {
					http.Redirect(w, r, data.Err500URL, http.StatusFound)
					return
				}
				return
			}

			log.Printf("%+v", err)
			http.Redirect(w, r, data.Err500URL, http.StatusFound)
			return
		}

		err = tools.SessionDataSet(w, r, validatedLoginInput)
		if err != nil {
			log.Printf("%+v", err)
			http.Redirect(w, r, data.Err500URL, http.StatusFound)
			return
		}
	}
}

/*err = data.UserCheck2("email", validatedLoginInput.Email, validatedLoginInput.Password)
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

http.Redirect(w, r, data.AlreadyExistURL, http.StatusFound)*/

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
			lastActivity := time.Now().Add(3 * time.Hour)
			err := tools.SessionDataSet(w, r, lastActivity)
			if err != nil {
				log.Printf("%+v", err)
				http.Redirect(w, r, data.RequestErrorURL, http.StatusFound)
				return
			}
		}

		http.Redirect(w, r, data.HomeURL, http.StatusFound)
	}
}
