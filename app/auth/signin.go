package auth

import (
	"database/sql"
	"log"
	"net/http"
	"time"

	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

func LogIn(w http.ResponseWriter, r *http.Request) {
	rememberMe := r.FormValue("rememberMe")
	if rememberMe == "" {
		log.Printf("%+v", errors.WithStack(errors.New("rememberMe: "+consts.NotExistErr)))
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	var validatedLoginInput tools.User

	if loginCounter > 0 {
		validatedLoginInput, err = tools.IsValidInput(r, false)
		if err != nil {

			if strings.Contains(err.Error(), "login") {
				err := data.SessionDataSet(w, r, "loginCounter", loginCounter-1)
				if err != nil {
					log.Printf("%+v", err)
					http.Redirect(w, r, consts.Err500URL, http.StatusFound)
					return
				}

				err = tools.TmplsRenderer(w, tools.BaseTmpl, "SignUp", tools.ErrMsg["login"])
				if err != nil {
					log.Printf("%+v", err)
					http.Redirect(w, r, consts.Err500URL, http.StatusFound)
					return
				}

				return
			}

			if strings.Contains(err.Error(), "email") {
				data.SessionDataSet(w, r, "loginCounter", loginCounter-1)
				if err != nil {
					log.Printf("%+v", err)
					http.Redirect(w, r, consts.Err500URL, http.StatusFound)
					return
				}

				err = tools.TmplsRenderer(w, tools.BaseTmpl, "SignUp", tools.ErrMsg["email"])
				if err != nil {
					log.Printf("%+v", err)
					http.Redirect(w, r, consts.Err500URL, http.StatusFound)
					return
				}

				return
			}

			if strings.Contains(err.Error(), "password") {
				err = data.SessionDataSet(w, r, "loginCounter", loginCounter-1)
				if err != nil {
					log.Printf("%+v", err)
					http.Redirect(w, r, consts.Err500URL, http.StatusFound)
					return
				}

				err = tools.TmplsRenderer(w, tools.BaseTmpl, "SignUp", tools.ErrMsg["password"])
				if err != nil {
					log.Printf("%+v", err)
					http.Redirect(w, r, consts.Err500URL, http.StatusFound)
					return
				}

				return
			}

			log.Printf("%+v", err)
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}

	}

	err = data.UserCheck("login", validatedLoginInput.Login, validatedLoginInput.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("%+v", err)
			http.Redirect(w, r, consts.UserNotExistURL, http.StatusFound)
			return
		}

		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			log.Printf("%+v", err)
			http.Redirect(w, r, consts.BadSignInURL, http.StatusFound)
			return
		}

		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	_, err = tools.TokenCreate(w, r, rememberMe, validatedLoginInput)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	if rememberMe == "false" {
		lastActivity := time.Now().Add(3 * time.Hour)
		err := data.SessionDataSet(w, r, "lastActivity", lastActivity)
		if err != nil {
			log.Printf("%+v", err)
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}
	}

	http.Redirect(w, r, consts.HomeURL, http.StatusFound)
}
