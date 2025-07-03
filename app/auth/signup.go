package auth

import (
	"database/sql"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/tmpls"
	"github.com/gimaevra94/auth/app/tools"
	"golang.org/x/crypto/bcrypt"

	"github.com/pkg/errors"
)

func InputCheck(w http.ResponseWriter, r *http.Request) {
	var validatedLoginInput tmpls.User

	loginCounter, err := data.SessionIntDataGet(r, "loginCounter")
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, tmpls.Err500URL, http.StatusFound)
		return
	}

	if loginCounter > 0 {
		validatedLoginInput, err = tools.IsValidInput(r, false)
		if err != nil {

			if strings.Contains(err.Error(), "login") {
				err := data.SessionDataSet(w, r, "loginCounter", loginCounter-1)
				if err != nil {
					log.Printf("%+v", err)
					http.Redirect(w, r, tmpls.Err500URL, http.StatusFound)
					return
				}

				err = tools.ErrRenderer(w, tools.BaseTmpl, tmpls.LoginMsg, tmpls.LoginReqs)
				if err != nil {
					log.Printf("%+v", err)
					http.Redirect(w, r, tmpls.Err500URL, http.StatusFound)
					return
				}

				return
			}

			if strings.Contains(err.Error(), "email") {
				data.SessionDataSet(w, r, "loginCounter", loginCounter-1)
				if err != nil {
					log.Printf("%+v", err)
					http.Redirect(w, r, tmpls.Err500URL, http.StatusFound)
					return
				}

				err := tools.ErrRenderer(w, tools.BaseTmpl, tmpls.EmailMsg, tmpls.EmailReqs)
				if err != nil {
					log.Printf("%+v", err)
					http.Redirect(w, r, tmpls.Err500URL, http.StatusFound)
					return
				}

				return
			}

			if strings.Contains(err.Error(), "password") {
				err = data.SessionDataSet(w, r, "loginCounter", loginCounter-1)
				if err != nil {
					log.Printf("%+v", err)
					http.Redirect(w, r, tmpls.Err500URL, http.StatusFound)
					return
				}

				err := tools.ErrRenderer(w, tools.BaseTmpl, tmpls.PasswrdMsg, tmpls.PswrdReqs)
				if err != nil {
					log.Printf("%+v", err)
					http.Redirect(w, r, tmpls.Err500URL, http.StatusFound)
					return
				}

				return
			}

			log.Printf("%+v", err)
			http.Redirect(w, r, tmpls.Err500URL, http.StatusFound)
			return
		}

	} else {
		loginTimer, err := data.SessionTimeDataGet(r, "loginTimer")
		if err != nil {
			log.Printf("%+v", err)
			http.Redirect(w, r, tmpls.Err500URL, http.StatusFound)
			return
		}

		if loginTimer.IsZero() {
			err = data.SessionDataSet(w, r, "loginTimer", 15*time.Minute)
			if err != nil {
				log.Printf("%+v", err)
				http.Redirect(w, r, tmpls.Err500URL, http.StatusFound)
				return
			}

			err := tools.Captcha(r)
			if err != nil {
				log.Printf("%+v", err)
				http.Redirect(w, r, tmpls.Err500URL, http.StatusFound)
				return
			}

		} else {
			if time.Now().After(loginTimer) {
				err = data.SessionDataSet(w, r, "loginCounter", loginCounter+3)
				if err != nil {
					log.Printf("%+v", err)
					http.Redirect(w, r, tmpls.Err500URL, http.StatusFound)
					return
				}

				http.Redirect(w, r, tmpls.InputCheckURL, http.StatusFound)
				return
			}

			err := tools.Captcha(r)
			if err != nil {
				log.Printf("%+v", err)
				http.Redirect(w, r, tmpls.Err500URL, http.StatusFound)
				return
			}
		}
	}

	err = data.SessionDataSet(w, r, "user", validatedLoginInput)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, tmpls.Err500URL, http.StatusFound)
		return
	}
}

func UserCheck(w http.ResponseWriter, r *http.Request) {
	user, err := data.SessionUserDataGet(r, "user")
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, tmpls.Err500URL, http.StatusFound)
	}

	err = data.UserCheck("login", user.Login, user.Password)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			err := data.SessionDataSet(w, r, "user", user)
			if err != nil {
				log.Printf("%+v", err)
				http.Redirect(w, r, tmpls.Err500URL, http.StatusFound)
				return
			}

			CodeSend(w, r)
			return
		}

		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			err = tools.ErrRenderer(w, tools.BaseTmpl, tmpls.PasswrdMsg, tmpls.PswrdReqs)
			if err != nil {
				log.Printf("%+v", err)
				http.Redirect(w, r, tmpls.Err500URL, http.StatusFound)
				return
			}

			return
		}

		log.Printf("%+v", err)
		http.Redirect(w, r, tmpls.Err500URL, http.StatusFound)
		return
	}

	err = tools.ErrRenderer(w, tools.BaseTmpl, tmpls.UserAlreadyExistMsg, []string{})
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, tmpls.Err500URL, http.StatusFound)
		return
	}
}

func CodeSend(w http.ResponseWriter, r *http.Request) {
	user, err := data.SessionUserDataGet(r, "user")
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, tmpls.Err500URL, http.StatusFound)
		return
	}

	msCode, err := tools.MailSendler(user.Email)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, tmpls.Err500URL, http.StatusFound)
		return
	}

	err = data.SessionDataSet(w, r, "msCode", msCode)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, tmpls.Err500URL, http.StatusFound)
	}

	http.Redirect(w, r, tmpls.CodeSendURL, http.StatusFound)
}

func UserAdd(w http.ResponseWriter, r *http.Request) {
	user, err := data.SessionUserDataGet(r, "user")
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, tmpls.Err500URL, http.StatusFound)
		return
	}

	rememberMe := r.FormValue("rememberMe")
	if rememberMe == "" {
		log.Printf("%+v", errors.WithStack(errors.New("rememberMe: "+tmpls.NotExistErr)))
		http.Redirect(w, r, tmpls.Err500URL, http.StatusFound)
		return
	}

	userCode := r.FormValue("userCode")
	if userCode == "" {
		log.Printf("%+v", errors.WithStack(errors.New("userCode: "+tmpls.NotExistErr)))
		http.Redirect(w, r, tmpls.Err500URL, http.StatusFound)
		return
	}

	msCode, err := data.SessionStringDataGet(r, "msCode")
	if err != nil {
		log.Printf("%+v", errors.WithStack(errors.New("msCode: "+tmpls.NotExistErr)))
		http.Redirect(w, r, tmpls.Err500URL, http.StatusFound)
		return
	}

	if userCode != msCode {
		err = tools.ErrRenderer(w, tools.BaseTmpl, tmpls.MsCodeMsg, []string{})
		if err != nil {
			log.Printf("%+v", err)
			http.Redirect(w, r, tmpls.Err500URL, http.StatusFound)
			return
		}
		return
	}

	err = data.UserAdd(user)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, tmpls.Err500URL, http.StatusFound)
		return
	}

	_, err = tools.TokenCreate(w, r, rememberMe, user)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, tmpls.Err500URL, http.StatusFound)
		return
	}

	if rememberMe == "false" {
		lastActivity := time.Now().Add(3 * time.Hour)
		err := data.SessionDataSet(w, r, "lastActivity", lastActivity)
		if err != nil {
			log.Printf("%+v", err)
			http.Redirect(w, r, tmpls.Err500URL, http.StatusFound)
			return
		}
	}

	http.Redirect(w, r, tmpls.HomeURL, http.StatusFound)
}
