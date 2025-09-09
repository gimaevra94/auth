package auth

import (
	"database/sql"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/tools"
	"golang.org/x/crypto/bcrypt"

	"github.com/pkg/errors"
)

func SignUpInputCheck(w http.ResponseWriter, r *http.Request) {
	tokenValue, err := data.CookieIsExist(r)
	if err != nil {
		var validatedLoginInput tools.User

		loginCounter, err := data.SessionIntDataGet(r, "loginCounter")
		if err != nil {
			log.Printf("%+v", err)
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}

		if loginCounter > 0 {
			validatedLoginInput, err = tools.IsValidInput(r, false, false)
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
					err := data.SessionDataSet(w, r, "loginCounter", loginCounter-1)
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

		} else {
			loginTimer, err := data.SessionTimeDataGet(r, "loginTimer")
			if err != nil {
				log.Printf("%+v", err)
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}

			if loginTimer.IsZero() {
				err = data.SessionDataSet(w, r, "loginTimer", 15*time.Minute)
				if err != nil {
					log.Printf("%+v", err)
					http.Redirect(w, r, consts.Err500URL, http.StatusFound)
					return
				}

				err := tools.Captcha(r)
				if err != nil {
					log.Printf("%+v", err)
					http.Redirect(w, r, consts.Err500URL, http.StatusFound)
					return
				}

			} else {
				if time.Now().After(loginTimer) {
					err = data.SessionDataSet(w, r, "loginCounter", loginCounter+3)
					if err != nil {
						log.Printf("%+v", err)
						http.Redirect(w, r, consts.Err500URL, http.StatusFound)
						return
					}

					http.Redirect(w, r, consts.SignInInputCheckURL, http.StatusFound)
					return
				}

				err := tools.Captcha(r)
				if err != nil {
					log.Printf("%+v", err)
					http.Redirect(w, r, consts.Err500URL, http.StatusFound)
					return
				}
			}
		}

		err = data.SessionDataSet(w, r, "user", validatedLoginInput)
		if err != nil {
			log.Printf("%+v", err)
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}

		SignUpUserCheck(w, r)
	} else {
		_, err = tools.IsValidToken(w, r, tokenValue)
		if err != nil {
			log.Printf("%+v", errors.WithStack(err))
			http.Redirect(w, r, consts.SignInURL, http.StatusFound)
			return
		}

		http.Redirect(w, r, consts.HomeURL, http.StatusFound)
	}
}

func SignUpUserCheck(w http.ResponseWriter, r *http.Request) {
	user, err := data.SessionUserDataGet(r, "user")
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
	}

	err = data.UserCheck("login", user.Login, user.Password)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			CodeSend(w, r)
			return
		}

		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
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

	err = tools.TmplsRenderer(w, tools.BaseTmpl, "SignUp", tools.ErrMsg["alreadyExist"])
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}
}

func CodeSend(w http.ResponseWriter, r *http.Request) {
	user, err := data.SessionUserDataGet(r, "user")
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	msCode, err := tools.AuthCodeSender(user.Email)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	err = data.SessionDataSet(w, r, "msCode", msCode)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
	}

	http.Redirect(w, r, consts.CodeSendURL, http.StatusFound)
}

func UserAdd(w http.ResponseWriter, r *http.Request) {
	user, err := data.SessionUserDataGet(r, "user")
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	userCode := r.FormValue("userCode")
	if userCode == "" {
		log.Printf("%+v", errors.WithStack(errors.New("userCode not exist")))
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	msCode, err := data.SessionStringDataGet(r, "msCode")
	if err != nil {
		log.Printf("%+v", errors.WithStack(errors.New("msCode not exist")))
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	if userCode != msCode {
		err = tools.TmplsRenderer(w, tools.BaseTmpl, "CodeSend", tools.ErrMsg["msCode"])
		if err != nil {
			log.Printf("%+v", err)
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}
		return
	}

	err = data.UserAdd(user)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	rememberMe := r.FormValue("rememberMe")
	if rememberMe == "" {
		log.Printf("%+v", errors.WithStack(errors.New("rememberMe not exist")))
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	signedToken, err := tools.TokenCreate(w, r, rememberMe, user)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}
	data.SetCookieWithToken(w, signedToken)

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

func PasswordReset(w http.ResponseWriter, r *http.Request) {

}
