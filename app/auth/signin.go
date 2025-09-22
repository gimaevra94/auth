package auth

import (
	"database/sql"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/structs"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

type SignInPageData struct {
	Msg                string
	ShowForgotPassword bool
}

func SignInInputCheck(w http.ResponseWriter, r *http.Request) {
	var validatedLoginInput structs.User

	loginCounter, err := data.SessionIntDataGet(r, "loginCounter")
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	if loginCounter > 0 {
		validatedLoginInput, err = tools.InputValidator(r, true, false)
		if err != nil {
			if strings.Contains(err.Error(), "login") {
				err := data.SessionDataSet(w, r, "loginCounter", loginCounter-1)
				if err != nil {
					log.Printf("%+v", err)
					http.Redirect(w, r, consts.Err500URL, http.StatusFound)
					return
				}

				err = tools.TmplsRenderer(w, tools.BaseTmpl, "SignIn", SignInPageData{Msg: tools.ErrMsg["login"].Msg})
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

				err = tools.TmplsRenderer(w, tools.BaseTmpl, "SignIn", SignInPageData{Msg: tools.ErrMsg["password"].Msg, ShowForgotPassword: true})
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
				loginCounter = 3
				err = data.SessionDataSet(w, r, "loginCounter", loginCounter)
				if err != nil {
					log.Printf("%+v", err)
					http.Redirect(w, r, consts.Err500URL, http.StatusFound)
					return
				}
			}
		}
	}

	err = data.SessionDataSet(w, r, "user", validatedLoginInput)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	SignInUserCheck(w, r)
}

func SignInUserCheck(w http.ResponseWriter, r *http.Request) {
	user, err := data.SessionUserDataGet(r, "user")
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
	}

	err = data.UserCheck("login", user.Login, user.Password)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			err = tools.TmplsRenderer(w, tools.BaseTmpl, "SignIn", SignInPageData{Msg: tools.ErrMsg["notExist"].Msg})
			if err != nil {
				log.Printf("%+v", err)
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}
			return
		}

		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			err = tools.TmplsRenderer(w, tools.BaseTmpl, "SignIn", SignInPageData{Msg: tools.ErrMsg["password"].Msg, ShowForgotPassword: true})
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

	//var loginCounter int = 3
	//err = data.SessionDataSet(w, r, "loginCounter", loginCounter)
	//if err != nil {
	//	log.Printf("%+v", err)
	//	http.Redirect(w, r, consts.Err500URL, http.StatusFound)
	//	return
	//}

	http.Redirect(w, r, consts.HomeURL, http.StatusFound)
}
