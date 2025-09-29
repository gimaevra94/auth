package auth

import (
	"database/sql"
	"log"
	"net/http"
	"strings"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/structs"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/pkg/errors"
)

func SignUpInputCheck(w http.ResponseWriter, r *http.Request) {
	var user structs.User

	captchaCounter, err := data.SessionGetCaptcha(r, "captcha")
	if err != nil {
		if strings.Contains(err.Error(), "not exist") {
			captchaCounter = 3
		} else {
			log.Printf("%+v", err)
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}
	}

	if captchaCounter > 0 {
		login := r.FormValue("login")
		email := r.FormValue("email")
		password := r.FormValue("password")

		user = structs.User{
			Login:    login,
			Email:    email,
			Password: password,
		}

		err = tools.InputValidator(r, user.Login, user.Email, user.Password, false, false)
		if err != nil {
			if strings.Contains(err.Error(), "login") {
				err := data.SessionDataSet(w, r, "captcha", captchaCounter-1)
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

			} else if strings.Contains(err.Error(), "email") {
				err := data.SessionDataSet(w, r, "captcha", captchaCounter-1)
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

			} else if strings.Contains(err.Error(), "password") {
				err := data.SessionDataSet(w, r, "captcha", captchaCounter-1)
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
		err := tools.Captcha(r)
		if err != nil {
			log.Printf("%+v", err)
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}
	}

	err = data.SessionDataSet(w, r, "auth", user)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	SignUpUserCheck(w, r)
}

func SignUpUserCheck(w http.ResponseWriter, r *http.Request) {
	user, err := data.SessionGetUser(r)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
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
	user, err := data.SessionGetUser(r)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	serverCode, err := tools.AuthCodeSender(user.Email)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}
	user.ServerCode = serverCode

	err = data.SessionDataSet(w, r, "auth", user)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	if r.URL.Path != "/code-send" && r.URL.Path != "/password-reset" {
		http.Redirect(w, r, consts.CodeSendURL, http.StatusFound)
		return
	}
}

func UserAdd(w http.ResponseWriter, r *http.Request) {
	user, err := data.SessionGetUser(r)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	clientCode := r.FormValue("clientCode")
	err = tools.CodeValidator(r, clientCode, user.ServerCode)
	if err != nil {
		if strings.Contains(err.Error(), "exist") {
			log.Printf("%+v", err)
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}

		err = tools.TmplsRenderer(w, tools.BaseTmpl, "CodeSend", tools.ErrMsg["serverCode"])
		if err != nil {
			log.Printf("%+v", err)
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}
	}

	rememberMe := r.FormValue("rememberMe") != ""

	refreshToken, err := tools.GenerateRefreshToken(consts.RefreshTokenExp7Days, rememberMe)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	err = tools.RefreshTokenValidator(refreshToken)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
	}

	temporaryUserID := uuid.New().String()
	permanentUserID := uuid.New().String()
	temporaryCancelled := false

	err = data.UserAdd(user.Login, user.Email, user.Password, temporaryUserID, permanentUserID, temporaryCancelled)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	tokenCancelled := false

	err = data.RefreshTokenAdd(permanentUserID, refreshToken, r.UserAgent(), tokenCancelled)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	captchaCounter := 3
	err = data.SessionDataSet(w, r, "captcha", captchaCounter)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	http.Redirect(w, r, consts.HomeURL, http.StatusFound)
}
