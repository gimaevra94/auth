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
	"golang.org/x/crypto/bcrypt"

	"github.com/pkg/errors"
)

func SignUpInputCheck(w http.ResponseWriter, r *http.Request) {
	var validatedLoginInput structs.User

	captchaCounter, err := data.SessionIntDataGet(r, "captcha", "captchaCounter")
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
		validatedLoginInput, err = tools.InputValidator(r, false, false)
		if err != nil {
			if strings.Contains(err.Error(), "login") {
				err := data.SessionDataSet(w, r, "captcha", "captchaCounter", captchaCounter-1)
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
				err := data.SessionDataSet(w, r, "captcha", "captchaCounter", captchaCounter-1)
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
				err := data.SessionDataSet(w, r, "captcha", "captchaCounter", captchaCounter-1)
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

	err = data.SessionDataSet(w, r, "auth", "user", validatedLoginInput)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	SignUpUserCheck(w, r)
}

func SignUpUserCheck(w http.ResponseWriter, r *http.Request) {
	user, err := data.SessionUserDataGet(r, "user")
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	_, err = data.UserCheck("login", user.Login, user.Password)
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

	err = data.SessionDataSet(w, r, "auth", "msCode", msCode)
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
			return
		}
	}

	rememberMe := r.FormValue("rememberMe") != ""
	signedRefreshToken, userID, expiresAt, err := tools.GenerateRefreshToken(rememberMe)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	user.UserID = userID
	user.Token = signedRefreshToken
	user.ExpiresAt = expiresAt
	user.DeviceInfo = r.UserAgent()

	err = data.UserAdd(user)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	err = data.RefreshTokenAdd(user)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	signedAccessToken, err := tools.GenerateAccessToken(user)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	data.SetAccessTokenCookie(w, signedAccessToken)

	err = data.SessionDataSet(w, r, "captcha", "captchaCounter", 3)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	http.Redirect(w, r, consts.HomeURL, http.StatusFound)
}
