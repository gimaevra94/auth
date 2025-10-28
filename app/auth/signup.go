package auth

import (
	"database/sql"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/structs"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/google/uuid"

	"github.com/pkg/errors"
)

func SignUpInputCheck(w http.ResponseWriter, r *http.Request) {
	var user structs.User
	var captchaShow bool

	login := r.FormValue("login")
	email := r.FormValue("email")
	password := r.FormValue("password")

	user = structs.User{
		Login:    login,
		Email:    email,
		Password: password,
	}

	captchaCounter, err := data.SessionCaptchaCounterGet(r)
	if err != nil {
		if strings.Contains(err.Error(), "exist") {
			captchaCounter = 3

			err2 := data.SessionCaptchaDataSet(w, r, "captchaCounter", captchaCounter)
			if err2 != nil {
				log.Printf("%+v", err2)
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}

		} else {
			log.Printf("%+v", err)
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}
	}

	captchaShow, err = data.SessionCaptchaShowGet(r)
	if err != nil {
		if strings.Contains(err.Error(), "exist") {
			captchaShow = false

			err2 := data.SessionCaptchaDataSet(w, r, "captchaShow", captchaShow)
			if err2 != nil {
				log.Printf("%+v", err2)
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}

		} else {
			log.Printf("%+v", err)
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}
	}

	if captchaShow {
		err = tools.CaptchaShow(r)
		if err != nil {
			if strings.Contains(err.Error(), "captchaToken not exist") {
				err = tools.TmplsRenderer(w, tools.BaseTmpl, "SignUp", tools.SignUpPageData{Msg: tools.ErrMsg["captchaRequired"].Msg, CaptchaShow: captchaShow, Regs: nil})
				if err != nil {
					log.Printf("%+v", err)
					http.Redirect(w, r, consts.Err500URL, http.StatusFound)
					return
				}
				return

			} else {
				log.Printf("%+v", err)
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}
		}
	}

	err = tools.InputValidate(r, user.Login, user.Email, user.Password, false)
	if err != nil {
		if strings.Contains(err.Error(), "login") {
			err := data.SessionCaptchaDataSet(w, r, "captchaCounter", captchaCounter-1)
			if err != nil {
				log.Printf("%+v", err)
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}

			captchaCounter -= 1
			if captchaCounter == 0 {
				captchaShow = true

				err = data.SessionCaptchaDataSet(w, r, "captchaShow", captchaShow)
				if err != nil {
					log.Printf("%+v", err)
					http.Redirect(w, r, consts.Err500URL, http.StatusFound)
					return
				}
			}

			err = tools.TmplsRenderer(w, tools.BaseTmpl, "SignUp", tools.SignUpPageData{Msg: tools.ErrMsg["login"].Msg, CaptchaShow: captchaShow, Regs: tools.ErrMsg["login"].Regs})
			if err != nil {
				log.Printf("%+v", err)
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}
			return

		} else if strings.Contains(err.Error(), "email") {
			err := data.SessionCaptchaDataSet(w, r, "captchaCounter", captchaCounter-1)
			if err != nil {
				log.Printf("%+v", err)
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}

			captchaCounter -= 1
			if captchaCounter == 0 {
				captchaShow = true

				err = data.SessionCaptchaDataSet(w, r, "captchaShow", captchaShow)
				if err != nil {
					log.Printf("%+v", err)
					http.Redirect(w, r, consts.Err500URL, http.StatusFound)
					return
				}
			}

			err = tools.TmplsRenderer(w, tools.BaseTmpl, "SignUp", tools.SignUpPageData{Msg: tools.ErrMsg["email"].Msg, CaptchaShow: captchaShow, Regs: tools.ErrMsg["email"].Regs})
			if err != nil {
				log.Printf("%+v", err)
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}

			return

		} else if strings.Contains(err.Error(), "password") {
			err := data.SessionCaptchaDataSet(w, r, "captchaCounter", captchaCounter-1)
			if err != nil {
				log.Printf("%+v", err)
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}

			captchaCounter -= 1
			if captchaCounter == 0 {
				captchaShow = true

				err = data.SessionCaptchaDataSet(w, r, "captchaShow", captchaShow)
				if err != nil {
					log.Printf("%+v", err)
					http.Redirect(w, r, consts.Err500URL, http.StatusFound)
					return
				}
			}

			err = tools.TmplsRenderer(w, tools.BaseTmpl, "SignUp", tools.SignUpPageData{Msg: tools.ErrMsg["password"].Msg, CaptchaShow: captchaShow, Regs: tools.ErrMsg["password"].Regs})
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

	err = data.AuthSessionDataSet(w, r, user)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	SignUpUserCheck(w, r)
}

func SignUpUserCheck(w http.ResponseWriter, r *http.Request) {
	user, err := data.SessionUserGet(r)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	captchaCounter, err := data.SessionCaptchaCounterGet(r)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	captchaShow, err := data.SessionCaptchaShowGet(r)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	err = data.SignUpUserCheck(user.Login)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			CodeSend(w, r)
			return
		}

		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	if captchaCounter == 0 {
		captchaShow = true
	}
	captchaCounter -= 1

	err = data.SessionCaptchaDataSet(w, r, "captchaCounter", captchaCounter)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}
	err = data.SessionCaptchaDataSet(w, r, "captchaShow", captchaShow)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	err = tools.TmplsRenderer(w, tools.BaseTmpl, "SignUp", tools.SignUpPageData{Msg: tools.ErrMsg["alreadyExist"].Msg, CaptchaShow: captchaShow})
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}
}

func CodeSend(w http.ResponseWriter, r *http.Request) {
	user, err := data.SessionUserGet(r)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	if user.ServerCode != "" {
		log.Println("Code already sent")
		http.Redirect(w, r, consts.CodeSendURL, http.StatusFound)
		return
	}

	serverCode, err := tools.AuthCodeSend(user.Email)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}
	user.ServerCode = serverCode

	err = data.AuthSessionDataSet(w, r, user)
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
	user, err := data.SessionUserGet(r)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	clientCode := r.FormValue("clientCode")
	err = tools.CodeValidate(r, clientCode, user.ServerCode)
	if err != nil {
		if strings.Contains(err.Error(), "exist") {
			err = tools.TmplsRenderer(w, tools.BaseTmpl, "CodeSend", tools.ErrMsg["userCode"])
			if err != nil {
				log.Printf("%+v", err)
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}
			return

		} else if strings.Contains(err.Error(), "match") {
			err = tools.TmplsRenderer(w, tools.BaseTmpl, "CodeSend", tools.ErrMsg["serverCode"])
			if err != nil {
				log.Printf("%+v", err)
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}
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

	temporaryUserID := uuid.New().String()
	data.TemporaryUserIDCookieSet(w, temporaryUserID)
	// Маркируем тип логина и сохраняем параметры для UA-контроля, как в SignIn
	http.SetCookie(w, &http.Cookie{
		Name:     "yauth",
		Value:    "0",
		Path:     "/",
		HttpOnly: false,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   consts.TemporaryUserIDExp,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "ua",
		Value:    url.QueryEscape(r.UserAgent()),
		Path:     "/",
		HttpOnly: false,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   consts.TemporaryUserIDExp,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "new_session",
		Value:    "1",
		Path:     "/",
		HttpOnly: false,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   consts.TemporaryUserIDExp,
	})
	permanentUserID := uuid.New().String()
	temporaryCancelled := false

	// Уведомление о первом входе с нового устройства выполняем после коммита ниже,
	// используя данные пользователя из сессии.

	tx, err := data.DB.Begin()
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}
	defer func() {
		r := recover()
		if r != nil {
			tx.Rollback()
			panic(r)
		}
	}()

	err = data.UserAddTx(tx, user.Login, user.Email, user.Password, temporaryUserID, permanentUserID, temporaryCancelled)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	tokenCancelled := false
	err = data.RefreshTokenAddTx(tx, permanentUserID, refreshToken, r.UserAgent(), tokenCancelled)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	err = tx.Commit()
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	err = tools.SendNewDeviceLoginEmail(user.Email, user.Login, r.UserAgent())
	if err != nil {
		log.Printf("%+v", err)
	}

	captchaCounter := 3
	err = data.SessionCaptchaDataSet(w, r, "captchaCounter", captchaCounter)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	err = data.SessionCaptchaDataSet(w, r, "captchaShow", false)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	err = data.AuthSessionEnd(w, r)
	if err != nil {
		log.Printf("%v", errors.WithStack(err))
		http.Redirect(w, r, consts.SignInURL, http.StatusFound)
		return
	}

	http.Redirect(w, r, consts.HomeURL, http.StatusFound)
}
