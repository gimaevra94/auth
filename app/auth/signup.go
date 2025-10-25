package auth

import (
	"database/sql"
	"log"
	"net/http"
	"strings"
    "net/url"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/structs"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/google/uuid"

	"github.com/pkg/errors"
)

type SignUpPageData struct {
	Msg         string
	CaptchaShow bool
	Regs        []string
}

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
			if err2 := data.CaptchaSessionDataSet(w, r, "captchaCounter", captchaCounter); err2 != nil {
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
			if err2 := data.CaptchaSessionDataSet(w, r, "captchaShow", captchaShow); err2 != nil {
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
		err = tools.Captcha(r)
		if err != nil {
			if strings.Contains(err.Error(), "captchaToken not exist") {
				err = tools.TmplsRenderer(w, tools.BaseTmpl, "SignUp", SignUpPageData{Msg: tools.ErrMsg["captchaRequired"].Msg, CaptchaShow: captchaShow, Regs: nil})
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
			err := data.CaptchaSessionDataSet(w, r, "captchaCounter", captchaCounter-1)
			if err != nil {
				log.Printf("%+v", err)
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}

			captchaCounter -= 1
			if captchaCounter == 0 {
				captchaShow = true

				err = data.CaptchaSessionDataSet(w, r, "captchaShow", captchaShow)
				if err != nil {
					log.Printf("%+v", err)
					http.Redirect(w, r, consts.Err500URL, http.StatusFound)
					return
				}
			}

			err = tools.TmplsRenderer(w, tools.BaseTmpl, "SignUp", SignUpPageData{Msg: tools.ErrMsg["login"].Msg, CaptchaShow: captchaShow, Regs: tools.ErrMsg["login"].Regs})
			if err != nil {
				log.Printf("%+v", err)
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}

			return

		} else if strings.Contains(err.Error(), "email") {
			err := data.CaptchaSessionDataSet(w, r, "captchaCounter", captchaCounter-1)
			if err != nil {
				log.Printf("%+v", err)
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}

			captchaCounter -= 1
			if captchaCounter == 0 {
				captchaShow = true

				err = data.CaptchaSessionDataSet(w, r, "captchaShow", captchaShow)
				if err != nil {
					log.Printf("%+v", err)
					http.Redirect(w, r, consts.Err500URL, http.StatusFound)
					return
				}
			}

			err = tools.TmplsRenderer(w, tools.BaseTmpl, "SignUp", SignUpPageData{Msg: tools.ErrMsg["email"].Msg, CaptchaShow: captchaShow, Regs: tools.ErrMsg["email"].Regs})
			if err != nil {
				log.Printf("%+v", err)
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}

			return

		} else if strings.Contains(err.Error(), "password") {
			err := data.CaptchaSessionDataSet(w, r, "captchaCounter", captchaCounter-1)
			if err != nil {
				log.Printf("%+v", err)
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}

			captchaCounter -= 1
			if captchaCounter == 0 {
				captchaShow = true

				err = data.CaptchaSessionDataSet(w, r, "captchaShow", captchaShow)
				if err != nil {
					log.Printf("%+v", err)
					http.Redirect(w, r, consts.Err500URL, http.StatusFound)
					return
				}
			}

			err = tools.TmplsRenderer(w, tools.BaseTmpl, "SignUp", SignUpPageData{Msg: tools.ErrMsg["password"].Msg, CaptchaShow: captchaShow, Regs: tools.ErrMsg["password"].Regs})
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
	} else {
	}

	captchaShow, err := data.SessionCaptchaShowGet(r)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	// 1) Проверка существования логина
	if row := data.DB.QueryRow(consts.YauthSelectQuery, user.Login); row != nil {
		var tmp string
		if err := row.Scan(&tmp); err == nil {
			// Логин уже существует -> показать alreadyExist
			captchaCounter -= 1
			if captchaCounter == 0 {
				captchaShow = true
			}
			if err := data.CaptchaSessionDataSet(w, r, "captchaCounter", captchaCounter); err != nil {
				log.Printf("%+v", err)
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}
			if err := data.CaptchaSessionDataSet(w, r, "captchaShow", captchaShow); err != nil {
				log.Printf("%+v", err)
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}
			if err := tools.TmplsRenderer(w, tools.BaseTmpl, "SignUp", SignUpPageData{Msg: tools.ErrMsg["alreadyExist"].Msg, CaptchaShow: captchaShow}); err != nil {
				log.Printf("%+v", err)
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}
			return
		} else if !errors.Is(err, sql.ErrNoRows) {
			log.Printf("%+v", err)
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}
	}

	// 2) Проверка существования email
	if row := data.DB.QueryRow(consts.PasswordResetEmailSelectQuery, user.Email); row != nil {
		var tmp string
		if err := row.Scan(&tmp); err == nil {
			// Email уже существует -> показать alreadyExist
			captchaCounter -= 1
			if captchaCounter == 0 {
				captchaShow = true
			}
			if err := data.CaptchaSessionDataSet(w, r, "captchaCounter", captchaCounter); err != nil {
				log.Printf("%+v", err)
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}
			if err := data.CaptchaSessionDataSet(w, r, "captchaShow", captchaShow); err != nil {
				log.Printf("%+v", err)
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}
			if err := tools.TmplsRenderer(w, tools.BaseTmpl, "SignUp", SignUpPageData{Msg: tools.ErrMsg["alreadyExist"].Msg, CaptchaShow: captchaShow}); err != nil {
				log.Printf("%+v", err)
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}
			return
		} else if !errors.Is(err, sql.ErrNoRows) {
			log.Printf("%+v", err)
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}
	}

	// 3) Если ни логин ни почта не существуют — запускаем отправку кода
	CodeSend(w, r)
	return
}

func CodeSend(w http.ResponseWriter, r *http.Request) {
	user, err := data.SessionUserGet(r)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	// Если serverCode уже существует, не отправляем повторно
	if user.ServerCode != "" {
		log.Println("Verification code already sent for user:", user.Email)
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
		if r := recover(); r != nil {
			tx.Rollback()
			panic(r)
		}
	}()
	defer tx.Rollback()

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

	// Отправляем письмо о входе с нового устройства для только что созданного пользователя
	if mailErr := tools.SendNewDeviceLoginEmail(user.Email, user.Login, r.UserAgent()); mailErr != nil {
		log.Printf("UserAdd: Error sending new device login email: %+v", mailErr)
		// Не блокируем пользователя из-за сбоя отправки письма
	} else {
		log.Printf("UserAdd: New device login email sent to %s for login %s", user.Email, user.Login)
	}

	captchaCounter := 3
	err = data.CaptchaSessionDataSet(w, r, "captchaCounter", captchaCounter)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	err = data.CaptchaSessionDataSet(w, r, "captchaShow", false)
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
