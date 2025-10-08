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
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

type SignInPageData struct {
	Msg                string
	ShowForgotPassword bool
	CaptchaShow        bool
	Regs               []string
}

func SignInInputCheck(w http.ResponseWriter, r *http.Request) {
	var user structs.User
	var captchaShow bool

	captchaCounter := 3

	login := r.FormValue("login")
	email := r.FormValue("email")
	password := r.FormValue("password")

	user = structs.User{
		Login:    login,
		Email:    email,
		Password: password,
	}

	err := tools.InputValidate(r, user.Login, "", user.Password, false)
	if err != nil {
		if strings.Contains(err.Error(), "login") {
			if captchaCounter-1 <= 0 {
				captchaShow = true
			}

			err = tools.TmplsRenderer(w, tools.BaseTmpl, "SignIn", SignInPageData{Msg: tools.ErrMsg["login"].Msg, CaptchaShow: captchaShow, Regs: tools.ErrMsg["login"].Regs})
			if err != nil {
				log.Printf("%+v", err)
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}
			return

		} else {
			if strings.Contains(err.Error(), "password") {
				if captchaCounter-1 <= 0 {
					captchaShow = true
				}

				err = tools.TmplsRenderer(w, tools.BaseTmpl, "SignIn", SignInPageData{Msg: tools.ErrMsg["password"].Msg, CaptchaShow: captchaShow, Regs: tools.ErrMsg["password"].Regs})
				if err != nil {
					log.Printf("%+v", err)
					http.Redirect(w, r, consts.Err500URL, http.StatusFound)
					return
				}
				return
			}
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

	err = data.CaptchaSessionDataSet(w, r, "captchaCounter", captchaCounter-1)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	err = data.CaptchaSessionDataSet(w, r, "captchaShow", captchaShow)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	SignUpUserCheck(w, r)
}

func SignInUserCheck(w http.ResponseWriter, r *http.Request) {
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

	permanentUserID, err := data.UserCheck(user.Login, user.Password)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			if captchaCounter-1 <= 0 {
				captchaShow = true
			}
			err = tools.TmplsRenderer(w, tools.BaseTmpl, "SignIn", SignInPageData{Msg: tools.ErrMsg["notExist"].Msg, CaptchaShow: captchaShow, Regs: tools.ErrMsg["notExist"].Regs})
			if err != nil {
				log.Printf("%+v", err)
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}
			return
		}

		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			if captchaCounter-1 <= 0 {
				captchaShow = true
			}
			err = tools.TmplsRenderer(w, tools.BaseTmpl, "SignIn", SignInPageData{Msg: tools.ErrMsg["password"].Msg, ShowForgotPassword: true, CaptchaShow: captchaShow, Regs: tools.ErrMsg["password"].Regs})
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

	temporaryUserID := uuid.New().String()
	data.TemporaryUserIDCookieSet(w, temporaryUserID)

	err = data.TemporaryUserIDAdd(user.Login, temporaryUserID)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	rememberMe := r.FormValue("rememberMe") != ""
	refreshToken, err := tools.GenerateRefreshToken(consts.RefreshTokenExp7Days, rememberMe)
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

	captchaCounter = 3
	err = data.CaptchaSessionDataSet(w, r, "captchaCounter", captchaCounter-1)
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
