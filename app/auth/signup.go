package auth

import (
	"database/sql"
	"net/http"
	"strings"

	"github.com/gimaevra94/auth/app/captcha"
	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/errs"
	"github.com/gimaevra94/auth/app/structs"
	"github.com/gimaevra94/auth/app/tmpls"
	"github.com/gimaevra94/auth/app/tools"

	"github.com/google/uuid"

	"github.com/pkg/errors"
)

func CheckInDbAndValidateSignUpUserInput(w http.ResponseWriter, r *http.Request) {
	captchaCounter, showCaptcha, err := captcha.InitCaptchaState(w, r)
	if err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}
	captchaMsgErr := captcha.ShowCaptchaMsg(r, showCaptcha)
	var msgForUser structs.MsgForUser

	login := r.FormValue("login")
	email := r.FormValue("email")
	password := r.FormValue("password")
	user := structs.User{
		Login:    login,
		Email:    email,
		Password: password,
	}

	yauth := false
	_, err = data.GetPermanentIdFromDbByEmail(user.Email, yauth)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			errMsgKey, err := tools.InputValidate(r, user.Login, user.Email, user.Password, false)
			if err != nil {
				if strings.Contains(err.Error(), "login") || strings.Contains(err.Error(), "email") || strings.Contains(err.Error(), "password") {
					if captchaCounter == 0 && r.Method == "POST" && captchaMsgErr {
						msgForUser = structs.MsgForUser{Msg: consts.MsgForUser["captchaRequired"].Msg, ShowCaptcha: showCaptcha}
					} else {
						msgForUser = structs.MsgForUser{Msg: consts.MsgForUser[errMsgKey].Msg, ShowCaptcha: showCaptcha, Regs: consts.MsgForUser[errMsgKey].Regs}
					}

					if err := captcha.UpdateCaptchaState(w, r, captchaCounter-1, showCaptcha); err != nil {
						errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
						return
					}
					if err := tmpls.TmplsRenderer(w, tmpls.BaseTmpl, "signUp", msgForUser); err != nil {
						errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
						return
					}
				}
				return
			}

			if err := data.SetAuthDataInSession(w, r, user); err != nil {
				errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}
			ServerAuthCodeSend(w, r)
			return
		}
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if captchaCounter == 0 && r.Method == "POST" && captchaMsgErr {
		msgForUser = structs.MsgForUser{Msg: consts.MsgForUser["captchaRequired"].Msg, ShowCaptcha: showCaptcha}
	} else {
		msgForUser = structs.MsgForUser{Msg: consts.MsgForUser["userAlreadyExist"].Msg, ShowCaptcha: showCaptcha}
	}

	if err := captcha.UpdateCaptchaState(w, r, captchaCounter-1, showCaptcha); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}
	if err := tmpls.TmplsRenderer(w, tmpls.BaseTmpl, "signUp", msgForUser); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}
}

func ServerAuthCodeSend(w http.ResponseWriter, r *http.Request) {
	user, err := data.GetAuthDataFromSession(r)
	if err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	authServerCode, err := tools.ServerAuthCodeSend(user.Email)
	if err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	user.ServerCode = authServerCode
	user.ServerCodeSendedConter++
	if err := data.SetAuthDataInSession(w, r, user); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	http.Redirect(w, r, consts.ServerAuthCodeSendURL, http.StatusFound)
}

func CodeValidate(w http.ResponseWriter, r *http.Request) {
	user, err := data.GetAuthDataFromSession(r)
	if err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	captchaCounter, err := data.GetCaptchaCounterFromSession(r)
	if err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	showCaptcha, err := data.GetShowCaptchaFromSession(r)
	if err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	clientCode := r.FormValue("clientCode")
	if clientCode == "" {
		err := errors.New("code invalid")
		tracedErr := errors.WithStack(err)
		errs.LogAndRedirectIfErrNotNill(w, r, tracedErr, consts.Err500URL)
		return
	}

	var msgForUser structs.MsgForUser
	captchaMsgErr := captcha.ShowCaptchaMsg(r, showCaptcha)

	if err := tools.CodeValidate(r, clientCode, user.ServerCode); err != nil {
		if captchaCounter == 0 && r.Method == "POST" && captchaMsgErr {
			msgForUser = structs.MsgForUser{Msg: consts.MsgForUser["captchaRequired"].Msg, ShowCaptcha: showCaptcha}
		} else {
			msgForUser = structs.MsgForUser{Msg: consts.MsgForUser["wrongCode"].Msg, ShowCaptcha: showCaptcha}
		}
	} else {
		SetUserInDb(w, r)
		return
	}

	if err := captcha.UpdateCaptchaState(w, r, captchaCounter-1, showCaptcha); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if err := tmpls.TmplsRenderer(w, tmpls.BaseTmpl, "serverAuthCodeSend", msgForUser); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}
}

func SetUserInDb(w http.ResponseWriter, r *http.Request) {
	user, err := data.GetAuthDataFromSession(r)
	if err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	tx, err := data.Db.Begin()
	if err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}
	defer func() {
		r := recover()
		if r != nil {
			tx.Rollback()
			panic(r)
		}
	}()

	permanentId := uuid.New().String()
	if err := data.SetLoginInDbTx(tx, permanentId, user.Login); err != nil {
		tx.Rollback()
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	yauth := false
	if err := data.SetEmailInDbTx(tx, permanentId, user.Email, yauth); err != nil {
		tx.Rollback()
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if err := data.SetPasswordInDbTx(tx, permanentId, user.Password); err != nil {
		tx.Rollback()
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	temporaryId := uuid.New().String()
	rememberMe := r.FormValue("rememberMe") != ""
	data.SetTemporaryIdInCookies(w, temporaryId, consts.Exp7Days, rememberMe)

	userAgent := r.UserAgent()
	if err := data.SetTemporaryIdInDbTx(tx, permanentId, temporaryId, userAgent, yauth); err != nil {
		tx.Rollback()
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	refreshToken, err := tools.GenerateRefreshToken(consts.Exp7Days, rememberMe)
	if err != nil {
		tx.Rollback()
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}
	if err := data.SetRefreshTokenInDbTx(tx, permanentId, refreshToken, userAgent, yauth); err != nil {
		tx.Rollback()
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if err = tx.Commit(); err != nil {
		tx.Rollback()
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if err = tools.SendNewDeviceLoginEmail(user.Login, user.Email, userAgent); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if err = data.EndAuthAndCaptchaSessions(w, r); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	http.Redirect(w, r, consts.HomeURL, http.StatusFound)
}
