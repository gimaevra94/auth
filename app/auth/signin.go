package auth

import (
	"database/sql"
	"net/http"
	"slices"
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

func CheckInDbAndValidateSignInUserInput(w http.ResponseWriter, r *http.Request) {
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

	if login == "" || password == "" {
		errMsgKey, err := tools.InputValidate(r, login, "", password, true)
		if err != nil {
			if captchaCounter == 0 && r.Method == "POST" && captchaMsgErr {
				msgForUser = structs.MsgForUser{Msg: consts.MsgForUser["captchaRequired"].Msg, ShowCaptcha: showCaptcha}
			} else {
				if strings.Contains(err.Error(), "password") {
					msgForUser = structs.MsgForUser{Msg: consts.MsgForUser[errMsgKey].Msg, ShowCaptcha: showCaptcha, Regs: consts.MsgForUser[errMsgKey].Regs}
				} else {
					msgForUser = structs.MsgForUser{Msg: consts.MsgForUser[errMsgKey].Msg, ShowCaptcha: showCaptcha, ShowForgotPassword: true, Regs: consts.MsgForUser[errMsgKey].Regs}
				}
			}

			if err := captcha.UpdateCaptchaState(w, r, captchaCounter-1, showCaptcha); err != nil {
				errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}
			if err := tmpls.TmplsRenderer(w, tmpls.BaseTmpl, "signIn", msgForUser); err != nil {
				errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}
			
			return
		}
	}

	permanentId, err := data.GetPermanentIdFromDbByLogin(user.Login)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			if captchaCounter == 0 && r.Method == "POST" && captchaMsgErr {
				msgForUser = structs.MsgForUser{Msg: consts.MsgForUser["captchaRequired"].Msg, ShowCaptcha: showCaptcha}
			} else {
				msgForUser = structs.MsgForUser{Msg: consts.MsgForUser["userNotExist"].Msg, ShowCaptcha: showCaptcha}
			}
		}

		if err := captcha.UpdateCaptchaState(w, r, captchaCounter-1, showCaptcha); err != nil {
			errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}
		if err := tmpls.TmplsRenderer(w, tmpls.BaseTmpl, "signIn", msgForUser); err != nil {
			errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}
		return
	}

	if err := data.IsOKPasswordHashInDb(permanentId, user.Password); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			if captchaCounter == 0 && r.Method == "POST" && captchaMsgErr {
				msgForUser = structs.MsgForUser{Msg: consts.MsgForUser["captchaRequired"].Msg, ShowCaptcha: showCaptcha}
			} else {
				msgForUser = structs.MsgForUser{Msg: consts.MsgForUser["passwordInvalid"].Msg, ShowCaptcha: showCaptcha, ShowForgotPassword: true, Regs: consts.MsgForUser["passwordInvalid"].Regs}
			}
		}

		if err := captcha.UpdateCaptchaState(w, r, captchaCounter-1, showCaptcha); err != nil {
			errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}
		if err := tmpls.TmplsRenderer(w, tmpls.BaseTmpl, "signIn", msgForUser); err != nil {
			errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}
		return
	}

	tx, err := data.Db.Begin()
	if err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	defer func() {
		if err := recover(); err != nil {
			tx.Rollback()
			panic(err)
		}
	}()

	temporaryId := uuid.New().String()
	rememberMe := r.FormValue("rememberMe") != ""
	data.SetTemporaryIdInCookies(w, temporaryId, consts.Exp7Days, rememberMe)

	userAgent := r.UserAgent()
	if err := data.SetTemporaryIdInDbTx(tx, permanentId, temporaryId, userAgent); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	refreshToken, err := tools.GenerateRefreshToken(consts.Exp7Days, rememberMe)
	if err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}
	if err := data.SetRefreshTokenInDbTx(tx, permanentId, refreshToken, userAgent); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if err = tx.Commit(); err != nil {
		tx.Rollback()
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	uniqueUserAgents, err := data.GetUniqueUserAgentsFromDb(permanentId)
	if err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	} else {
		isNewDevice := !slices.Contains(uniqueUserAgents, r.UserAgent())
		if isNewDevice {
			if err := tools.SendNewDeviceLoginEmail(user.Login, user.Email, r.UserAgent()); err != nil {
				errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}
		}
	}

	if err = data.EndAuthAndCaptchaSessions(w, r); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	http.Redirect(w, r, consts.HomeURL, http.StatusFound)
}
