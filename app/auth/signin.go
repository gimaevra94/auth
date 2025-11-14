package auth

import (
	"database/sql"
	"net/http"
	"slices"
	"strings"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/errs"
	"github.com/gimaevra94/auth/app/structs"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

func ValidateSignInInput(w http.ResponseWriter, r *http.Request) {
	var user structs.User
	var showCaptcha bool
	login := r.FormValue("login")
	password := r.FormValue("password")
	user = structs.User{
		Login:    login,
		Password: password,
	}

	captchaCounter, err := data.GetCaptchaCounterFromSession(r)
	if err != nil {
		if strings.Contains(err.Error(), "exist") {
			captchaCounter = 3
			if err := data.SetCaptchaDataInSession(w, r, "captchaCounter", captchaCounter); err != nil {
				errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}
		}
	}

	showCaptcha, err = data.GetShowCaptchaFromSession(r)
	if err != nil {
		if strings.Contains(err.Error(), "exist") {
			showCaptcha = false
			if err := data.SetCaptchaDataInSession(w, r, "showCaptcha", showCaptcha); err != nil {
				errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}
		}
	}

	captchaMsgErr, err := errs.ShowCaptchaMsg(r, showCaptcha)
	if err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	var msgForUserdata structs.SignInPageData
	errmsgKey, err := tools.InputValidate(r, user.Login, "", user.Password, true)
	if err != nil {
		if strings.Contains(err.Error(), "login") || strings.Contains(err.Error(), "password") {
			if captchaCounter == 0 && r.Method == "POST" && captchaMsgErr {
				msgForUserdata = structs.SignInPageData{
					Msg:         consts.MsgForUser["captchaRequired"].Msg,
					ShowCaptcha: showCaptcha,
					Regs:        nil}
			} else {
				msgForUserdata = structs.SignInPageData{
					Msg:         consts.MsgForUser[errmsgKey].Msg,
					ShowCaptcha: showCaptcha,
					Regs:        consts.MsgForUser[errmsgKey].Regs,
				}
			}
		}
	}

	if msgForUserdata.Msg != "" {
		if err := tools.UpdateCaptchaState(w, r, captchaCounter-1, showCaptcha); err != nil {
			errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}
		if err := tools.TmplsRenderer(w, tools.BaseTmpl, "signIn", msgForUserdata); err != nil {
			errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}
		return
	}

	if err := data.SetAuthSessionData(w, r, user); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	CheckSignInUserInDb(w, r)
}

func CheckSignInUserInDb(w http.ResponseWriter, r *http.Request) {
	user, err := data.GetUserFromSession(r)
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

	captchaMsgErr, err := errs.ShowCaptchaMsg(r, showCaptcha)
	if err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	var msgForUserdata structs.SignInPageData
	passwordHash, permanentId, err := data.GetPasswordHashAndPermanentIdFromDb(user.Login, user.Password)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			if err := tools.UpdateCaptchaState(w, r, captchaCounter-1, showCaptcha); err != nil {
				errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}
			msgForUserdata = structs.SignInPageData{Msg: consts.MsgForUser["userNotExist"].Msg, ShowCaptcha: showCaptcha, Regs: nil}
		} else {
			errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}
	} else if !passwordHash.Valid {
		if err := tools.UpdateCaptchaState(w, r, captchaCounter-1, showCaptcha); err != nil {
			errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}
		msgForUserdata = structs.SignInPageData{Msg: consts.MsgForUser["pleaseSignInByYandex"].Msg, ShowCaptcha: showCaptcha, Regs: nil}
	} else {
		if err = bcrypt.CompareHashAndPassword([]byte(passwordHash.String), []byte(user.Password)); err != nil {
			if err := tools.UpdateCaptchaState(w, r, captchaCounter-1, showCaptcha); err != nil {
				errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}
			msgForUserdata = structs.SignInPageData{Msg: consts.MsgForUser["passwordInvalid"].Msg, ShowCaptcha: showCaptcha, Regs: consts.MsgForUser["passwordInvalid"].Regs}
		}
	}

	if msgForUserdata.Msg != "" {
		if captchaCounter == 0 && r.Method == "POST" && captchaMsgErr {
			msgForUserdata = structs.SignInPageData{Msg: consts.MsgForUser["captchaRequired"].Msg, ShowCaptcha: showCaptcha, Regs: nil}
		}
		if err := tools.TmplsRenderer(w, tools.BaseTmpl, "signIn", msgForUserdata); err != nil {
			errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}
		return
	}

	temporaryId := uuid.New().String()
	data.SetTemporaryIdInCookies(w, temporaryId)

	rememberMe := r.FormValue("rememberMe") != ""
	refreshToken, err := tools.GeneraterefreshToken(consts.RefreshTokenExp7Days, rememberMe)
	if err != nil {
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

	temporaryIdCancelled := false
	if err = data.SetTemporaryIdInDbByLoginTx(tx, user.Login, temporaryId, temporaryIdCancelled); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	refreshTokenCancelled := false
	if err = data.SetRefreshTokenInDbTx(tx, permanentId, refreshToken, r.UserAgent(), refreshTokenCancelled); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if err = tx.Commit(); err != nil {
		tx.Rollback()
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if err = data.EndAuthAndCaptchaSessions(w, r); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	http.Redirect(w, r, consts.HomeURL, http.StatusFound)
}
