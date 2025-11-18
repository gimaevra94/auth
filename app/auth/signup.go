package auth

import (
	"database/sql"
	"net/http"
	"strings"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/errs"
	"github.com/gimaevra94/auth/app/structs"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/pkg/errors"
)

func CheckAndValidateSignUpUserInDb(w http.ResponseWriter, r *http.Request) {
	captchaCounter, showCaptcha, err := tools.CaptchaShowAndCaptchaCounterInit(w, r)
	if err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}
	captchaMsgErr := errs.ShowCaptchaMsg(r, showCaptcha)
	var msgForUserdata structs.SignUpPageData

	login := r.FormValue("login")
	email := r.FormValue("email")
	password := r.FormValue("password")
	var user structs.User
	user = structs.User{
		Login:    login,
		Email:    email,
		Password: password,
	}

	_, err = data.GetPermanentIdFromDb(user.Email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			errmsgKey, err := tools.InputValidate(r, user.Login, user.Email, user.Password, false)
			if err != nil {
				if strings.Contains(err.Error(), "login") || strings.Contains(err.Error(), "email") || strings.Contains(err.Error(), "password") {
					if captchaCounter == 0 && r.Method == "POST" && captchaMsgErr {
						msgForUserdata = structs.SignUpPageData{
							Msg:         consts.MsgForUser["captchaRequired"].Msg,
							ShowCaptcha: showCaptcha,
							Regs:        nil}
					} else {
						msgForUserdata = structs.SignUpPageData{
							Msg:         consts.MsgForUser[errmsgKey].Msg,
							ShowCaptcha: showCaptcha,
							Regs:        consts.MsgForUser[errmsgKey].Regs,
						}
					}
				}

				if err := tools.UpdateCaptchaState(w, r, captchaCounter-1, showCaptcha); err != nil {
					errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
					return
				}
				if err := tools.TmplsRenderer(w, tools.BaseTmpl, "signUp", msgForUserdata); err != nil {
					errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
					return
				}
			}

			if err := data.SetAuthSessionData(w, r, user); err != nil {
				errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}
			if err := tools.ServerAuthCodeSend(w, r); err != nil {
				errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}
		}
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if captchaCounter == 0 && r.Method == "POST" && captchaMsgErr {
		msgForUserdata = structs.SignUpPageData{Msg: consts.MsgForUser["captchaRequired"].Msg, ShowCaptcha: showCaptcha, Regs: nil}
		return
	} else {
		msgForUserdata = structs.SignUpPageData{Msg: consts.MsgForUser["userAlreadyExist"].Msg, ShowCaptcha: showCaptcha, Regs: nil}
		return
	}
}

func SetUserInDb(w http.ResponseWriter, r *http.Request) {
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

	var captchaMsgErr bool
	var msgForUserdata structs.SignUpPageData
	clientCode := r.FormValue("clientCode")
	if clientCode != "" {
		if err := tools.CodeValidate(r, clientCode, user.ServerCode); err != nil {
			captchaMsgErr = errs.ShowCaptchaMsg(r, showCaptcha)
			if captchaCounter == 0 && r.Method == "POST" && captchaMsgErr {
				msgForUserdata = structs.SignUpPageData{Msg: consts.MsgForUser["captchaRequired"].Msg, ShowCaptcha: showCaptcha, Regs: nil}
			} else {
				msgForUserdata = structs.SignUpPageData{Msg: consts.MsgForUser["wrongCode"].Msg, ShowCaptcha: showCaptcha, Regs: nil}
			}
		}
	} else {
		err := errors.New("empty code")
		tracedErr := errors.WithStack(err)
		errs.LogAndRedirectIfErrNotNill(w, r, tracedErr, consts.Err500URL)
		return
	}

	if msgForUserdata.Msg != "" {
		if err := tools.UpdateCaptchaState(w, r, captchaCounter-1, showCaptcha); err != nil {
			errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}
		if msgForUserdata.Msg == consts.MsgForUser["wrongCode"].Msg {
			if err := tools.TmplsRenderer(w, tools.BaseTmpl, "serverAuthCodeSend", msgForUserdata); err != nil {
				errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}
		} else {
			if err := tools.TmplsRenderer(w, tools.BaseTmpl, "signUp", msgForUserdata); err != nil {
				errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}
		}

		return
	}

	rememberMe := r.FormValue("rememberMe") != ""
	refreshToken, err := tools.GeneraterefreshToken(consts.RefreshTokenExp7Days, rememberMe)
	if err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	temporaryId := uuid.New().String()
	data.SetTemporaryIdInCookies(w, temporaryId)
	permanentId := uuid.New().String()
	temporaryIdCancelled := false

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password),
		bcrypt.DefaultCost)
	if err != nil {
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

	if err := data.SetUserInDbTx(tx, user.Login, user.Email, permanentId, temporaryId, hashedPassword, temporaryIdCancelled); err != nil {
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

	if err = tools.SendNewDeviceLoginEmail(user.Login, user.Email, r.UserAgent()); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
	}

	if err = data.EndAuthAndCaptchaSessions(w, r); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	http.Redirect(w, r, consts.HomeURL, http.StatusFound)
}
