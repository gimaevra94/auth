package auth

import (
	"database/sql"
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

func ValidateSignUpInput(w http.ResponseWriter, r *http.Request) {
	var user structs.User
	var showCaptcha bool
	login := r.FormValue("login")
	email := r.FormValue("email")
	password := r.FormValue("password")
	user = structs.User{
		Login:    login,
		Email:    email,
		Password: password,
	}

	captchaCounter, err := data.GetCaptchaCounterFromSession(r)
	if err != nil {
		if strings.Contains(err.Error(), "exist") {
			captchaCounter = 3
			if err := data.SetCaptchaDataInSession(w, r, "captchaCounter", captchaCounter); err != nil {
				tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}
		}
	}

	showCaptcha, err = data.GetShowCaptchaFromSession(r)
	if err != nil {
		if strings.Contains(err.Error(), "exist") {
			showCaptcha = false
			if err := data.SetCaptchaDataInSession(w, r, "showCaptcha", showCaptcha); err != nil {
				tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}
		}
	}

	var captchaMsgErr bool
	if showCaptcha {
		if err := tools.ShowCaptcha(r); err != nil {
			if strings.Contains(err.Error(), "captchaToken not exist") {
				captchaMsgErr = true
			}
		}
	}

	errmsgKey, err := tools.InputValidate(r, user.Login, user.Email, user.Password, false)
	if err != nil {
		if strings.Contains(err.Error(), "login") || strings.Contains(err.Error(), "email") || strings.Contains(err.Error(), "password") {
			var data structs.SignUpPageData
			if captchaCounter == 0 && r.Method == "POST" && captchaMsgErr {
				data = structs.SignUpPageData{
					Msg:         consts.MsgForUser["captchaRequired"].Msg,
					ShowCaptcha: showCaptcha,
					Regs:        nil}
			} else {
				data = structs.SignUpPageData{
					Msg:         consts.MsgForUser[errmsgKey].Msg,
					ShowCaptcha: showCaptcha,
					Regs:        consts.MsgForUser[errmsgKey].Regs,
				}
			}
			tools.UpdateCaptchaState(w, r, captchaCounter-1, showCaptcha)
			if err := tools.TmplsRenderer(w, tools.BaseTmpl, "signUp", data); err != nil {
				tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}
		}
		return
	}

	if err := data.SetAuthSessionData(w, r, user); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	CheckSignUpUserInDb(w, r)
}

func CheckSignUpUserInDb(w http.ResponseWriter, r *http.Request) {

	user, err := data.GetUserFromSession(r)
	if err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	captchaCounter, err := data.GetCaptchaCounterFromSession(r)
	if err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	showCaptcha, err := data.GetShowCaptchaFromSession(r)
	if err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	_, err = data.GetPermanentIdFromDb(user.Email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			ServerAuthCodeSend(w, r)
			return
		}
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if err := tools.UpdateCaptchaState(w, r, captchaCounter-1, showCaptcha); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	data := structs.SignUpPageData{Msg: consts.MsgForUser["userAlreadyExist"].Msg, ShowCaptcha: showCaptcha, Regs: nil}
	if err := tools.TmplsRenderer(w, tools.BaseTmpl, "signUp", data); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}
}

func ServerAuthCodeSend(w http.ResponseWriter, r *http.Request) {
	user, err := data.GetUserFromSession(r)
	if err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if user.ServerCode != "" {
		err := errors.New("code already sent")
		tracedErr := errors.WithStack(err)
		tools.LogAndRedirectIfErrNotNill(w, r, tracedErr, consts.ServerAuthCodeSendURL)
		return
	}

	serverCode, err := tools.ServerAuthCodeSend(user.Email)
	if err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}
	user.ServerCode = serverCode

	if err := data.SetAuthSessionData(w, r, user); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if r.URL.Path != consts.ServerAuthCodeSendURL {
		http.Redirect(w, r, consts.ServerAuthCodeSendURL, http.StatusFound)
		return
	}
}

func SetUserInDb(w http.ResponseWriter, r *http.Request) {
	user, err := data.GetUserFromSession(r)
	if err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	clientCode := r.FormValue("clientCode")
	if err := tools.CodeValidate(r, clientCode, user.ServerCode); err != nil {
		if strings.Contains(err.Error(), "exist") {
			data := structs.MsgForUser{Msg: consts.MsgForUser["userCode"].Msg, Regs: nil}
			if err := tools.TmplsRenderer(w, tools.BaseTmpl, "CodeSend", data); err != nil {
				tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}
			return
		} else if strings.Contains(err.Error(), "match") {
			data := structs.SignUpPageData{Msg: consts.MsgForUser["serverCode"].Msg, Regs: nil}
			if err := tools.TmplsRenderer(w, tools.BaseTmpl, "CodeSend", data); err != nil {
				tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}
			return
		}
	}

	rememberMe := r.FormValue("rememberMe") != ""
	refreshToken, err := tools.GeneraterefreshToken(consts.RefreshTokenExp7Days, rememberMe)
	if err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	tx, err := data.Db.Begin()
	if err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}
	defer func() {
		r := recover()
		if r != nil {
			tx.Rollback()
			panic(r)
		}
	}()

	temporaryId := uuid.New().String()
	data.SetTemporaryIdInCookies(w, temporaryId)
	permanentId := uuid.New().String()
	temporaryIdCancelled := false

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password),
		bcrypt.DefaultCost)
	if err != nil {
		return
	}

	if err := data.SetUserInDbTx(tx, user.Login, user.Email, permanentId, temporaryId, hashedPassword, temporaryIdCancelled); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	refreshTokenCancelled := false
	if err = data.SetRefreshTokenInDbTx(tx, permanentId, refreshToken, r.UserAgent(), refreshTokenCancelled); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if err = tx.Commit(); err != nil {
		tx.Rollback()
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if err = tools.SendNewDeviceLoginEmail(user.Email, user.Login, r.UserAgent()); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
	}

	captchaCounter := 3
	if err = data.SetCaptchaDataInSession(w, r, "captchaCounter", captchaCounter); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	ShowCaptcha := false
	if err = data.SetCaptchaDataInSession(w, r, "ShowCaptcha", ShowCaptcha); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if err = data.EndAuthSession(w, r); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	http.Redirect(w, r, consts.HomeURL, http.StatusFound)
}
