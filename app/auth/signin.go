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
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

func SignInInputValidate(w http.ResponseWriter, r *http.Request) {
	var user structs.User
	var captchaShow bool
	login := r.FormValue("login")
	password := r.FormValue("password")
	user = structs.User{
		Login:    login,
		Password: password,
	}

	captchaCounter, err := data.SessionCaptchaCounterGet(r)
	if err != nil {
		if strings.Contains(err.Error(), "exist") {
			captchaCounter = 3
			err2 := data.SessionCaptchaDataSet(w, r, "captchaCounter", captchaCounter)
			errs.LogAndRedirIfErrNotNill(w, r, err2, consts.Err500URL)
			return
		} else {
			errs.LogAndRedirIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}
	}

	captchaShow, err = data.SessionCaptchaShowGet(r)
	if err != nil {
		if strings.Contains(err.Error(), "exist") {
			captchaShow = false
			err2 := data.SessionCaptchaDataSet(w, r, "captchaShow", captchaShow)
			errs.LogAndRedirIfErrNotNill(w, r, err2, consts.Err500URL)
			return
		} else {
			errs.LogAndRedirIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}
	}

	if captchaShow {
		if err = tools.CaptchaShow(r); err != nil {
			if strings.Contains(err.Error(), "captchaToken not exist") {
				err = tools.TmplsRenderer(w, tools.BaseTmpl, "SignIn", structs.SignInPageData{Msg: tools.ErrMsg["captchaRequired"].Msg, CaptchaShow: captchaShow, Regs: nil})
				errs.LogAndRedirIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}
			errs.LogAndRedirIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}
	}

	if err = tools.InputValidate(r, user.Login, "", user.Password, true); err != nil {
		if strings.Contains(err.Error(), "login") || strings.Contains(err.Error(), "password") {
			err2 := tools.CaptchaStateUpdateAndRender(w, r, captchaCounter, captchaShow)
			errs.LogAndRedirIfErrNotNill(w, r, err2, consts.Err500URL)
			return
		}
	}

	if err = data.AuthSessionDataSet(w, r, user); err!=nil {
		errs.LogAndRedirIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	SignInUserCheck(w, r)
}

func SignInUserCheck(w http.ResponseWriter, r *http.Request) {
	user, err := data.SessionUserGet(r)
	if err != nil {
		errs.LogAndRedirIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	captchaCounter, err := data.SessionCaptchaCounterGet(r)
	if err != nil {
		errs.LogAndRedirIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	captchaShow, err := data.SessionCaptchaShowGet(r)
	if err != nil {
		errs.LogAndRedirIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	permanentUserID, err := data.SignInUserCheck(user.Login, user.Password)
	if err != nil {
		if strings.Contains(err.Error(), "password not found") || errors.Is(err, sql.ErrNoRows) || errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			err2 := tools.CaptchaStateUpdateAndRender(w, r, captchaCounter, captchaShow)
			errs.LogAndRedirIfErrNotNill(w, r, err2, consts.Err500URL)
			return
		}
	}

	temporaryUserID := uuid.New().String()
	data.TemporaryUserIDCookieSet(w, temporaryUserID)
	rememberMe := r.FormValue("rememberMe") != ""

	refreshToken, err := tools.GenerateRefreshToken(consts.RefreshTokenExp7Days, rememberMe)
	if err != nil {
		errs.LogAndRedirIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	

	tx, err := data.DB.Begin()
	if err != nil {
		errs.LogAndRedirIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	defer func() {
		if err := recover(); err != nil {
			tx.Rollback()
			panic(err)
		}
	}()

	temporaryCancelled := false
	if err = data.TemporaryUserIDUpdateTx(tx, user.Login, temporaryUserID, temporaryCancelled); err != nil {
		errs.LogAndRedirIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	tokenCancelled := false
	if err = data.RefreshTokenUpdateTx(tx, permanentUserID, refreshToken, r.UserAgent(), tokenCancelled); err != nil {
		errs.LogAndRedirIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if err = tx.Commit(); err != nil {
		errs.LogAndRedirIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	captchaCounter = 3
	if err = data.SessionCaptchaDataSet(w, r, "captchaCounter", captchaCounter); err != nil {
		errs.LogAndRedirIfErrNotNill(w, r, err, consts.Err500URL)
		return
	
	}
	if err = data.SessionCaptchaDataSet(w, r, "captchaShow", false); err != nil {
		errs.LogAndRedirIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if err = data.AuthSessionEnd(w, r); err != nil {
		errs.LogAndRedirIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if err = data.AuthSessionEnd(w, r); err != nil {
		errs.LogAndRedirIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	http.Redirect(w, r, consts.HomeURL, http.StatusFound)
}
