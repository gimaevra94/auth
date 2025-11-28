package auth

import (
	"database/sql"
	"net/http"
	"net/url"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/errs"
	"github.com/gimaevra94/auth/app/structs"
	"github.com/gimaevra94/auth/app/tmpls"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/pkg/errors"
)

func GeneratePasswordResetLink(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	if email == "" {
		err := errors.New("email not exist")
		wrappedErr := errors.WithStack(err)
		errs.LogAndRedirectIfErrNotNill(w, r, wrappedErr, consts.Err500URL)
		return
	}

	if err := tools.EmailValidate(email); err != nil {
		data := structs.MsgForUser{Msg: consts.MsgForUser["invalidEmail"].Msg, Regs: nil}
		if err := tmpls.TmplsRenderer(w, tmpls.BaseTmpl, "generatePasswordResetLink", data); err != nil {
			errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}
		return
	}

	yauth := false
	if _, err := data.GetPermanentIdFromDbByEmail(email, yauth); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			data := structs.MsgForUser{Msg: consts.MsgForUser["userNotExist"].Msg, Regs: nil}
			if err := tmpls.TmplsRenderer(w, tmpls.BaseTmpl, "generatePasswordResetLink", data); err != nil {
				errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}
			return
		}
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	baseURL := "http://localhost:8080/set-new-password"
	passwordResetLink, err := tools.GeneratePasswordResetLink(email, baseURL)
	if err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	url, err := url.Parse(passwordResetLink)
	if err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	resetToken := url.Query().Get("token")
	if err := data.SetPasswordResetTokenInDb(resetToken); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	var msgFromUserData structs.MsgForUser
	if err := tools.PasswordResetEmailSend(email, passwordResetLink); err != nil {
		msgFromUserData = structs.MsgForUser{Msg: consts.MsgForUser["failedMailSendingStatus"].Msg}
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	} else {
		msgFromUserData = structs.MsgForUser{Msg: consts.MsgForUser["successfulMailSendingStatus"].Msg}
	}
	if err := tmpls.TmplsRenderer(w, tmpls.BaseTmpl, "generatePasswordResetLink", msgFromUserData); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}
}

func SetNewPassword(w http.ResponseWriter, r *http.Request) {
	resetToken := r.FormValue("token")
	if err := data.IsPasswordResetTokenCancelled(resetToken); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	claims, err := tools.ResetTokenValidate(resetToken)
	if err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	newPassword := r.FormValue("newPassword")
	if newPassword == "" {
		err := errors.New("new-password not exist")
		wrappederr := errors.WithStack(err)
		errs.LogAndRedirectIfErrNotNill(w, r, wrappederr, consts.Err500URL)
		return
	}
	confirmPassword := r.FormValue("confirmPassword")
	if confirmPassword == "" {
		err := errors.New("confirm-password not exist")
		wrappederr := errors.WithStack(err)
		errs.LogAndRedirectIfErrNotNill(w, r, wrappederr, consts.Err500URL)
		return
	}

	if newPassword != confirmPassword {
		data := structs.MsgForUser{Msg: consts.MsgForUser["passwordsNotMatch"].Msg, Regs: nil}
		if err := tmpls.TmplsRenderer(w, tmpls.BaseTmpl, "setNewPassword", data); err != nil {
			errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}
		return
	}

	if err := tools.PasswordValidate(newPassword); err != nil {
		data := structs.MsgForUser{Msg: consts.MsgForUser["invalidPassword"].Msg, Regs: nil}
		if err := tmpls.TmplsRenderer(w, tmpls.BaseTmpl, "setNewPassword", data); err != nil {
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

	yauth := false
	permanentId, err := data.GetPermanentIdFromDbByEmail(claims.Email, yauth)
	if err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if err := data.SetPasswordInDbTx(tx, permanentId, newPassword); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	userAgent := r.UserAgent()
	if err := data.SetTemporaryIdCancelledInDbTx(tx, permanentId, userAgent); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if err := data.SetRefreshTokenCancelledInDbTx(tx, permanentId, userAgent); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if err := tx.Commit(); err != nil {
		tx.Rollback()
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	successMsg := "Password has been set successfully."
	http.Redirect(w, r, consts.SignInURL+"?msg="+url.QueryEscape(successMsg), http.StatusFound)
}
