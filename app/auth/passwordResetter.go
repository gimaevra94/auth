package auth

import (
	"database/sql"
	"net/http"
	"net/url"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/structs"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

func GeneratePasswordResetLink(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	if err := tools.EmailValidate(email); err != nil {
		data := structs.MsgForUser{Msg: consts.MsgForUser["invalidEmail"].Msg, Regs: nil}
		if err := tools.TmplsRenderer(w, tools.BaseTmpl, "PasswordReset", data); err != nil {
			tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}
	}

	if _, err := data.GetPermanentIdFromDb(email); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			data := structs.MsgForUser{Msg: consts.MsgForUser["userNotExist"].Msg, Regs: nil}
			if err := tools.TmplsRenderer(w, tools.BaseTmpl, "PasswordReset", data); err != nil {
				tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}
			return
		}
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	baseURL := "http://localhost:8080/set-new-password"
	passwordResetLink, err := tools.GeneratePasswordResetLink(email, baseURL)
	if err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	url, err := url.Parse(passwordResetLink)
	if err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	resetToken := url.Query().Get("token")
	if resetToken != "" {
		tx, err := data.Db.Begin()
		if err != nil {
			tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}

		defer func() {
			if err := recover(); err != nil {
				tx.Rollback()
				panic(err)
			}
		}()

		if err := data.SetPasswordResetTokenInDbTx(tx, resetToken); err != nil {
			tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}

		if err := tx.Commit(); err != nil {
			tx.Rollback()
			tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}
	}

	if err := tools.SendPasswordResetEmail(email, passwordResetLink); err != nil {
		data := structs.MsgForUser{Msg: consts.MsgForUser["failedMailSendingStatus"].Msg, Regs: nil}
		if err := tools.TmplsRenderer(w, tools.BaseTmpl, "PasswordReset", data); err != nil {
			tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}
		return
	}

	if r.Method == http.MethodPost {
		data := structs.MsgForUser{Msg: consts.MsgForUser["successfulMailSendingStatus"].Msg, Regs: nil}
		if err := tools.TmplsRenderer(w, tools.BaseTmpl, "PasswordReset", data); err != nil {
			tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}
		return
	}
}

func SetNewPassword(w http.ResponseWriter, r *http.Request) {
	resetToken := r.FormValue("token")
	if resetToken == "" {
		err := errors.New("reset-token not exist")
		wrappederr := errors.WithStack(err)
		tools.LogAndRedirectIfErrNotNill(w, r, wrappederr, consts.Err500URL)
		return
	}

	claims, err := tools.ResetTokenValidate(resetToken)
	if err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	cancelled, err := data.GetResetTokenCancelledFromDb(resetToken)
	if err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if cancelled {
		err := errors.New("reset-token invalid")
		wrappederr := errors.WithStack(err)
		tools.LogAndRedirectIfErrNotNill(w, r, wrappederr, consts.Err500URL)
		return
	}

	newPassword := r.FormValue("newPassword")
	confirmPassword := r.FormValue("confirmPassword")

	if newPassword != confirmPassword {
		data := structs.MsgForUser{Msg: consts.MsgForUser["passwordsNotMatch"].Msg, Regs: nil}
		if err := tools.TmplsRenderer(w, tools.BaseTmpl, "SetNewPassword", data); err != nil {
			tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}
		return
	}

	if err := tools.PasswordValidate(newPassword); err != nil {
		data := structs.MsgForUser{Msg: consts.MsgForUser["invalidPassword"].Msg, Regs: nil}
		if err := tools.TmplsRenderer(w, tools.BaseTmpl, "SetNewPassword", data); err != nil {
			tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}
		return
	}

	permanentId, err := data.GetPermanentIdFromDb(claims.Email)
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
		if err := recover(); err != nil {
			tx.Rollback()
			panic(err)
		}
	}()

	if err := data.SetPasswordInDbByEmailTx(tx, claims.Email, newPassword); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if err := data.SetPasswordResetTokenCancelledInDbTx(tx, resetToken); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	temporaryId := uuid.New().String()
	temporaryIdCancelled := false
	if err := data.SetTemporaryIdInDbByEmailTx(tx, claims.Email, temporaryId, temporaryIdCancelled); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	rememberMe := false
	refreshToken, err := tools.GeneraterefreshToken(consts.RefreshTokenExp7Days, rememberMe)
	if err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	refreshTokenCancelled := false
	if err := data.SetRefreshTokenInDbTx(tx, permanentId, refreshToken, r.UserAgent(), refreshTokenCancelled); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if err := tx.Commit(); err != nil {
		tx.Rollback()
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	data.SetTemporaryIdInCookies(w, temporaryId)
	http.Redirect(w, r, consts.HomeURL, http.StatusFound)
}

func SetFirstTimePassword(w http.ResponseWriter, r *http.Request) {
	cookies, err := data.GetTemporaryIdFromCookies(r)
	if err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	temporaryId := cookies.Value
	passwordHash, err := data.GetPasswordFromDb(temporaryId)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if passwordHash != "" {
		err := errors.New("password already set")
		wrappedErr := errors.WithStack(err)
		tools.LogAndRedirectIfErrNotNill(w, r, wrappedErr, consts.Err500URL)
		return
	}

	password := r.FormValue("password")
	confirmPassword := r.FormValue("confirmPassword")

	if password != confirmPassword {
		data := structs.MsgForUser{Msg: consts.MsgForUser["passwordsNotMatch"].Msg,
			Regs: nil}
		if err := tools.TmplsRenderer(w, tools.BaseTmpl, "SetFirstTimePassword", data); err != nil {
			tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}
		return
	}

	if err := tools.PasswordValidate(password); err != nil {
		data := structs.MsgForUser{Msg: consts.MsgForUser["invalidPassword"].Msg,
			Regs: nil}
		if err := tools.TmplsRenderer(w, tools.BaseTmpl, "SetFirstTimePassword", data); err != nil {
			tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if err := data.SetPasswordInDbByTemporaryId(temporaryId, hashedPassword); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	successmsg := "Password has been set successfully."
	http.Redirect(w, r, consts.HomeURL+"?msg="+url.QueryEscape(successmsg), http.StatusFound)
}
