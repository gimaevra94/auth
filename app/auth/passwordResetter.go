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
	userEmail := r.FormValue("email")
	if err := tools.EmailValIdate(userEmail); err != nil {
		data := structs.MessagesForUser{Msg: consts.MessagesForUser["invalidEmail"].Msg, Regs: nil}
		if err := tools.TmplsRenderer(w, tools.BaseTmpl, "PasswordReset", data); err != nil {
			tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}
	}

	if _, err := data.GetPermanentUserIdFromDb(userEmail); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			data := structs.MessagesForUser{Msg: consts.MessagesForUser["userNotExist"].Msg, Regs: nil}
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
	passwordResetLink, err := tools.GeneratePasswordResetLink(userEmail, baseURL)
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
			tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}
	}

	if err := tools.SendPasswordResetEmail(userEmail, passwordResetLink); err != nil {
		data := structs.MessagesForUser{Msg: consts.MessagesForUser["failedMailSendingStatus"].Msg, Regs: nil}
		if err := tools.TmplsRenderer(w, tools.BaseTmpl, "PasswordReset", data); err != nil {
			tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}
		return
	}

	if r.Method == http.MethodPost {
		data := structs.MessagesForUser{Msg: consts.MessagesForUser["successfulMailSendingStatus"].Msg, Regs: nil}
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

	claims, err := tools.ValIdateResetToken(resetToken)
	if err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	cancelled, err := data.GetResetTokenCancelledFlagFromDb(resetToken)
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
		data := structs.MessagesForUser{Msg: consts.MessagesForUser["passwordsDoNotMatch"].Msg, Regs: nil}
		if err := tools.TmplsRenderer(w, tools.BaseTmpl, "SetNewPassword", data); err != nil {
			tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}
		return
	}

	if err := tools.PasswordValIdate(newPassword); err != nil {
		data := structs.MessagesForUser{Msg: consts.MessagesForUser["invalidPassword"].Msg, Regs: nil}
		if err := tools.TmplsRenderer(w, tools.BaseTmpl, "SetNewPassword", data); err != nil {
			tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}
		return
	}

	permanentUserId, err := data.GetPermanentUserIdFromDb(claims.Email)
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

	if err := data.SetUserPasswordInDbByEmailTx(tx, claims.Email, newPassword); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if err := data.SetPasswordResetTokenCancelledFlagFromDbTx(tx, resetToken); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	temporaryUserId := uuid.New().String()
	temporaryUserIdCancelled := false
	if err := data.SetTemporaryUserIdInDbByEmailTx(tx, claims.Email, temporaryUserId, temporaryUserIdCancelled); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	rememberMe := false
	refreshToken, err := tools.GenerateUserRefreshToken(consts.RefreshTokenExp7Days, rememberMe)
	if err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	refreshTokenCancelled := false
	if err := data.SetUserRefreshTokenInDbTx(tx, permanentUserId, refreshToken, r.UserAgent(), refreshTokenCancelled); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if err := tx.Commit(); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	data.SetTemporaryUserIdInCookies(w, temporaryUserId)
	http.Redirect(w, r, consts.HomeURL, http.StatusFound)
}

func SetFirstTimePassword(w http.ResponseWriter, r *http.Request) {
	cookies, err := data.GetTemporaryUserIdFromCookies(r)
	if err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	temporaryUserId := cookies.Value
	passwordHash, err := data.GetUserPasswordFromDb(temporaryUserId)
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
		data := structs.MessagesForUser{Msg: consts.MessagesForUser["passwordsDoNotMatch"].Msg,
			Regs: nil}
		if err := tools.TmplsRenderer(w, tools.BaseTmpl, "SetFirstTimePassword", data); err != nil {
			tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}
		return
	}

	if err := tools.PasswordValIdate(password); err != nil {
		data := structs.MessagesForUser{Msg: consts.MessagesForUser["invalidPassword"].Msg,
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

	if err := data.SetUserPasswordInDbByTemporaryUserId(temporaryUserId, hashedPassword); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	successMessage := "Password has been set successfully."
	http.Redirect(w, r, consts.HomeURL+"?msg="+url.QueryEscape(successMessage), http.StatusFound)
}
