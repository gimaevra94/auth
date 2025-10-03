package auth

import (
	"database/sql"
	"log"
	"net/http"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/pkg/errors"
)

func PasswordResetCheckEmail(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	err := tools.PasswordResetEmailValidate(email)
	if err != nil {
		err := tools.TmplsRenderer(w, tools.BaseTmpl, "PasswordReset", struct{ Msg string }{Msg: tools.ErrMsg["email"].Msg})
		if err != nil {
			log.Printf("%+v", err)
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}
		return
	}

	permanentUserID, err := data.PasswordResetEmailCheck(email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			err := tools.TmplsRenderer(w, tools.BaseTmpl, "PasswordReset", struct{ Msg string }{Msg: tools.ErrMsg["notExist"].Msg})
			if err != nil {
				log.Printf("%+v", errors.WithStack(err))
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}
			return
		}

		log.Printf("%+v", errors.WithStack(err))
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	baseURL := "http://localhost:8080/set-new-password"
	resetLink, expiresAt, tokenString, err := tools.GenerateResetLink(email, permanentUserID, baseURL)
	if err != nil {
		log.Printf("%+v", errors.Wrap(err, "failed to generate reset link"))
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	err = data.SaveResetToken(tokenString, permanentUserID, email, expiresAt)
	if err != nil {
		log.Printf("%+v", errors.Wrap(err, "failed to save reset token to DB"))
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	err = tools.SendPasswordResetEmail(email, resetLink)
	if err != nil {
		log.Printf("%+v", errors.Wrap(err, "failed to send password reset email"))
		err := tools.TmplsRenderer(w, tools.BaseTmpl, "PasswordReset", struct{ Msg string }{Msg: tools.MailSendingStatusMsg})
		if err != nil {
			log.Printf("%+v", errors.Wrap(err, "failed to render success message"))
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}
	}
}

// SetNewPasswordHandler обрабатывает установку нового пароля после сброса
func SetNewPasswordHandler(w http.ResponseWriter, r *http.Request) {
	tokenString := r.URL.Query().Get("token")
	if tokenString == "" {
		log.Println("Reset token missing")
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	claims, err := tools.ValidateResetToken(tokenString)
	if err != nil {
		log.Printf("%+v", errors.Wrap(err, "invalid or expired reset token"))
		http.Redirect(w, r, consts.Err500URL, http.StatusFound) // или на страницу с ошибкой токена
		return
	}

	// Проверяем, отозван ли токен
	revoked, err := data.IsResetTokenRevoked(tokenString)
	if err != nil {
		log.Printf("%+v", errors.Wrap(err, "failed to check if reset token is revoked"))
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}
	if revoked {
		log.Println("Attempt to use a revoked or non-existent reset token")
		http.Redirect(w, r, consts.Err500URL, http.StatusFound) // Токен отозван
		return
	}

	newPassword := r.FormValue("newPassword")
	confirmPassword := r.FormValue("confirmPassword")

	// Заглушка: Здесь должна быть валидация пароля
	if newPassword == "" || newPassword != confirmPassword {
		log.Println("New password validation failed")
		err := tools.TmplsRenderer(w, tools.BaseTmpl, "SetNewPassword", struct{ Msg string }{Msg: tools.ErrMsg["password"].Msg})
		if err != nil {
			log.Printf("%+v", errors.Wrap(err, "failed to render password reset error"))
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}
		return
	}

	// Заглушка: Обновление пароля в базе данных
	// claims.Subject будет содержать email пользователя, для которого нужно сбросить пароль
	err = data.UpdatePassword(claims.Email, newPassword) // Теперь используем claims.Email
	if err != nil {
		log.Printf("%+v", errors.Wrap(err, "failed to update password in DB"))
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	// Отзываем токен после успешного сброса пароля
	err = data.RevokeResetToken(tokenString)
	if err != nil {
		log.Printf("%+v", errors.Wrap(err, "failed to revoke reset token"))
		// Мы не перенаправляем на 500, так как пароль уже изменен. Просто логируем.
	}

	// Успешный сброс пароля, перенаправление на страницу входа
	http.Redirect(w, r, consts.SignInURL+"?msg=PasswordSuccessfullyReset", http.StatusFound)
}
