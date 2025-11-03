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
)

func ResetPasswordFromDb(w http.ResponseWriter, r *http.Request) {
	userEmail := r.FormValue("email")
	if err := tools.EmailValIdate(userEmail); err != nil {
		if err := tools.TmplsRenderer(w, tools.BaseTmpl, "PasswordReset", structs.MessagesForUser{Msg: tools.MessagesForUser["invalidEmail"].Msg, Regs: nil}); err != nil {
			tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}
	}

	if err := data.GetPermanentUserIdFromDb(userEmail); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			if err := tools.TmplsRenderer(w, tools.BaseTmpl, "PasswordReset", structs.MessagesForUser{Msg: tools.MessagesForUser["userNotExist"].Msg, Regs: nil}); err != nil {
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
		tx, err := data.DB.Begin()
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

		if err := data.SetResetTokenInDbTx(tx, resetToken); err != nil {
			tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}

		if err := tx.Commit(); err != nil {
			tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}
	}

	if err := tools.SendPasswordResetEmail(userEmail, passwordResetLink); err != nil {
		if err := tools.TmplsRenderer(w, tools.BaseTmpl, "PasswordReset", structs.MessagesForUser{Msg: tools.MessagesForUser["failedMailSendingStatus"].Msg, Regs: nil}); err != nil {
			tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}
		return
	}

	if r.Method == http.MethodPost {
		if err := tools.TmplsRenderer(w, tools.BaseTmpl, "PasswordReset", structs.MessagesForUser{Msg: tools.MessagesForUser["successfulMailSendingStatus"].Msg, Regs: nil}); err != nil {
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

	cancelled, err := data.GetCancelledFlagForResetToken(resetToken)
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
		if err := tools.TmplsRenderer(w, tools.BaseTmpl, "SetNewPassword", structs.MessagesForUser{Msg: tools.MessagesForUser["passwordsDoNotMatch"].Msg, Regs: nil}); err != nil {
			tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}
		return
	}

	if err := tools.PasswordValIdate(newPassword); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	// Получаем permanentUserId по email (нужен для записи refresh токена)
	var permanentUserId string
	row := data.DB.QueryRow(consts.PasswordResetEmailSelectQuery, claims.Email)
	if err := row.Scan(&permanentUserId); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	tx, err := data.DB.Begin()
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
	defer tx.Rollback()

	// 1) Обновляем пароль
	if err := data.UpdatePasswordTx(tx, claims.Email, newPassword); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	// 2) Аннулируем reset token
	if err := data.ResetTokenCancelTx(tx, resetToken); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	// 3) Создаём auth-сессию как при входе
	temporaryUserId := uuid.New().String()
	if err := data.TemporaryUserIdAddByEmailTx(tx, claims.Email, temporaryUserId, false); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	rememberMe := false
	refreshToken, err := tools.GenerateRefreshToken(consts.RefreshTokenExp7Days, rememberMe)
	if err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if err := data.RefreshTokenAddTx(tx, permanentUserId, refreshToken, r.UserAgent(), false); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if err := tx.Commit(); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	// Ставим куку и ведём в личный кабинет
	data.SetTemporaryUserIdInCookies(w, temporaryUserId)
	http.Redirect(w, r, consts.HomeURL, http.StatusFound)
}

func SubmitPassword(w http.ResponseWriter, r *http.Request) {
	// 1. Получаем temporaryUserId из куки
	Cookies, err := data.GetTemporaryUserIdFromCookies(r)
	if err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.SignInURL)
		return
	}
	temporaryUserId := Cookies.Value

	// 2. Получаем данные пользователя (проверяем, что пароль ещё не задан)
	row := data.DB.QueryRow(consts.PasswordSetQuery, temporaryUserId)
	var login, email, permanentUserId string
	if err := row.Scan(&login, &email, &permanentUserId); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			tools.LogAndRedirectIfErrNotNill(w, r, errors.New("user not found or password already set"), consts.SignInURL)
			return
		}
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	// 3. Получаем данные формы
	password := r.FormValue("password")
	confirmPassword := r.FormValue("confirmPassword")

	// 4. Проверка совпадения
	if password != confirmPassword {
		http.Redirect(w, r, consts.SetPasswordURL+"?msg=Passwords+do+not+match", http.StatusFound)
		return
	}

	// 5. Валидация пароля
	if err := tools.PasswordValIdate(password); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	// 6. Начинаем транзакцию и обновляем пароль
	tx, err := data.DB.Begin()
	if err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}
	defer tx.Rollback()

	if err := data.UpdatePasswordByPermanentIdTx(tx, permanentUserId, password); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if err := tx.Commit(); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	// Обновляем маркер входа: после установки пароля считаем, что вход больше не только через Яндекс
	data.SetTemporaryUserIdInCookies(w, temporaryUserId)
	http.SetCookies(w, &http.Cookies{
		Name:     "yauth",
		Value:    "0",
		Path:     "/",
		HttpOnly: false,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   consts.TemporaryUserIdExp,
	})

	successMessage := "Password has been set successfully." // Сообщение на английском
	http.Redirect(w, r, consts.HomeURL+"?msg="+url.QueryEscape(successMessage), http.StatusFound)
}
