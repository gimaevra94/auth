package auth

import (
	"database/sql"
	"log"
	"net/http"
	"net/url"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

func PasswordResetEmailCheck(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	err := tools.EmailValidate(email)
	if err != nil {
		err := tools.TmplsRenderer(w, tools.BaseTmpl, "PasswordReset", struct{ Msg string }{Msg: tools.ErrMsg["email"].Msg})
		if err != nil {
			log.Printf("%+v", err)
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}
		return
	}

	err = data.PasswordResetEmailCheck(email)
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
	resetLink, err := tools.GenerateResetLink(email, baseURL)
	if err != nil {
		log.Printf("%+v", errors.WithStack(err))
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	// Сохраняем reset-token в БД, чтобы последующая проверка прошла успешно
	// Токен берём из query параметра ссылки
	if u, perr := url.Parse(resetLink); perr == nil {
		token := u.Query().Get("token")
		if token != "" {
			tx, terr := data.DB.Begin()
			if terr != nil {
				log.Printf("%+v", errors.WithStack(terr))
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}
			defer func() {
				if r := recover(); r != nil {
					tx.Rollback()
					panic(r)
				}
			}()
			defer tx.Rollback()

			if aerr := data.ResetTokenAddTx(tx, token); aerr != nil {
				log.Printf("%+v", errors.WithStack(aerr))
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}

			if cerr := tx.Commit(); cerr != nil {
				log.Printf("%+v", errors.WithStack(cerr))
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}
		}
	}

	err = tools.SendPasswordResetEmail(email, resetLink)
	if err != nil {
		log.Printf("%+v", errors.WithStack(err))
		err := tools.TmplsRenderer(w, tools.BaseTmpl, "PasswordReset", struct{ Msg string }{Msg: "Не удалось отправить письмо. Проверьте адрес или позже попробуйте снова."})
		if err != nil {
			log.Printf("%+v", errors.WithStack(err))
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}
		return
	}

	// Успех: показываем понятное подтверждение
	if r.Method == http.MethodPost {
		if err := tools.TmplsRenderer(w, tools.BaseTmpl, "PasswordReset", struct{ Msg string }{Msg: "Password reset link has been sent to your email."}); err != nil {
			log.Printf("%+v", errors.WithStack(err))
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}
		return
	}
}

func SetNewPassword(w http.ResponseWriter, r *http.Request) {
	signedToken := r.FormValue("token")
	if signedToken == "" {
		log.Println("reset-token not exist")
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	claims, err := tools.ValidateResetToken(signedToken)
	if err != nil {
		log.Printf("%+v", errors.WithStack(err))
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	cancelled, err := data.ResetTokenCheck(signedToken)
	if err != nil {
		log.Printf("%+v", errors.WithStack(err))
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}
	if cancelled {
		err := errors.New("reset-token invalid")
		log.Printf("%+v", errors.WithStack(err))
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	newPassword := r.FormValue("newPassword")
	confirmPassword := r.FormValue("confirmPassword")

	if newPassword != confirmPassword {
		log.Println("New password validation failed")
		err := tools.TmplsRenderer(w, tools.BaseTmpl, "SetNewPassword", struct{ Msg string }{Msg: tools.ErrMsg["password"].Msg})
		if err != nil {
			log.Printf("%+v", errors.WithStack(err))
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}

		err = tools.PasswordValidate(newPassword)
		if err != nil {
			log.Printf("%+v", errors.WithStack(err))
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}
	}

	// Получаем permanentUserID по email (нужен для записи refresh токена)
	var permanentUserID string
	row := data.DB.QueryRow(consts.PasswordResetEmailSelectQuery, claims.Email)
	if err := row.Scan(&permanentUserID); err != nil {
		log.Printf("%+v", errors.WithStack(err))
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	tx, err := data.DB.Begin()
	if err != nil {
		log.Printf("%+v", errors.WithStack(err))
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			panic(r)
		}
	}()
	defer tx.Rollback()

	// 1) Обновляем пароль
	err = data.UpdatePasswordTx(tx, claims.Email, newPassword)
	if err != nil {
		log.Printf("%+v", errors.WithStack(err))
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	// 2) Аннулируем reset token
	err = data.ResetTokenCancelTx(tx, signedToken)
	if err != nil {
		log.Printf("%+v", errors.WithStack(err))
	}

	// 3) Создаём auth-сессию как при входе
	temporaryUserID := uuid.New().String()
	if err := data.TemporaryUserIDAddByEmailTx(tx, claims.Email, temporaryUserID, false); err != nil {
		log.Printf("%+v", errors.WithStack(err))
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	rememberMe := false
	refreshToken, err := tools.GenerateRefreshToken(consts.RefreshTokenExp7Days, rememberMe)
	if err != nil {
		log.Printf("%+v", errors.WithStack(err))
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	if err := data.RefreshTokenAddTx(tx, permanentUserID, refreshToken, r.UserAgent(), false); err != nil {
		log.Printf("%+v", errors.WithStack(err))
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	err = tx.Commit()
	if err != nil {
		log.Printf("%+v", errors.WithStack(err))
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	// Ставим куку и ведём в личный кабинет
	data.TemporaryUserIDCookieSet(w, temporaryUserID)
	http.Redirect(w, r, consts.HomeURL, http.StatusFound)
}

func SubmitPassword(w http.ResponseWriter, r *http.Request) {
	// 1. Получаем temporaryUserID из куки
	cookie, err := data.TemporaryUserIDCookiesGet(r)
	if err != nil {
		log.Printf("SetPasswordHandler: no temporaryUserID cookie: %+v", err)
		http.Redirect(w, r, consts.SignInURL, http.StatusFound)
		return
	}
	temporaryUserID := cookie.Value

	// 2. Получаем данные пользователя (проверяем, что пароль ещё не задан)
	row := data.DB.QueryRow(consts.PasswordSetQuery, temporaryUserID)
	var login, email, permanentUserID string
	err = row.Scan(&login, &email, &permanentUserID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			log.Println("SetPasswordHandler: user not found or password already set")
			http.Redirect(w, r, consts.SignInURL, http.StatusFound)
			return
		}
		log.Printf("SetPasswordHandler: DB error: %+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
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
	err = tools.PasswordValidate(password) // login и email пустые, проверяем только пароль
	if err != nil {
		log.Printf("SetPasswordHandler: validation error: %+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	// 6. Начинаем транзакцию и обновляем пароль
	tx, err := data.DB.Begin()
	if err != nil {
		log.Printf("SetPasswordHandler: DB.Begin failed: %+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}
	defer tx.Rollback()

	err = data.UpdatePasswordByPermanentIDTx(tx, permanentUserID, password)
	if err != nil {
		log.Printf("SetPasswordHandler: UpdatePasswordByPermanentIDTx failed: %+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	err = tx.Commit()
	if err != nil {
		log.Printf("SetPasswordHandler: tx.Commit failed: %+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	// Обновляем маркер входа: после установки пароля считаем, что вход больше не только через Яндекс
	http.SetCookie(w, &http.Cookie{
		Name:     "yauth",
		Value:    "0",
		Path:     "/",
		HttpOnly: false,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   consts.TemporaryUserIDExp,
	})

	successMessage := "Password has been set successfully." // Сообщение на английском
	http.Redirect(w, r, consts.HomeURL+"?msg="+url.QueryEscape(successMessage), http.StatusFound)
}
