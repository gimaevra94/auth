// Package auth предоставляет функции для аутентификации и авторизации.
//
// Файл содержит функции для защиты различных маршрутов приложения:
//   - AuthGuardForSignUpAndSignInPath: защита маршрутов регистрации и входа
//   - AuthGuardForServerAuthCodeSendPath: защита маршрута отправки кода авторизации сервера
//   - ResetTokenGuard: защита маршрутов сброса пароля
//   - AuthGuardForHomePath: защита домашней страницы
//   - Logout: функция выхода из системы
//
// Каждый защитник проверяет различные условия аутентификации и выполняет
// перенаправления или передает управление следующему обработчику.
package auth

import (
	"database/sql"
	"net/http"
	"strings"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/errs"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/pkg/errors"
)

// AuthGuardForSignUpAndSignInPath защищает маршруты регистрации и входа.
// Проверяет наличие и валидность temporaryId в cookie.
// Если cookie отсутствует или temporaryId отменен - передает управление следующему обработчику.
// Если temporaryId валиден - перенаправляет на домашнюю страницу.
// При ошибках базы данных перенаправляет на страницу 500.
var AuthGuardForSignUpAndSignInPath = func(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Cookies, err := data.GetTemporaryIdFromCookies(r)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		temporaryId := Cookies.Value
		if err := data.IsTemporaryIdCancelled(temporaryId); err != nil {
			if strings.Contains(err.Error(), "temporaryId cancelled") {
				next.ServeHTTP(w, r)
				return
			}
			errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}

		http.Redirect(w, r, consts.HomeURL, http.StatusFound)
	})
}

// AuthGuardForServerAuthCodeSendPath защищает маршрут отправки кода авторизации сервера.
// Проверяет наличие пользовательской сессии и наличие ServerCode.
// Если сессия отсутствует или ServerCode пуст - перенаправляет на страницу регистрации.
// При успешной проверке передает управление следующему обработчику.
func AuthGuardForServerAuthCodeSendPath(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		user, err := data.GetAuthDataFromSession(r)
		if err != nil {
			http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
			return
		}

		if user.ServerCode == "" {
			http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ResetTokenGuard защищает маршруты сброса пароля.
// Проверяет наличие токена в параметрах запроса, его валидность и статус отмены.
// Если токен отсутствует, невалиден или отменен - перенаправляет на страницу регистрации.
// При успешной проверке передает управление следующему обработчику.
func ResetTokenGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if token == "" {
			http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
			return
		}

		if _, err := tools.ResetTokenValidate(token); err != nil {
			http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
			return
		}

		if err := data.IsPasswordResetTokenCancelled(token); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
				return
			}
			errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// AuthGuardForHomePath защищает домашнюю страницу.
// Проверяет наличие temporaryId, получает permanentId и userAgent из базы данных.
// Проверяет совпадение User-Agent с текущим запросом - при несовпадении отправляет уведомление и выполняет выход.
// Проверяет наличие и валидность refresh токена - при отсутствии или невалидности выполняет выход.
// При успешной проверке передает управление следующему обработчику.
func AuthGuardForHomePath(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		Cookies, err := data.GetTemporaryIdFromCookies(r)
		if err != nil {
			http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
			return
		}

		temporaryId := Cookies.Value

		permanentId, userAgent, err := data.GetTemporaryIdKeysFromDb(temporaryId)
		if err != nil {
			errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}

		email, err := data.GetEmailFromDb(permanentId)
		if err != nil {
			errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}

		if userAgent != r.UserAgent() {
			if err := tools.SuspiciousLoginEmailSend(email, r.UserAgent()); err != nil {
				errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}
			Logout(w, r)
			return
		}

		refreshToken, err := data.GetRefreshTokenFromDb(permanentId, userAgent)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				Logout(w, r)
				return
			}
			errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}

		if err := tools.RefreshTokenValidate(refreshToken); err != nil {
			Logout(w, r)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Logout выполняет выход пользователя из системы.
// Получает temporaryId из cookie, извлекает permanentId и userAgent из базы данных.
// В транзакции отменяет temporaryId и refresh токены пользователя.
// Очищает cookie и перенаправляет на страницу регистрации.
// При ошибках базы данных перенаправляет на страницу 500.
// При панике во время транзакции выполняет откат для сохранения целостности данных.
func Logout(w http.ResponseWriter, r *http.Request) {

	cookie, err := data.GetTemporaryIdFromCookies(r)
	if err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	temporaryId := cookie.Value

	permanentId, userAgent, err := data.GetTemporaryIdKeysFromDb(temporaryId)
	if err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
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

	if err := data.SetTemporaryIdCancelledInDbTx(tx, permanentId, userAgent); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if err := data.SetRefreshTokenCancelledInDbTx(tx, permanentId, userAgent); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if err = tx.Commit(); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	data.ClearTemporaryIdInCookies(w)

	http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
}
