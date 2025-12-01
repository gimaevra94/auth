// Package data предоставляет функции для работы с базой данных сессиями и cookie.
//
// Файл содержит функции для управления cookie аутентификации:
//   - SetTemporaryIdInCookies: устанавливает временный ID в cookie
//   - GetTemporaryIdFromCookies: получает временный ID из cookie
//   - ClearTemporaryIdInCookies: удаляет временный ID из cookie
//   - ClearCookiesDev: очищает все cookie и завершает сессии (для разработки)
package data

import (
	"net/http"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/pkg/errors"
)

// SetTemporaryIdInCookies устанавливает временный ID в cookie.
//
// Создает cookie с именем "temporaryId" для хранения временного идентификатора сессии.
// Если rememberMe=false, устанавливает срок действия 24 часа.
// Cookie настраивается с флагами HttpOnly, SameSiteLaxMode для безопасности.
var SetTemporaryIdInCookies = func(w http.ResponseWriter, value string, temporaryIdExp int, rememberMe bool) {
	temporaryIdExp24Hours := 24 * 60 * 60
	if !rememberMe {
		temporaryIdExp = temporaryIdExp24Hours
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "temporaryId",
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		Value:    value,
		MaxAge:   temporaryIdExp,
	})
}

// GetTemporaryIdFromCookies получает временный ID из cookie.
//
// Извлекает cookie с именем "temporaryId" из HTTP запроса.
// Проверяет наличие и непустоту значения cookie.
// Возвращает ошибку, если cookie отсутствует или пустой.
func GetTemporaryIdFromCookies(r *http.Request) (*http.Cookie, error) {
	Cookies, err := r.Cookie("temporaryId")
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if Cookies.Value == "" {
		return nil, errors.New("temporaryId not exist")
	}
	return Cookies, nil
}

// ClearTemporaryIdInCookies удаляет временный ID из cookie.
//
// Создает cookie с тем же именем "temporaryId", но с отрицательным MaxAge
// для немедленного удаления cookie из браузера клиента.
func ClearTemporaryIdInCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "temporaryId",
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// ClearCookiesDev очищает все cookie и завершает сессии (для разработки).
//
// Удаляет временный ID из cookie, завершает все сессии аутентификации и капчи.
// Перенаправляет пользователя на страницу регистрации.
// Используется для отладки и тестирования в среде разработки.
func ClearCookiesDev(w http.ResponseWriter, r *http.Request) {
	ClearTemporaryIdInCookies(w)
	if err := EndAuthAndCaptchaSessions(w, r); err != nil {
		errors.WithStack(err)
	}
	http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
}
