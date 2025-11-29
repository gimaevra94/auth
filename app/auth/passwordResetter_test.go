// Package auth предоставляет тесты для модуля аутентификации и авторизации.
// 
// Этот файл содержит модульные тесты для функциональности сброса пароля:
//   - GeneratePasswordResetLink: генерация ссылки для сброса пароля
//   - SetNewPassword: установка нового пароля пользователя
//
// Тесты используют моки (mock) для изоляции от внешних зависимостей:
//   - sqlmock для мокирования базы данных
//   - моки для функций валидации, отправки email и других утилит
//
// Основные сценарии тестирования:
//   - Успешная генерация ссылки сброса пароля
//   - Обработка невалидного email
//   - Обработка несуществующего пользователя
//   - Успешная установка нового пароля
//   - Обработка отменённых/невалидных токенов
//   - Валидация паролей и их соответствие
package auth

import (
	"database/sql"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/structs"
	"github.com/gimaevra94/auth/app/tmpls"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/golang-jwt/jwt"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTest подготавливает тестовое окружение для каждого теста.
//
// Создаёт мок базы данных с помощью sqlmock.New(), сохраняет оригинальные
// значения глобальных переменных и функций, заменяет их на моки, а также
// возвращает функцию очистки для восстановления исходного состояния.
//
// Параметры:
//   - t *testing.T: тестовый контекст для assert и require
//
// Возвращает:
//   - *sql.DB: мок базы данных
//   - sqlmock.Sqlmock: интерфейс для настройки ожиданий SQL запросов
//   - func(): функция очистки, восстанавливающая исходное состояние
func setupTest(t *testing.T) (*sql.DB, sqlmock.Sqlmock, func()) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)

	oldDB := data.Db
	oldTmplsRenderer := tmpls.TmplsRenderer
	oldEmailValidate := tools.EmailValidate
	oldGetPermanentIdFromDbByEmail := data.GetPermanentIdFromDbByEmail
	oldGeneratePasswordResetLink := tools.GeneratePasswordResetLink
	oldResetTokenValidate := tools.ResetTokenValidate
	oldSetPasswordResetTokenInDb := data.SetPasswordResetTokenInDb
	oldPasswordResetEmailSend := tools.PasswordResetEmailSend
	oldSetPasswordInDbTx := data.SetPasswordInDbTx
	oldSetTemporaryIdCancelledInDbTx := data.SetTemporaryIdCancelledInDbTx
	oldSetRefreshTokenCancelledInDbTx := data.SetRefreshTokenCancelledInDbTx
	oldIsPasswordResetTokenCancelled := data.IsPasswordResetTokenCancelled

	data.Db = db

	return db, mock, func() {
		data.Db = oldDB
		db.Close()
		tmpls.TmplsRenderer = oldTmplsRenderer
		tools.EmailValidate = oldEmailValidate
		data.GetPermanentIdFromDbByEmail = oldGetPermanentIdFromDbByEmail
		tools.GeneratePasswordResetLink = oldGeneratePasswordResetLink
		tools.ResetTokenValidate = oldResetTokenValidate
		data.SetPasswordResetTokenInDb = oldSetPasswordResetTokenInDb
		tools.PasswordResetEmailSend = oldPasswordResetEmailSend
		data.SetPasswordInDbTx = oldSetPasswordInDbTx
		data.SetTemporaryIdCancelledInDbTx = oldSetTemporaryIdCancelledInDbTx
		data.SetRefreshTokenCancelledInDbTx = oldSetRefreshTokenCancelledInDbTx
		data.IsPasswordResetTokenCancelled = oldIsPasswordResetTokenCancelled
	}
}

// TestGeneratePasswordResetLink_Success проверяет успешный сценарий генерации ссылки для сброса пароля.
//
// Тестирует полный путь выполнения функции:
//   - Валидация email проходит успешно
//   - Пользователь найден в базе данных
//   - Ссылка для сброса сгенерирована
//   - Токен сохранён в базе данных
//   - Email с ссылкой отправлен успешно
//   - Пользователю показано сообщение об успешной отправке
//
// Ожидаемый результат:
//   - HTTP статус 200
//   - Вызов рендерера шаблона с сообщением об успешной отправке
func TestGeneratePasswordResetLink_Success(t *testing.T) {
	_, mock, teardown := setupTest(t)
	defer teardown()

	tools.EmailValidate = func(email string) error { return nil }
	data.GetPermanentIdFromDbByEmail = func(email string, yauth bool) (string, error) {
		return "permanent-123", nil
	}
	tools.GeneratePasswordResetLink = func(email, baseURL string) (string, error) {
		return "http://localhost:8080/set-new-password?token=mock-token-123", nil
	}
	data.SetPasswordResetTokenInDb = func(token string) error {
		return nil
	}
	tools.PasswordResetEmailSend = func(email, link string) error {
		return nil
	}

	tmpls.TmplsRenderer = func(w http.ResponseWriter, tmpl *template.Template, templateName string, data interface{}) error {
		assert.Equal(t, "generatePasswordResetLink", templateName)
		if msgData, ok := data.(structs.MsgForUser); ok {
			assert.Equal(t, consts.MsgForUser["successfulMailSendingStatus"].Msg, msgData.Msg)
		} else {
			t.Errorf("Expected structs.MsgForUser, got %T", data)
		}
		return nil
	}

	form := url.Values{}
	form.Add("email", "test@example.com")
	req := httptest.NewRequest("POST", "/generate-password-reset-link", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	GeneratePasswordResetLink(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestGeneratePasswordResetLink_InvalidEmail проверяет обработку невалидного email адреса.
//
// Тестирует сценарий когда:
//   - Email не проходит валидацию
//   - Функция должна показать сообщение об ошибке без отправки email
//
// Мокируется:
//   - EmailValidate возвращает ошибку валидации
//
// Ожидаемый результат:
//   - HTTP статус 200
//   - Вызов рендерера шаблона с сообщением о невалидном email
func TestGeneratePasswordResetLink_InvalidEmail(t *testing.T) {
	_, mock, teardown := setupTest(t)
	defer teardown()

	tools.EmailValidate = func(email string) error {
		return errors.New("email invalid")
	}

	tmpls.TmplsRenderer = func(w http.ResponseWriter, tmpl *template.Template, templateName string, data interface{}) error {
		assert.Equal(t, "generatePasswordResetLink", templateName)
		if msgData, ok := data.(structs.MsgForUser); ok {
			assert.Equal(t, consts.MsgForUser["invalidEmail"].Msg, msgData.Msg)
		} else {
			t.Errorf("Expected structs.MsgForUser, got %T", data)
		}
		return nil
	}

	form := url.Values{}
	form.Add("email", "invalid-email")
	req := httptest.NewRequest("POST", "/generate-password-reset-link", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	GeneratePasswordResetLink(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestGeneratePasswordResetLink_UserNotFound проверяет обработку несуществующего пользователя.
//
// Тестирует сценарий когда:
//   - Email валиден, но пользователь не найден в базе данных
//   - Функция должна показать сообщение о несуществующем пользователе
//
// Мокируется:
//   - EmailValidate возвращает nil (успешная валидация)
//   - GetPermanentIdFromDbByEmail возвращает sql.ErrNoRows
//
// Ожидаемый результат:
//   - HTTP статус 200
//   - Вызов рендерера шаблона с сообщением о несуществующем пользователе
func TestGeneratePasswordResetLink_UserNotFound(t *testing.T) {
	_, mock, teardown := setupTest(t)
	defer teardown()

	tools.EmailValidate = func(email string) error { return nil }
	data.GetPermanentIdFromDbByEmail = func(email string, yauth bool) (string, error) {
		return "", sql.ErrNoRows
	}

	tmpls.TmplsRenderer = func(w http.ResponseWriter, tmpl *template.Template, templateName string, data interface{}) error {
		assert.Equal(t, "generatePasswordResetLink", templateName)
		if msgData, ok := data.(structs.MsgForUser); ok {
			assert.Equal(t, consts.MsgForUser["userNotExist"].Msg, msgData.Msg)
		} else {
			t.Errorf("Expected structs.MsgForUser, got %T", data)
		}
		return nil
	}

	form := url.Values{}
	form.Add("email", "notfound@example.com")
	req := httptest.NewRequest("POST", "/generate-password-reset-link", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	GeneratePasswordResetLink(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestSetNewPassword_Success проверяет успешный сценарий установки нового пароля.
//
// Тестирует полный путь выполнения функции:
//   - Токен валиден и не отменён
//   - Пароли совпадают и проходят валидацию
//   - Пользователь найден по email из токена
//   - Все операции выполняются в транзакции:
//     - Установка нового пароля
//     - Отмена временных ID
//     - Отмена refresh токенов
//   - Транзакция успешно коммитится
//   - Пользователь перенаправляется на страницу входа с сообщением об успехе
//
// Мокируется:
//   - IsPasswordResetTokenCancelled возвращает nil
//   - ResetTokenValidate возвращает валидные claims
//   - PasswordValidate возвращает nil
//   - GetPermanentIdFromDbByEmail возвращает permanent ID
//   - Все функции работы с базой данных в транзакции возвращают nil
//
// Ожидаемый результат:
//   - HTTP статус 302 (redirect)
//   - Redirect на страницу входа с сообщением об успехе
func TestSetNewPassword_Success(t *testing.T) {
    db, mock, teardown := setupTest(t)
    defer teardown()

    oldDb := data.Db
    data.Db = db
    defer func() { data.Db = oldDb }()

    mock.ExpectBegin()

    data.IsPasswordResetTokenCancelled = func(token string) error { return nil }
    tools.ResetTokenValidate = func(token string) (*structs.PasswordResetTokenClaims, error) {
        return &structs.PasswordResetTokenClaims{StandardClaims: jwt.StandardClaims{}, Email: "test@example.com"}, nil
    }
    tools.PasswordValidate = func(password string) error { return nil }
    data.GetPermanentIdFromDbByEmail = func(email string, yauth bool) (string, error) {
        return "perm-123", nil
    }
    data.SetPasswordInDbTx = func(tx *sql.Tx, permanentId, password string) error {
        return nil
    }
    data.SetTemporaryIdCancelledInDbTx = func(tx *sql.Tx, permanentId, userAgent string) error {
        return nil
    }
    data.SetRefreshTokenCancelledInDbTx = func(tx *sql.Tx, permanentId, userAgent string) error {
        return nil
    }

    mock.ExpectCommit()

    form := url.Values{}
    form.Add("token", "valid-token-123")
    form.Add("newPassword", "NewValidPassword123!")
    form.Add("confirmPassword", "NewValidPassword123!")
    req := httptest.NewRequest("POST", "/set-new-password", strings.NewReader(form.Encode()))
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    req.Header.Set("User-Agent", "test-user-agent")
    w := httptest.NewRecorder()

    SetNewPassword(w, req)

    assert.Equal(t, http.StatusFound, w.Code)
    assert.Contains(t, w.Header().Get("Location"), consts.SignInURL)
    assert.Contains(t, w.Header().Get("Location"), "Password+has+been+set+successfully")

    assert.NoError(t, mock.ExpectationsWereMet())
}

// TestSetNewPassword_TokenCancelled проверяет обработку отменённого токена сброса пароля.
//
// Тестирует сценарий когда:
//   - Токен сброса пароля был отменён (использован или просрочен)
//   - Функция должна перенаправить на страницу ошибки
//
// Мокируется:
//   - IsPasswordResetTokenCancelled возвращает ошибку
//
// Ожидаемый результат:
//   - HTTP статус 302 (redirect)
//   - Redirect на страницу ошибки 500
func TestSetNewPassword_TokenCancelled(t *testing.T) {
	_, mock, teardown := setupTest(t)
	defer teardown()

	data.IsPasswordResetTokenCancelled = func(token string) error {
		return errors.New("passwordResetToken cancelled")
	}

	form := url.Values{}
	form.Add("token", "cancelled-token-123")
	req := httptest.NewRequest("POST", "/set-new-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	SetNewPassword(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Contains(t, w.Header().Get("Location"), consts.Err500URL)

	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestSetNewPassword_InvalidToken проверяет обработку невалидного токена сброса пароля.
//
// Тестирует сценарий когда:
//   - Токен не отменён, но не проходит валидацию (невалидная подпись, просрочен и т.д.)
//   - Функция должна перенаправить на страницу ошибки
//
// Мокируется:
//   - IsPasswordResetTokenCancelled возвращает nil (токен не отменён)
//   - ResetTokenValidate возвращает ошибку валидации токена
//
// Ожидаемый результат:
//   - HTTP статус 302 (redirect)
//   - Redirect на страницу ошибки 500
func TestSetNewPassword_InvalidToken(t *testing.T) {
	_, mock, teardown := setupTest(t)
	defer teardown()

	data.IsPasswordResetTokenCancelled = func(token string) error { return nil }
	tools.ResetTokenValidate = func(token string) (*structs.PasswordResetTokenClaims, error) {
		return nil, errors.New("token invalid")
	}

	form := url.Values{}
	form.Add("token", "invalid-token-123")
	req := httptest.NewRequest("POST", "/set-new-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	SetNewPassword(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Contains(t, w.Header().Get("Location"), consts.Err500URL)

	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestSetNewPassword_PasswordsDontMatch проверяет обработку несовпадающих паролей.
//
// Тестирует сценарий когда:
//   - Токен валиден и не отменён
//   - Новый пароль и подтверждение пароля не совпадают
//   - Функция должна показать сообщение об ошибке без изменения пароля
//
// Мокируется:
//   - IsPasswordResetTokenCancelled возвращает nil
//   - ResetTokenValidate возвращает валидные claims
//
// Ожидаемый результат:
//   - HTTP статус 200
//   - Вызов рендерера шаблона с сообщением о несовпадении паролей
func TestSetNewPassword_PasswordsDontMatch(t *testing.T) {
	_, mock, teardown := setupTest(t)
	defer teardown()

	data.IsPasswordResetTokenCancelled = func(token string) error { return nil }
	tools.ResetTokenValidate = func(token string) (*structs.PasswordResetTokenClaims, error) {
		return &structs.PasswordResetTokenClaims{StandardClaims: jwt.StandardClaims{}, Email: "test@example.com"}, nil
	}

	tmpls.TmplsRenderer = func(w http.ResponseWriter, tmpl *template.Template, templateName string, data interface{}) error {
		assert.Equal(t, "setNewPassword", templateName)
		if msgData, ok := data.(structs.MsgForUser); ok {
			assert.Equal(t, consts.MsgForUser["passwordsNotMatch"].Msg, msgData.Msg)
		} else {
			t.Errorf("Expected structs.MsgForUser, got %T", data)
		}
		return nil
	}

	form := url.Values{}
	form.Add("token", "valid-token-123")
	form.Add("newPassword", "password1")
	form.Add("confirmPassword", "password2")
	req := httptest.NewRequest("POST", "/set-new-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	SetNewPassword(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestSetNewPassword_InvalidNewPassword проверяет обработку невалидного нового пароля.
//
// Тестирует сценарий когда:
//   - Токен валиден и не отменён
//   - Пароли совпадают, но не проходят валидацию (слишком короткие, простые и т.д.)
//   - Функция должна показать сообщение об ошибке без изменения пароля
//
// Мокируется:
//   - IsPasswordResetTokenCancelled возвращает nil
//   - ResetTokenValidate возвращает валидные claims
//   - PasswordValidate возвращает ошибку валидации пароля
//
// Ожидаемый результат:
//   - HTTP статус 200
//   - Вызов рендерера шаблона с сообщением о невалидном пароле
func TestSetNewPassword_InvalidNewPassword(t *testing.T) {
	_, mock, teardown := setupTest(t)
	defer teardown()

	data.IsPasswordResetTokenCancelled = func(token string) error { return nil }
	tools.ResetTokenValidate = func(token string) (*structs.PasswordResetTokenClaims, error) {
		return &structs.PasswordResetTokenClaims{StandardClaims: jwt.StandardClaims{}, Email: "test@example.com"}, nil
	}
	tools.PasswordValidate = func(password string) error {
		return errors.New("password invalid")
	}

	tmpls.TmplsRenderer = func(w http.ResponseWriter, tmpl *template.Template, templateName string, data interface{}) error {
		assert.Equal(t, "setNewPassword", templateName)
		if msgData, ok := data.(structs.MsgForUser); ok {
			assert.Equal(t, consts.MsgForUser["invalidPassword"].Msg, msgData.Msg)
		} else {
			t.Errorf("Expected structs.MsgForUser, got %T", data)
		}
		return nil
	}

	form := url.Values{}
	form.Add("token", "valid-token-123")
	form.Add("newPassword", "bad")
	form.Add("confirmPassword", "bad")
	req := httptest.NewRequest("POST", "/set-new-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	SetNewPassword(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}
