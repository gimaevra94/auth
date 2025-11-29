// Package auth предоставляет тесты для модуля аутентификации и авторизации.
// Файл тестирует функции GeneratePasswordResetLink и SetNewPassword.
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

// setupTest создаёт мок базы данных и заменяет глобальные зависимости.
// Возвращает мок и функцию очистки.
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

// TestGeneratePasswordResetLink_Success проверяет успешную генерацию ссылки.
// Ожидается: HTTP 200, сообщение об отправке.
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

// TestGeneratePasswordResetLink_InvalidEmail проверяет обработку невалидного email.
// Ожидается: HTTP 200, сообщение об ошибке.
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
// Ожидается: HTTP 200, сообщение "пользователь не существует".
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

// TestSetNewPassword_Success проверяет успешную установку пароля.
// Ожидается: HTTP 302, редирект на страницу входа.
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

// TestSetNewPassword_TokenCancelled проверяет обработку отменённого токена.
// Ожидается: HTTP 302, редирект на 500.
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

// TestSetNewPassword_InvalidToken проверяет обработку невалидного токена.
// Ожидается: HTTP 302, редирект на 500.
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

// TestSetNewPassword_PasswordsDontMatch проверяет несовпадение паролей.
// Ожидается: HTTP 200, сообщение об ошибке.
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

// TestSetNewPassword_InvalidNewPassword проверяет невалидный пароль.
// Ожидается: HTTP 200, сообщение об ошибке.
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