package auth

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/structs"
	"github.com/gimaevra94/auth/app/tmpls"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mock для шаблонизатора
type mockTemplateRenderer struct{}

func (m *mockTemplateRenderer) TmplsRenderer(w http.ResponseWriter, baseTmpl, tmplName string, data interface{}) error {
	return nil
}

// Mock для отправки email
type mockEmailSender struct {
	sendFunc func(email, link string) error
}

func (m *mockEmailSender) PasswordResetEmailSend(email, link string) error {
	return m.sendFunc(email, link)
}

// Mock для работы с токенами
type mockTokenHandler struct {
	generateFunc func(email, baseURL string) (string, error)
	validateFunc func(token string) (*structs.Claims, error)
}

func (m *mockTokenHandler) GeneratePasswordResetLink(email, baseURL string) (string, error) {
	return m.generateFunc(email, baseURL)
}

func (m *mockTokenHandler) ResetTokenValidate(token string) (*structs.Claims, error) {
	return m.validateFunc(token)
}

func setupTest(t *testing.T) (*sql.DB, sqlmock.Sqlmock, func()) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)

	// Сохраняем оригинальные зависимости
	oldDB := data.Db
	oldTmpls := tmpls.TmplsRenderer
	oldEmailSender := tools.PasswordResetEmailSend
	oldTokenGenerator := tools.GeneratePasswordResetLink
	oldTokenValidator := tools.ResetTokenValidate

	// Подменяем зависимости на моки
	data.Db = db
	tmpls.TmplsRenderer = (&mockTemplateRenderer{}).TmplsRenderer

	// Настройка мока для отправки email
	tools.PasswordResetEmailSend = func(email, link string) error {
		return nil
	}

	// Настройка мока для генерации токена
	tools.GeneratePasswordResetLink = func(email, baseURL string) (string, error) {
		return "http://localhost:8080/set-new-password?token=mock-token", nil
	}

	// Настройка мока для валидации токена
	tools.ResetTokenValidate = func(token string) (*structs.Claims, error) {
		return &structs.Claims{Email: "test@example.com"}, nil
	}

	return db, mock, func() {
		// Восстанавливаем оригинальные зависимости
		data.Db = oldDB
		tmpls.TmplsRenderer = oldTmpls
		tools.PasswordResetEmailSend = oldEmailSender
		tools.GeneratePasswordResetLink = oldTokenGenerator
		tools.ResetTokenValidate = oldTokenValidator
		db.Close()
	}
}

func TestGeneratePasswordResetLink_Success(t *testing.T) {
	db, mock, teardown := setupTest(t)
	defer teardown()

	// Настраиваем ожидания
	rows := sqlmock.NewRows([]string{"id"}).AddRow(1)
	mock.ExpectQuery("SELECT id FROM users").
		WithArgs("test@example.com", false).
		WillReturnRows(rows)
	mock.ExpectExec("INSERT INTO password_reset_tokens").
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Подготавливаем запрос
	form := url.Values{}
	form.Add("email", "test@example.com")
	req := httptest.NewRequest("POST", "/generate-password-reset", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	// Вызываем тестируемую функцию
	GeneratePasswordResetLink(w, req)

	// Проверяем результаты
	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGeneratePasswordResetLink_InvalidEmail(t *testing.T) {
	_, _, teardown := setupTest(t)
	defer teardown()

	// Подготавливаем запрос с невалидным email
	form := url.Values{}
	form.Add("email", "invalid-email")
	req := httptest.NewRequest("POST", "/generate-password-reset", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	// Вызываем тестируемую функцию
	GeneratePasswordResetLink(w, req)

	// Проверяем, что вернулся ответ с кодом 200 (форма с ошибкой)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSetNewPassword_Success(t *testing.T) {
	db, mock, teardown := setupTest(t)
	defer teardown()

	// Настраиваем ожидания
	mock.ExpectQuery("SELECT 1 FROM password_reset_tokens").
		WithArgs("valid-token").
		WillReturnRows(sqlmock.NewRows([]string{"1"}).AddRow(1))
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT id FROM users").
		WithArgs("test@example.com", false).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
	mock.ExpectExec("UPDATE users").
		WithArgs(sqlmock.AnyArg(), 1).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("UPDATE temporary_ids").
		WithArgs(sqlmock.AnyArg(), 1).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("UPDATE refresh_tokens").
		WithArgs(sqlmock.AnyArg(), 1).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	// Подготавливаем запрос
	form := url.Values{
		"token":           {"valid-token"},
		"newPassword":     {"NewValidPassword123!"},
		"confirmPassword": {"NewValidPassword123!"},
	}
	req := httptest.NewRequest("POST", "/set-new-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	// Вызываем тестируемую функцию
	SetNewPassword(w, req)

	// Проверяем результаты
	assert.Equal(t, http.StatusFound, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSetNewPassword_PasswordsDontMatch(t *testing.T) {
	_, mock, teardown := setupTest(t)
	defer teardown()

	// Настраиваем ожидания
	mock.ExpectQuery("SELECT 1 FROM password_reset_tokens").
		WithArgs("valid-token").
		WillReturnRows(sqlmock.NewRows([]string{"1"}).AddRow(1))

	// Подготавливаем запрос с несовпадающими паролями
	form := url.Values{
		"token":           {"valid-token"},
		"newPassword":     {"password1"},
		"confirmPassword": {"password2"},
	}
	req := httptest.NewRequest("POST", "/set-new-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	// Вызываем тестируемую функцию
	SetNewPassword(w, req)

	// Проверяем результаты
	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}
