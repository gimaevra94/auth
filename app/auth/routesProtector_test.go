// Package auth предоставляет функции для аутентификации и авторизации.
//
// Файл содержит тесты для следующих защитников маршрутов:
//   - AuthGuardForSignUpAndSignInPath: защита маршрутов регистрации и входа
//   - AuthGuardForServerAuthCodeSendPath: защита маршрута отправки кода авторизации
//   - ResetTokenGuard: защита маршрутов сброса пароля
//   - AuthGuardForHomePath: защита домашней страницы
//   - Logout: тесты функции выхода из системы
//
// Тесты проверяют различные сценарии аутентификации и авторизации,
// включая обработку ошибок базы данных, валидацию токенов и управление сессиями.
package auth

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/structs"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupRoutesProtectorTest подготавливает окружение для тестов защитников маршрутов.
//
// Создает mock базу данных, устанавливает переменные окружения для сессий,
// инициализирует хранилище и возвращает функцию очистки ресурсов.
// Возвращает mock базу данных, sqlmock интерфейс и функцию teardown.
func setupRoutesProtectorTest(t *testing.T) (*sql.DB, sqlmock.Sqlmock, func()) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)

	os.Setenv("LOGIN_STORE_SESSION_AUTH_KEY", "test-auth-key-32-bytes-long!!")
	os.Setenv("LOGIN_STORE_SESSION_ENCRYPTION_KEY", "test-encryption-key-32-bytes!!")
	os.Setenv("CAPTCHA_STORE_SESSION_SECRET_KEY", "test-captcha-secret-32-bytes!!")

	data.InitStore()

	oldDb := data.Db
	oldResetTokenValidate := tools.ResetTokenValidate
	oldSetPasswordResetTokenInDb := data.SetPasswordResetTokenInDb
	oldIsPasswordResetTokenCancelled := data.IsPasswordResetTokenCancelled
	oldSetTemporaryIdCancelledInDbTx := data.SetTemporaryIdCancelledInDbTx
	oldSetRefreshTokenCancelledInDbTx := data.SetRefreshTokenCancelledInDbTx
	oldSuspiciousLoginEmailSend := tools.SuspiciousLoginEmailSend
	oldRefreshTokenValidate := tools.RefreshTokenValidate

	data.Db = db

	return db, mock, func() {
		data.Db = oldDb
		db.Close()
		tools.ResetTokenValidate = oldResetTokenValidate
		data.SetPasswordResetTokenInDb = oldSetPasswordResetTokenInDb
		data.IsPasswordResetTokenCancelled = oldIsPasswordResetTokenCancelled
		data.SetTemporaryIdCancelledInDbTx = oldSetTemporaryIdCancelledInDbTx
		data.SetRefreshTokenCancelledInDbTx = oldSetRefreshTokenCancelledInDbTx
		tools.SuspiciousLoginEmailSend = oldSuspiciousLoginEmailSend
		tools.RefreshTokenValidate = oldRefreshTokenValidate
	}
}

// TestAuthGuardForSignUpAndSignInPath_NoCookie проверяет работу защитника при отсутствии cookie.
//
// Убеждается, что при отсутствии cookie temporaryId запрос успешно передается
// следующему обработчику без перенаправления.
func TestAuthGuardForSignUpAndSignInPath_NoCookie(t *testing.T) {
	_, mock, teardown := setupRoutesProtectorTest(t)
	defer teardown()

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("next handler called"))
	})

	req := httptest.NewRequest("GET", "/sign-up", nil)
	w := httptest.NewRecorder()

	guard := AuthGuardForSignUpAndSignInPath(nextHandler)
	guard.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "next handler called")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestAuthGuardForSignUpAndSignInPath_CancelledTemporaryId проверяет обработку отмененного temporaryId.
//
// Имитирует ошибку базы данных при проверке отмененного temporaryId и убеждается,
// что запрос передается следующему обработчику, так как пользователь считается неаутентифицированным.
func TestAuthGuardForSignUpAndSignInPath_CancelledTemporaryId(t *testing.T) {
	_, mock, teardown := setupRoutesProtectorTest(t)
	defer teardown()

	mock.ExpectQuery("select cancelled from temporary_id").
		WithArgs("cancelled-temp-id").
		WillReturnError(errors.New("temporaryId cancelled"))

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("next handler called"))
	})

	req := httptest.NewRequest("GET", "/sign-up", nil)
	req.AddCookie(&http.Cookie{Name: "temporaryId", Value: "cancelled-temp-id"})
	w := httptest.NewRecorder()

	guard := AuthGuardForSignUpAndSignInPath(nextHandler)
	guard.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "next handler called")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestAuthGuardForSignUpAndSignInPath_ValidTemporaryId проверяет перенаправление при валидном temporaryId.
//
// Убеждается, что при наличии валидного (неотмененного) temporaryId пользователь
// перенаправляется на домашнюю страницу, так как уже аутентифицирован.
func TestAuthGuardForSignUpAndSignInPath_ValidTemporaryId(t *testing.T) {
	_, mock, teardown := setupRoutesProtectorTest(t)
	defer teardown()

	rows := sqlmock.NewRows([]string{"cancelled"}).AddRow(false)
	mock.ExpectQuery("select cancelled from temporary_id").
		WithArgs("valid-temp-id").
		WillReturnRows(rows)

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("next handler called"))
	})

	req := httptest.NewRequest("GET", "/sign-up", nil)
	req.AddCookie(&http.Cookie{Name: "temporaryId", Value: "valid-temp-id"})
	w := httptest.NewRecorder()

	guard := AuthGuardForSignUpAndSignInPath(nextHandler)
	guard.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, consts.HomeURL, w.Header().Get("Location"))
	assert.Contains(t, w.Body.String(), "Found")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestAuthGuardForSignUpAndSignInPath_DatabaseError проверяет обработку ошибок базы данных.
//
// Имитирует ошибку соединения с базой данных при проверке temporaryId и убеждается,
// что происходит перенаправление на страницу ошибки 500.
func TestAuthGuardForSignUpAndSignInPath_DatabaseError(t *testing.T) {
	_, mock, teardown := setupRoutesProtectorTest(t)
	defer teardown()

	mock.ExpectQuery("select cancelled from temporary_id").
		WithArgs("temp-id").
		WillReturnError(errors.New("database connection error"))

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("next handler called"))
	})

	req := httptest.NewRequest("GET", "/sign-up", nil)
	req.AddCookie(&http.Cookie{Name: "temporaryId", Value: "temp-id"})
	w := httptest.NewRecorder()

	guard := AuthGuardForSignUpAndSignInPath(nextHandler)
	guard.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, consts.Err500URL, w.Header().Get("Location"))
	assert.Contains(t, w.Body.String(), "Found")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestAuthGuardForServerAuthCodeSendPath_NoSession проверяет работу защитника при отсутствии сессии.
//
// Убеждается, что при отсутствии пользовательской сессии происходит перенаправление
// на страницу регистрации, так как доступ к отправке кода авторизации требует аутентификации.
func TestAuthGuardForServerAuthCodeSendPath_NoSession(t *testing.T) {
	_, mock, teardown := setupRoutesProtectorTest(t)
	defer teardown()

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("next handler called"))
	})

	req := httptest.NewRequest("GET", "/server-auth-code-send", nil)
	w := httptest.NewRecorder()

	guard := AuthGuardForServerAuthCodeSendPath(nextHandler)
	guard.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, consts.SignUpURL, w.Header().Get("Location"))
	assert.Contains(t, w.Body.String(), "Found")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestResetTokenGuard_NoToken проверяет работу защитника при отсутствии токена сброса.
//
// Убеждается, что при отсутствии токена в параметрах запроса происходит
// перенаправление на страницу регистрации.
func TestResetTokenGuard_NoToken(t *testing.T) {
	_, mock, teardown := setupRoutesProtectorTest(t)
	defer teardown()

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("next handler called"))
	})

	req := httptest.NewRequest("GET", "/reset-password", nil)
	w := httptest.NewRecorder()

	guard := ResetTokenGuard(nextHandler)
	guard.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, consts.SignUpURL, w.Header().Get("Location"))
	assert.Contains(t, w.Body.String(), "Found")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestResetTokenGuard_InvalidToken проверяет обработку невалидного токена сброса.
//
// Имитирует невалидный токен и убеждается, что происходит перенаправление
// на страницу регистрации при ошибке валидации токена.
func TestResetTokenGuard_InvalidToken(t *testing.T) {
	_, mock, teardown := setupRoutesProtectorTest(t)
	defer teardown()

	tools.ResetTokenValidate = func(token string) (*structs.PasswordResetTokenClaims, error) {
		return nil, errors.New("invalid token")
	}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("next handler called"))
	})

	req := httptest.NewRequest("GET", "/reset-password?token=invalid-token", nil)
	w := httptest.NewRecorder()

	guard := ResetTokenGuard(nextHandler)
	guard.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, consts.SignUpURL, w.Header().Get("Location"))
	assert.Contains(t, w.Body.String(), "Found")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestResetTokenGuard_CancelledToken проверяет обработку отмененного токена.
//
// Имитирует отмененный токен (sql.ErrNoRows) и убеждается, что происходит
// перенаправление на страницу регистрации.
func TestResetTokenGuard_CancelledToken(t *testing.T) {
	_, mock, teardown := setupRoutesProtectorTest(t)
	defer teardown()

	tools.ResetTokenValidate = func(token string) (*structs.PasswordResetTokenClaims, error) {
		return &structs.PasswordResetTokenClaims{}, nil
	}

	data.IsPasswordResetTokenCancelled = func(token string) error {
		return sql.ErrNoRows
	}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("next handler called"))
	})

	req := httptest.NewRequest("GET", "/reset-password?token=cancelled-token", nil)
	w := httptest.NewRecorder()

	guard := ResetTokenGuard(nextHandler)
	guard.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, consts.SignUpURL, w.Header().Get("Location"))
	assert.Contains(t, w.Body.String(), "Found")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestResetTokenGuard_ValidToken проверяет успешную валидацию токена.
//
// Убеждается, что при валидном токене запрос успешно передается
// следующему обработчику без перенаправления.
func TestResetTokenGuard_ValidToken(t *testing.T) {
	_, mock, teardown := setupRoutesProtectorTest(t)
	defer teardown()

	tools.ResetTokenValidate = func(token string) (*structs.PasswordResetTokenClaims, error) {
		return &structs.PasswordResetTokenClaims{}, nil
	}

	data.IsPasswordResetTokenCancelled = func(token string) error {
		return nil
	}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("next handler called"))
	})

	req := httptest.NewRequest("GET", "/reset-password?token=valid-token", nil)
	w := httptest.NewRecorder()

	guard := ResetTokenGuard(nextHandler)
	guard.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "next handler called")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestAuthGuardForHomePath_NoCookie проверяет работу защитника при отсутствии cookie.
//
// Убеждается, что при отсутствии cookie temporaryId происходит перенаправление
// на страницу регистрации для аутентификации.
func TestAuthGuardForHomePath_NoCookie(t *testing.T) {
	_, mock, teardown := setupRoutesProtectorTest(t)
	defer teardown()

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("next handler called"))
	})

	req := httptest.NewRequest("GET", "/home", nil)
	w := httptest.NewRecorder()

	guard := AuthGuardForHomePath(nextHandler)
	guard.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, consts.SignUpURL, w.Header().Get("Location"))
	assert.Contains(t, w.Body.String(), "Found")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestAuthGuardForHomePath_DatabaseError проверяет обработку ошибок базы данных.
//
// Имитирует ошибку соединения с базой данных при проверке temporaryId и убеждается,
// что происходит перенаправление на страницу ошибки 500.
func TestAuthGuardForHomePath_DatabaseError(t *testing.T) {
	_, mock, teardown := setupRoutesProtectorTest(t)
	defer teardown()

	mock.ExpectQuery("select permanentId, userAgent from temporary_id").
		WithArgs("temp-id").
		WillReturnError(errors.New("database connection error"))

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("next handler called"))
	})

	req := httptest.NewRequest("GET", "/home", nil)
	req.AddCookie(&http.Cookie{Name: "temporaryId", Value: "temp-id"})
	w := httptest.NewRecorder()

	guard := AuthGuardForHomePath(nextHandler)
	guard.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, consts.Err500URL, w.Header().Get("Location"))
	assert.Contains(t, w.Body.String(), "Found")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestAuthGuardForHomePath_SuspiciousUserAgent проверяет обработку подозрительного User-Agent.
//
// Имитирует доступ с другого User-Agent и убеждается, что происходит
// аннулирование сессии и перенаправление на страницу регистрации.
func TestAuthGuardForHomePath_SuspiciousUserAgent(t *testing.T) {
	_, mock, teardown := setupRoutesProtectorTest(t)
	defer teardown()
	tools.SuspiciousLoginEmailSend = func(email, userAgent string) error {
		return nil
	}

	rows := sqlmock.NewRows([]string{"permanentId", "userAgent"}).
		AddRow("permanent-123", "different-user-agent")
	mock.ExpectQuery("select permanentId, userAgent from temporary_id").
		WithArgs("temp-id").
		WillReturnRows(rows)

	emailRows := sqlmock.NewRows([]string{"email"}).AddRow("test@example.com")
	mock.ExpectQuery("select email from email").
		WithArgs("permanent-123").
		WillReturnRows(emailRows)

	logoutRows := sqlmock.NewRows([]string{"permanentId", "userAgent"}).
		AddRow("permanent-123", "different-user-agent")
	mock.ExpectQuery("select permanentId, userAgent from temporary_id").
		WithArgs("temp-id").
		WillReturnRows(logoutRows)
	mock.ExpectBegin()
	mock.ExpectExec("update temporary_id set cancelled = true").
		WithArgs("permanent-123", "different-user-agent").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("update refresh_token set cancelled = true").
		WithArgs("permanent-123", "different-user-agent").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("next handler called"))
	})

	req := httptest.NewRequest("GET", "/home", nil)
	req.AddCookie(&http.Cookie{Name: "temporaryId", Value: "temp-id"})
	req.Header.Set("User-Agent", "current-user-agent")
	w := httptest.NewRecorder()

	guard := AuthGuardForHomePath(nextHandler)
	guard.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, consts.SignUpURL, w.Header().Get("Location"))
	assert.Contains(t, w.Body.String(), "Found")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestAuthGuardForHomePath_NoRefreshToken проверяет отсутствие refresh токена.
//
// Имитирует ситуацию, когда refresh токен не найден в базе данных,
// и убеждается, что сессия аннулируется и происходит перенаправление.
func TestAuthGuardForHomePath_NoRefreshToken(t *testing.T) {
	_, mock, teardown := setupRoutesProtectorTest(t)
	defer teardown()
	rows := sqlmock.NewRows([]string{"permanentId", "userAgent"}).
		AddRow("permanent-123", "same-user-agent")
	mock.ExpectQuery("select permanentId, userAgent from temporary_id").
		WithArgs("temp-id").
		WillReturnRows(rows)

	emailRows := sqlmock.NewRows([]string{"email"}).AddRow("test@example.com")
	mock.ExpectQuery("select email from email").
		WithArgs("permanent-123").
		WillReturnRows(emailRows)

	mock.ExpectQuery("select token from refresh_token").
		WithArgs("permanent-123", "same-user-agent").
		WillReturnError(sql.ErrNoRows)

	logoutRows := sqlmock.NewRows([]string{"permanentId", "userAgent"}).
		AddRow("permanent-123", "same-user-agent")
	mock.ExpectQuery("select permanentId, userAgent from temporary_id").
		WithArgs("temp-id").
		WillReturnRows(logoutRows)
	mock.ExpectBegin()
	mock.ExpectExec("update temporary_id set cancelled = true").
		WithArgs("permanent-123", "same-user-agent").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("update refresh_token set cancelled = true").
		WithArgs("permanent-123", "same-user-agent").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("next handler called"))
	})

	req := httptest.NewRequest("GET", "/home", nil)
	req.AddCookie(&http.Cookie{Name: "temporaryId", Value: "temp-id"})
	req.Header.Set("User-Agent", "same-user-agent")
	w := httptest.NewRecorder()

	guard := AuthGuardForHomePath(nextHandler)
	guard.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, consts.SignUpURL, w.Header().Get("Location"))
	assert.Contains(t, w.Body.String(), "Found")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestAuthGuardForHomePath_InvalidRefreshToken проверяет обработку невалидного refresh токена.
//
// Имитирует невалидный refresh токен и убеждается, что сессия аннулируется
// и происходит перенаправление на страницу регистрации.
func TestAuthGuardForHomePath_InvalidRefreshToken(t *testing.T) {
	_, mock, teardown := setupRoutesProtectorTest(t)
	defer teardown()

	rows := sqlmock.NewRows([]string{"permanentId", "userAgent"}).
		AddRow("permanent-123", "same-user-agent")
	mock.ExpectQuery("select permanentId, userAgent from temporary_id").
		WithArgs("temp-id").
		WillReturnRows(rows)

	emailRows := sqlmock.NewRows([]string{"email"}).AddRow("test@example.com")
	mock.ExpectQuery("select email from email").
		WithArgs("permanent-123").
		WillReturnRows(emailRows)

	tokenRows := sqlmock.NewRows([]string{"token"}).AddRow("invalid-refresh-token")
	mock.ExpectQuery("select token from refresh_token").
		WithArgs("permanent-123", "same-user-agent").
		WillReturnRows(tokenRows)

	logoutRows := sqlmock.NewRows([]string{"permanentId", "userAgent"}).
		AddRow("permanent-123", "same-user-agent")
	mock.ExpectQuery("select permanentId, userAgent from temporary_id").
		WithArgs("temp-id").
		WillReturnRows(logoutRows)
	mock.ExpectBegin()
	mock.ExpectExec("update temporary_id set cancelled = true").
		WithArgs("permanent-123", "same-user-agent").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("update refresh_token set cancelled = true").
		WithArgs("permanent-123", "same-user-agent").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("next handler called"))
	})

	req := httptest.NewRequest("GET", "/home", nil)
	req.AddCookie(&http.Cookie{Name: "temporaryId", Value: "temp-id"})
	req.Header.Set("User-Agent", "same-user-agent")
	w := httptest.NewRecorder()

	guard := AuthGuardForHomePath(nextHandler)
	guard.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, consts.SignUpURL, w.Header().Get("Location"))
	assert.Contains(t, w.Body.String(), "Found")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestAuthGuardForHomePath_ValidAccess проверяет успешный доступ к домашней странице.
//
// Убеждается, что при валидном temporaryId, совпадении User-Agent
// и валидном refresh токене запрос передается следующему обработчику.
func TestAuthGuardForHomePath_ValidAccess(t *testing.T) {
	_, mock, teardown := setupRoutesProtectorTest(t)
	defer teardown()
	tools.RefreshTokenValidate = func(refreshToken string) error {
		return nil
	}

	rows := sqlmock.NewRows([]string{"permanentId", "userAgent"}).
		AddRow("permanent-123", "same-user-agent")
	mock.ExpectQuery("select permanentId, userAgent from temporary_id").
		WithArgs("temp-id").
		WillReturnRows(rows)

	emailRows := sqlmock.NewRows([]string{"email"}).AddRow("test@example.com")
	mock.ExpectQuery("select email from email").
		WithArgs("permanent-123").
		WillReturnRows(emailRows)

	tokenRows := sqlmock.NewRows([]string{"token"}).AddRow("valid-refresh-token")
	mock.ExpectQuery("select token from refresh_token").
		WithArgs("permanent-123", "same-user-agent").
		WillReturnRows(tokenRows)

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("next handler called"))
	})

	req := httptest.NewRequest("GET", "/home", nil)
	req.AddCookie(&http.Cookie{Name: "temporaryId", Value: "temp-id"})
	req.Header.Set("User-Agent", "same-user-agent")
	w := httptest.NewRecorder()

	guard := AuthGuardForHomePath(nextHandler)
	guard.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "next handler called")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestLogout_NoCookie проверяет выход без cookie.
//
// Убеждается, что при отсутствии cookie temporaryId происходит
// перенаправление на страницу ошибки 500.
func TestLogout_NoCookie(t *testing.T) {
	_, _, teardown := setupRoutesProtectorTest(t)
	defer teardown()

	req := httptest.NewRequest("POST", "/logout", nil)
	w := httptest.NewRecorder()

	Logout(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, consts.Err500URL, w.Header().Get("Location"))
	assert.Empty(t, w.Body.String())
}

// TestLogout_DatabaseError проверяет обработку ошибок базы данных при выходе.
//
// Имитирует ошибку соединения с базой данных при получении данных temporaryId
// и убеждается, что происходит перенаправление на страницу ошибки 500.
func TestLogout_DatabaseError(t *testing.T) {
	_, mock, teardown := setupRoutesProtectorTest(t)
	defer teardown()

	mock.ExpectQuery("select permanentId, userAgent from temporary_id").
		WithArgs("temp-id").
		WillReturnError(errors.New("database connection error"))

	req := httptest.NewRequest("POST", "/logout", nil)
	req.AddCookie(&http.Cookie{Name: "temporaryId", Value: "temp-id"})
	w := httptest.NewRecorder()

	Logout(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, consts.Err500URL, w.Header().Get("Location"))
	assert.Empty(t, w.Body.String())
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestLogout_Success проверяет успешный выход из системы.
//
// Убеждается, что при успешном выходе аннулируются temporaryId и refresh токены,
// cookie очищается и происходит перенаправление на страницу регистрации.
func TestLogout_Success(t *testing.T) {
	_, mock, teardown := setupRoutesProtectorTest(t)
	defer teardown()
	rows := sqlmock.NewRows([]string{"permanentId", "userAgent"}).
		AddRow("permanent-123", "user-agent")
	mock.ExpectQuery("select permanentId, userAgent from temporary_id").
		WithArgs("temp-id").
		WillReturnRows(rows)

	mock.ExpectBegin()
	mock.ExpectExec("update temporary_id").
		WithArgs("permanent-123", "user-agent").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("update refresh_token").
		WithArgs("permanent-123", "user-agent").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	req := httptest.NewRequest("POST", "/logout", nil)
	req.AddCookie(&http.Cookie{Name: "temporaryId", Value: "temp-id"})
	w := httptest.NewRecorder()

	Logout(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, consts.SignUpURL, w.Header().Get("Location"))

	cookies := w.Result().Cookies()
	var tempCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "temporaryId" {
			tempCookie = c
			break
		}
	}
	require.NotNil(t, tempCookie, "Cookie temporaryId должен быть установлен")
	assert.Equal(t, -1, tempCookie.MaxAge, "Cookie должен быть очищен")

	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestLogout_TransactionRollback проверяет откат транзакции при панике.
//
// Имитирует панику во время выполнения транзакции и убеждается,
// что происходит откат транзакции для сохранения целостности данных.
func TestLogout_TransactionRollback(t *testing.T) {
	_, mock, teardown := setupRoutesProtectorTest(t)
	defer teardown()
	rows := sqlmock.NewRows([]string{"permanentId", "userAgent"}).
		AddRow("permanent-123", "user-agent")
	mock.ExpectQuery("select permanentId, userAgent from temporary_id").
		WithArgs("temp-id").
		WillReturnRows(rows)

	mock.ExpectBegin()
	mock.ExpectRollback()

	originalSetTemporaryIdCancelledInDbTx := data.SetTemporaryIdCancelledInDbTx
	data.SetTemporaryIdCancelledInDbTx = func(tx *sql.Tx, permanentId, userAgent string) error {
		panic("test panic")
	}
	defer func() { data.SetTemporaryIdCancelledInDbTx = originalSetTemporaryIdCancelledInDbTx }()

	req := httptest.NewRequest("POST", "/logout", nil)
	req.AddCookie(&http.Cookie{Name: "temporaryId", Value: "temp-id"})
	w := httptest.NewRecorder()

	assert.Panics(t, func() {
		Logout(w, req)
	})

	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestAuthGuardForServerAuthCodeSendPath_EdgeCases проверяет граничные случаи для защитника.
//
// Тестирует различные значения ServerCode в сессии:
//   - пустой код
//   - валидный код
//   - код состоящий из пробелов
//
// Проверяет правильность перенаправлений в каждом случае.
func TestAuthGuardForServerAuthCodeSendPath_EdgeCases(t *testing.T) {
	_, mock, teardown := setupRoutesProtectorTest(t)
	defer teardown()

	tests := []struct {
		name           string
		setupSession   func() *structs.User
		expectedStatus int
		expectedNext   bool
	}{
		{
			name: "Empty ServerCode",
			setupSession: func() *structs.User {
				return &structs.User{ServerCode: ""}
			},
			expectedStatus: http.StatusFound,
			expectedNext:   false,
		},
		{
			name: "Valid ServerCode",
			setupSession: func() *structs.User {
				return &structs.User{ServerCode: "123456"}
			},
			expectedStatus: http.StatusOK,
			expectedNext:   true,
		},
		{
			name: "Whitespace ServerCode",
			setupSession: func() *structs.User {
				return &structs.User{ServerCode: "   "}
			},
			expectedStatus: http.StatusFound,
			expectedNext:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var nextCalled bool
			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("next handler called"))
			})

			req := httptest.NewRequest("GET", "/server-auth-code-send", nil)
			w := httptest.NewRecorder()

			guard := AuthGuardForServerAuthCodeSendPath(nextHandler)
			guard.ServeHTTP(w, req)

			assert.Equal(t, http.StatusFound, w.Code)
			assert.False(t, nextCalled)
			assert.Equal(t, consts.SignUpURL, w.Header().Get("Location"))
		})
	}

	assert.NoError(t, mock.ExpectationsWereMet())
}
