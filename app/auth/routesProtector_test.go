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
