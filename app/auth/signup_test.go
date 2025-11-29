// Package auth предоставляет тесты для модуля регистрации пользователей.
//
// Файл тестирует функции CheckInDbAndValidateSignUpUserInput, ServerAuthCodeSend,
// CodeValidate и SetUserInDb, покрывая все основные сценарии регистрации,
// включая валидацию данных, обработку ошибок и успешное создание пользователя.
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
	"github.com/gimaevra94/auth/app/captcha"
	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/structs"
	"github.com/gimaevra94/auth/app/tmpls"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupSignUpTest создаёт мок базы данных и заменяет глобальные зависимости.
// Возвращает мок и функцию очистки.
func setupSignUpTest(t *testing.T) (*sql.DB, sqlmock.Sqlmock, func()) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)

	t.Setenv("LOGIN_STORE_SESSION_AUTH_KEY", "test-auth-key-32-bytes-long")
	t.Setenv("LOGIN_STORE_SESSION_ENCRYPTION_KEY", "test-encryption-key-32-bytes-long")
	t.Setenv("CAPTCHA_STORE_SESSION_SECRET_KEY", "test-captcha-secret-key-32-bytes")
	
	data.InitStore()

	oldDB := data.Db
	oldTmplsRenderer := tmpls.TmplsRenderer
	oldInitCaptchaState := captcha.InitCaptchaState
	oldShowCaptchaMsg := captcha.ShowCaptchaMsg
	oldUpdateCaptchaState := captcha.UpdateCaptchaState
	oldInputValidate := tools.InputValidate
	oldGetPermanentIdFromDbByEmail := data.GetPermanentIdFromDbByEmail
	oldSetAuthDataInSession := data.SetAuthDataInSession
	oldGetAuthDataFromSession := data.GetAuthDataFromSession
	oldServerAuthCodeSend := tools.ServerAuthCodeSend
	oldGetCaptchaCounterFromSession := data.GetCaptchaCounterFromSession
	oldGetShowCaptchaFromSession := data.GetShowCaptchaFromSession
	oldCodeValidate := tools.CodeValidate
	oldSetLoginInDbTx := data.SetLoginInDbTx
	oldSetEmailInDbTx := data.SetEmailInDbTx
	oldSetPasswordInDbTx := data.SetPasswordInDbTx
	oldSetTemporaryIdInCookies := data.SetTemporaryIdInCookies
	oldSetTemporaryIdInDbTx := data.SetTemporaryIdInDbTx
	oldGenerateRefreshToken := tools.GenerateRefreshToken
	oldSetRefreshTokenInDbTx := data.SetRefreshTokenInDbTx
	oldSendNewDeviceLoginEmail := tools.SendNewDeviceLoginEmail
	oldEndAuthAndCaptchaSessions := data.EndAuthAndCaptchaSessions

	data.Db = db

	return db, mock, func() {
		data.Db = oldDB
		db.Close()
		tmpls.TmplsRenderer = oldTmplsRenderer
		captcha.InitCaptchaState = oldInitCaptchaState
		captcha.ShowCaptchaMsg = oldShowCaptchaMsg
		captcha.UpdateCaptchaState = oldUpdateCaptchaState
		tools.InputValidate = oldInputValidate
		data.GetPermanentIdFromDbByEmail = oldGetPermanentIdFromDbByEmail
		data.SetAuthDataInSession = oldSetAuthDataInSession
		data.GetAuthDataFromSession = oldGetAuthDataFromSession
		tools.ServerAuthCodeSend = oldServerAuthCodeSend
		data.GetCaptchaCounterFromSession = oldGetCaptchaCounterFromSession
		data.GetShowCaptchaFromSession = oldGetShowCaptchaFromSession
		tools.CodeValidate = oldCodeValidate
		data.SetLoginInDbTx = oldSetLoginInDbTx
		data.SetEmailInDbTx = oldSetEmailInDbTx
		data.SetPasswordInDbTx = oldSetPasswordInDbTx
		data.SetTemporaryIdInCookies = oldSetTemporaryIdInCookies
		data.SetTemporaryIdInDbTx = oldSetTemporaryIdInDbTx
		tools.GenerateRefreshToken = oldGenerateRefreshToken
		data.SetRefreshTokenInDbTx = oldSetRefreshTokenInDbTx
		tools.SendNewDeviceLoginEmail = oldSendNewDeviceLoginEmail
		data.EndAuthAndCaptchaSessions = oldEndAuthAndCaptchaSessions
	}
}

// TestCheckInDbAndValidateSignUpUserInput_Success проверяет успешную валидацию данных регистрации.
// Ожидается: HTTP 302, редирект на страницу отправки кода.
func TestCheckInDbAndValidateSignUpUserInput_Success(t *testing.T) {
	_, mock, teardown := setupSignUpTest(t)
	defer teardown()

	captcha.InitCaptchaState = func(w http.ResponseWriter, r *http.Request) (int64, bool, error) {
		return 3, false, nil
	}
	captcha.ShowCaptchaMsg = func(r *http.Request, showCaptcha bool) bool {
		return false
	}
	data.GetPermanentIdFromDbByEmail = func(email string, isOAuth bool) (string, error) {
		return "", sql.ErrNoRows
	}
	tools.InputValidate = func(r *http.Request, login, email, password string, isSignIn bool) (string, error) {
		return "", nil
	}
	data.SetAuthDataInSession = func(w http.ResponseWriter, r *http.Request, consts any) error {
		return nil
	}
	tools.ServerAuthCodeSend = func(email string) (string, error) {
		return "123456", nil
	}
	data.GetAuthDataFromSession = func(r *http.Request) (structs.User, error) {
		return structs.User{Email: "test@example.com"}, nil
	}

	form := url.Values{}
	form.Add("login", "testuser")
	form.Add("email", "test@example.com")
	form.Add("password", "ValidPassword123!")
	req := httptest.NewRequest("POST", "/sign-up", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	CheckInDbAndValidateSignUpUserInput(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, consts.ServerAuthCodeSendURL, w.Header().Get("Location"))
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestCheckInDbAndValidateSignUpUserInput_InvalidLogin проверяет обработку невалидного логина.
// Ожидается: HTTP 200, сообщение об ошибке валидации логина.
func TestCheckInDbAndValidateSignUpUserInput_InvalidLogin(t *testing.T) {
	_, mock, teardown := setupSignUpTest(t)
	defer teardown()

	captcha.InitCaptchaState = func(w http.ResponseWriter, r *http.Request) (int64, bool, error) {
		return 3, false, nil
	}
	captcha.ShowCaptchaMsg = func(r *http.Request, showCaptcha bool) bool {
		return false
	}
	captcha.UpdateCaptchaState = func(w http.ResponseWriter, r *http.Request, captchaCounter int64, showCaptcha bool) error {
		return nil
	}
	data.GetPermanentIdFromDbByEmail = func(email string, isOAuth bool) (string, error) {
		return "", sql.ErrNoRows
	}
	tools.InputValidate = func(r *http.Request, login, email, password string, isSignIn bool) (string, error) {
		return "loginInvalid", errors.New("login invalid")
	}

	tmpls.TmplsRenderer = func(w http.ResponseWriter, tmpl *template.Template, templateName string, data interface{}) error {
		assert.Equal(t, "signUp", templateName)
		if msgData, ok := data.(structs.MsgForUser); ok {
			assert.Equal(t, consts.MsgForUser["loginInvalid"].Msg, msgData.Msg)
			assert.False(t, msgData.ShowCaptcha)
			assert.Equal(t, consts.MsgForUser["loginInvalid"].Regs, msgData.Regs)
		} else {
			t.Errorf("Expected structs.MsgForUser, got %T", data)
		}
		return nil
	}

	form := url.Values{}
	form.Add("login", "ab")
	form.Add("email", "test@example.com")
	form.Add("password", "ValidPassword123!")
	req := httptest.NewRequest("POST", "/sign-up", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	CheckInDbAndValidateSignUpUserInput(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestCheckInDbAndValidateSignUpUserInput_InvalidEmail проверяет обработку невалидного email.
// Ожидается: HTTP 200, сообщение об ошибке валидации email.
func TestCheckInDbAndValidateSignUpUserInput_InvalidEmail(t *testing.T) {
	_, mock, teardown := setupSignUpTest(t)
	defer teardown()

	captcha.InitCaptchaState = func(w http.ResponseWriter, r *http.Request) (int64, bool, error) {
		return 3, false, nil
	}
	captcha.ShowCaptchaMsg = func(r *http.Request, showCaptcha bool) bool {
		return false
	}
	captcha.UpdateCaptchaState = func(w http.ResponseWriter, r *http.Request, captchaCounter int64, showCaptcha bool) error {
		return nil
	}
	data.GetPermanentIdFromDbByEmail = func(email string, isOAuth bool) (string, error) {
		return "", sql.ErrNoRows
	}
	tools.InputValidate = func(r *http.Request, login, email, password string, isSignIn bool) (string, error) {
		return "emailInvalid", errors.New("email invalid")
	}

	tmpls.TmplsRenderer = func(w http.ResponseWriter, tmpl *template.Template, templateName string, data interface{}) error {
		assert.Equal(t, "signUp", templateName)
		if msgData, ok := data.(structs.MsgForUser); ok {
			assert.Equal(t, consts.MsgForUser["emailInvalid"].Msg, msgData.Msg)
			assert.False(t, msgData.ShowCaptcha)
			assert.Equal(t, consts.MsgForUser["emailInvalid"].Regs, msgData.Regs)
		} else {
			t.Errorf("Expected structs.MsgForUser, got %T", data)
		}
		return nil
	}

	form := url.Values{}
	form.Add("login", "testuser")
	form.Add("email", "invalid-email")
	form.Add("password", "ValidPassword123!")
	req := httptest.NewRequest("POST", "/sign-up", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	CheckInDbAndValidateSignUpUserInput(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestCheckInDbAndValidateSignUpUserInput_InvalidPassword проверяет обработку невалидного пароля.
// Ожидается: HTTP 200, сообщение об ошибке валидации пароля.
func TestCheckInDbAndValidateSignUpUserInput_InvalidPassword(t *testing.T) {
	_, mock, teardown := setupSignUpTest(t)
	defer teardown()

	captcha.InitCaptchaState = func(w http.ResponseWriter, r *http.Request) (int64, bool, error) {
		return 3, false, nil
	}
	captcha.ShowCaptchaMsg = func(r *http.Request, showCaptcha bool) bool {
		return false
	}
	captcha.UpdateCaptchaState = func(w http.ResponseWriter, r *http.Request, captchaCounter int64, showCaptcha bool) error {
		return nil
	}
	data.GetPermanentIdFromDbByEmail = func(email string, isOAuth bool) (string, error) {
		return "", sql.ErrNoRows
	}
	tools.InputValidate = func(r *http.Request, login, email, password string, isSignIn bool) (string, error) {
		return "passwordInvalid", errors.New("password invalid")
	}

	tmpls.TmplsRenderer = func(w http.ResponseWriter, tmpl *template.Template, templateName string, data interface{}) error {
		assert.Equal(t, "signUp", templateName)
		if msgData, ok := data.(structs.MsgForUser); ok {
			assert.Equal(t, consts.MsgForUser["passwordInvalid"].Msg, msgData.Msg)
			assert.False(t, msgData.ShowCaptcha)
			assert.Equal(t, consts.MsgForUser["passwordInvalid"].Regs, msgData.Regs)
		} else {
			t.Errorf("Expected structs.MsgForUser, got %T", data)
		}
		return nil
	}

	form := url.Values{}
	form.Add("login", "testuser")
	form.Add("email", "test@example.com")
	form.Add("password", "weak")
	req := httptest.NewRequest("POST", "/sign-up", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	CheckInDbAndValidateSignUpUserInput(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestCheckInDbAndValidateSignUpUserInput_UserAlreadyExists проверяет обработку существующего пользователя.
// Ожидается: HTTP 200, сообщение о том, что пользователь уже существует.
func TestCheckInDbAndValidateSignUpUserInput_UserAlreadyExists(t *testing.T) {
	_, mock, teardown := setupSignUpTest(t)
	defer teardown()

	captcha.InitCaptchaState = func(w http.ResponseWriter, r *http.Request) (int64, bool, error) {
		return 3, false, nil
	}
	captcha.ShowCaptchaMsg = func(r *http.Request, showCaptcha bool) bool {
		return false
	}
	captcha.UpdateCaptchaState = func(w http.ResponseWriter, r *http.Request, captchaCounter int64, showCaptcha bool) error {
		return nil
	}
	data.GetPermanentIdFromDbByEmail = func(email string, isOAuth bool) (string, error) {
		return "permanent-123", nil
	}

	tmpls.TmplsRenderer = func(w http.ResponseWriter, tmpl *template.Template, templateName string, data interface{}) error {
		assert.Equal(t, "signUp", templateName)
		if msgData, ok := data.(structs.MsgForUser); ok {
			assert.Equal(t, consts.MsgForUser["userAlreadyExist"].Msg, msgData.Msg)
			assert.False(t, msgData.ShowCaptcha)
		} else {
			t.Errorf("Expected structs.MsgForUser, got %T", data)
		}
		return nil
	}

	form := url.Values{}
	form.Add("login", "testuser")
	form.Add("email", "existing@example.com")
	form.Add("password", "ValidPassword123!")
	req := httptest.NewRequest("POST", "/sign-up", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	CheckInDbAndValidateSignUpUserInput(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestCheckInDbAndValidateSignUpUserInput_CaptchaRequired проверяет требование капчи при ошибках.
// Ожидается: HTTP 200, сообщение о требовании капчи.
func TestCheckInDbAndValidateSignUpUserInput_CaptchaRequired(t *testing.T) {
	_, mock, teardown := setupSignUpTest(t)
	defer teardown()

	captcha.InitCaptchaState = func(w http.ResponseWriter, r *http.Request) (int64, bool, error) {
		return 0, true, nil
	}
	captcha.ShowCaptchaMsg = func(r *http.Request, showCaptcha bool) bool {
		return true
	}
	captcha.UpdateCaptchaState = func(w http.ResponseWriter, r *http.Request, captchaCounter int64, showCaptcha bool) error {
		return nil
	}
	data.GetPermanentIdFromDbByEmail = func(email string, isOAuth bool) (string, error) {
		return "", sql.ErrNoRows
	}
	tools.InputValidate = func(r *http.Request, login, email, password string, isSignIn bool) (string, error) {
		return "loginInvalid", errors.New("login invalid")
	}

	tmpls.TmplsRenderer = func(w http.ResponseWriter, tmpl *template.Template, templateName string, data interface{}) error {
		assert.Equal(t, "signUp", templateName)
		if msgData, ok := data.(structs.MsgForUser); ok {
			assert.Equal(t, consts.MsgForUser["captchaRequired"].Msg, msgData.Msg)
			assert.True(t, msgData.ShowCaptcha)
		} else {
			t.Errorf("Expected structs.MsgForUser, got %T", data)
		}
		return nil
	}

	form := url.Values{}
	form.Add("login", "ab")
	form.Add("email", "test@example.com")
	form.Add("password", "ValidPassword123!")
	req := httptest.NewRequest("POST", "/sign-up", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	CheckInDbAndValidateSignUpUserInput(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestCheckInDbAndValidateSignUpUserInput_CaptchaRequired_UserExists проверяет требование капчи при существующем пользователе.
// Ожидается: HTTP 200, сообщение о требовании капчи.
func TestCheckInDbAndValidateSignUpUserInput_CaptchaRequired_UserExists(t *testing.T) {
	_, mock, teardown := setupSignUpTest(t)
	defer teardown()

	captcha.InitCaptchaState = func(w http.ResponseWriter, r *http.Request) (int64, bool, error) {
		return 0, true, nil
	}
	captcha.ShowCaptchaMsg = func(r *http.Request, showCaptcha bool) bool {
		return true
	}
	captcha.UpdateCaptchaState = func(w http.ResponseWriter, r *http.Request, captchaCounter int64, showCaptcha bool) error {
		return nil
	}
	data.GetPermanentIdFromDbByEmail = func(email string, isOAuth bool) (string, error) {
		return "permanent-123", nil
	}

	tmpls.TmplsRenderer = func(w http.ResponseWriter, tmpl *template.Template, templateName string, data interface{}) error {
		assert.Equal(t, "signUp", templateName)
		if msgData, ok := data.(structs.MsgForUser); ok {
			assert.Equal(t, consts.MsgForUser["captchaRequired"].Msg, msgData.Msg)
			assert.True(t, msgData.ShowCaptcha)
		} else {
			t.Errorf("Expected structs.MsgForUser, got %T", data)
		}
		return nil
	}

	form := url.Values{}
	form.Add("login", "testuser")
	form.Add("email", "existing@example.com")
	form.Add("password", "ValidPassword123!")
	req := httptest.NewRequest("POST", "/sign-up", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	CheckInDbAndValidateSignUpUserInput(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestCheckInDbAndValidateSignUpUserInput_DatabaseError проверяет обработку ошибки базы данных.
// Ожидается: HTTP 302, редирект на 500.
func TestCheckInDbAndValidateSignUpUserInput_DatabaseError(t *testing.T) {
	_, mock, teardown := setupSignUpTest(t)
	defer teardown()

	captcha.InitCaptchaState = func(w http.ResponseWriter, r *http.Request) (int64, bool, error) {
		return 3, false, errors.New("database error")
	}

	form := url.Values{}
	form.Add("login", "testuser")
	form.Add("email", "test@example.com")
	form.Add("password", "ValidPassword123!")
	req := httptest.NewRequest("POST", "/sign-up", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	CheckInDbAndValidateSignUpUserInput(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, consts.Err500URL, w.Header().Get("Location"))
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestCheckInDbAndValidateSignUpUserInput_SessionError проверяет обработку ошибки сессии.
// Ожидается: HTTP 302, редирект на 500.
func TestCheckInDbAndValidateSignUpUserInput_SessionError(t *testing.T) {
	_, mock, teardown := setupSignUpTest(t)
	defer teardown()

	captcha.InitCaptchaState = func(w http.ResponseWriter, r *http.Request) (int64, bool, error) {
		return 3, false, nil
	}
	captcha.ShowCaptchaMsg = func(r *http.Request, showCaptcha bool) bool {
		return false
	}
	data.GetPermanentIdFromDbByEmail = func(email string, isOAuth bool) (string, error) {
		return "", sql.ErrNoRows
	}
	tools.InputValidate = func(r *http.Request, login, email, password string, isSignIn bool) (string, error) {
		return "", nil
	}
	data.SetAuthDataInSession = func(w http.ResponseWriter, r *http.Request, consts any) error {
		return errors.New("session error")
	}

	form := url.Values{}
	form.Add("login", "testuser")
	form.Add("email", "test@example.com")
	form.Add("password", "ValidPassword123!")
	req := httptest.NewRequest("POST", "/sign-up", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	CheckInDbAndValidateSignUpUserInput(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, consts.Err500URL, w.Header().Get("Location"))
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestServerAuthCodeSend_Success проверяет успешную отправку кода аутентификации.
// Ожидается: HTTP 302, редирект на страницу ввода кода.
func TestServerAuthCodeSend_Success(t *testing.T) {
	_, mock, teardown := setupSignUpTest(t)
	defer teardown()

	data.GetAuthDataFromSession = func(r *http.Request) (structs.User, error) {
		return structs.User{Email: "test@example.com"}, nil
	}
	tools.ServerAuthCodeSend = func(email string) (string, error) {
		return "123456", nil
	}
	data.SetAuthDataInSession = func(w http.ResponseWriter, r *http.Request, consts any) error {
		return nil
	}

	req := httptest.NewRequest("GET", "/server-auth-code-send", nil)
	w := httptest.NewRecorder()

	ServerAuthCodeSend(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, consts.ServerAuthCodeSendURL, w.Header().Get("Location"))
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestServerAuthCodeSend_SessionError проверяет обработку ошибки сессии при отправке кода.
// Ожидается: HTTP 302, редирект на 500.
func TestServerAuthCodeSend_SessionError(t *testing.T) {
	_, mock, teardown := setupSignUpTest(t)
	defer teardown()

	data.GetAuthDataFromSession = func(r *http.Request) (structs.User, error) {
		return structs.User{}, errors.New("session error")
	}

	req := httptest.NewRequest("GET", "/server-auth-code-send", nil)
	w := httptest.NewRecorder()

	ServerAuthCodeSend(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, consts.Err500URL, w.Header().Get("Location"))
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestServerAuthCodeSend_EmailError проверяет обработку ошибки отправки email.
// Ожидается: HTTP 302, редирект на 500.
func TestServerAuthCodeSend_EmailError(t *testing.T) {
	_, mock, teardown := setupSignUpTest(t)
	defer teardown()

	data.GetAuthDataFromSession = func(r *http.Request) (structs.User, error) {
		return structs.User{Email: "test@example.com"}, nil
	}
	tools.ServerAuthCodeSend = func(email string) (string, error) {
		return "", errors.New("email send error")
	}

	req := httptest.NewRequest("GET", "/server-auth-code-send", nil)
	w := httptest.NewRecorder()

	ServerAuthCodeSend(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, consts.Err500URL, w.Header().Get("Location"))
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestCodeValidate_Success проверяет успешную валидацию кода.
// Ожидается: HTTP 302, редирект на домашнюю страницу.
func TestCodeValidate_Success(t *testing.T) {
	_, mock, teardown := setupSignUpTest(t)
	defer teardown()

	data.GetAuthDataFromSession = func(r *http.Request) (structs.User, error) {
		return structs.User{ServerCode: "123456"}, nil
	}
	data.GetCaptchaCounterFromSession = func(r *http.Request) (int64, error) {
		return 3, nil
	}
	data.GetShowCaptchaFromSession = func(r *http.Request) (bool, error) {
		return false, nil
	}
	tools.CodeValidate = func(r *http.Request, clientCode, serverCode string) error {
		return nil
	}
	data.SetTemporaryIdInCookies = func(w http.ResponseWriter, value string, temporaryIdExp int, rememberMe bool) {
	}
	data.SetTemporaryIdInDbTx = func(tx *sql.Tx, permanentId, temporaryId, userAgent string, isOAuth bool) error {
		return nil
	}
	tools.GenerateRefreshToken = func(refreshTokenExp int, rememberMe bool) (string, error) {
		return "refresh-token-123", nil
	}
	data.SetRefreshTokenInDbTx = func(tx *sql.Tx, permanentId, refreshToken, userAgent string, isOAuth bool) error {
		return nil
	}
	tools.SendNewDeviceLoginEmail = func(login, email, userAgent string) error {
		return nil
	}
	data.EndAuthAndCaptchaSessions = func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}

	mock.ExpectBegin()
	mock.ExpectExec("update login set cancelled = true").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("insert into login").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("update email set cancelled = true").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("insert into email").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("update password_hash set cancelled = true").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("insert into password_hash").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	form := url.Values{}
	form.Add("clientCode", "123456")
	req := httptest.NewRequest("POST", "/code-validate", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "test-user-agent")
	w := httptest.NewRecorder()

	CodeValidate(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, consts.HomeURL, w.Header().Get("Location"))
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestCodeValidate_EmptyCode проверяет обработку пустого кода.
// Ожидается: HTTP 302, редирект на 500.
func TestCodeValidate_EmptyCode(t *testing.T) {
	_, mock, teardown := setupSignUpTest(t)
	defer teardown()

	data.GetAuthDataFromSession = func(r *http.Request) (structs.User, error) {
		return structs.User{ServerCode: "123456"}, nil
	}
	data.GetCaptchaCounterFromSession = func(r *http.Request) (int64, error) {
		return 3, nil
	}
	data.GetShowCaptchaFromSession = func(r *http.Request) (bool, error) {
		return false, nil
	}

	form := url.Values{}
	form.Add("clientCode", "")
	req := httptest.NewRequest("POST", "/code-validate", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	CodeValidate(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, consts.Err500URL, w.Header().Get("Location"))
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestCodeValidate_WrongCode проверяет обработку неверного кода.
// Ожидается: HTTP 200, сообщение о неверном коде.
func TestCodeValidate_WrongCode(t *testing.T) {
	_, mock, teardown := setupSignUpTest(t)
	defer teardown()

	data.GetAuthDataFromSession = func(r *http.Request) (structs.User, error) {
		return structs.User{ServerCode: "123456"}, nil
	}
	data.GetCaptchaCounterFromSession = func(r *http.Request) (int64, error) {
		return 3, nil
	}
	data.GetShowCaptchaFromSession = func(r *http.Request) (bool, error) {
		return false, nil
	}
	tools.CodeValidate = func(r *http.Request, clientCode, serverCode string) error {
		return errors.New("wrong code")
	}
	captcha.UpdateCaptchaState = func(w http.ResponseWriter, r *http.Request, captchaCounter int64, showCaptcha bool) error {
		return nil
	}

	tmpls.TmplsRenderer = func(w http.ResponseWriter, tmpl *template.Template, templateName string, data interface{}) error {
		assert.Equal(t, "serverAuthCodeSend", templateName)
		if msgData, ok := data.(structs.MsgForUser); ok {
			assert.Equal(t, consts.MsgForUser["wrongCode"].Msg, msgData.Msg)
			assert.False(t, msgData.ShowCaptcha)
		} else {
			t.Errorf("Expected structs.MsgForUser, got %T", data)
		}
		return nil
	}

	form := url.Values{}
	form.Add("clientCode", "000000")
	req := httptest.NewRequest("POST", "/code-validate", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	CodeValidate(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestCodeValidate_CaptchaRequired проверяет требование капчи при неверном коде.
// Ожидается: HTTP 200, сообщение о требовании капчи.
func TestCodeValidate_CaptchaRequired(t *testing.T) {
	_, mock, teardown := setupSignUpTest(t)
	defer teardown()

	data.GetAuthDataFromSession = func(r *http.Request) (structs.User, error) {
		return structs.User{ServerCode: "123456"}, nil
	}
	data.GetCaptchaCounterFromSession = func(r *http.Request) (int64, error) {
		return 0, nil
	}
	data.GetShowCaptchaFromSession = func(r *http.Request) (bool, error) {
		return true, nil
	}
	captcha.ShowCaptchaMsg = func(r *http.Request, showCaptcha bool) bool {
		return true
	}
	tools.CodeValidate = func(r *http.Request, clientCode, serverCode string) error {
		return errors.New("wrong code")
	}
	captcha.UpdateCaptchaState = func(w http.ResponseWriter, r *http.Request, captchaCounter int64, showCaptcha bool) error {
		return nil
	}

	tmpls.TmplsRenderer = func(w http.ResponseWriter, tmpl *template.Template, templateName string, data interface{}) error {
		assert.Equal(t, "serverAuthCodeSend", templateName)
		if msgData, ok := data.(structs.MsgForUser); ok {
			assert.Equal(t, consts.MsgForUser["captchaRequired"].Msg, msgData.Msg)
			assert.True(t, msgData.ShowCaptcha)
		} else {
			t.Errorf("Expected structs.MsgForUser, got %T", data)
		}
		return nil
	}

	form := url.Values{}
	form.Add("clientCode", "000000")
	req := httptest.NewRequest("POST", "/code-validate", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	CodeValidate(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestCodeValidate_SessionError проверяет обработку ошибки сессии при валидации кода.
// Ожидается: HTTP 302, редирект на 500.
func TestCodeValidate_SessionError(t *testing.T) {
	_, mock, teardown := setupSignUpTest(t)
	defer teardown()

	data.GetAuthDataFromSession = func(r *http.Request) (structs.User, error) {
		return structs.User{}, errors.New("session error")
	}

	form := url.Values{}
	form.Add("clientCode", "123456")
	req := httptest.NewRequest("POST", "/code-validate", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	CodeValidate(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, consts.Err500URL, w.Header().Get("Location"))
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestSetUserInDb_Success проверяет успешное сохранение пользователя в базе данных.
// Ожидается: HTTP 302, редирект на домашнюю страницу.
func TestSetUserInDb_Success(t *testing.T) {
	_, mock, teardown := setupSignUpTest(t)
	defer teardown()

	data.GetAuthDataFromSession = func(r *http.Request) (structs.User, error) {
		return structs.User{
			Login:    "testuser",
			Email:    "test@example.com",
			Password: "hashedpassword",
		}, nil
	}
	data.SetTemporaryIdInCookies = func(w http.ResponseWriter, value string, temporaryIdExp int, rememberMe bool) {
	}
	data.SetTemporaryIdInDbTx = func(tx *sql.Tx, permanentId, temporaryId, userAgent string, isOAuth bool) error {
		return nil
	}
	tools.GenerateRefreshToken = func(refreshTokenExp int, rememberMe bool) (string, error) {
		return "refresh-token-123", nil
	}
	data.SetRefreshTokenInDbTx = func(tx *sql.Tx, permanentId, refreshToken, userAgent string, isOAuth bool) error {
		return nil
	}
	tools.SendNewDeviceLoginEmail = func(login, email, userAgent string) error {
		return nil
	}
	data.EndAuthAndCaptchaSessions = func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}

	mock.ExpectBegin()
	mock.ExpectExec("update login set cancelled = true").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("insert into login").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("update email set cancelled = true").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("insert into email").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("update password_hash set cancelled = true").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("insert into password_hash").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	form := url.Values{}
	req := httptest.NewRequest("POST", "/set-user", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "test-user-agent")
	w := httptest.NewRecorder()

	SetUserInDb(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, consts.HomeURL, w.Header().Get("Location"))
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestSetUserInDb_WithRememberMe проверяет успешное сохранение пользователя с опцией "Запомнить меня".
// Ожидается: HTTP 302, редирект на домашнюю страницу.
func TestSetUserInDb_WithRememberMe(t *testing.T) {
	_, mock, teardown := setupSignUpTest(t)
	defer teardown()

	data.GetAuthDataFromSession = func(r *http.Request) (structs.User, error) {
		return structs.User{
			Login:    "testuser",
			Email:    "test@example.com",
			Password: "hashedpassword",
		}, nil
	}
	data.SetTemporaryIdInCookies = func(w http.ResponseWriter, value string, temporaryIdExp int, rememberMe bool) {
	}
	data.SetTemporaryIdInDbTx = func(tx *sql.Tx, permanentId, temporaryId, userAgent string, isOAuth bool) error {
		return nil
	}
	tools.GenerateRefreshToken = func(refreshTokenExp int, rememberMe bool) (string, error) {
		return "refresh-token-123", nil
	}
	data.SetRefreshTokenInDbTx = func(tx *sql.Tx, permanentId, refreshToken, userAgent string, isOAuth bool) error {
		return nil
	}
	tools.SendNewDeviceLoginEmail = func(login, email, userAgent string) error {
		return nil
	}
	data.EndAuthAndCaptchaSessions = func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}

	mock.ExpectBegin()
	mock.ExpectExec("update login set cancelled = true").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("insert into login").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("update email set cancelled = true").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("insert into email").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("update password_hash set cancelled = true").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("insert into password_hash").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	form := url.Values{}
	form.Add("rememberMe", "on")
	req := httptest.NewRequest("POST", "/set-user", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "test-user-agent")
	w := httptest.NewRecorder()

	SetUserInDb(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, consts.HomeURL, w.Header().Get("Location"))
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestSetUserInDb_SessionError проверяет обработку ошибки сессии при сохранении пользователя.
// Ожидается: HTTP 302, редирект на 500.
func TestSetUserInDb_SessionError(t *testing.T) {
	_, mock, teardown := setupSignUpTest(t)
	defer teardown()

	data.GetAuthDataFromSession = func(r *http.Request) (structs.User, error) {
		return structs.User{}, errors.New("session error")
	}

	form := url.Values{}
	req := httptest.NewRequest("POST", "/set-user", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	SetUserInDb(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, consts.Err500URL, w.Header().Get("Location"))
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestSetUserInDb_TransactionError проверяет обработку ошибки транзакции.
// Ожидается: HTTP 302, редирект на 500.
func TestSetUserInDb_TransactionError(t *testing.T) {
	_, mock, teardown := setupSignUpTest(t)
	defer teardown()

	data.GetAuthDataFromSession = func(r *http.Request) (structs.User, error) {
		return structs.User{
			Login:    "testuser",
			Email:    "test@example.com",
			Password: "hashedpassword",
		}, nil
	}

	mock.ExpectBegin().WillReturnError(errors.New("transaction error"))

	form := url.Values{}
	req := httptest.NewRequest("POST", "/set-user", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	SetUserInDb(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, consts.Err500URL, w.Header().Get("Location"))
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestSetUserInDb_LoginError проверяет обработку ошибки при сохранении логина.
// Ожидается: HTTP 302, редирект на 500.
func TestSetUserInDb_LoginError(t *testing.T) {
	_, mock, teardown := setupSignUpTest(t)
	defer teardown()

	data.GetAuthDataFromSession = func(r *http.Request) (structs.User, error) {
		return structs.User{
			Login:    "testuser",
			Email:    "test@example.com",
			Password: "hashedpassword",
		}, nil
	}

	mock.ExpectBegin()
	mock.ExpectExec("update login set cancelled = true").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("insert into login").WillReturnError(errors.New("login error"))
	mock.ExpectRollback()

	form := url.Values{}
	req := httptest.NewRequest("POST", "/set-user", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	SetUserInDb(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, consts.Err500URL, w.Header().Get("Location"))
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestSetUserInDb_EmailError проверяет обработку ошибки при сохранении email.
// Ожидается: HTTP 302, редирект на 500.
func TestSetUserInDb_EmailError(t *testing.T) {
	_, mock, teardown := setupSignUpTest(t)
	defer teardown()

	data.GetAuthDataFromSession = func(r *http.Request) (structs.User, error) {
		return structs.User{
			Login:    "testuser",
			Email:    "test@example.com",
			Password: "hashedpassword",
		}, nil
	}

	mock.ExpectBegin()
	mock.ExpectExec("update login set cancelled = true").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("insert into login").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("update email set cancelled = true").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("insert into email").WillReturnError(errors.New("email error"))
	mock.ExpectRollback()

	form := url.Values{}
	req := httptest.NewRequest("POST", "/set-user", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	SetUserInDb(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, consts.Err500URL, w.Header().Get("Location"))
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestSetUserInDb_PasswordError проверяет обработку ошибки при сохранении пароля.
// Ожидается: HTTP 302, редирект на 500.
func TestSetUserInDb_PasswordError(t *testing.T) {
	_, mock, teardown := setupSignUpTest(t)
	defer teardown()

	data.GetAuthDataFromSession = func(r *http.Request) (structs.User, error) {
		return structs.User{
			Login:    "testuser",
			Email:    "test@example.com",
			Password: "hashedpassword",
		}, nil
	}

	mock.ExpectBegin()
	mock.ExpectExec("update login set cancelled = true").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("insert into login").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("update email set cancelled = true").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("insert into email").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("update password_hash set cancelled = true").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("insert into password_hash").WillReturnError(errors.New("password error"))
	mock.ExpectRollback()

	form := url.Values{}
	req := httptest.NewRequest("POST", "/set-user", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	SetUserInDb(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, consts.Err500URL, w.Header().Get("Location"))
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestSetUserInDb_TemporaryIdError проверяет обработку ошибки при сохранении временного ID.
// Ожидается: HTTP 302, редирект на 500.
func TestSetUserInDb_TemporaryIdError(t *testing.T) {
	_, mock, teardown := setupSignUpTest(t)
	defer teardown()

	data.GetAuthDataFromSession = func(r *http.Request) (structs.User, error) {
		return structs.User{
			Login:    "testuser",
			Email:    "test@example.com",
			Password: "hashedpassword",
		}, nil
	}
	data.SetTemporaryIdInCookies = func(w http.ResponseWriter, value string, temporaryIdExp int, rememberMe bool) {
	}
	data.SetTemporaryIdInDbTx = func(tx *sql.Tx, permanentId, temporaryId, userAgent string, isOAuth bool) error {
		return errors.New("temporary id error")
	}

	mock.ExpectBegin()
	mock.ExpectExec("update login set cancelled = true").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("insert into login").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("update email set cancelled = true").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("insert into email").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("update password_hash set cancelled = true").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("insert into password_hash").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectRollback()

	form := url.Values{}
	req := httptest.NewRequest("POST", "/set-user", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "test-user-agent")
	w := httptest.NewRecorder()

	SetUserInDb(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, consts.Err500URL, w.Header().Get("Location"))
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestSetUserInDb_RefreshTokenError проверяет обработку ошибки при генерации refresh токена.
// Ожидается: HTTP 302, редирект на 500.
func TestSetUserInDb_RefreshTokenError(t *testing.T) {
	_, mock, teardown := setupSignUpTest(t)
	defer teardown()

	data.GetAuthDataFromSession = func(r *http.Request) (structs.User, error) {
		return structs.User{
			Login:    "testuser",
			Email:    "test@example.com",
			Password: "hashedpassword",
		}, nil
	}
	data.SetTemporaryIdInCookies = func(w http.ResponseWriter, value string, temporaryIdExp int, rememberMe bool) {
	}
	data.SetTemporaryIdInDbTx = func(tx *sql.Tx, permanentId, temporaryId, userAgent string, isOAuth bool) error {
		return nil
	}
	tools.GenerateRefreshToken = func(refreshTokenExp int, rememberMe bool) (string, error) {
		return "", errors.New("refresh token error")
	}

	mock.ExpectBegin()
	mock.ExpectExec("update login set cancelled = true").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("insert into login").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("update email set cancelled = true").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("insert into email").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("update password_hash set cancelled = true").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("insert into password_hash").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectRollback()

	form := url.Values{}
	req := httptest.NewRequest("POST", "/set-user", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "test-user-agent")
	w := httptest.NewRecorder()

	SetUserInDb(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, consts.Err500URL, w.Header().Get("Location"))
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestSetUserInDb_RefreshTokenDbError проверяет обработку ошибки при сохранении refresh токена в БД.
// Ожидается: HTTP 302, редирект на 500.
func TestSetUserInDb_RefreshTokenDbError(t *testing.T) {
	_, mock, teardown := setupSignUpTest(t)
	defer teardown()

	data.GetAuthDataFromSession = func(r *http.Request) (structs.User, error) {
		return structs.User{
			Login:    "testuser",
			Email:    "test@example.com",
			Password: "hashedpassword",
		}, nil
	}
	data.SetTemporaryIdInCookies = func(w http.ResponseWriter, value string, temporaryIdExp int, rememberMe bool) {
	}
	data.SetTemporaryIdInDbTx = func(tx *sql.Tx, permanentId, temporaryId, userAgent string, isOAuth bool) error {
		return nil
	}
	tools.GenerateRefreshToken = func(refreshTokenExp int, rememberMe bool) (string, error) {
		return "refresh-token-123", nil
	}
	data.SetRefreshTokenInDbTx = func(tx *sql.Tx, permanentId, refreshToken, userAgent string, isOAuth bool) error {
		return errors.New("refresh token db error")
	}

	mock.ExpectBegin()
	mock.ExpectExec("update login set cancelled = true").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("insert into login").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("update email set cancelled = true").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("insert into email").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("update password_hash set cancelled = true").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("insert into password_hash").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectRollback()

	form := url.Values{}
	req := httptest.NewRequest("POST", "/set-user", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "test-user-agent")
	w := httptest.NewRecorder()

	SetUserInDb(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, consts.Err500URL, w.Header().Get("Location"))
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestSetUserInDb_CommitError проверяет обработку ошибки при коммите транзакции.
// Ожидается: HTTP 302, редирект на 500.
func TestSetUserInDb_CommitError(t *testing.T) {
	_, mock, teardown := setupSignUpTest(t)
	defer teardown()

	data.GetAuthDataFromSession = func(r *http.Request) (structs.User, error) {
		return structs.User{
			Login:    "testuser",
			Email:    "test@example.com",
			Password: "hashedpassword",
		}, nil
	}
	data.SetTemporaryIdInCookies = func(w http.ResponseWriter, value string, temporaryIdExp int, rememberMe bool) {
	}
	data.SetTemporaryIdInDbTx = func(tx *sql.Tx, permanentId, temporaryId, userAgent string, isOAuth bool) error {
		return nil
	}
	tools.GenerateRefreshToken = func(refreshTokenExp int, rememberMe bool) (string, error) {
		return "refresh-token-123", nil
	}
	data.SetRefreshTokenInDbTx = func(tx *sql.Tx, permanentId, refreshToken, userAgent string, isOAuth bool) error {
		return nil
	}

	mock.ExpectBegin()
	mock.ExpectExec("update login set cancelled = true").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("insert into login").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("update email set cancelled = true").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("insert into email").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("update password_hash set cancelled = true").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("insert into password_hash").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit().WillReturnError(errors.New("commit error"))

	form := url.Values{}
	req := httptest.NewRequest("POST", "/set-user", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "test-user-agent")
	w := httptest.NewRecorder()

	SetUserInDb(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, consts.Err500URL, w.Header().Get("Location"))
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestSetUserInDb_EmailNotificationError проверяет обработку ошибки при отправке email уведомления.
// Ожидается: HTTP 302, редирект на 500.
func TestSetUserInDb_EmailNotificationError(t *testing.T) {
	_, mock, teardown := setupSignUpTest(t)
	defer teardown()

	data.GetAuthDataFromSession = func(r *http.Request) (structs.User, error) {
		return structs.User{
			Login:    "testuser",
			Email:    "test@example.com",
			Password: "hashedpassword",
		}, nil
	}
	data.SetTemporaryIdInCookies = func(w http.ResponseWriter, value string, temporaryIdExp int, rememberMe bool) {
	}
	data.SetTemporaryIdInDbTx = func(tx *sql.Tx, permanentId, temporaryId, userAgent string, isOAuth bool) error {
		return nil
	}
	tools.GenerateRefreshToken = func(refreshTokenExp int, rememberMe bool) (string, error) {
		return "refresh-token-123", nil
	}
	data.SetRefreshTokenInDbTx = func(tx *sql.Tx, permanentId, refreshToken, userAgent string, isOAuth bool) error {
		return nil
	}
	tools.SendNewDeviceLoginEmail = func(login, email, userAgent string) error {
		return errors.New("email notification error")
	}
	data.EndAuthAndCaptchaSessions = func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}

	mock.ExpectBegin()
	mock.ExpectExec("update login set cancelled = true").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("insert into login").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("update email set cancelled = true").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("insert into email").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("update password_hash set cancelled = true").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("insert into password_hash").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	form := url.Values{}
	req := httptest.NewRequest("POST", "/set-user", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "test-user-agent")
	w := httptest.NewRecorder()

	SetUserInDb(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, consts.Err500URL, w.Header().Get("Location"))
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestSetUserInDb_EndSessionError проверяет обработку ошибки при завершении сессии.
// Ожидается: HTTP 302, редирект на 500.
func TestSetUserInDb_EndSessionError(t *testing.T) {
	_, mock, teardown := setupSignUpTest(t)
	defer teardown()

	data.GetAuthDataFromSession = func(r *http.Request) (structs.User, error) {
		return structs.User{
			Login:    "testuser",
			Email:    "test@example.com",
			Password: "hashedpassword",
		}, nil
	}
	data.SetTemporaryIdInCookies = func(w http.ResponseWriter, value string, temporaryIdExp int, rememberMe bool) {
	}
	data.SetTemporaryIdInDbTx = func(tx *sql.Tx, permanentId, temporaryId, userAgent string, isOAuth bool) error {
		return nil
	}
	tools.GenerateRefreshToken = func(refreshTokenExp int, rememberMe bool) (string, error) {
		return "refresh-token-123", nil
	}
	data.SetRefreshTokenInDbTx = func(tx *sql.Tx, permanentId, refreshToken, userAgent string, isOAuth bool) error {
		return nil
	}
	tools.SendNewDeviceLoginEmail = func(login, email, userAgent string) error {
		return nil
	}
	data.EndAuthAndCaptchaSessions = func(w http.ResponseWriter, r *http.Request) error {
		return errors.New("end session error")
	}

	mock.ExpectBegin()
	mock.ExpectExec("update login set cancelled = true").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("insert into login").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("update email set cancelled = true").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("insert into email").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("update password_hash set cancelled = true").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("insert into password_hash").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	form := url.Values{}
	req := httptest.NewRequest("POST", "/set-user", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "test-user-agent")
	w := httptest.NewRecorder()

	SetUserInDb(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, consts.Err500URL, w.Header().Get("Location"))
	assert.NoError(t, mock.ExpectationsWereMet())
}
