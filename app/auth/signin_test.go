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

func setupSignInTest(t *testing.T) (*sql.DB, sqlmock.Sqlmock, func()) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)

	oldDB := data.Db
	oldTmplsRenderer := tmpls.TmplsRenderer
	oldInitCaptchaState := captcha.InitCaptchaState
	oldShowCaptchaMsg := captcha.ShowCaptchaMsg
	oldUpdateCaptchaState := captcha.UpdateCaptchaState
	oldInputValidate := tools.InputValidate
	oldGetPermanentIdFromDbByLogin := data.GetPermanentIdFromDbByLogin
	oldIsOKPasswordHashInDb := data.IsOKPasswordHashInDb
	oldSetTemporaryIdInCookies := data.SetTemporaryIdInCookies
	oldSetTemporaryIdInDbTx := data.SetTemporaryIdInDbTx
	oldGenerateRefreshToken := tools.GenerateRefreshToken
	oldSetRefreshTokenInDbTx := data.SetRefreshTokenInDbTx
	oldGetUniqueUserAgentsFromDb := data.GetUniqueUserAgentsFromDb
	oldEndAuthAndCaptchaSessions := data.EndAuthAndCaptchaSessions
	oldSendNewDeviceLoginEmail := tools.SendNewDeviceLoginEmail

	data.Db = db

	return db, mock, func() {
		data.Db = oldDB
		db.Close()
		tmpls.TmplsRenderer = oldTmplsRenderer
		captcha.InitCaptchaState = oldInitCaptchaState
		captcha.ShowCaptchaMsg = oldShowCaptchaMsg
		captcha.UpdateCaptchaState = oldUpdateCaptchaState
		tools.InputValidate = oldInputValidate
		data.GetPermanentIdFromDbByLogin = oldGetPermanentIdFromDbByLogin
		data.IsOKPasswordHashInDb = oldIsOKPasswordHashInDb
		data.SetTemporaryIdInCookies = oldSetTemporaryIdInCookies
		data.SetTemporaryIdInDbTx = oldSetTemporaryIdInDbTx
		tools.GenerateRefreshToken = oldGenerateRefreshToken
		data.SetRefreshTokenInDbTx = oldSetRefreshTokenInDbTx
		data.GetUniqueUserAgentsFromDb = oldGetUniqueUserAgentsFromDb
		data.EndAuthAndCaptchaSessions = oldEndAuthAndCaptchaSessions
		tools.SendNewDeviceLoginEmail = oldSendNewDeviceLoginEmail
	}
}

func TestCheckInDbAndValidateSignInUserInput_Success(t *testing.T) {
	_, mock, teardown := setupSignInTest(t)
	defer teardown()

	captcha.InitCaptchaState = func(w http.ResponseWriter, r *http.Request) (int64, bool, error) {
		return 3, false, nil
	}
	captcha.ShowCaptchaMsg = func(r *http.Request, showCaptcha bool) bool {
		return false
	}
	tools.InputValidate = func(r *http.Request, login, email, password string, isSignIn bool) (string, error) {
		return "", nil
	}
	data.GetPermanentIdFromDbByLogin = func(login string) (string, error) {
		return "permanent-123", nil
	}
	data.IsOKPasswordHashInDb = func(permanentId, password string) error {
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
	data.GetUniqueUserAgentsFromDb = func(permanentId string) ([]string, error) {
		return []string{"test-user-agent"}, nil
	}
	data.EndAuthAndCaptchaSessions = func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}

	mock.ExpectBegin()
	mock.ExpectCommit()

	form := url.Values{}
	form.Add("login", "testuser")
	form.Add("password", "ValidPassword123!")
	req := httptest.NewRequest("POST", "/sign-in", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "test-user-agent")
	w := httptest.NewRecorder()

	CheckInDbAndValidateSignInUserInput(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, consts.HomeURL, w.Header().Get("Location"))
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCheckInDbAndValidateSignInUserInput_EmptyLogin(t *testing.T) {
	_, mock, teardown := setupSignInTest(t)
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
	tools.InputValidate = func(r *http.Request, login, email, password string, isSignIn bool) (string, error) {
		return "loginInvalid", errors.New("login invalid")
	}

	tmpls.TmplsRenderer = func(w http.ResponseWriter, tmpl *template.Template, templateName string, data interface{}) error {
		assert.Equal(t, "signIn", templateName)
		if msgData, ok := data.(structs.MsgForUser); ok {
			assert.Equal(t, consts.MsgForUser["loginInvalid"].Msg, msgData.Msg)
			assert.False(t, msgData.ShowCaptcha)
		} else {
			t.Errorf("Expected structs.MsgForUser, got %T", data)
		}
		return nil
	}

	form := url.Values{}
	form.Add("login", "")
	form.Add("password", "ValidPassword123!")
	req := httptest.NewRequest("POST", "/sign-in", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	CheckInDbAndValidateSignInUserInput(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCheckInDbAndValidateSignInUserInput_EmptyPassword(t *testing.T) {
	_, mock, teardown := setupSignInTest(t)
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
	tools.InputValidate = func(r *http.Request, login, email, password string, isSignIn bool) (string, error) {
		return "passwordInvalid", errors.New("password invalid")
	}

	tmpls.TmplsRenderer = func(w http.ResponseWriter, tmpl *template.Template, templateName string, data interface{}) error {
		assert.Equal(t, "signIn", templateName)
		if msgData, ok := data.(structs.MsgForUser); ok {
			assert.Equal(t, consts.MsgForUser["passwordInvalid"].Msg, msgData.Msg)
			assert.False(t, msgData.ShowCaptcha)
			assert.False(t, msgData.ShowForgotPassword)
		} else {
			t.Errorf("Expected structs.MsgForUser, got %T", data)
		}
		return nil
	}

	form := url.Values{}
	form.Add("login", "testuser")
	form.Add("password", "")
	req := httptest.NewRequest("POST", "/sign-in", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	CheckInDbAndValidateSignInUserInput(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCheckInDbAndValidateSignInUserInput_UserNotFound(t *testing.T) {
	_, mock, teardown := setupSignInTest(t)
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
	tools.InputValidate = func(r *http.Request, login, email, password string, isSignIn bool) (string, error) {
		return "", nil
	}
	data.GetPermanentIdFromDbByLogin = func(login string) (string, error) {
		return "", sql.ErrNoRows
	}

	tmpls.TmplsRenderer = func(w http.ResponseWriter, tmpl *template.Template, templateName string, data interface{}) error {
		assert.Equal(t, "signIn", templateName)
		if msgData, ok := data.(structs.MsgForUser); ok {
			assert.Equal(t, consts.MsgForUser["userNotExist"].Msg, msgData.Msg)
			assert.False(t, msgData.ShowCaptcha)
		} else {
			t.Errorf("Expected structs.MsgForUser, got %T", data)
		}
		return nil
	}

	form := url.Values{}
	form.Add("login", "nonexistentuser")
	form.Add("password", "ValidPassword123!")
	req := httptest.NewRequest("POST", "/sign-in", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	CheckInDbAndValidateSignInUserInput(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCheckInDbAndValidateSignInUserInput_InvalidPassword(t *testing.T) {
	_, mock, teardown := setupSignInTest(t)
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
	tools.InputValidate = func(r *http.Request, login, email, password string, isSignIn bool) (string, error) {
		return "", nil
	}
	data.GetPermanentIdFromDbByLogin = func(login string) (string, error) {
		return "permanent-123", nil
	}
	data.IsOKPasswordHashInDb = func(permanentId, password string) error {
		return errors.New("password invalid")
	}

	tmpls.TmplsRenderer = func(w http.ResponseWriter, tmpl *template.Template, templateName string, data interface{}) error {
		assert.Equal(t, "signIn", templateName)
		if msgData, ok := data.(structs.MsgForUser); ok {
			assert.Equal(t, consts.MsgForUser["passwordInvalid"].Msg, msgData.Msg)
			assert.False(t, msgData.ShowCaptcha)
			assert.True(t, msgData.ShowForgotPassword)
		} else {
			t.Errorf("Expected structs.MsgForUser, got %T", data)
		}
		return nil
	}

	form := url.Values{}
	form.Add("login", "testuser")
	form.Add("password", "WrongPassword123!")
	req := httptest.NewRequest("POST", "/sign-in", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	CheckInDbAndValidateSignInUserInput(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCheckInDbAndValidateSignInUserInput_CaptchaRequired(t *testing.T) {
	_, mock, teardown := setupSignInTest(t)
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
	tools.InputValidate = func(r *http.Request, login, email, password string, isSignIn bool) (string, error) {
		return "loginInvalid", errors.New("login invalid")
	}

	tmpls.TmplsRenderer = func(w http.ResponseWriter, tmpl *template.Template, templateName string, data interface{}) error {
		assert.Equal(t, "signIn", templateName)
		if msgData, ok := data.(structs.MsgForUser); ok {
			assert.Equal(t, consts.MsgForUser["captchaRequired"].Msg, msgData.Msg)
			assert.True(t, msgData.ShowCaptcha)
		} else {
			t.Errorf("Expected structs.MsgForUser, got %T", data)
		}
		return nil
	}

	form := url.Values{}
	form.Add("login", "")
	form.Add("password", "ValidPassword123!")
	req := httptest.NewRequest("POST", "/sign-in", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	CheckInDbAndValidateSignInUserInput(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCheckInDbAndValidateSignInUserInput_NewDeviceNotification(t *testing.T) {
	_, mock, teardown := setupSignInTest(t)
	defer teardown()

	captcha.InitCaptchaState = func(w http.ResponseWriter, r *http.Request) (int64, bool, error) {
		return 3, false, nil
	}
	captcha.ShowCaptchaMsg = func(r *http.Request, showCaptcha bool) bool {
		return false
	}
	tools.InputValidate = func(r *http.Request, login, email, password string, isSignIn bool) (string, error) {
		return "", nil
	}
	data.GetPermanentIdFromDbByLogin = func(login string) (string, error) {
		return "permanent-123", nil
	}
	data.IsOKPasswordHashInDb = func(permanentId, password string) error {
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
	data.GetUniqueUserAgentsFromDb = func(permanentId string) ([]string, error) {
		return []string{"old-user-agent"}, nil
	}
	tools.SendNewDeviceLoginEmail = func(login, email, userAgent string) error {
		return nil
	}
	data.EndAuthAndCaptchaSessions = func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}

	mock.ExpectBegin()
	mock.ExpectCommit()

	form := url.Values{}
	form.Add("login", "testuser")
	form.Add("password", "ValidPassword123!")
	req := httptest.NewRequest("POST", "/sign-in", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "new-user-agent")
	w := httptest.NewRecorder()

	CheckInDbAndValidateSignInUserInput(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, consts.HomeURL, w.Header().Get("Location"))
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCheckInDbAndValidateSignInUserInput_DatabaseError(t *testing.T) {
	_, mock, teardown := setupSignInTest(t)
	defer teardown()

	captcha.InitCaptchaState = func(w http.ResponseWriter, r *http.Request) (int64, bool, error) {
		return 3, false, errors.New("database error")
	}

	form := url.Values{}
	form.Add("login", "testuser")
	form.Add("password", "ValidPassword123!")
	req := httptest.NewRequest("POST", "/sign-in", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	CheckInDbAndValidateSignInUserInput(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, consts.Err500URL, w.Header().Get("Location"))
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCheckInDbAndValidateSignInUserInput_TransactionError(t *testing.T) {
	_, mock, teardown := setupSignInTest(t)
	defer teardown()

	captcha.InitCaptchaState = func(w http.ResponseWriter, r *http.Request) (int64, bool, error) {
		return 3, false, nil
	}
	captcha.ShowCaptchaMsg = func(r *http.Request, showCaptcha bool) bool {
		return false
	}
	tools.InputValidate = func(r *http.Request, login, email, password string, isSignIn bool) (string, error) {
		return "", nil
	}
	data.GetPermanentIdFromDbByLogin = func(login string) (string, error) {
		return "permanent-123", nil
	}
	data.IsOKPasswordHashInDb = func(permanentId, password string) error {
		return nil
	}

	mock.ExpectBegin().WillReturnError(errors.New("transaction error"))

	form := url.Values{}
	form.Add("login", "testuser")
	form.Add("password", "ValidPassword123!")
	req := httptest.NewRequest("POST", "/sign-in", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	CheckInDbAndValidateSignInUserInput(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, consts.Err500URL, w.Header().Get("Location"))
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCheckInDbAndValidateSignInUserInput_WithRememberMe(t *testing.T) {
	_, mock, teardown := setupSignInTest(t)
	defer teardown()

	captcha.InitCaptchaState = func(w http.ResponseWriter, r *http.Request) (int64, bool, error) {
		return 3, false, nil
	}
	captcha.ShowCaptchaMsg = func(r *http.Request, showCaptcha bool) bool {
		return false
	}
	tools.InputValidate = func(r *http.Request, login, email, password string, isSignIn bool) (string, error) {
		return "", nil
	}
	data.GetPermanentIdFromDbByLogin = func(login string) (string, error) {
		return "permanent-123", nil
	}
	data.IsOKPasswordHashInDb = func(permanentId, password string) error {
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
	data.GetUniqueUserAgentsFromDb = func(permanentId string) ([]string, error) {
		return []string{"test-user-agent"}, nil
	}
	data.EndAuthAndCaptchaSessions = func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}

	mock.ExpectBegin()
	mock.ExpectCommit()

	form := url.Values{}
	form.Add("login", "testuser")
	form.Add("password", "ValidPassword123!")
	form.Add("rememberMe", "on")
	req := httptest.NewRequest("POST", "/sign-in", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "test-user-agent")
	w := httptest.NewRecorder()

	CheckInDbAndValidateSignInUserInput(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, consts.HomeURL, w.Header().Get("Location"))
	assert.NoError(t, mock.ExpectationsWereMet())
}
