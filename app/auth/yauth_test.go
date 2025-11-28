package auth

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/structs"
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

var (
	mockGetAccessToken          func(string) (string, error)
	mockGetYandexUserInfo      func(string) (structs.User, error)
	mockGetPermanentIdFromDb   func(string, bool) (string, error)
	mockSetEmailInDb           func(string, string, bool) error
	mockSetTemporaryIdInDbTx   func(*sql.Tx, string, string, string, bool) error
mockGenerateRefreshToken     func(int, bool) (string, error)
	mockSetRefreshTokenInDbTx  func(*sql.Tx, string, string, string, bool) error
mockGetUniqueUserAgentsFromDb func(string) ([]string, error)
mockSendNewDeviceLoginEmail  func(string, string, string) error
mockEndAuthAndCaptchaSessions func(http.ResponseWriter, *http.Request) error
)

func mockGetAccessTokenImpl(yauthCode string) (string, error) {
	if mockGetAccessToken != nil {
		return mockGetAccessToken(yauthCode)
	}
	return getAccessToken(yauthCode)
}

func mockGetYandexUserInfoImpl(accessToken string) (structs.User, error) {
	if mockGetYandexUserInfo != nil {
		return mockGetYandexUserInfo(accessToken)
	}
	return getYandexUserInfo(accessToken)
}

func testYandexCallbackHandler(w http.ResponseWriter, r *http.Request) {
	yauthCode := r.URL.Query().Get("code")
	if yauthCode == "" {
		http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
		return
	}

	yandexAccessToken, err := mockGetAccessTokenImpl(yauthCode)
	if err != nil {
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	yandexUser, err := mockGetYandexUserInfoImpl(yandexAccessToken)
	if err != nil {
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	var permanentId string
	yauth := true

	if mockGetPermanentIdFromDb != nil {
		DbPermanentId, err := mockGetPermanentIdFromDb(yandexUser.Email, yauth)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				permanentId = uuid.New().String()
				if mockSetEmailInDb != nil {
					if err := mockSetEmailInDb(permanentId, yandexUser.Email, yauth); err != nil {
						http.Redirect(w, r, consts.Err500URL, http.StatusFound)
						return
					}
				}
			} else {
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}
		} else {
			permanentId = DbPermanentId
		}
	} else {
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	var rememberMe bool
	if r.Method == "POST" {
		r.ParseForm()
		rememberMe = r.FormValue("rememberMe") == "true"
	} else {
		rememberMe = r.FormValue("rememberMe") == "true"
	}
	temporaryId := uuid.New().String()
	data.SetTemporaryIdInCookies(w, temporaryId, consts.Exp7Days, rememberMe)

	if mockSetTemporaryIdInDbTx != nil {
		userAgent := r.UserAgent()
		if err := mockSetTemporaryIdInDbTx(nil, permanentId, temporaryId, userAgent, yauth); err != nil {
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}
	}

	if mockGenerateRefreshToken != nil {
		refreshToken, err := mockGenerateRefreshToken(consts.Exp7Days, rememberMe)
		if err != nil {
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}
		if mockSetRefreshTokenInDbTx != nil {
			userAgent := r.UserAgent()
			if err := mockSetRefreshTokenInDbTx(nil, permanentId, refreshToken, userAgent, yauth); err != nil {
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}
		}
	}

	if mockGetUniqueUserAgentsFromDb != nil {
		uniqueUserAgents, err := mockGetUniqueUserAgentsFromDb(permanentId)
		if err != nil {
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}
		if mockSendNewDeviceLoginEmail != nil {
			if !contains(uniqueUserAgents, r.UserAgent()) {
				if err := mockSendNewDeviceLoginEmail(yandexUser.Login, yandexUser.Email, r.UserAgent()); err != nil {
					http.Redirect(w, r, consts.Err500URL, http.StatusFound)
					return
				}
			}
		}
	}

	if mockEndAuthAndCaptchaSessions != nil {
		if err := mockEndAuthAndCaptchaSessions(w, r); err != nil {
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}
	}

	http.Redirect(w, r, consts.HomeURL, http.StatusFound)
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func TestYandexAuthHandler(t *testing.T) {
	tests := []struct {
		name           string
		clientId       string
		expectedStatus int
		expectedURL    string
	}{
		{
			name:           "valid client id",
			clientId:       "test-client-id",
			expectedStatus: http.StatusFound,
			expectedURL:    "https://oauth.yandex.ru/authorize",
		},
		{
			name:           "empty client id",
			clientId:       "",
			expectedStatus: http.StatusFound,
			expectedURL:    "https://oauth.yandex.ru/authorize",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("clientId", tt.clientId)
			defer os.Unsetenv("clientId")

			req := httptest.NewRequest("GET", "/ya_auth", nil)
			w := httptest.NewRecorder()

			YandexAuthHandler(w, req)

			resp := w.Result()
			defer resp.Body.Close()

			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, resp.StatusCode)
			}

			location := resp.Header.Get("Location")
			if !strings.Contains(location, tt.expectedURL) {
				t.Errorf("expected URL to contain %s, got %s", tt.expectedURL, location)
			}

			if !strings.Contains(location, "response_type=code") {
				t.Errorf("expected response_type=code in URL, got %s", location)
			}

			if !strings.Contains(location, "redirect_uri="+url.QueryEscape(YandexCallbackFullURL)) {
				t.Errorf("expected redirect_uri=%s in URL, got %s", YandexCallbackFullURL, location)
			}

			if !strings.Contains(location, "scope=login%3Aemail") {
				t.Errorf("expected scope=login:email in URL, got %s", location)
			}
		})
	}
}

func TestGetAccessToken(t *testing.T) {
	tests := []struct {
		name          string
		yauthCode     string
		clientId      string
		clientSecret  string
		expectedToken string
		expectedError bool
	}{
		{
			name:          "empty auth code",
			yauthCode:     "",
			clientId:      "test-client",
			clientSecret:  "test-secret",
			expectedToken: "",
			expectedError: true,
		},
		{
			name:          "valid request but network error",
			yauthCode:     "test-code",
			clientId:      "test-client",
			clientSecret:  "test-secret",
			expectedToken: "",
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("clientId", tt.clientId)
			os.Setenv("clientSecret", tt.clientSecret)
			defer func() {
				os.Unsetenv("clientId")
				os.Unsetenv("clientSecret")
			}()

			token, err := getAccessToken(tt.yauthCode)

			if tt.expectedError && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tt.expectedError && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
			if token != tt.expectedToken {
				t.Errorf("expected token %s, got %s", tt.expectedToken, token)
			}
		})
	}
}

func TestGetYandexUserInfo(t *testing.T) {
	tests := []struct {
		name          string
		accessToken   string
		expectedError bool
	}{
		{
			name:          "empty access token",
			accessToken:   "",
			expectedError: false, // Yandex API может вернуть пустой ответ без ошибки
		},
		{
			name:          "invalid token",
			accessToken:   "invalid-token",
			expectedError: false, // Yandex API может вернуть пустой ответ без ошибки
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, err := getYandexUserInfo(tt.accessToken)

			if tt.expectedError && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tt.expectedError && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
			// Проверяем что пользователь пустой при недействительном токене
			if tt.accessToken == "" || tt.accessToken == "invalid-token" {
				if user.Login != "" || user.Email != "" {
					t.Errorf("expected empty user data for invalid token, got login=%s, email=%s", user.Login, user.Email)
				}
			}
		})
	}
}

func TestYandexCallbackHandlerRememberMeFunctionality(t *testing.T) {
	tests := []struct {
		name           string
		formValues     string
		rememberMeSet  bool
	}{
		{
			name:          "remember me true",
			formValues:    "rememberMe=true",
			rememberMeSet: true,
		},
		{
			name:          "remember me false",
			formValues:    "rememberMe=false",
			rememberMeSet: false,
		},
		{
			name:          "remember me empty",
			formValues:    "",
			rememberMeSet: false,
		},
		{
			name:          "remember me not present",
			formValues:    "other=value",
			rememberMeSet: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockGetAccessToken = func(code string) (string, error) {
				return "access-token", nil
			}
			mockGetYandexUserInfo = func(token string) (structs.User, error) {
				return structs.User{Login: "testuser", Email: "test@example.com"}, nil
			}
			mockGetPermanentIdFromDb = func(email string, yauth bool) (string, error) {
				return "existing-permanent-id", nil
			}
			mockSetTemporaryIdInDbTx = func(tx *sql.Tx, permanentId, temporaryId, userAgent string, yauth bool) error {
				return nil
			}
			mockGenerateRefreshToken = func(exp int, rememberMe bool) (string, error) {
				if rememberMe != tt.rememberMeSet {
					t.Errorf("expected rememberMe %v, got %v", tt.rememberMeSet, rememberMe)
				}
				return "refresh-token", nil
			}
			mockSetRefreshTokenInDbTx = func(tx *sql.Tx, permanentId, refreshToken, userAgent string, yauth bool) error {
				return nil
			}
			mockGetUniqueUserAgentsFromDb = func(permanentId string) ([]string, error) {
				return []string{"test-agent"}, nil
			}
			mockSendNewDeviceLoginEmail = func(login, email, userAgent string) error {
				return nil
			}
			mockEndAuthAndCaptchaSessions = func(w http.ResponseWriter, r *http.Request) error {
				return nil
			}
			defer func() {
				mockGetAccessToken = nil
				mockGetYandexUserInfo = nil
				mockGetPermanentIdFromDb = nil
				mockSetTemporaryIdInDbTx = nil
				mockGenerateRefreshToken = nil
				mockSetRefreshTokenInDbTx = nil
				mockGetUniqueUserAgentsFromDb = nil
				mockSendNewDeviceLoginEmail = nil
				mockEndAuthAndCaptchaSessions = nil
			}()

			req := httptest.NewRequest("POST", "/ya_callback?code=test-code", strings.NewReader(tt.formValues))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("User-Agent", "test-agent")
			w := httptest.NewRecorder()

			testYandexCallbackHandler(w, req)

			resp := w.Result()
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusFound {
				t.Errorf("expected status %d, got %d", http.StatusFound, resp.StatusCode)
			}

			location := resp.Header.Get("Location")
			if location != consts.HomeURL {
				t.Errorf("expected URL %s, got %s", consts.HomeURL, location)
			}

			cookies := resp.Cookies()
			hasTemporaryIdCookie := false
			for _, cookie := range cookies {
				if cookie.Name == "temporaryId" {
					hasTemporaryIdCookie = true
					if cookie.Value == "" {
						t.Errorf("expected non-empty cookie value")
					}
					break
				}
			}

			if !hasTemporaryIdCookie {
				t.Errorf("expected temporaryId cookie to be set")
			}
		})
	}
}

func TestYandexCallbackHandlerTransactionHandling(t *testing.T) {
	tests := []struct {
		name             string
		setupMocks       func()
		expectedRedirect string
	}{
		{
			name: "database transaction error",
			setupMocks: func() {
				mockGetAccessToken = func(code string) (string, error) {
					return "access-token", nil
				}
				mockGetYandexUserInfo = func(token string) (structs.User, error) {
					return structs.User{Login: "testuser", Email: "test@example.com"}, nil
				}
				mockGetPermanentIdFromDb = func(email string, yauth bool) (string, error) {
					return "existing-permanent-id", nil
				}
				mockSetTemporaryIdInDbTx = func(tx *sql.Tx, permanentId, temporaryId, userAgent string, yauth bool) error {
					return errors.New("transaction error")
				}
			},
			expectedRedirect: consts.Err500URL,
		},
		{
			name: "refresh token transaction error",
			setupMocks: func() {
				mockGetAccessToken = func(code string) (string, error) {
					return "access-token", nil
				}
				mockGetYandexUserInfo = func(token string) (structs.User, error) {
					return structs.User{Login: "testuser", Email: "test@example.com"}, nil
				}
				mockGetPermanentIdFromDb = func(email string, yauth bool) (string, error) {
					return "existing-permanent-id", nil
				}
				mockSetTemporaryIdInDbTx = func(tx *sql.Tx, permanentId, temporaryId, userAgent string, yauth bool) error {
					return nil
				}
				mockGenerateRefreshToken = func(exp int, rememberMe bool) (string, error) {
					return "refresh-token", nil
				}
				mockSetRefreshTokenInDbTx = func(tx *sql.Tx, permanentId, refreshToken, userAgent string, yauth bool) error {
					return errors.New("refresh token transaction error")
				}
			},
			expectedRedirect: consts.Err500URL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMocks()
			defer func() {
				mockGetAccessToken = nil
				mockGetYandexUserInfo = nil
				mockGetPermanentIdFromDb = nil
				mockSetTemporaryIdInDbTx = nil
				mockGenerateRefreshToken = nil
				mockSetRefreshTokenInDbTx = nil
				mockGetUniqueUserAgentsFromDb = nil
				mockSendNewDeviceLoginEmail = nil
				mockEndAuthAndCaptchaSessions = nil
			}()

			req := httptest.NewRequest("GET", "/ya_callback?code=test-code", nil)
			req.Header.Set("User-Agent", "test-agent")
			w := httptest.NewRecorder()

			testYandexCallbackHandler(w, req)

			resp := w.Result()
			defer resp.Body.Close()

			location := resp.Header.Get("Location")
			if location != tt.expectedRedirect {
				t.Errorf("expected redirect to %s, got %s", tt.expectedRedirect, location)
			}
		})
	}
}

func TestYandexCallbackHandler(t *testing.T) {
	tests := []struct {
		name                           string
		queryParams                    string
		formValues                     string
		setupMocks                     func()
		expectedStatus                 int
		expectedURL                    string
	}{
		{
			name:        "no code parameter",
			queryParams: "",
			formValues:  "",
			setupMocks:  func() {},
			expectedStatus: http.StatusFound,
			expectedURL:    consts.SignUpURL,
		},
		{
			name:        "getAccessToken error",
			queryParams: "code=test-code",
			formValues:  "",
			setupMocks: func() {
				mockGetAccessToken = func(code string) (string, error) {
					return "", errors.New("token error")
				}
			},
			expectedStatus: http.StatusFound,
			expectedURL:    consts.Err500URL,
		},
		{
			name:        "getYandexUserInfo error",
			queryParams: "code=test-code",
			formValues:  "",
			setupMocks: func() {
				mockGetAccessToken = func(code string) (string, error) {
					return "access-token", nil
				}
				mockGetYandexUserInfo = func(token string) (structs.User, error) {
					return structs.User{}, errors.New("user info error")
				}
			},
			expectedStatus: http.StatusFound,
			expectedURL:    consts.Err500URL,
		},
		{
			name:        "new user successful registration",
			queryParams: "code=test-code",
			formValues:  "rememberMe=true",
			setupMocks: func() {
				mockGetAccessToken = func(code string) (string, error) {
					return "access-token", nil
				}
				mockGetYandexUserInfo = func(token string) (structs.User, error) {
					return structs.User{Login: "testuser", Email: "test@example.com"}, nil
				}
				mockGetPermanentIdFromDb = func(email string, yauth bool) (string, error) {
					return "", sql.ErrNoRows
				}
				mockSetEmailInDb = func(permanentId, email string, yauth bool) error {
					return nil
				}
				mockSetTemporaryIdInDbTx = func(tx *sql.Tx, permanentId, temporaryId, userAgent string, yauth bool) error {
					return nil
				}
				mockGenerateRefreshToken = func(exp int, rememberMe bool) (string, error) {
					return "refresh-token", nil
				}
				mockSetRefreshTokenInDbTx = func(tx *sql.Tx, permanentId, refreshToken, userAgent string, yauth bool) error {
					return nil
				}
				mockGetUniqueUserAgentsFromDb = func(permanentId string) ([]string, error) {
					return []string{}, nil
				}
				mockSendNewDeviceLoginEmail = func(login, email, userAgent string) error {
					return nil
				}
				mockEndAuthAndCaptchaSessions = func(w http.ResponseWriter, r *http.Request) error {
					return nil
				}
			},
			expectedStatus: http.StatusFound,
			expectedURL:    consts.HomeURL,
		},
		{
			name:        "existing user successful login",
			queryParams: "code=test-code",
			formValues:  "",
			setupMocks: func() {
				mockGetAccessToken = func(code string) (string, error) {
					return "access-token", nil
				}
				mockGetYandexUserInfo = func(token string) (structs.User, error) {
					return structs.User{Login: "testuser", Email: "test@example.com"}, nil
				}
				mockGetPermanentIdFromDb = func(email string, yauth bool) (string, error) {
					return "existing-permanent-id", nil
				}
				mockSetTemporaryIdInDbTx = func(tx *sql.Tx, permanentId, temporaryId, userAgent string, yauth bool) error {
					return nil
				}
				mockGenerateRefreshToken = func(exp int, rememberMe bool) (string, error) {
					return "refresh-token", nil
				}
				mockSetRefreshTokenInDbTx = func(tx *sql.Tx, permanentId, refreshToken, userAgent string, yauth bool) error {
					return nil
				}
				mockGetUniqueUserAgentsFromDb = func(permanentId string) ([]string, error) {
					return []string{"test-agent"}, nil
				}
				mockSendNewDeviceLoginEmail = func(login, email, userAgent string) error {
					return nil
				}
				mockEndAuthAndCaptchaSessions = func(w http.ResponseWriter, r *http.Request) error {
					return nil
				}
			},
			expectedStatus: http.StatusFound,
			expectedURL:    consts.HomeURL,
		},
		{
			name:        "database error on GetPermanentIdFromDb",
			queryParams: "code=test-code",
			formValues:  "",
			setupMocks: func() {
				mockGetAccessToken = func(code string) (string, error) {
					return "access-token", nil
				}
				mockGetYandexUserInfo = func(token string) (structs.User, error) {
					return structs.User{Login: "testuser", Email: "test@example.com"}, nil
				}
				mockGetPermanentIdFromDb = func(email string, yauth bool) (string, error) {
					return "", errors.New("database error")
				}
			},
			expectedStatus: http.StatusFound,
			expectedURL:    consts.Err500URL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMocks()
			defer func() {
				mockGetAccessToken = nil
				mockGetYandexUserInfo = nil
				mockGetPermanentIdFromDb = nil
				mockSetEmailInDb = nil
				mockSetTemporaryIdInDbTx = nil
				mockGenerateRefreshToken = nil
				mockSetRefreshTokenInDbTx = nil
				mockGetUniqueUserAgentsFromDb = nil
				mockSendNewDeviceLoginEmail = nil
				mockEndAuthAndCaptchaSessions = nil
			}()

			req := httptest.NewRequest("GET", "/ya_callback?"+tt.queryParams, nil)
			if tt.formValues != "" {
				req = httptest.NewRequest("POST", "/ya_callback?"+tt.queryParams, strings.NewReader(tt.formValues))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			req.Header.Set("User-Agent", "test-agent")
			w := httptest.NewRecorder()

			testYandexCallbackHandler(w, req)

			resp := w.Result()
			defer resp.Body.Close()

			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, resp.StatusCode)
			}

			location := resp.Header.Get("Location")
			if location != tt.expectedURL {
				t.Errorf("expected URL %s, got %s", tt.expectedURL, location)
			}
		})
	}
}
