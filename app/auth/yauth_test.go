package auth

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/structs"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

type MockDependencies struct {
	GetAccessToken            func(string) (string, error)
	GetYandexUserInfo         func(string) (structs.User, error)
	GetPermanentIdFromDb      func(string, bool) (string, error)
	SetEmailInDb              func(string, string, bool) error
	SetTemporaryIdInDbTx      func(*sql.Tx, string, string, string, bool) error
	GenerateRefreshToken      func(int, bool) (string, error)
	SetRefreshTokenInDbTx     func(*sql.Tx, string, string, string, bool) error
	GetUniqueUserAgentsFromDb func(string) ([]string, error)
	SendNewDeviceLoginEmail   func(string, string, string) error
	EndAuthAndCaptchaSessions func(http.ResponseWriter, *http.Request) error
	BeginTransaction          func() (*sql.Tx, error)
}

func YandexCallbackHandlerWithDeps(w http.ResponseWriter, r *http.Request, deps *MockDependencies) {
	yauthCode := r.URL.Query().Get("code")
	if yauthCode == "" {
		http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
		return
	}

	var yandexAccessToken string
	var err error
	if deps != nil && deps.GetAccessToken != nil {
		yandexAccessToken, err = deps.GetAccessToken(yauthCode)
	} else {
		yandexAccessToken, err = getAccessToken(yauthCode)
	}
	if err != nil {
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	var yandexUser structs.User
	if deps != nil && deps.GetYandexUserInfo != nil {
		yandexUser, err = deps.GetYandexUserInfo(yandexAccessToken)
	} else {
		yandexUser, err = getYandexUserInfo(yandexAccessToken)
	}
	if err != nil {
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	var permanentId string
	yauth := true

	var getPermanentIdFunc func(string, bool) (string, error)
	if deps != nil && deps.GetPermanentIdFromDb != nil {
		getPermanentIdFunc = deps.GetPermanentIdFromDb
	} else {
		getPermanentIdFunc = data.GetPermanentIdFromDbByEmail
	}

	DbPermanentId, err := getPermanentIdFunc(yandexUser.Email, yauth)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			permanentId = uuid.New().String()
			var setEmailFunc func(string, string, bool) error
			if deps != nil && deps.SetEmailInDb != nil {
				setEmailFunc = deps.SetEmailInDb
			} else {
				setEmailFunc = data.SetEmailInDb
			}
			if err := setEmailFunc(permanentId, yandexUser.Email, yauth); err != nil {
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}
		} else {
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}
	} else {
		permanentId = DbPermanentId
	}

	var tx *sql.Tx
	if deps != nil && deps.BeginTransaction != nil {
		tx, err = deps.BeginTransaction()
	} else {
		tx, err = data.Db.Begin()
	}
	if err != nil {
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}
	defer func() {
		r := recover()
		if r != nil {
			tx.Rollback()
			panic(r)
		}
	}()

	rememberMe := r.FormValue("rememberMe") == "true"
	temporaryId := uuid.New().String()
	data.SetTemporaryIdInCookies(w, temporaryId, consts.Exp7Days, rememberMe)

	userAgent := r.UserAgent()
	var setTemporaryIdFunc func(*sql.Tx, string, string, string, bool) error
	if deps != nil && deps.SetTemporaryIdInDbTx != nil {
		setTemporaryIdFunc = deps.SetTemporaryIdInDbTx
	} else {
		setTemporaryIdFunc = data.SetTemporaryIdInDbTx
	}
	if err := setTemporaryIdFunc(tx, permanentId, temporaryId, userAgent, yauth); err != nil {
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	var refreshToken string
	var generateTokenFunc func(int, bool) (string, error)
	if deps != nil && deps.GenerateRefreshToken != nil {
		generateTokenFunc = deps.GenerateRefreshToken
	} else {
		generateTokenFunc = tools.GenerateRefreshToken
	}
	refreshToken, err = generateTokenFunc(consts.Exp7Days, rememberMe)
	if err != nil {
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	var setRefreshTokenFunc func(*sql.Tx, string, string, string, bool) error
	if deps != nil && deps.SetRefreshTokenInDbTx != nil {
		setRefreshTokenFunc = deps.SetRefreshTokenInDbTx
	} else {
		setRefreshTokenFunc = data.SetRefreshTokenInDbTx
	}
	if err := setRefreshTokenFunc(tx, permanentId, refreshToken, userAgent, yauth); err != nil {
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	if err = tx.Commit(); err != nil {
		tx.Rollback()
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	var getUniqueAgentsFunc func(string) ([]string, error)
	if deps != nil && deps.GetUniqueUserAgentsFromDb != nil {
		getUniqueAgentsFunc = deps.GetUniqueUserAgentsFromDb
	} else {
		getUniqueAgentsFunc = data.GetUniqueUserAgentsFromDb
	}
	uniqueUserAgents, err := getUniqueAgentsFunc(permanentId)
	if err != nil {
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}

	if !contains(uniqueUserAgents, r.UserAgent()) {
		var sendEmailFunc func(string, string, string) error
		if deps != nil && deps.SendNewDeviceLoginEmail != nil {
			sendEmailFunc = deps.SendNewDeviceLoginEmail
		} else {
			sendEmailFunc = tools.SendNewDeviceLoginEmail
		}
		if err := sendEmailFunc(yandexUser.Login, yandexUser.Email, r.UserAgent()); err != nil {
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}
	}

	var endSessionsFunc func(http.ResponseWriter, *http.Request) error
	if deps != nil && deps.EndAuthAndCaptchaSessions != nil {
		endSessionsFunc = deps.EndAuthAndCaptchaSessions
	} else {
		endSessionsFunc = data.EndAuthAndCaptchaSessions
	}
	if err = endSessionsFunc(w, r); err != nil {
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
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

func getAccessTokenWithURL(yauthCode string, tokenServerURL string) (string, error) {
	tokenParams := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {yauthCode},
		"client_id":     {os.Getenv("clientId")},
		"client_secret": {os.Getenv("clientSecret")},
		"redirect_uri":  {YandexCallbackFullURL},
	}

	resp, err := http.PostForm(tokenServerURL, tokenParams)
	if err != nil {
		return "", errors.WithStack(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", errors.WithStack(err)
	}

	var result map[string]interface{}
	if err = json.Unmarshal(body, &result); err != nil {
		return "", errors.WithStack(err)
	}

	accessToken, ok := result["access_token"].(string)
	if !ok {
		err := errors.New("access_token: not exist")
		return "", errors.WithStack(err)
	}

	return accessToken, nil
}

func getYandexUserInfoWithURL(accessToken string, userInfoServerURL string) (structs.User, error) {
	userInfoURLWithParams := userInfoServerURL + "?format=json&with_openId_Identity=1&with_email=1"

	req, err := http.NewRequest("GET", userInfoURLWithParams, nil)
	if err != nil {
		return structs.User{}, errors.WithStack(err)
	}

	req.Header.Set("Authorization", "OAuth "+accessToken)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return structs.User{}, errors.WithStack(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return structs.User{}, errors.WithStack(err)
	}

	var user structs.User
	if err = json.Unmarshal(body, &user); err != nil {
		return structs.User{}, errors.WithStack(err)
	}

	return user, nil
}

func TestGetAccessTokenWithMockServer(t *testing.T) {
	tests := []struct {
		name          string
		responseCode  int
		responseBody  string
		expectedToken string
		expectedError bool
	}{
		{
			name:          "successful token exchange",
			responseCode:  200,
			responseBody:  `{"access_token":"test-access-token","token_type":"bearer"}`,
			expectedToken: "test-access-token",
			expectedError: false,
		},
		{
			name:          "invalid response without access_token",
			responseCode:  200,
			responseBody:  `{"error":"invalid_grant"}`,
			expectedToken: "",
			expectedError: true,
		},
		{
			name:          "malformed JSON response",
			responseCode:  200,
			responseBody:  `{"access_token":"test","token_type":`,
			expectedToken: "",
			expectedError: true,
		},
		{
			name:          "HTTP error response",
			responseCode:  400,
			responseBody:  `{"error":"invalid_request"}`,
			expectedToken: "",
			expectedError: true,
		},
		{
			name:          "network error simulation",
			responseCode:  500,
			responseBody:  `Internal Server Error`,
			expectedToken: "",
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.responseCode)
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, tt.responseBody)
			}))
			defer mockServer.Close()

			os.Setenv("clientId", "test-client")
			os.Setenv("clientSecret", "test-secret")
			defer func() {
				os.Unsetenv("clientId")
				os.Unsetenv("clientSecret")
			}()

			token, err := getAccessTokenWithURL("test-code", mockServer.URL)

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

func TestGetYandexUserInfoWithMockServer(t *testing.T) {
	tests := []struct {
		name          string
		accessToken   string
		responseCode  int
		responseBody  string
		expectedUser  structs.User
		expectedError bool
	}{
		{
			name:          "successful user info retrieval",
			accessToken:   "valid-token",
			responseCode:  200,
			responseBody:  `{"login":"testuser","default_email":"test@example.com","id":"12345"}`,
			expectedUser:  structs.User{Login: "testuser", Email: "test@example.com"},
			expectedError: false,
		},
		{
			name:          "invalid token response",
			accessToken:   "invalid-token",
			responseCode:  401,
			responseBody:  `{"error":"invalid_token"}`,
			expectedUser:  structs.User{},
			expectedError: false,
		},
		{
			name:          "malformed JSON response",
			accessToken:   "valid-token",
			responseCode:  200,
			responseBody:  `{"login":"testuser","email":`,
			expectedUser:  structs.User{},
			expectedError: true,
		},
		{
			name:          "empty user info",
			accessToken:   "empty-token",
			responseCode:  200,
			responseBody:  `{}`,
			expectedUser:  structs.User{},
			expectedError: false,
		},
		{
			name:          "network timeout simulation",
			accessToken:   "timeout-token",
			responseCode:  500,
			responseBody:  `Internal Server Error`,
			expectedUser:  structs.User{},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				authHeader := r.Header.Get("Authorization")
				expectedAuth := "OAuth " + tt.accessToken
				if authHeader != expectedAuth {
					t.Errorf("expected Authorization header %s, got %s", expectedAuth, authHeader)
				}

				w.WriteHeader(tt.responseCode)
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, tt.responseBody)
			}))
			defer mockServer.Close()

			user, err := getYandexUserInfoWithURL(tt.accessToken, mockServer.URL)

			if tt.expectedError && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tt.expectedError && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
			if user.Login != tt.expectedUser.Login || user.Email != tt.expectedUser.Email {
				t.Errorf("expected user %+v, got %+v", tt.expectedUser, user)
			}
		})
	}
}

func TestYandexCallbackHandlerWithDeps(t *testing.T) {
	tests := []struct {
		name              string
		queryParams       string
		formValues        string
		deps              *MockDependencies
		expectedStatus    int
		expectedURL       string
		expectedCookies   map[string]string
		expectedEmailSent bool
	}{
		{
			name:            "no code parameter",
			queryParams:     "",
			formValues:      "",
			deps:            nil,
			expectedStatus:  http.StatusFound,
			expectedURL:     consts.SignUpURL,
			expectedCookies: nil,
		},
		{
			name:        "getAccessToken error",
			queryParams: "code=test-code",
			formValues:  "",
			deps: &MockDependencies{
				GetAccessToken: func(code string) (string, error) {
					return "", errors.New("token error")
				},
			},
			expectedStatus:  http.StatusFound,
			expectedURL:     consts.Err500URL,
			expectedCookies: nil,
		},
		{
			name:        "new user successful registration with remember me",
			queryParams: "code=test-code",
			formValues:  "rememberMe=true",
			deps: &MockDependencies{
				GetAccessToken: func(code string) (string, error) {
					return "access-token", nil
				},
				GetYandexUserInfo: func(token string) (structs.User, error) {
					return structs.User{Login: "testuser", Email: "test@example.com"}, nil
				},
				GetPermanentIdFromDb: func(email string, yauth bool) (string, error) {
					return "", sql.ErrNoRows
				},
				SetEmailInDb: func(permanentId, email string, yauth bool) error {
					return nil
				},
				BeginTransaction: func() (*sql.Tx, error) {
					db, mock, err := sqlmock.New()
					if err != nil {
						return nil, err
					}
					mock.ExpectBegin().WillReturnError(nil)
					mock.ExpectCommit()
					tx, err := db.Begin()
					return tx, err
				},
				SetTemporaryIdInDbTx: func(tx *sql.Tx, permanentId, temporaryId, userAgent string, yauth bool) error {
					return nil
				},
				GenerateRefreshToken: func(exp int, rememberMe bool) (string, error) {
					if !rememberMe {
						t.Errorf("expected rememberMe=true, got false")
					}
					return "refresh-token", nil
				},
				SetRefreshTokenInDbTx: func(tx *sql.Tx, permanentId, refreshToken, userAgent string, yauth bool) error {
					return nil
				},
				GetUniqueUserAgentsFromDb: func(permanentId string) ([]string, error) {
					return []string{}, nil
				},
				SendNewDeviceLoginEmail: func(login, email, userAgent string) error {
					return nil
				},
				EndAuthAndCaptchaSessions: func(w http.ResponseWriter, r *http.Request) error {
					return nil
				},
			},
			expectedStatus:    http.StatusFound,
			expectedURL:       consts.HomeURL,
			expectedCookies:   map[string]string{"temporaryId": ""},
			expectedEmailSent: true,
		},
		{
			name:        "existing user login without remember me",
			queryParams: "code=test-code",
			formValues:  "rememberMe=false",
			deps: &MockDependencies{
				GetAccessToken: func(code string) (string, error) {
					return "access-token", nil
				},
				GetYandexUserInfo: func(token string) (structs.User, error) {
					return structs.User{Login: "testuser", Email: "test@example.com"}, nil
				},
				GetPermanentIdFromDb: func(email string, yauth bool) (string, error) {
					return "existing-permanent-id", nil
				},
				BeginTransaction: func() (*sql.Tx, error) {
					db, mock, err := sqlmock.New()
					if err != nil {
						return nil, err
					}
					mock.ExpectBegin().WillReturnError(nil)
					mock.ExpectCommit()
					tx, err := db.Begin()
					return tx, err
				},
				SetTemporaryIdInDbTx: func(tx *sql.Tx, permanentId, temporaryId, userAgent string, yauth bool) error {
					return nil
				},
				GenerateRefreshToken: func(exp int, rememberMe bool) (string, error) {
					if rememberMe {
						t.Errorf("expected rememberMe=false, got true")
					}
					return "refresh-token", nil
				},
				SetRefreshTokenInDbTx: func(tx *sql.Tx, permanentId, refreshToken, userAgent string, yauth bool) error {
					return nil
				},
				GetUniqueUserAgentsFromDb: func(permanentId string) ([]string, error) {
					return []string{"test-agent"}, nil
				},
				SendNewDeviceLoginEmail: func(login, email, userAgent string) error {
					t.Errorf("email should not be sent for existing device")
					return nil
				},
				EndAuthAndCaptchaSessions: func(w http.ResponseWriter, r *http.Request) error {
					return nil
				},
			},
			expectedStatus:    http.StatusFound,
			expectedURL:       consts.HomeURL,
			expectedCookies:   map[string]string{"temporaryId": ""},
			expectedEmailSent: false,
		},
		{
			name:        "transaction rollback on error",
			queryParams: "code=test-code",
			formValues:  "",
			deps: &MockDependencies{
				GetAccessToken: func(code string) (string, error) {
					return "access-token", nil
				},
				GetYandexUserInfo: func(token string) (structs.User, error) {
					return structs.User{Login: "testuser", Email: "test@example.com"}, nil
				},
				GetPermanentIdFromDb: func(email string, yauth bool) (string, error) {
					return "existing-permanent-id", nil
				},
				BeginTransaction: func() (*sql.Tx, error) {
					db, mock, err := sqlmock.New()
					if err != nil {
						return nil, err
					}
					mock.ExpectBegin().WillReturnError(nil)
					mock.ExpectRollback()
					tx, err := db.Begin()
					return tx, err
				},
				SetTemporaryIdInDbTx: func(tx *sql.Tx, permanentId, temporaryId, userAgent string, yauth bool) error {
					return errors.New("transaction error")
				},
			},
			expectedStatus:  http.StatusFound,
			expectedURL:     consts.Err500URL,
			expectedCookies: map[string]string{"temporaryId": ""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/ya_callback?"+tt.queryParams, nil)
			if tt.formValues != "" {
				req = httptest.NewRequest("POST", "/ya_callback?"+tt.queryParams, strings.NewReader(tt.formValues))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			req.Header.Set("User-Agent", "test-agent")
			w := httptest.NewRecorder()

			YandexCallbackHandlerWithDeps(w, req, tt.deps)

			resp := w.Result()
			defer resp.Body.Close()

			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, resp.StatusCode)
			}

			location := resp.Header.Get("Location")
			if location != tt.expectedURL {
				t.Errorf("expected URL %s, got %s", tt.expectedURL, location)
			}

			cookies := resp.Cookies()
			cookieMap := make(map[string]string)
			for _, cookie := range cookies {
				cookieMap[cookie.Name] = cookie.Value
			}

			if tt.expectedCookies != nil {
				for expectedName := range tt.expectedCookies {
					if _, exists := cookieMap[expectedName]; !exists {
						t.Errorf("expected cookie %s to be set", expectedName)
					}
				}
			} else {
				if len(cookies) > 0 {
					t.Errorf("expected no cookies, got %d", len(cookies))
				}
			}

			if tt.expectedCookies != nil {
				for _, cookie := range cookies {
					if cookie.Name == "temporaryId" {
						if cookie.Value == "" {
							t.Errorf("temporaryId cookie should have non-empty value")
						}
						if cookie.MaxAge <= 0 {
							t.Errorf("temporaryId cookie should have positive MaxAge")
						}
						if tt.formValues == "rememberMe=true" && cookie.MaxAge < consts.Exp7Days-1 {
							t.Errorf("rememberMe=true should set longer cookie expiration")
						}
					}
				}
			}
		})
	}
}

func TestYandexCallbackHandlerEdgeCases(t *testing.T) {
	tests := []struct {
		name           string
		queryParams    string
		formValues     string
		deps           *MockDependencies
		expectedStatus int
		expectedURL    string
	}{
		{
			name:        "malicious code parameter",
			queryParams: "code=<script>alert('xss')</script>",
			formValues:  "",
			deps: &MockDependencies{
				GetAccessToken: func(code string) (string, error) {
					if code != "<script>alert('xss')</script>" {
						t.Errorf("expected malicious code to be passed as-is")
					}
					return "", errors.New("invalid code")
				},
			},
			expectedStatus: http.StatusFound,
			expectedURL:    consts.Err500URL,
		},
		{
			name:        "very long user agent",
			queryParams: "code=test-code",
			formValues:  "",
			deps: &MockDependencies{
				GetAccessToken: func(code string) (string, error) {
					return "access-token", nil
				},
				GetYandexUserInfo: func(token string) (structs.User, error) {
					return structs.User{Login: "testuser", Email: "test@example.com"}, nil
				},
				GetPermanentIdFromDb: func(email string, yauth bool) (string, error) {
					return "existing-permanent-id", nil
				},
				BeginTransaction: func() (*sql.Tx, error) {
					db, mock, err := sqlmock.New()
					if err != nil {
						return nil, err
					}
					mock.ExpectBegin().WillReturnError(nil)
					mock.ExpectCommit()
					tx, err := db.Begin()
					return tx, err
				},
				SetTemporaryIdInDbTx: func(tx *sql.Tx, permanentId, temporaryId, userAgent string, yauth bool) error {
					if len(userAgent) != 1000 {
						t.Errorf("expected long user agent")
					}
					return nil
				},
				GenerateRefreshToken: func(exp int, rememberMe bool) (string, error) {
					return "refresh-token", nil
				},
				SetRefreshTokenInDbTx: func(tx *sql.Tx, permanentId, refreshToken, userAgent string, yauth bool) error {
					return nil
				},
				GetUniqueUserAgentsFromDb: func(permanentId string) ([]string, error) {
					return []string{}, nil
				},
				SendNewDeviceLoginEmail: func(login, email, userAgent string) error {
					return nil
				},
				EndAuthAndCaptchaSessions: func(w http.ResponseWriter, r *http.Request) error {
					return nil
				},
			},
			expectedStatus: http.StatusFound,
			expectedURL:    consts.HomeURL,
		},
		{
			name:        "concurrent requests simulation",
			queryParams: "code=test-code",
			formValues:  "rememberMe=true",
			deps: &MockDependencies{
				GetAccessToken: func(code string) (string, error) {
					time.Sleep(10 * time.Millisecond) // Simulate network delay
					return "access-token", nil
				},
				GetYandexUserInfo: func(token string) (structs.User, error) {
					return structs.User{Login: "testuser", Email: "test@example.com"}, nil
				},
				GetPermanentIdFromDb: func(email string, yauth bool) (string, error) {
					return "existing-permanent-id", nil
				},
				BeginTransaction: func() (*sql.Tx, error) {
					db, mock, err := sqlmock.New()
					if err != nil {
						return nil, err
					}
					mock.ExpectBegin().WillReturnError(nil)
					mock.ExpectCommit()
					tx, err := db.Begin()
					return tx, err
				},
				SetTemporaryIdInDbTx: func(tx *sql.Tx, permanentId, temporaryId, userAgent string, yauth bool) error {
					time.Sleep(5 * time.Millisecond) // Simulate DB delay
					return nil
				},
				GenerateRefreshToken: func(exp int, rememberMe bool) (string, error) {
					return "refresh-token", nil
				},
				SetRefreshTokenInDbTx: func(tx *sql.Tx, permanentId, refreshToken, userAgent string, yauth bool) error {
					return nil
				},
				GetUniqueUserAgentsFromDb: func(permanentId string) ([]string, error) {
					return []string{}, nil
				},
				SendNewDeviceLoginEmail: func(login, email, userAgent string) error {
					return nil
				},
				EndAuthAndCaptchaSessions: func(w http.ResponseWriter, r *http.Request) error {
					return nil
				},
			},
			expectedStatus: http.StatusFound,
			expectedURL:    consts.HomeURL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/ya_callback?"+tt.queryParams, nil)
			if tt.formValues != "" {
				req = httptest.NewRequest("POST", "/ya_callback?"+tt.queryParams, strings.NewReader(tt.formValues))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}

			if tt.name == "very long user agent" {
				longUserAgent := strings.Repeat("a", 1000)
				req.Header.Set("User-Agent", longUserAgent)
			} else {
				req.Header.Set("User-Agent", "test-agent")
			}

			w := httptest.NewRecorder()

			YandexCallbackHandlerWithDeps(w, req, tt.deps)

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
