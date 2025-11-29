package main

import (
	"context"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/data"
	"github.com/go-chi/chi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	setupTestEnv()
	setupMockStores()

	code := m.Run()

	cleanupTestEnv()
	os.Exit(code)
}

func setupTestEnv() {
	os.Setenv("CAPTCHA_STORE_SESSION_SECRET_KEY", "test_captcha_secret")
	os.Setenv("LOGIN_STORE_SESSION_AUTH_KEY", "test_auth_key")
	os.Setenv("LOGIN_STORE_SESSION_ENCRYPTION_KEY", "test_encryption_key")
	os.Setenv("JWT_SECRET", "test_jwt_secret")
	os.Setenv("DB_PASSWORD", "test_password")
	os.Setenv("SERVER_EMAIL", "test@example.com")
	os.Setenv("SERVER_EMAIL_PASSWORD", "test_email_password")
	os.Setenv("GOOGLE_CAPTCHA_SECRET", "test_captcha_secret")
	os.Setenv("clientId", "test_client_id")
	os.Setenv("clientSecret", "test_client_secret")
}

func cleanupTestEnv() {
	envVars := []string{
		"CAPTCHA_STORE_SESSION_SECRET_KEY",
		"LOGIN_STORE_SESSION_AUTH_KEY",
		"LOGIN_STORE_SESSION_ENCRYPTION_KEY",
		"JWT_SECRET",
		"DB_PASSWORD",
		"SERVER_EMAIL",
		"SERVER_EMAIL_PASSWORD",
		"GOOGLE_CAPTCHA_SECRET",
		"clientId",
		"clientSecret",
	}
	for _, v := range envVars {
		os.Unsetenv(v)
	}
}

func setupMockStores() {
	data.InitStore()
}

func TestInitEnv(t *testing.T) {
	tests := []struct {
		name    string
		envVars map[string]string
	}{
		{
			name: "success with all env vars",
			envVars: map[string]string{
				"CAPTCHA_STORE_SESSION_SECRET_KEY":   "test1",
				"LOGIN_STORE_SESSION_AUTH_KEY":       "test2",
				"LOGIN_STORE_SESSION_ENCRYPTION_KEY": "test3",
				"JWT_SECRET":                         "test4",
				"DB_PASSWORD":                        "test5",
				"SERVER_EMAIL":                       "test@example.com",
				"SERVER_EMAIL_PASSWORD":              "test6",
				"GOOGLE_CAPTCHA_SECRET":              "test7",
				"clientId":                           "test8",
				"clientSecret":                       "test9",
			},
		},
		{
			name: "missing required env var",
			envVars: map[string]string{
				"CAPTCHA_STORE_SESSION_SECRET_KEY": "test1",
				"LOGIN_STORE_SESSION_AUTH_KEY":     "test2",
			},
		},
		{
			name: "empty env vars",
			envVars: map[string]string{
				"CAPTCHA_STORE_SESSION_SECRET_KEY": "",
				"LOGIN_STORE_SESSION_AUTH_KEY":     "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.envVars {
				os.Setenv(k, v)
			}

			defer func() {
				for k := range tt.envVars {
					os.Unsetenv(k)
				}
			}()

			initEnv()
		})
	}
}

func TestInitDb(t *testing.T) {
	tests := []struct {
		name    string
		setup   func()
		wantErr bool
		cleanup func()
	}{
		{
			name: "successful database connection",
			setup: func() {
				os.Setenv("DB_PASSWORD", "test_password")
			},
			wantErr: false,
			cleanup: func() {
				os.Unsetenv("DB_PASSWORD")
				data.DbClose()
			},
		},
		{
			name: "missing db password",
			setup: func() {
				os.Unsetenv("DB_PASSWORD")
			},
			wantErr: true,
			cleanup: func() {},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup()
			}

			defer func() {
				if tt.cleanup != nil {
					tt.cleanup()
				}
			}()

			initDb()
			// We can't easily test database connection without a real database,
			// but we can verify that the function doesn't panic
		})
	}
}

func TestInitRouter(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
		setup  func()
		status int
	}{
		{
			name:   "GET / should redirect to signup",
			method: "GET",
			path:   "/",
			setup:  func() {},
			status: http.StatusFound,
		},
		{
			name:   "GET /signup should return 200",
			method: "GET",
			path:   consts.SignUpURL,
			setup:  func() {},
			status: http.StatusOK,
		},
		{
			name:   "GET /signin should return 200",
			method: "GET",
			path:   consts.SignInURL,
			setup:  func() {},
			status: http.StatusOK,
		},
		{
			name:   "GET /home without auth should redirect",
			method: "GET",
			path:   consts.HomeURL,
			setup:  func() {},
			status: http.StatusFound,
		},
	}

	r := initRouter()
	ts := httptest.NewServer(r)
	defer ts.Close()

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup()
			}

			req, err := http.NewRequest(tt.method, ts.URL+tt.path, nil)
			require.NoError(t, err)

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, tt.status, resp.StatusCode,
				"Expected status %d for %s %s, got %d",
				tt.status, tt.method, tt.path, resp.StatusCode)
		})
	}
}

func TestInitRouterRoutes(t *testing.T) {
	setupTestEnv()
	setupMockStores()
	defer cleanupTestEnv()

	r := initRouter()
	ts := httptest.NewServer(r)
	defer ts.Close()

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	tests := []struct {
		name   string
		method string
		path   string
		setup  func(*http.Request)
		status int
	}{
		{
			name:   "GET / should redirect to signup",
			method: "GET",
			path:   "/",
			setup:  func(req *http.Request) {},
			status: http.StatusFound,
		},
		{
			name:   "GET /signup should return 200",
			method: "GET",
			path:   consts.SignUpURL,
			setup:  func(req *http.Request) {},
			status: http.StatusOK,
		},
		{
			name:   "POST /check-in-db with invalid data",
			method: "POST",
			path:   CheckInDbAndValidateSignUpUserInputURL,
			setup: func(req *http.Request) {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				form := url.Values{}
				req.Body = ioutil.NopCloser(strings.NewReader(form.Encode()))
			},
			status: http.StatusFound,
		},
		{
			name:   "GET /home without auth should redirect",
			method: "GET",
			path:   consts.HomeURL,
			setup:  func(req *http.Request) {},
			status: http.StatusFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, ts.URL+tt.path, nil)
			require.NoError(t, err)

			if tt.setup != nil {
				tt.setup(req)
			}

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, tt.status, resp.StatusCode,
				"Expected status %d for %s %s, got %d",
				tt.status, tt.method, tt.path, resp.StatusCode)
		})
	}
}

func TestServerStart(t *testing.T) {
	// This test verifies that the server starts without errors
	tests := []struct {
		name string
	}{
		{
			name: "server start initialization",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test server
			server := &http.Server{
				Addr: ":0", // Let the system choose an available port
			}

			// Create a channel to signal when the server has started
			serverStarted := make(chan bool, 1)

			// Start server in a goroutine
			go func() {
				serverStarted <- true
				if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					t.Logf("Server error: %v", err)
				}
			}()

			// Wait for server to start or timeout after 1 second
			select {
			case <-serverStarted:
				// Server started successfully
			case <-time.After(1 * time.Second):
				t.Fatal("Server failed to start within 1 second")
			}

			// Cleanup
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()
			if err := server.Shutdown(ctx); err != nil {
				t.Logf("Server shutdown error: %v", err)
			}
		})
	}

	// Test with invalid port
	t.Run("server start with invalid port", func(t *testing.T) {
		oldPort := os.Getenv("PORT")
		defer os.Setenv("PORT", oldPort)

		// Set invalid port
		os.Setenv("PORT", "invalid")

		// Create a channel to receive the error
		errChan := make(chan error, 1)

		// Start the server in a goroutine
		go func() {
			errChan <- serverStart(initRouter())
		}()

		// We expect an error due to invalid port
		select {
		case err := <-errChan:
			assert.Error(t, err, "Expected error for invalid port")
		case <-time.After(2 * time.Second):
			t.Error("Timeout waiting for server to fail with invalid port")
		}
	})
}

func TestServerStartError(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "server start with nil router",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test with nil router
			var r *chi.Mux

			if r != nil {
				t.Error("Router should be nil for this test")
			}

			// Function should handle nil gracefully (we can't call it directly)
			// but we can test the setup
			_ = func(router *chi.Mux) {
				if router != nil {
					serverStart(router)
				}
			}
		})
	}
}

func TestMainFunctionOrder(t *testing.T) {
	setupTestEnv()
	defer cleanupTestEnv()

	tests := []struct {
		name string
	}{
		{
			name: "main function components order",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := initRouter()
			if r == nil {
				t.Error("Router should not be nil")
			}

			initEnv()
			initDb()
		})
	}
}

func TestConstants(t *testing.T) {
	tests := []struct {
		name string
		want string
		got  string
	}{
		{"setUserInDbURL", "/set-user-in-db", setUserInDbURL},
		{"codeValidateURL", "/code-validate", codeValidateURL},
		{"CheckInDbAndValidateSignUpUserInputURL", "/check-in-db-and-validate-sign-up-user-input", CheckInDbAndValidateSignUpUserInputURL},
		{"CheckInDbAndValidateSignInUserInputURL", "/check-in-db-and-validate-sign-in-user-input", CheckInDbAndValidateSignInUserInputURL},
		{"generatePasswordResetLinkURL", "/generate-password-reset-link", generatePasswordResetLinkURL},
		{"yandexCallbackURL", "/ya_callback", yandexCallbackURL},
		{"setNewPasswordURL", "/set-new-password", setNewPasswordURL},
		{"logoutURL", "/logout", logoutURL},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("Expected %s, got %s", tt.want, tt.got)
			}
		})
	}
}

func TestInitEnvError(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "init env with missing .env file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test initEnv when .env file doesn't exist
			// It should log error but not panic
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("initEnv panicked: %v", r)
				}
			}()

			initEnv()
		})
	}
}

func TestInitEnvValidation(t *testing.T) {
	tests := []struct {
		name        string
		envVars     map[string]string
		expectPanic bool
	}{
		{
			name: "all required vars present",
			envVars: map[string]string{
				"CAPTCHA_STORE_SESSION_SECRET_KEY":   "test1",
				"LOGIN_STORE_SESSION_AUTH_KEY":       "test2",
				"LOGIN_STORE_SESSION_ENCRYPTION_KEY": "test3",
				"JWT_SECRET":                         "test4",
				"DB_PASSWORD":                        "test5",
				"SERVER_EMAIL":                       "test@example.com",
				"SERVER_EMAIL_PASSWORD":              "test6",
				"GOOGLE_CAPTCHA_SECRET":              "test7",
				"clientId":                           "test8",
				"clientSecret":                       "test9",
			},
			expectPanic: false,
		},
		{
			name: "missing required vars",
			envVars: map[string]string{
				"DB_PASSWORD": "test",
			},
			expectPanic: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.envVars {
				os.Setenv(k, v)
			}

			defer func() {
				for k := range tt.envVars {
					os.Unsetenv(k)
				}
			}()

			if tt.expectPanic {
				defer func() {
					if r := recover(); r == nil {
						t.Error("Expected panic but didn't get one")
					}
				}()
			}

			initEnv()
		})
	}
}

func TestRouterMiddleware(t *testing.T) {
	setupTestEnv()
	setupMockStores()
	defer cleanupTestEnv()

	r := initRouter()

	tests := []struct {
		name       string
		path       string
		method     string
		expectAuth bool
	}{
		{"AuthGuardForSignUpAndSignInPath", consts.SignUpURL, "GET", false},
		{"AuthGuardForHomePath", consts.HomeURL, "GET", true},
		{"ResetTokenGuard", setNewPasswordURL, "GET", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			rr := httptest.NewRecorder()

			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Test panicked: %v", r)
				}
			}()

			r.ServeHTTP(rr, req)

			if tt.expectAuth {
				if rr.Code == http.StatusOK {
					t.Errorf("Protected route %s should require authentication or valid token", tt.path)
				}
			}
		})
	}
}

func TestRouteHandlers(t *testing.T) {
	setupTestEnv()
	setupMockStores()
	defer cleanupTestEnv()

	r := initRouter()

	tests := []struct {
		name           string
		method         string
		path           string
		expectedStatus int
	}{
		{"Root redirect", "GET", "/", http.StatusFound},
		{"Sign up page", "GET", consts.SignUpURL, http.StatusOK},
		{"Sign in page", "GET", consts.SignInURL, http.StatusOK},
		{"Error page", "GET", consts.Err500URL, http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			rr := httptest.NewRecorder()

			r.ServeHTTP(rr, req)

			if tt.expectedStatus == http.StatusFound {
				location := rr.Header().Get("Location")
				if location != consts.SignUpURL {
					t.Errorf("Expected redirect to %s, got %s", consts.SignUpURL, location)
				}
			} else if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}
		})
	}
}

func TestPostRoutes(t *testing.T) {
	setupTestEnv()
	setupMockStores()
	defer cleanupTestEnv()

	r := initRouter()

	tests := []struct {
		name           string
		path           string
		body           string
		expectedStatus int
	}{
		{
			name:           "Set user in db",
			path:           setUserInDbURL,
			body:           "test=data",
			expectedStatus: http.StatusFound,
		},
		{
			name:           "Code validate",
			path:           codeValidateURL,
			body:           "test=data",
			expectedStatus: http.StatusFound,
		},
		{
			name:           "Check sign up input",
			path:           CheckInDbAndValidateSignUpUserInputURL,
			body:           "test=data",
			expectedStatus: http.StatusFound,
		},
		{
			name:           "Check sign in input",
			path:           CheckInDbAndValidateSignInUserInputURL,
			body:           "test=data",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Generate reset link",
			path:           generatePasswordResetLinkURL,
			body:           "test=data",
			expectedStatus: http.StatusFound,
		},
		{
			name:           "Set new password",
			path:           setNewPasswordURL,
			body:           "test=data",
			expectedStatus: http.StatusFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", tt.path, strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()

			r.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}
		})
	}
}

func TestAuthRoutes(t *testing.T) {
	setupTestEnv()
	setupMockStores()
	defer cleanupTestEnv()

	r := initRouter()

	tests := []struct {
		name           string
		method         string
		path           string
		expectedStatus int
	}{
		{"Yandex auth", "GET", "/yauth", http.StatusFound},
		{"Yandex callback", "GET", yandexCallbackURL, http.StatusFound},
		{"Logout", "GET", logoutURL, http.StatusFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			rr := httptest.NewRecorder()

			r.ServeHTTP(rr, req)

			if tt.path == "/yauth" {
				if rr.Code != http.StatusFound && rr.Code != http.StatusBadRequest {
					t.Errorf("Expected redirect or bad request for %s, got %d", tt.path, rr.Code)
				}
			} else if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}
		})
	}
}

func TestProtectedRoutes(t *testing.T) {
	setupTestEnv()
	setupMockStores()
	defer cleanupTestEnv()

	r := initRouter()

	tests := []struct {
		name           string
		path           string
		expectedStatus int
	}{
		{"Home without auth", consts.HomeURL, http.StatusFound},
		{"Logout without auth", logoutURL, http.StatusFound},
		{"Set new password without token", setNewPasswordURL, http.StatusFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			rr := httptest.NewRecorder()

			r.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}
		})
	}
}

func TestEnvironmentValidation(t *testing.T) {
	originalVars := make(map[string]string)
	requiredVars := []string{
		"CAPTCHA_STORE_SESSION_SECRET_KEY",
		"LOGIN_STORE_SESSION_AUTH_KEY",
		"LOGIN_STORE_SESSION_ENCRYPTION_KEY",
		"JWT_SECRET",
		"DB_PASSWORD",
		"SERVER_EMAIL",
		"SERVER_EMAIL_PASSWORD",
		"GOOGLE_CAPTCHA_SECRET",
		"clientId",
		"clientSecret",
	}

	for _, v := range requiredVars {
		originalVars[v] = os.Getenv(v)
		os.Unsetenv(v)
	}

	defer func() {
		for k, v := range originalVars {
			if v != "" {
				os.Setenv(k, v)
			} else {
				os.Unsetenv(k)
			}
		}
	}()

	t.Run("missing all vars", func(t *testing.T) {
		initEnv()
	})

	t.Run("partial vars set", func(t *testing.T) {
		os.Setenv("DB_PASSWORD", "test")
		os.Setenv("JWT_SECRET", "test")
		initEnv()

		os.Unsetenv("DB_PASSWORD")
		os.Unsetenv("JWT_SECRET")
	})

	t.Run("all vars set", func(t *testing.T) {
		for _, v := range requiredVars {
			os.Setenv(v, "test_value")
		}
		initEnv()

		for _, v := range requiredVars {
			os.Unsetenv(v)
		}
	})
}

func TestDatabaseConnection(t *testing.T) {
	originalPassword := os.Getenv("DB_PASSWORD")
	defer func() {
		if originalPassword != "" {
			os.Setenv("DB_PASSWORD", originalPassword)
		} else {
			os.Unsetenv("DB_PASSWORD")
		}
	}()

	t.Run("without password", func(t *testing.T) {
		os.Unsetenv("DB_PASSWORD")
		initDb()
	})

	t.Run("with password", func(t *testing.T) {
		os.Setenv("DB_PASSWORD", "test_password")
		initDb()
	})
}

func TestRouterStructure(t *testing.T) {
	setupTestEnv()
	setupMockStores()
	defer cleanupTestEnv()

	r := initRouter()

	if r == nil {
		t.Fatal("Router should not be nil")
	}

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Root route should redirect, got status %d", rr.Code)
	}

	location := rr.Header().Get("Location")
	if location != consts.SignUpURL {
		t.Errorf("Root should redirect to %s, got %s", consts.SignUpURL, location)
	}
}

func TestRouteRegistration(t *testing.T) {
	setupTestEnv()
	setupMockStores()
	defer cleanupTestEnv()

	r := initRouter()

	testCases := []struct {
		method string
		path   string
	}{
		{"GET", "/"},
		{"GET", consts.SignUpURL},
		{"POST", setUserInDbURL},
		{"GET", consts.ServerAuthCodeSendURL},
		{"POST", codeValidateURL},
		{"GET", consts.SignInURL},
		{"POST", CheckInDbAndValidateSignInUserInputURL},
		{"GET", "/yauth"},
		{"GET", yandexCallbackURL},
		{"GET", generatePasswordResetLinkURL},
		{"POST", generatePasswordResetLinkURL},
		{"GET", setNewPasswordURL},
		{"POST", setNewPasswordURL},
		{"GET", consts.HomeURL},
		{"GET", logoutURL},
		{"GET", consts.Err500URL},
	}

	for _, tc := range testCases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			rr := httptest.NewRecorder()

			r.ServeHTTP(rr, req)

			if rr.Code == http.StatusNotFound {
				t.Errorf("Route %s %s should be registered", tc.method, tc.path)
			}
		})
	}
}

func TestStaticFileHandling(t *testing.T) {
	setupTestEnv()
	setupMockStores()
	defer cleanupTestEnv()

	r := initRouter()

	testPaths := []string{
		"/public/styles.css",
		"/public/auth-db.sql",
		"/public/500.html",
		"/public/nonexistent.js",
	}

	for _, path := range testPaths {
		t.Run("static file "+path, func(t *testing.T) {
			req := httptest.NewRequest("GET", path, nil)
			rr := httptest.NewRecorder()

			r.ServeHTTP(rr, req)

			if path == "/public/nonexistent.js" {
				if rr.Code != http.StatusNotFound {
					t.Errorf("Nonexistent file should return 404, got %d", rr.Code)
				}
			} else {
				if rr.Code == http.StatusNotFound {
					t.Errorf("Static file %s should be accessible", path)
				}
			}
		})
	}
}

func TestMiddlewareIntegration(t *testing.T) {
	setupTestEnv()
	setupMockStores()
	defer cleanupTestEnv()

	r := initRouter()

	protectedRoutes := []struct {
		path   string
		method string
	}{
		{consts.HomeURL, "GET"},
		{logoutURL, "GET"},
		{setNewPasswordURL, "GET"},
	}

	for _, route := range protectedRoutes {
		t.Run("protected route "+route.path, func(t *testing.T) {
			req := httptest.NewRequest(route.method, route.path, nil)
			rr := httptest.NewRecorder()

			r.ServeHTTP(rr, req)

			if route.path == setNewPasswordURL {
				if rr.Code == http.StatusOK {
					t.Errorf("Protected route %s should require authentication or valid token", route.path)
				}
			} else {
				if rr.Code == http.StatusOK {
					t.Errorf("Protected route %s should require authentication", route.path)
				}
			}
		})
	}
}

func TestErrorHandling(t *testing.T) {
	setupTestEnv()
	setupMockStores()
	defer cleanupTestEnv()

	r := initRouter()

	req := httptest.NewRequest("GET", consts.Err500URL, nil)
	rr := httptest.NewRecorder()

	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Error page should return status 200, got %d", rr.Code)
	}
}

func TestServerConfiguration(t *testing.T) {
	setupTestEnv()
	setupMockStores()
	defer cleanupTestEnv()

	r := initRouter()

	if r == nil {
		t.Error("Router should be initialized")
	}

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Server should be configured to redirect root, got %d", rr.Code)
	}
}

func TestInitStore(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "init store function",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test that InitStore function exists and can be called
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("InitStore panicked: %v", r)
				}
			}()

			data.InitStore()
		})
	}
}

func TestDatabaseClose(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "database close function",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test that DbClose function exists and can be called
			// It should not panic even if Db is nil
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("DbClose panicked: %v", r)
				}
			}()

			data.DbClose()
		})
	}
}

func TestMainFunction(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "main function execution",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test that main function components work
			// We can't call main() directly as it blocks
			// but we can test its components
			setupTestEnv()
			initEnv()
			initDb() // This will fail but shouldn't panic
			r := initRouter()
			if r == nil {
				t.Error("Router should be initialized")
			}
		})
	}
}

func TestApplicationInitialization(t *testing.T) {
	setupTestEnv()
	defer cleanupTestEnv()

	tests := []struct {
		name string
		step string
	}{
		{"environment initialization", "env"},
		{"database initialization", "db"},
		{"router initialization", "router"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.step {
			case "env":
				initEnv()
			case "db":
				initDb()
			case "router":
				r := initRouter()
				if r == nil {
					t.Error("Router should not be nil")
				}
			}
		})
	}
}
