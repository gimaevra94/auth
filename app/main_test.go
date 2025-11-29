package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gimaevra94/auth/app/auth"
	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/tmpls"
	"github.com/go-chi/chi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockDbConn struct {
	mock.Mock
}

func (m *MockDbConn) Conn() error {
	args := m.Called()
	return args.Error(0)
}

type MockHttpServer struct {
	mock.Mock
}

func (m *MockHttpServer) ListenAndServe(addr string, handler http.Handler) error {
	args := m.Called(addr, handler)
	return args.Error(0)
}

func TestInitEnv(t *testing.T) {
	tests := []struct {
		name    string
		envVars map[string]string
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
		},
		{
			name: "missing required vars",
			envVars: map[string]string{
				"DB_PASSWORD": "test",
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
		cleanup func()
	}{
		{
			name: "with db password",
			setup: func() {
				os.Setenv("DB_PASSWORD", "test_password")
			},
			cleanup: func() {
				os.Unsetenv("DB_PASSWORD")
			},
		},
		{
			name: "without db password",
			setup: func() {
				os.Unsetenv("DB_PASSWORD")
			},
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
		})
	}
}

func TestInitRouter(t *testing.T) {
	r := initRouter()

	assert.NotNil(t, r, "initRouter should return non-nil *chi.Mux")

	safeRoutes := []struct {
		method string
		path   string
	}{
		{"GET", "/"},
		{"GET", consts.Err500URL},
	}

	for _, route := range safeRoutes {
		t.Run("route_registered_"+route.method+"_"+route.path, func(t *testing.T) {
			req := httptest.NewRequest(route.method, route.path, nil)
			rr := httptest.NewRecorder()

			r.ServeHTTP(rr, req)

			assert.NotEqual(t, http.StatusNotFound, rr.Code, "Route %s %s should be registered", route.method, route.path)
		})
	}
}

func TestInitRouterMiddleware(t *testing.T) {
	r := initRouter()

	req := httptest.NewRequest("GET", consts.HomeURL, nil)
	rr := httptest.NewRecorder()

	r.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code, "Protected route should redirect without auth")
}

func TestInitRouterStaticFiles(t *testing.T) {
	r := initRouter()

	req := httptest.NewRequest("GET", "/public/styles.css", nil)
	rr := httptest.NewRecorder()

	r.ServeHTTP(rr, req)

	assert.NotEqual(t, http.StatusNotFound, rr.Code, "Static files should be handled")
}

func TestServerStart(t *testing.T) {
	tests := []struct {
		name        string
		portEnv     string
		expectError bool
	}{
		{
			name:        "invalid port",
			portEnv:     "invalid",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldPort := os.Getenv("PORT")
			os.Setenv("PORT", tt.portEnv)
			defer os.Setenv("PORT", oldPort)

			r := chi.NewRouter()

			mockHandler := func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}
			r.Get("/test", mockHandler)

			err := serverStart(r)

			if tt.expectError {
				assert.Error(t, err, "serverStart should return error for invalid port")
			}
		})
	}
}

func TestMainConstants(t *testing.T) {
	expectedConstants := map[string]string{
		"setUserInDbURL":                         "/set-user-in-db",
		"codeValidateURL":                        "/code-validate",
		"CheckInDbAndValidateSignUpUserInputURL": "/check-in-db-and-validate-sign-up-user-input",
		"CheckInDbAndValidateSignInUserInputURL": "/check-in-db-and-validate-sign-in-user-input",
		"generatePasswordResetLinkURL":           "/generate-password-reset-link",
		"yandexCallbackURL":                      "/ya_callback",
		"setNewPasswordURL":                      "/set-new-password",
		"logoutURL":                              "/logout",
	}

	actualConstants := map[string]string{
		"setUserInDbURL":                         setUserInDbURL,
		"codeValidateURL":                        codeValidateURL,
		"CheckInDbAndValidateSignUpUserInputURL": CheckInDbAndValidateSignUpUserInputURL,
		"CheckInDbAndValidateSignInUserInputURL": CheckInDbAndValidateSignInUserInputURL,
		"generatePasswordResetLinkURL":           generatePasswordResetLinkURL,
		"yandexCallbackURL":                      yandexCallbackURL,
		"setNewPasswordURL":                      setNewPasswordURL,
		"logoutURL":                              logoutURL,
	}

	for name, expected := range expectedConstants {
		t.Run(name, func(t *testing.T) {
			actual := actualConstants[name]
			assert.Equal(t, expected, actual, "Constant %s should match expected value", name)
		})
	}
}

func TestInitRouterHandlerTypes(t *testing.T) {
	r := initRouter()

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	r.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code, "Root handler should redirect")

	location := rr.Header().Get("Location")
	assert.Equal(t, consts.SignUpURL, location, "Root should redirect to signup")
}

func TestInitRouterWithMockHandlers(t *testing.T) {
	originalAuthHandler := auth.CheckInDbAndValidateSignUpUserInput
	originalTmplHandler := tmpls.SignUp
	originalAuthGuard := auth.AuthGuardForSignUpAndSignInPath

	defer func() {
		auth.CheckInDbAndValidateSignUpUserInput = originalAuthHandler
		tmpls.SignUp = originalTmplHandler
		auth.AuthGuardForSignUpAndSignInPath = originalAuthGuard
	}()

	mockAuthHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("mock auth handler"))
	}
	auth.CheckInDbAndValidateSignUpUserInput = mockAuthHandler

	mockTmplHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("mock template handler"))
	}
	tmpls.SignUp = mockTmplHandler

	mockAuthGuard := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Middleware-Applied", "true")
			next.ServeHTTP(w, r)
		})
	}
	auth.AuthGuardForSignUpAndSignInPath = mockAuthGuard

	r := initRouter()

	t.Run("mock_auth_handler", func(t *testing.T) {
		req := httptest.NewRequest("POST", CheckInDbAndValidateSignUpUserInputURL, nil)
		rr := httptest.NewRecorder()

		r.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "mock auth handler", rr.Body.String())
	})

	t.Run("mock_template_handler", func(t *testing.T) {
		req := httptest.NewRequest("GET", consts.SignUpURL, nil)
		rr := httptest.NewRecorder()

		r.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "mock template handler", rr.Body.String())
		assert.Equal(t, "true", rr.Header().Get("X-Middleware-Applied"))
	})
}

func TestMockDbConn(t *testing.T) {
	mockDb := new(MockDbConn)

	mockDb.On("Conn").Return(nil)

	err := mockDb.Conn()

	assert.NoError(t, err)
	mockDb.AssertExpectations(t)
}

func TestMockHttpServer(t *testing.T) {
	mockServer := new(MockHttpServer)

	mockServer.On("ListenAndServe", ":8080", mock.Anything).Return(nil)

	err := mockServer.ListenAndServe(":8080", nil)

	assert.NoError(t, err)
	mockServer.AssertExpectations(t)
}
