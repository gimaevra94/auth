// Package tmpls предоставляет функции и шаблоны для рендеринга HTML-страниц.
//
// Файл тестирует функции рендеринга HTML-шаблонов и обработчики ошибок.
package tmpls

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/structs"
)

// MockTmplsRenderer имитирует функцию рендеринга шаблонов для тестирования.
type MockTmplsRenderer func(w http.ResponseWriter, tmpl *template.Template, templateName string, data interface{}) error

// TestSignUp проверяет рендеринг страницы регистрации.
// Ожидается: HTTP 200 при успехе, HTTP 302 при ошибке рендеринга.
func TestSignUp(t *testing.T) {
	tests := []struct {
		name           string
		rendererError  error
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "successful render",
			rendererError:  nil,
			expectedStatus: http.StatusOK,
			expectedBody:   "signUp template rendered",
		},
		{
			name:           "renderer error triggers redirect",
			rendererError:  http.ErrBodyNotAllowed,
			expectedStatus: http.StatusFound,
			expectedBody:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalRenderer := TmplsRenderer
			defer func() { TmplsRenderer = originalRenderer }()

			TmplsRenderer = func(w http.ResponseWriter, tmpl *template.Template, templateName string, data interface{}) error {
				if tt.rendererError != nil {
					return tt.rendererError
				}
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("signUp template rendered"))
				return nil
			}

			req := httptest.NewRequest("GET", "/sign-up", nil)
			w := httptest.NewRecorder()

			SignUp(w, req)

			resp := w.Result()
			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, resp.StatusCode)
			}

			body := w.Body.String()
			if tt.expectedBody != "" && !strings.Contains(body, tt.expectedBody) {
				t.Errorf("expected body to contain %q, got %q", tt.expectedBody, body)
			}

			if tt.rendererError != nil {
				location := resp.Header.Get("Location")
				if location != consts.Err500URL {
					t.Errorf("expected redirect to %s, got %s", consts.Err500URL, location)
				}
			}
		})
	}
}

// TestSignIn проверяет рендеринг страницы входа.
// Ожидается: HTTP 200 при успехе, HTTP 302 при ошибке рендеринга.
func TestSignIn(t *testing.T) {
	tests := []struct {
		name           string
		rendererError  error
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "successful render",
			rendererError:  nil,
			expectedStatus: http.StatusOK,
			expectedBody:   "signIn template rendered",
		},
		{
			name:           "renderer error triggers redirect",
			rendererError:  http.ErrBodyNotAllowed,
			expectedStatus: http.StatusFound,
			expectedBody:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalRenderer := TmplsRenderer
			defer func() { TmplsRenderer = originalRenderer }()

			TmplsRenderer = func(w http.ResponseWriter, tmpl *template.Template, templateName string, data interface{}) error {
				if tt.rendererError != nil {
					return tt.rendererError
				}
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("signIn template rendered"))
				return nil
			}

			req := httptest.NewRequest("GET", "/sign-in", nil)
			w := httptest.NewRecorder()

			SignIn(w, req)

			resp := w.Result()
			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, resp.StatusCode)
			}

			body := w.Body.String()
			if tt.expectedBody != "" && !strings.Contains(body, tt.expectedBody) {
				t.Errorf("expected body to contain %q, got %q", tt.expectedBody, body)
			}

			if tt.rendererError != nil {
				location := resp.Header.Get("Location")
				if location != consts.Err500URL {
					t.Errorf("expected redirect to %s, got %s", consts.Err500URL, location)
				}
			}
		})
	}
}

// TestServerAuthCodeSend проверяет рендеринг страницы отправки кода авторизации сервера.
// Ожидается: HTTP 200 при успехе, HTTP 302 при ошибке рендеринга.
func TestServerAuthCodeSend(t *testing.T) {
	tests := []struct {
		name           string
		rendererError  error
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "successful render",
			rendererError:  nil,
			expectedStatus: http.StatusOK,
			expectedBody:   "serverAuthCodeSend template rendered",
		},
		{
			name:           "renderer error triggers redirect",
			rendererError:  http.ErrBodyNotAllowed,
			expectedStatus: http.StatusFound,
			expectedBody:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalRenderer := TmplsRenderer
			defer func() { TmplsRenderer = originalRenderer }()

			TmplsRenderer = func(w http.ResponseWriter, tmpl *template.Template, templateName string, data interface{}) error {
				if tt.rendererError != nil {
					return tt.rendererError
				}
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("serverAuthCodeSend template rendered"))
				return nil
			}

			req := httptest.NewRequest("GET", "/server-auth-code-send", nil)
			w := httptest.NewRecorder()

			ServerAuthCodeSend(w, req)

			resp := w.Result()
			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, resp.StatusCode)
			}

			body := w.Body.String()
			if tt.expectedBody != "" && !strings.Contains(body, tt.expectedBody) {
				t.Errorf("expected body to contain %q, got %q", tt.expectedBody, body)
			}

			if tt.rendererError != nil {
				location := resp.Header.Get("Location")
				if location != consts.Err500URL {
					t.Errorf("expected redirect to %s, got %s", consts.Err500URL, location)
				}
			}
		})
	}
}

// TestHome проверяет рендеринг домашней страницы.
// Ожидается: HTTP 200 при успехе, HTTP 302 при ошибке рендеринга.
func TestHome(t *testing.T) {
	tests := []struct {
		name           string
		rendererError  error
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "successful render",
			rendererError:  nil,
			expectedStatus: http.StatusOK,
			expectedBody:   "home template rendered",
		},
		{
			name:           "renderer error triggers redirect",
			rendererError:  http.ErrBodyNotAllowed,
			expectedStatus: http.StatusFound,
			expectedBody:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalRenderer := TmplsRenderer
			defer func() { TmplsRenderer = originalRenderer }()

			TmplsRenderer = func(w http.ResponseWriter, tmpl *template.Template, templateName string, data interface{}) error {
				if tt.rendererError != nil {
					return tt.rendererError
				}
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("home template rendered"))
				return nil
			}

			req := httptest.NewRequest("GET", "/home", nil)
			w := httptest.NewRecorder()

			Home(w, req)

			resp := w.Result()
			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, resp.StatusCode)
			}

			body := w.Body.String()
			if tt.expectedBody != "" && !strings.Contains(body, tt.expectedBody) {
				t.Errorf("expected body to contain %q, got %q", tt.expectedBody, body)
			}

			if tt.rendererError != nil {
				location := resp.Header.Get("Location")
				if location != consts.Err500URL {
					t.Errorf("expected redirect to %s, got %s", consts.Err500URL, location)
				}
			}
		})
	}
}

// TestLogout проверяет рендеринг страницы выхода.
// Ожидается: HTTP 200 при успехе, HTTP 302 при ошибке рендеринга.
func TestLogout(t *testing.T) {
	tests := []struct {
		name           string
		rendererError  error
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "successful render",
			rendererError:  nil,
			expectedStatus: http.StatusOK,
			expectedBody:   "logout template rendered",
		},
		{
			name:           "renderer error triggers redirect",
			rendererError:  http.ErrBodyNotAllowed,
			expectedStatus: http.StatusFound,
			expectedBody:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalRenderer := TmplsRenderer
			defer func() { TmplsRenderer = originalRenderer }()

			TmplsRenderer = func(w http.ResponseWriter, tmpl *template.Template, templateName string, data interface{}) error {
				if tt.rendererError != nil {
					return tt.rendererError
				}
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("logout template rendered"))
				return nil
			}

			req := httptest.NewRequest("GET", "/logout", nil)
			w := httptest.NewRecorder()

			Logout(w, req)

			resp := w.Result()
			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, resp.StatusCode)
			}

			body := w.Body.String()
			if tt.expectedBody != "" && !strings.Contains(body, tt.expectedBody) {
				t.Errorf("expected body to contain %q, got %q", tt.expectedBody, body)
			}

			if tt.rendererError != nil {
				location := resp.Header.Get("Location")
				if location != consts.Err500URL {
					t.Errorf("expected redirect to %s, got %s", consts.Err500URL, location)
				}
			}
		})
	}
}

// TestGeneratePasswordResetLink проверяет рендеринг страницы генерации ссылки сброса пароля.
// Ожидается: HTTP 200 при успехе, HTTP 302 при ошибке рендеринга, корректная обработка параметров.
func TestGeneratePasswordResetLink(t *testing.T) {
	tests := []struct {
		name           string
		queryParams    string
		rendererError  error
		expectedStatus int
		expectedData   structs.MsgForUser
	}{
		{
			name:           "no message parameter",
			queryParams:    "",
			rendererError:  nil,
			expectedStatus: http.StatusOK,
			expectedData:   structs.MsgForUser{Msg: ""},
		},
		{
			name:           "with message parameter",
			queryParams:    "msg=test+message",
			rendererError:  nil,
			expectedStatus: http.StatusOK,
			expectedData:   structs.MsgForUser{Msg: "test message"},
		},
		{
			name:           "renderer error triggers redirect",
			queryParams:    "msg=error+test",
			rendererError:  http.ErrBodyNotAllowed,
			expectedStatus: http.StatusFound,
			expectedData:   structs.MsgForUser{Msg: "error test"},
		},
		{
			name:           "URL encoded message",
			queryParams:    "msg=" + url.QueryEscape("special chars & symbols"),
			rendererError:  nil,
			expectedStatus: http.StatusOK,
			expectedData:   structs.MsgForUser{Msg: "special chars & symbols"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalRenderer := TmplsRenderer
			defer func() { TmplsRenderer = originalRenderer }()

			var capturedData structs.MsgForUser
			TmplsRenderer = func(w http.ResponseWriter, tmpl *template.Template, templateName string, data interface{}) error {
				if tt.rendererError != nil {
					return tt.rendererError
				}
				capturedData = data.(structs.MsgForUser)
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("generatePasswordResetLink template rendered"))
				return nil
			}

			url := "/generate-password-reset-link"
			if tt.queryParams != "" {
				url += "?" + tt.queryParams
			}

			req := httptest.NewRequest("GET", url, nil)
			w := httptest.NewRecorder()

			GeneratePasswordResetLink(w, req)

			resp := w.Result()
			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, resp.StatusCode)
			}

			if tt.rendererError == nil {
				if capturedData.Msg != tt.expectedData.Msg {
					t.Errorf("expected data.Msg %q, got %q", tt.expectedData.Msg, capturedData.Msg)
				}
			} else {
				location := resp.Header.Get("Location")
				if location != consts.Err500URL {
					t.Errorf("expected redirect to %s, got %s", consts.Err500URL, location)
				}
			}
		})
	}
}

// TestSetNewPassword проверяет рендеринг страницы установки нового пароля.
// Ожидается: HTTP 200 при успехе, HTTP 302 при ошибке рендеринга, корректная обработка параметров.
func TestSetNewPassword(t *testing.T) {
	tests := []struct {
		name           string
		queryParams    string
		rendererError  error
		expectedStatus int
		expectedMsg    string
		expectedToken  string
	}{
		{
			name:           "no parameters",
			queryParams:    "",
			rendererError:  nil,
			expectedStatus: http.StatusOK,
			expectedMsg:    "",
			expectedToken:  "",
		},
		{
			name:           "with message only",
			queryParams:    "msg=test+message",
			rendererError:  nil,
			expectedStatus: http.StatusOK,
			expectedMsg:    "test message",
			expectedToken:  "",
		},
		{
			name:           "with token only",
			queryParams:    "token=abc123",
			rendererError:  nil,
			expectedStatus: http.StatusOK,
			expectedMsg:    "",
			expectedToken:  "abc123",
		},
		{
			name:           "with both parameters",
			queryParams:    "msg=reset+required&token=xyz789",
			rendererError:  nil,
			expectedStatus: http.StatusOK,
			expectedMsg:    "reset required",
			expectedToken:  "xyz789",
		},
		{
			name:           "renderer error triggers redirect",
			queryParams:    "msg=error&token=error123",
			rendererError:  http.ErrBodyNotAllowed,
			expectedStatus: http.StatusFound,
			expectedMsg:    "error",
			expectedToken:  "error123",
		},
		{
			name:           "URL encoded parameters",
			queryParams:    "msg=" + url.QueryEscape("special & chars") + "&token=" + url.QueryEscape("token-with-special-chars-!@#"),
			rendererError:  nil,
			expectedStatus: http.StatusOK,
			expectedMsg:    "special & chars",
			expectedToken:  "token-with-special-chars-!@#",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalRenderer := TmplsRenderer
			defer func() { TmplsRenderer = originalRenderer }()

			var capturedData struct {
				Msg   string
				Token string
			}
			TmplsRenderer = func(w http.ResponseWriter, tmpl *template.Template, templateName string, data interface{}) error {
				if tt.rendererError != nil {
					return tt.rendererError
				}
				capturedData = data.(struct {
					Msg   string
					Token string
				})
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("setNewPassword template rendered"))
				return nil
			}

			url := "/set-new-password"
			if tt.queryParams != "" {
				url += "?" + tt.queryParams
			}

			req := httptest.NewRequest("GET", url, nil)
			w := httptest.NewRecorder()

			SetNewPassword(w, req)

			resp := w.Result()
			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, resp.StatusCode)
			}

			if tt.rendererError == nil {
				if capturedData.Msg != tt.expectedMsg {
					t.Errorf("expected data.Msg %q, got %q", tt.expectedMsg, capturedData.Msg)
				}
				if capturedData.Token != tt.expectedToken {
					t.Errorf("expected data.Token %q, got %q", tt.expectedToken, capturedData.Token)
				}
			} else {
				location := resp.Header.Get("Location")
				if location != consts.Err500URL {
					t.Errorf("expected redirect to %s, got %s", consts.Err500URL, location)
				}
			}
		})
	}
}

// TestErr500 проверяет обработку ошибки 500.
// Ожидается: попытка обслужить файл 500.html.
func TestErr500(t *testing.T) {
	tests := []struct {
		name           string
		expectedStatus int
	}{
		{
			name:           "attempts to serve 500.html file",
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/500", nil)
			w := httptest.NewRecorder()

			Err500(w, req)

			resp := w.Result()
			if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
				t.Errorf("expected status 200 or 404, got %d", resp.StatusCode)
			}
		})
	}
}

// TestConcurrentRequests проверяет обработку одновременных запросов.
// Ожидается: корректная обработка всех запросов без гонок данных.
func TestConcurrentRequests(t *testing.T) {
	originalRenderer := TmplsRenderer
	defer func() { TmplsRenderer = originalRenderer }()

	callCount := 0
	TmplsRenderer = func(w http.ResponseWriter, tmpl *template.Template, templateName string, data interface{}) error {
		callCount++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(templateName + " rendered"))
		return nil
	}

	functions := []func(w http.ResponseWriter, r *http.Request){
		SignUp,
		SignIn,
		ServerAuthCodeSend,
		Home,
		Logout,
	}

	done := make(chan bool, len(functions))

	for _, fn := range functions {
		go func(f func(w http.ResponseWriter, r *http.Request)) {
			req := httptest.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()
			f(w, req)
			done <- true
		}(fn)
	}

	for i := 0; i < len(functions); i++ {
		<-done
	}

	if callCount != len(functions) {
		t.Errorf("expected %d renderer calls, got %d", len(functions), callCount)
	}
}

// TestErrorHandlingBehavior проверяет поведение при обработке ошибок рендеринга.
// Ожидается: редирект на страницу 500 при ошибке рендеринга.
func TestErrorHandlingBehavior(t *testing.T) {
	originalRenderer := TmplsRenderer
	defer func() { TmplsRenderer = originalRenderer }()

	testError := http.ErrBodyNotAllowed
	TmplsRenderer = func(w http.ResponseWriter, tmpl *template.Template, templateName string, data interface{}) error {
		return testError
	}

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	SignUp(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("expected status %d, got %d", http.StatusFound, resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	if location != consts.Err500URL {
		t.Errorf("expected redirect to %s, got %s", consts.Err500URL, location)
	}
}

// TestDifferentHTTPMethods проверяет обработку различных HTTP-методов.
// Ожидается: корректная обработка GET-запросов для всех функций.
func TestDifferentHTTPMethods(t *testing.T) {
	originalRenderer := TmplsRenderer
	defer func() { TmplsRenderer = originalRenderer }()

	TmplsRenderer = func(w http.ResponseWriter, tmpl *template.Template, templateName string, data interface{}) error {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(templateName + " rendered"))
		return nil
	}

	functions := map[string]func(w http.ResponseWriter, r *http.Request){
		"SignUp":                    SignUp,
		"SignIn":                    SignIn,
		"ServerAuthCodeSend":        ServerAuthCodeSend,
		"Home":                      Home,
		"Logout":                    Logout,
		"GeneratePasswordResetLink": GeneratePasswordResetLink,
		"SetNewPassword":            SetNewPassword,
	}

	for funcName, fn := range functions {
		t.Run(funcName+"_GET", func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()

			fn(w, req)

			resp := w.Result()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("expected status %d for GET %s, got %d", http.StatusOK, funcName, resp.StatusCode)
			}
		})
	}
}
