// Package errs предоставляет утилиты для обработки ошибок.
//
// Файл тестирует функцию LogAndRedirectIfErrNotNill, которая логирует ошибки
// и выполняет перенаправление пользователя на указанный URL.
package errs

import (
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gimaevra94/auth/app/consts"
)

// TestLogAndRedirectIfErrNotNill проверяет основную функциональность обработки ошибок.
// Ожидается: HTTP 302, редирект на соответствующий URL в зависимости от ошибки и параметров.
func TestLogAndRedirectIfErrNotNill(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		url            string
		expectedStatus int
		expectedURL    string
	}{
		{
			name:           "Ошибка с пустым URL",
			err:            &testError{msg: "тестовая ошибка"},
			url:            "",
			expectedStatus: http.StatusFound,
			expectedURL:    consts.Err500URL,
		},
		{
			name:           "Ошибка с корневым URL",
			err:            &testError{msg: "тестовая ошибка"},
			url:            "/",
			expectedStatus: http.StatusFound,
			expectedURL:    consts.Err500URL,
		},
		{
			name:           "Ошибка с кастомным URL",
			err:            &testError{msg: "тестовая ошибка"},
			url:            "/custom-error",
			expectedStatus: http.StatusFound,
			expectedURL:    "/custom-error",
		},
		{
			name:           "Ошибка с относительным URL",
			err:            &testError{msg: "тестовая ошибка"},
			url:            "/sign-in",
			expectedStatus: http.StatusFound,
			expectedURL:    "/sign-in",
		},
		{
			name:           "Ошибка с абсолютным URL",
			err:            &testError{msg: "тестовая ошибка"},
			url:            "https://example.com/error",
			expectedStatus: http.StatusFound,
			expectedURL:    "https://example.com/error",
		},
		{
			name:           "Ошибка с URL содержащим параметры",
			err:            &testError{msg: "тестовая ошибка"},
			url:            "/error?code=500&msg=test",
			expectedStatus: http.StatusFound,
			expectedURL:    "/error?code=500&msg=test",
		},
		{
			name:           "Ошибка с URL содержащим фрагмент",
			err:            &testError{msg: "тестовая ошибка"},
			url:            "/error#section",
			expectedStatus: http.StatusFound,
			expectedURL:    "/error#section",
		},
		{
			name:           "Ошибка с длинным URL",
			err:            &testError{msg: "тестовая ошибка"},
			url:            "/very/long/error/path/with/many/segments",
			expectedStatus: http.StatusFound,
			expectedURL:    "/very/long/error/path/with/many/segments",
		},
		{
			name:           "Ошибка с URL содержащим Unicode",
			err:            &testError{msg: "тестовая ошибка"},
			url:            "/ошибка",
			expectedStatus: http.StatusFound,
			expectedURL:    "/%d0%be%d1%88%d0%b8%d0%b1%d0%ba%d0%b0",
		},
		{
			name:           "Ошибка с URL содержащим пробелы",
			err:            &testError{msg: "тестовая ошибка"},
			url:            "/error page",
			expectedStatus: http.StatusFound,
			expectedURL:    "/error page",
		},
		{
			name:           "Ошибка с nil ошибкой",
			err:            nil,
			url:            "/test",
			expectedStatus: http.StatusFound,
			expectedURL:    "/test",
		},
		{
			name:           "Ошибка с пустым сообщением",
			err:            &testError{msg: ""},
			url:            "/test",
			expectedStatus: http.StatusFound,
			expectedURL:    "/test",
		},
		{
			name:           "Ошибка с очень длинным сообщением",
			err:            &testError{msg: strings.Repeat("ошибка ", 1000)},
			url:            "/test",
			expectedStatus: http.StatusFound,
			expectedURL:    "/test",
		},
		{
			name:           "Ошибка с специальными символами в сообщении",
			err:            &testError{msg: "ошибка: !@#$%^&*()_+-=[]{}|;':\",./<>?"},
			url:            "/test",
			expectedStatus: http.StatusFound,
			expectedURL:    "/test",
		},
		{
			name:           "Ошибка с переносами строк в сообщении",
			err:            &testError{msg: "ошибка\nвторая строка\nтретья строка"},
			url:            "/test",
			expectedStatus: http.StatusFound,
			expectedURL:    "/test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logOutput strings.Builder
			log.SetOutput(&logOutput)

			req := httptest.NewRequest("GET", "/", nil)
			w := httptest.NewRecorder()

			LogAndRedirectIfErrNotNill(w, req, tt.err, tt.url)

			resp := w.Result()
			defer resp.Body.Close()

			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("Ожидаемый статус %d, получен %d", tt.expectedStatus, resp.StatusCode)
			}

			location := resp.Header.Get("Location")
			if location != tt.expectedURL {
				t.Errorf("Ожидаемый URL %s, получен %s", tt.expectedURL, location)
			}

			if tt.err != nil {
				if !strings.Contains(logOutput.String(), tt.err.Error()) {
					t.Errorf("Лог не содержит сообщение об ошибке: %s", tt.err.Error())
				}
			}
		})
	}
}

// TestLogAndRedirectIfErrNotNillWithDifferentHTTPMethods проверяет работу функции с различными HTTP методами.
// Ожидается: HTTP 302 для всех методов, редирект на указанный URL.
func TestLogAndRedirectIfErrNotNillWithDifferentHTTPMethods(t *testing.T) {
	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH"}
	err := &testError{msg: "тестовая ошибка"}
	url := "/test-error"

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/", nil)
			w := httptest.NewRecorder()

			LogAndRedirectIfErrNotNill(w, req, err, url)

			resp := w.Result()
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusFound {
				t.Errorf("Ожидаемый статус %d для метода %s, получен %d", http.StatusFound, method, resp.StatusCode)
			}

			location := resp.Header.Get("Location")
			if location != url {
				t.Errorf("Ожидаемый URL %s для метода %s, получен %s", url, method, location)
			}
		})
	}
}

// TestLogAndRedirectIfErrNotNillWithDifferentErrorTypes проверяет работу функции с различными типами ошибок.
// Ожидается: HTTP 302, редирект на указанный URL для всех типов ошибок.
func TestLogAndRedirectIfErrNotNillWithDifferentErrorTypes(t *testing.T) {
	errors := []struct {
		name string
		err  error
	}{
		{"Стандартная ошибка", &testError{msg: "стандартная ошибка"}},
		{"Ошибка с форматированием", &testError{msg: "ошибка с кодом: %d"}},
		{"Ошибка без сообщения", &testError{msg: ""}},
		{"Nil ошибка", nil},
	}

	url := "/test-error"

	for _, testErr := range errors {
		t.Run(testErr.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			w := httptest.NewRecorder()

			LogAndRedirectIfErrNotNill(w, req, testErr.err, url)

			resp := w.Result()
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusFound {
				t.Errorf("Ожидаемый статус %d, получен %d", http.StatusFound, resp.StatusCode)
			}

			location := resp.Header.Get("Location")
			if location != url {
				t.Errorf("Ожидаемый URL %s, получен %s", url, location)
			}
		})
	}
}

// TestLogAndRedirectIfErrNotNillEdgeCases проверяет граничные случаи обработки ошибок.
// Ожидается: HTTP 302, корректная обработка специальных символов и пустых URL.
func TestLogAndRedirectIfErrNotNillEdgeCases(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		url            string
		expectedStatus int
		expectedURL    string
	}{
		{
			name:           "URL только с пробелами",
			err:            &testError{msg: "ошибка"},
			url:            "   ",
			expectedStatus: http.StatusFound,
			expectedURL:    "/   ",
		},
		{
			name:           "URL с табуляцией",
			err:            &testError{msg: "ошибка"},
			url:            "\t",
			expectedStatus: http.StatusFound,
			expectedURL:    "\t",
		},
		{
			name:           "URL с новой строкой",
			err:            &testError{msg: "ошибка"},
			url:            "\n",
			expectedStatus: http.StatusFound,
			expectedURL:    "\n",
		},
		{
			name:           "URL с нулевым символом",
			err:            &testError{msg: "ошибка"},
			url:            "\000",
			expectedStatus: http.StatusFound,
			expectedURL:    "\000",
		},
		{
			name:           "Пустой URL с ошибкой",
			err:            &testError{msg: "ошибка"},
			url:            "",
			expectedStatus: http.StatusFound,
			expectedURL:    consts.Err500URL,
		},
		{
			name:           "Корневой URL с ошибкой",
			err:            &testError{msg: "ошибка"},
			url:            "/",
			expectedStatus: http.StatusFound,
			expectedURL:    consts.Err500URL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			w := httptest.NewRecorder()

			LogAndRedirectIfErrNotNill(w, req, tt.err, tt.url)

			resp := w.Result()
			defer resp.Body.Close()

			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("Ожидаемый статус %d, получен %d", tt.expectedStatus, resp.StatusCode)
			}

			location := resp.Header.Get("Location")
			if location != tt.expectedURL {
				t.Errorf("Ожидаемый URL %s, получен %s", tt.expectedURL, location)
			}
		})
	}
}

// TestLogAndRedirectIfErrNotNillConcurrent проверяет работу функции при параллельных вызовах.
// Ожидается: HTTP 302 для всех параллельных запросов, отсутствие гонок данных.
func TestLogAndRedirectIfErrNotNillConcurrent(t *testing.T) {
	t.Run("Параллельные вызовы", func(t *testing.T) {
		t.Parallel()

		for i := 0; i < 100; i++ {
			i := i
			t.Run("", func(t *testing.T) {
				t.Parallel()
				req := httptest.NewRequest("GET", "/", nil)
				w := httptest.NewRecorder()

				err := &testError{msg: "ошибка"}
				url := "/test"

				LogAndRedirectIfErrNotNill(w, req, err, url)

				resp := w.Result()
				defer resp.Body.Close()

				if resp.StatusCode != http.StatusFound {
					t.Errorf("Итерация %d: ожидаемый статус %d, получен %d", i, http.StatusFound, resp.StatusCode)
				}

				location := resp.Header.Get("Location")
				if location != url {
					t.Errorf("Итерация %d: ожидаемый URL %s, получен %s", i, url, location)
				}
			})
		}
	})
}

// testError является тестовой реализацией интерфейса error для использования в тестах.
type testError struct {
	msg string
}

// Error возвращает сообщение об ошибке для тестовой реализации.
func (e *testError) Error() string {
	return e.msg
}
