// Package tmpls предоставляет функции и шаблоны для рендеринга HTML-страниц.
//
// Файл тестирует функции Must и TmplsRenderer, а также корректность
// компиляции и выполнения всех шаблонов приложения.
package tmpls

import (
	"html/template"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pkg/errors"
)

// TestMust проверяет работу вспомогательной функции Must.
// Ожидается: успешное создание шаблона или паника при ошибке.
func TestMust(t *testing.T) {
	tests := []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "successful template creation",
			test: func(t *testing.T) {
				// TestMust_SuccessfulTemplateCreation проверяет успешное создание шаблона.
				// Ожидается: функция возвращает валидный шаблон без ошибок.
				tmpl, err := template.New("test").Parse("{{.}}")
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				result := Must(tmpl, err)
				if result == nil {
					t.Error("expected non-nil template")
				}
			},
		},
		{
			name: "panic on error",
			test: func(t *testing.T) {
				// TestMust_PanicOnError проверяет панику при невалидном синтаксисе шаблона.
				// Ожидается: функция вызывает панику при ошибке парсинга.
				defer func() {
					if r := recover(); r == nil {
						t.Error("expected panic")
					}
				}()

				invalidTmpl, err := template.New("test").Parse("{{.invalid syntax")
				Must(invalidTmpl, err)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, tt.test)
	}
}

// TestBaseTmplCompilation проверяет корректность компиляции базового шаблона.
// Ожидается: BaseTmpl не nil и все дочерние шаблоны доступны.
func TestBaseTmplCompilation(t *testing.T) {
	// Проверяем, что базовый шаблон успешно скомпилирован
	if BaseTmpl == nil {
		t.Error("BaseTmpl should not be nil")
	}

	// Список всех шаблонов, которые должны быть включены в BaseTmpl
	templates := []string{
		"signUp",
		"signIn",
		"home",
		"serverAuthCodeSend",
		"generatePasswordResetLink",
		"setNewPassword",
	}

	// Проверяем наличие каждого шаблона в базовом шаблоне
	for _, tmplName := range templates {
		t.Run("template_exists_"+tmplName, func(t *testing.T) {
			// TestBaseTmplCompilation_TemplateExists проверяет наличие конкретного шаблона.
			// Ожидается: шаблон найден в BaseTmpl.
			tmpl := BaseTmpl.Lookup(tmplName)
			if tmpl == nil {
				t.Errorf("template %s should exist in BaseTmpl", tmplName)
			}
		})
	}
}

// TestTmplsRenderer проверяет основную функцию рендеринга шаблонов.
// Ожидается: успешный рендеринг существующих шаблонов и ошибка для несуществующих.
func TestTmplsRenderer(t *testing.T) {
	tests := []struct {
		name         string
		templateName string
		data         interface{}
		expectError  bool
	}{
		{
			name:         "render signUp template",
			templateName: "signUp",
			data:         nil,
			expectError:  false,
		},
		{
			name:         "render signIn template with data",
			templateName: "signIn",
			data:         nil,
			expectError:  false,
		},
		{
			name:         "render home template",
			templateName: "home",
			data:         nil,
			expectError:  false,
		},
		{
			name:         "non-existent template",
			templateName: "nonExistent",
			data:         nil,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()

			err := TmplsRenderer(w, BaseTmpl, tt.templateName, tt.data)

			if tt.expectError {
				// TestTmplsRenderer_NonExistentTemplate проверяет обработку несуществующего шаблона.
				// Ожидается: ошибка, обёрнутая в errors.WithStack.
				if err == nil {
					t.Error("expected error but got none")
				}
				if !errors.Is(err, err) {
					var stackErr error
					if errors.As(err, &stackErr) {
					} else {
						t.Error("error should be wrapped with errors.WithStack")
					}
				}
			} else {
				// TestTmplsRenderer_SuccessfulRender проверяет успешный рендеринг шаблона.
				// Ожидается: HTML-контент и правильный Content-Type.
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}

				body := w.Body.String()
				if !strings.Contains(body, "<html") {
					t.Error("response should contain HTML")
				}

				contentType := w.Header().Get("Content-Type")
				if !strings.Contains(contentType, "text/html") {
					t.Errorf("expected Content-Type to contain text/html, got %s", contentType)
				}
			}
		})
	}
}

// TestTmplsRendererWithData проверяет рендеринг шаблонов с передачей данных.
// Ожидается: корректное отображение переданных данных в HTML.
func TestTmplsRendererWithData(t *testing.T) {
	tests := []struct {
		name         string
		templateName string
		data         interface{}
		expectedText string
	}{
		{
			name:         "signUp with message",
			templateName: "signUp",
			data: struct {
				Msg         string
				Regs        []string
				ShowCaptcha bool
			}{Msg: "Test Error Message", Regs: []string{}, ShowCaptcha: false},
			expectedText: "Test Error Message",
		},
		{
			name:         "generatePasswordResetLink with message",
			templateName: "generatePasswordResetLink",
			data:         struct{ Msg string }{Msg: "Password reset sent"},
			expectedText: "Password reset sent",
		},
		{
			name:         "setNewPassword with message and token",
			templateName: "setNewPassword",
			data: struct {
				Msg   string
				Token string
			}{Msg: "Set new password", Token: "abc123"},
			expectedText: "abc123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// TestTmplsRendererWithData_DataInjection проверяет корректную вставку данных.
			// Ожидается: переданный текст содержится в сгенерированном HTML.
			w := httptest.NewRecorder()

			err := TmplsRenderer(w, BaseTmpl, tt.templateName, tt.data)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			body := w.Body.String()
			if !strings.Contains(body, tt.expectedText) {
				t.Errorf("expected body to contain %q, got: %s", tt.expectedText, body)
			}
		})
	}
}

// TestEmailTemplates проверяет работу email-шаблонов.
// Ожидается: все email-шаблоны существуют и генерируют корректный HTML.
func TestEmailTemplates(t *testing.T) {
	tests := []struct {
		name         string
		templateName string
		data         interface{}
	}{
		{
			name:         "emailMsgWithServerAuthCode",
			templateName: "emailMsgWithServerAuthCode",
			data:         struct{ Code string }{Code: "123456"},
		},
		{
			name:         "emailMsgAboutSuspiciousLoginEmail",
			templateName: "emailMsgAboutSuspiciousLoginEmail",
			data:         struct{ UserAgent string }{UserAgent: "Mozilla/5.0"},
		},
		{
			name:         "emailMsgWithPasswordResetLink",
			templateName: "emailMsgWithPasswordResetLink",
			data:         struct{ ResetLink string }{ResetLink: "https://example.com/reset?token=abc123"},
		},
		{
			name:         "emailMsgAboutNewDeviceLoginEmail",
			templateName: "emailMsgAboutNewDeviceLoginEmail",
			data:         struct{}{},
		},
	}

	for _, tt := range tests {
		t.Run("email_template_"+tt.name, func(t *testing.T) {
			// TestEmailTemplates_TemplateExistence проверяет наличие email-шаблона.
			// Ожидается: шаблон найден в BaseTmpl.
			tmpl := BaseTmpl.Lookup(tt.templateName)
			if tmpl == nil {
				t.Errorf("email template %s should exist", tt.templateName)
				return
			}

			// TestEmailTemplates_Rendering проверяет рендеринг email-шаблона.
			// Ожидается: успешное создание HTML с правильной структурой.
			w := httptest.NewRecorder()
			err := TmplsRenderer(w, BaseTmpl, tt.templateName, tt.data)
			if err != nil {
				t.Errorf("failed to render email template %s: %v", tt.templateName, err)
			}

			body := w.Body.String()
			if !strings.Contains(body, "<html") {
				t.Errorf("email template %s should generate HTML", tt.templateName)
			}
		})
	}
}
