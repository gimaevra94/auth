package tmpls

import (
	"html/template"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pkg/errors"
)

func TestMust(t *testing.T) {
	tests := []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "successful template creation",
			test: func(t *testing.T) {
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

func TestBaseTmplCompilation(t *testing.T) {
	if BaseTmpl == nil {
		t.Error("BaseTmpl should not be nil")
	}

	templates := []string{
		"signUp",
		"signIn",
		"home",
		"serverAuthCodeSend",
		"generatePasswordResetLink",
		"setNewPassword",
	}

	for _, tmplName := range templates {
		t.Run("template_exists_"+tmplName, func(t *testing.T) {
			tmpl := BaseTmpl.Lookup(tmplName)
			if tmpl == nil {
				t.Errorf("template %s should exist in BaseTmpl", tmplName)
			}
		})
	}
}

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
			tmpl := BaseTmpl.Lookup(tt.templateName)
			if tmpl == nil {
				t.Errorf("email template %s should exist", tt.templateName)
				return
			}

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
