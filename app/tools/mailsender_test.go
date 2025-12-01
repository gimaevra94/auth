package tools

import (
	"net/smtp"
	"os"
	"strings"
	"testing"

	"github.com/gimaevra94/auth/app/tmpls"
	"github.com/pkg/errors"
)

type mockSMTPClient struct {
	shouldFail bool
	sentFrom   string
	sentTo     []string
	sentMsg    []byte
}

func (m *mockSMTPClient) SendMail(addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
	if m.shouldFail {
		return errors.New("SMTP send failed")
	}
	m.sentFrom = from
	m.sentTo = to
	m.sentMsg = msg
	return nil
}

var mockClient = &mockSMTPClient{}

func mockSendMail(addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
	return mockClient.SendMail(addr, auth, from, to, msg)
}

func TestServerAuthCodeGenerate(t *testing.T) {
	code := serverAuthCodeGenerate()

	if len(code) != 4 {
		t.Errorf("Expected code length 4, got %d", len(code))
	}

	for _, char := range code {
		if char < '0' || char > '9' {
			t.Errorf("Code contains non-numeric character: %c", char)
		}
	}

	codeInt := 0
	for _, char := range code {
		codeInt = codeInt*10 + int(char-'0')
	}

	if codeInt < 1000 || codeInt > 9999 {
		t.Errorf("Code %d is not in range 1000-9999", codeInt)
	}

	codes := make(map[string]bool)
	for i := 0; i < 100; i++ {
		code := serverAuthCodeGenerate()
		codes[code] = true
	}

	if len(codes) < 50 { 
		t.Errorf("Expected high uniqueness in generated codes, got only %d unique codes out of 100", len(codes))
	}
}

func TestSMTPServerAuth(t *testing.T) {
	serverEmail := "test@example.com"
	os.Setenv("SERVER_EMAIL_PASSWORD", "testpassword")
	defer os.Unsetenv("SERVER_EMAIL_PASSWORD")

	auth, addr := sMTPServerAuth(serverEmail)

	if auth == nil {
		t.Error("Expected non-nil auth object")
	}

	if addr != "smtp.yandex.ru" {
		t.Errorf("Expected address 'smtp.yandex.ru', got '%s'", addr)
	}

	serverEmail = ""
	auth, addr = sMTPServerAuth(serverEmail)

	if auth == nil {
		t.Error("Expected non-nil auth object even with empty server email")
	}
}

func TestExecuteTmpl(t *testing.T) {
	serverEmail := "server@example.com"
	userEmail := "user@example.com"

	data := struct{ Code string }{Code: "1234"}
	msg, err := executeTmpl(serverEmail, userEmail, authCodeSubject, data)
	if err != nil {
		t.Fatalf("Failed to execute auth code template: %v", err)
	}

	msgStr := string(msg)
	if !strings.Contains(msgStr, "From: "+serverEmail) {
		t.Error("Missing From header")
	}
	if !strings.Contains(msgStr, "To: "+userEmail) {
		t.Error("Missing To header")
	}
	if !strings.Contains(msgStr, "Subject: "+authCodeSubject) {
		t.Error("Missing Subject header")
	}
	if !strings.Contains(msgStr, "MIME-Version: 1.0") {
		t.Error("Missing MIME-Version header")
	}
	if !strings.Contains(msgStr, "Content-Type: text/html; charset=\"UTF-8\"") {
		t.Error("Missing Content-Type header")
	}
	if !strings.Contains(msgStr, "1234") {
		t.Error("Auth code 1234 not found in email body")
	}

	data2 := struct{ UserAgent string }{UserAgent: "Mozilla/5.0"}
	msg, err = executeTmpl(serverEmail, userEmail, suspiciousLoginSubject, data2)
	if err != nil {
		t.Fatalf("Failed to execute suspicious login template: %v", err)
	}

	if !strings.Contains(string(msg), "Subject: "+suspiciousLoginSubject) {
		t.Error("Wrong subject in suspicious login email")
	}
	if !strings.Contains(string(msg), "Mozilla/5.0") {
		t.Error("User-Agent Mozilla/5.0 not found in suspicious login email body")
	}

	data3 := struct {
		login     string
		userAgent string
	}{login: "testuser", userAgent: "Chrome"}
	msg, err = executeTmpl(serverEmail, userEmail, newDeviceLoginSubject, data3)
	if err != nil {
		t.Fatalf("Failed to execute new device login template: %v", err)
	}

	if !strings.Contains(string(msg), "Subject: "+newDeviceLoginSubject) {
		t.Error("Wrong subject in new device login email")
	}

	if !strings.Contains(string(msg), "new device") {
		t.Error("New device login information not found in email body")
	}

	if !strings.Contains(string(msg), "login") {
		t.Error("Login information not found in new device login email body")
	}

	data4 := struct{ ResetLink string }{ResetLink: "https://example.com/reset"}
	msg, err = executeTmpl(serverEmail, userEmail, passwordResetSubject, data4)
	if err != nil {
		t.Fatalf("Failed to execute password reset template: %v", err)
	}

	if !strings.Contains(string(msg), "Subject: "+passwordResetSubject) {
		t.Error("Wrong subject in password reset email")
	}
	if !strings.Contains(string(msg), "https://example.com/reset") {
		t.Error("Reset link https://example.com/reset not found in password reset email body")
	}

	_, err = executeTmpl(serverEmail, userEmail, "Unknown Subject", data)
	if err != nil {
		t.Errorf("Unexpected error with unknown subject: %v", err)
	}

	_, err = executeTmpl("", "", authCodeSubject, data)
	if err != nil {
		t.Errorf("Should handle empty parameters gracefully: %v", err)
	}
}

func TestMailSend(t *testing.T) {
	originalSendMailFunc := sendMailFunc
	defer func() { sendMailFunc = originalSendMailFunc }()
	sendMailFunc = mockSendMail
	
	serverEmail := "server@example.com"
	userEmail := "user@example.com"
	auth := smtp.PlainAuth("", serverEmail, "password", "smtp.example.com")
	addr := "smtp.example.com"
	msg := []byte("Test message")

	mockClient.shouldFail = false
	err := mailSend(serverEmail, userEmail, auth, addr, msg)
	if err != nil {
		t.Errorf("Unexpected error in mailSend: %v", err)
	}

	err = mailSend("", userEmail, auth, addr, msg)
	if err == nil {
		t.Error("Expected error with empty server email")
	}
}

func TestSendNewDeviceLoginEmail(t *testing.T) {
	originalSendMailFunc := sendMailFunc
	defer func() { sendMailFunc = originalSendMailFunc }()
	sendMailFunc = mockSendMail
	
	os.Setenv("SERVER_EMAIL", "server@example.com")
	os.Setenv("SERVER_EMAIL_PASSWORD", "password")
	defer func() {
		os.Unsetenv("SERVER_EMAIL")
		os.Unsetenv("SERVER_EMAIL_PASSWORD")
	}()

	login := "testuser"
	userEmail := "user@example.com"
	userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

	mockClient.shouldFail = false
	err := SendNewDeviceLoginEmail(login, userEmail, userAgent)
	if err != nil {
		t.Errorf("Unexpected error in SendNewDeviceLoginEmail: %v", err)
	}

	err = SendNewDeviceLoginEmail("", userEmail, userAgent)
	if err != nil {
		t.Errorf("Should handle empty login gracefully: %v", err)
	}

	err = SendNewDeviceLoginEmail(login, "", userAgent)
	if err != nil {
		t.Errorf("Should handle empty user email gracefully: %v", err)
	}
}

func TestSuspiciousLoginEmailSend(t *testing.T) {
	originalSendMailFunc := sendMailFunc
	defer func() { sendMailFunc = originalSendMailFunc }()
	sendMailFunc = mockSendMail
	
	os.Setenv("SERVER_EMAIL", "server@example.com")
	os.Setenv("SERVER_EMAIL_PASSWORD", "password")
	defer func() {
		os.Unsetenv("SERVER_EMAIL")
		os.Unsetenv("SERVER_EMAIL_PASSWORD")
	}()

	userEmail := "user@example.com"
	userAgent := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"

	mockClient.shouldFail = false
	err := SuspiciousLoginEmailSend(userEmail, userAgent)
	if err != nil {
		t.Errorf("Unexpected error in SuspiciousLoginEmailSend: %v", err)
	}

	err = SuspiciousLoginEmailSend("", userAgent)
	if err != nil {
		t.Errorf("Should handle empty user email gracefully: %v", err)
	}

	err = SuspiciousLoginEmailSend(userEmail, "")
	if err != nil {
		t.Errorf("Should handle empty user agent gracefully: %v", err)
	}
}

func TestPasswordResetEmailSend(t *testing.T) {
	originalSendMailFunc := sendMailFunc
	defer func() { sendMailFunc = originalSendMailFunc }()
	sendMailFunc = mockSendMail
	
	os.Setenv("SERVER_EMAIL", "server@example.com")
	os.Setenv("SERVER_EMAIL_PASSWORD", "password")
	defer func() {
		os.Unsetenv("SERVER_EMAIL")
		os.Unsetenv("SERVER_EMAIL_PASSWORD")
	}()

	userEmail := "user@example.com"
	resetLink := "https://example.com/reset?token=abc123"

	mockClient.shouldFail = false
	err := PasswordResetEmailSend(userEmail, resetLink)
	if err != nil {
		t.Errorf("Unexpected error in PasswordResetEmailSend: %v", err)
	}

	err = PasswordResetEmailSend("", resetLink)
	if err != nil {
		t.Errorf("Should handle empty user email gracefully: %v", err)
	}

	err = PasswordResetEmailSend(userEmail, "")
	if err != nil {
		t.Errorf("Should handle empty reset link gracefully: %v", err)
	}
}

func TestServerAuthCodeSend(t *testing.T) {
	originalSendMailFunc := sendMailFunc
	defer func() { sendMailFunc = originalSendMailFunc }()
	sendMailFunc = mockSendMail
	
	os.Setenv("SERVER_EMAIL", "server@example.com")
	os.Setenv("SERVER_EMAIL_PASSWORD", "password")
	defer func() {
		os.Unsetenv("SERVER_EMAIL")
		os.Unsetenv("SERVER_EMAIL_PASSWORD")
	}()

	userEmail := "user@example.com"

	mockClient.shouldFail = false
	code, err := ServerAuthCodeSend(userEmail)
	if err != nil {
		t.Errorf("Unexpected error in ServerAuthCodeSend: %v", err)
	}

	if len(code) != 4 {
		t.Errorf("Expected 4-digit code, got code of length %d", len(code))
	}

	for _, char := range code {
		if char < '0' || char > '9' {
			t.Errorf("Code contains non-numeric character: %c", char)
		}
	}

	_, err = ServerAuthCodeSend("")
	if err != nil {
		t.Errorf("Should handle empty user email gracefully: %v", err)
	}
}

func TestEmailSubjects(t *testing.T) {
	tests := []struct {
		name     string
		subject  string
		expected string
	}{
		{"AuthCodeSubject", authCodeSubject, "Auth code"},
		{"SuspiciousLoginSubject", suspiciousLoginSubject, "Suspicious login alert!"},
		{"NewDeviceLoginSubject", newDeviceLoginSubject, "New device login"},
		{"PasswordResetSubject", passwordResetSubject, "Password reset request"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.subject != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, tt.subject)
			}
		})
	}
}

func TestErrorHandling(t *testing.T) {
	os.Unsetenv("SERVER_EMAIL")
	os.Unsetenv("SERVER_EMAIL_PASSWORD")
	defer func() {
		os.Unsetenv("SERVER_EMAIL")
		os.Unsetenv("SERVER_EMAIL_PASSWORD")
	}()

	userEmail := "user@example.com"

	_, err := ServerAuthCodeSend(userEmail)
	if err == nil {
		t.Error("Expected error when SERVER_EMAIL is not set")
	}

	err = SendNewDeviceLoginEmail("testuser", userEmail, "Mozilla/5.0")
	if err == nil {
		t.Error("Expected error when SERVER_EMAIL is not set")
	}

	err = SuspiciousLoginEmailSend(userEmail, "Mozilla/5.0")
	if err == nil {
		t.Error("Expected error when SERVER_EMAIL is not set")
	}

	err = PasswordResetEmailSend(userEmail, "https://example.com/reset")
	if err == nil {
		t.Error("Expected error when SERVER_EMAIL is not set")
	}
}

func TestConcurrentCodeGeneration(t *testing.T) {
	const numGoroutines = 10
	const numCodesPerGoroutine = 100

	codeChan := make(chan string, numGoroutines*numCodesPerGoroutine)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			for j := 0; j < numCodesPerGoroutine; j++ {
				codeChan <- serverAuthCodeGenerate()
			}
		}()
	}

	codes := make(map[string]bool)
	for i := 0; i < numGoroutines*numCodesPerGoroutine; i++ {
		code := <-codeChan
		codes[code] = true

		if len(code) != 4 {
			t.Errorf("Generated code %s has invalid length", code)
		}

		for _, char := range code {
			if char < '0' || char > '9' {
				t.Errorf("Generated code %s contains non-numeric character", code)
			}
		}
	}

	if len(codes) < numGoroutines*numCodesPerGoroutine/2 {
		t.Errorf("Low uniqueness in concurrent generation: %d unique codes out of %d total",
			len(codes), numGoroutines*numCodesPerGoroutine)
	}
}

func BenchmarkServerAuthCodeGenerate(b *testing.B) {
	for i := 0; i < b.N; i++ {
		serverAuthCodeGenerate()
	}
}

func BenchmarkExecuteTmpl(b *testing.B) {
	serverEmail := "server@example.com"
	userEmail := "user@example.com"
	data := struct{ Code string }{Code: "1234"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = executeTmpl(serverEmail, userEmail, authCodeSubject, data)
	}
}

func TestTemplateIntegration(t *testing.T) {
	if tmpls.BaseTmpl == nil {
		t.Skip("Templates not initialized, skipping integration test")
		return
	}

	serverEmail := "server@example.com"
	userEmail := "user@example.com"

	testCases := []struct {
		name    string
		subject string
		data    interface{}
	}{
		{
			name:    "AuthCode",
			subject: authCodeSubject,
			data:    struct{ Code string }{Code: "1234"},
		},
		{
			name:    "SuspiciousLogin",
			subject: suspiciousLoginSubject,
			data:    struct{ UserAgent string }{UserAgent: "Test Browser"},
		},
		{
			name:    "NewDeviceLogin",
			subject: newDeviceLoginSubject,
			data: struct {
				login     string
				userAgent string
			}{login: "testuser", userAgent: "Test Browser"},
		},
		{
			name:    "PasswordReset",
			subject: passwordResetSubject,
			data:    struct{ ResetLink string }{ResetLink: "https://example.com/reset"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			msg, err := executeTmpl(serverEmail, userEmail, tc.subject, tc.data)
			if err != nil {
				t.Fatalf("Failed to execute template %s: %v", tc.name, err)
			}

			msgStr := string(msg)

			requiredHeaders := []string{
				"From: " + serverEmail,
				"To: " + userEmail,
				"Subject: " + tc.subject,
				"MIME-Version: 1.0",
				"Content-Type: text/html; charset=\"UTF-8\"",
			}

			for _, header := range requiredHeaders {
				if !strings.Contains(msgStr, header) {
					t.Errorf("Missing required header in %s: %s", tc.name, header)
				}
			}

			if !strings.Contains(msgStr, "\r\n\r\n") {
				t.Errorf("Email body appears to be empty in %s", tc.name)
			}
			
			switch tc.name {
			case "AuthCode":
				if !strings.Contains(msgStr, "1234") {
					t.Errorf("Auth code 1234 not found in %s email body", tc.name)
				}
			case "SuspiciousLogin":
				if !strings.Contains(msgStr, "Test Browser") {
					t.Errorf("User-Agent Test Browser not found in %s email body", tc.name)
				}
			case "NewDeviceLogin":
				if !strings.Contains(msgStr, "new device") {
					t.Errorf("New device login information not found in %s email body", tc.name)
				}
				if !strings.Contains(msgStr, "login") {
					t.Errorf("Login information not found in %s email body", tc.name)
				}
			case "PasswordReset":
				if !strings.Contains(msgStr, "https://example.com/reset") {
					t.Errorf("Reset link not found in %s email body", tc.name)
				}
			}
		})
	}
}
