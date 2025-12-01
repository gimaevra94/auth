package tools

import (
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gimaevra94/auth/app/structs"
	"github.com/golang-jwt/jwt"
)

func TestInputValidate_SignIn_ValidData(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)

	errMsgKey, err := InputValidate(r, "testuser", "", "password123", true)

	if errMsgKey != "" {
		t.Errorf("Expected empty error message key, got %s", errMsgKey)
	}

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestInputValidate_SignIn_InvalidLogin(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)

	testCases := []struct {
		login    string
		expected string
	}{
		{"", "loginInvalid"},
		{"ab", "loginInvalid"},
		{"a!", "loginInvalid"},
		{"thisisaverylongusernamethatexceedsthirty", "loginInvalid"},
	}

	for _, tc := range testCases {
		errMsgKey, err := InputValidate(r, tc.login, "", "password123", true)

		if errMsgKey != tc.expected {
			t.Errorf("Expected error message key %s for login %s, got %s", tc.expected, tc.login, errMsgKey)
		}

		if err == nil {
			t.Errorf("Expected error for login %s, got nil", tc.login)
		}
	}
}

func TestInputValidate_SignIn_InvalidPassword(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)

	testCases := []struct {
		password string
		expected string
	}{
		{"", "passwordInvalid"},
		{"abc", "passwordInvalid"},
		{"thisisaverylongpasswordthatexceedsthirty", "passwordInvalid"},
		{"password(", "passwordInvalid"},
	}

	for _, tc := range testCases {
		errMsgKey, err := InputValidate(r, "testuser", "", tc.password, true)

		if errMsgKey != tc.expected {
			t.Errorf("Expected error message key %s for password %s, got %s", tc.expected, tc.password, errMsgKey)
		}

		if err == nil {
			t.Errorf("Expected error for password %s, got nil", tc.password)
		}
	}
}

func TestInputValidate_SignUp_ValidData(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)

	errMsgKey, err := InputValidate(r, "testuser", "test@example.com", "password123", false)

	if errMsgKey != "" {
		t.Errorf("Expected empty error message key, got %s", errMsgKey)
	}

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestInputValidate_SignUp_InvalidEmail(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)

	testCases := []struct {
		email    string
		expected string
	}{
		{"", "emailInvalid"},
		{"invalid", "emailInvalid"},
		{"@example.com", "emailInvalid"},
		{"test@", "emailInvalid"},
		{"test.example.com", "emailInvalid"},
		{"test@.com", "emailInvalid"},
		{"test@example.", "emailInvalid"},
		{"test@example..com", "emailInvalid"},
	}

	for _, tc := range testCases {
		errMsgKey, err := InputValidate(r, "testuser", tc.email, "password123", false)

		if errMsgKey != tc.expected {
			t.Errorf("Expected error message key %s for email %s, got %s", tc.expected, tc.email, errMsgKey)
		}

		if err == nil {
			t.Errorf("Expected error for email %s, got nil", tc.email)
		}
	}
}

func TestInputValidate_SignUp_EmailNotRequiredForSignIn(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)

	errMsgKey, err := InputValidate(r, "testuser", "", "password123", true)

	if errMsgKey != "" {
		t.Errorf("Expected empty error message key, got %s", errMsgKey)
	}

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestInputValidate_CyrillicLogin(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)

	errMsgKey, err := InputValidate(r, "пользователь", "", "пароль123", true)

	if errMsgKey != "" {
		t.Errorf("Expected empty error message key, got %s", errMsgKey)
	}

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestInputValidate_CyrillicPassword(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)

	errMsgKey, err := InputValidate(r, "testuser", "", "пароль123", true)

	if errMsgKey != "" {
		t.Errorf("Expected empty error message key, got %s", errMsgKey)
	}

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestInputValidate_SpecialCharactersPassword(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)

	testCases := []string{
		"password123!",
		"password@123",
		"password#123",
		"password$123",
		"password%123",
		"password^123",
		"password&123",
		"password*123",
		"password-123",
		"password)123",
	}

	for _, password := range testCases {
		errMsgKey, err := InputValidate(r, "testuser", "", password, true)

		if errMsgKey != "" {
			t.Errorf("Expected empty error message key for password %s, got %s", password, errMsgKey)
		}

		if err != nil {
			t.Errorf("Expected no error for password %s, got %v", password, err)
		}
	}
}

func TestRefreshTokenValidate_ValidToken(t *testing.T) {
	os.Setenv("JWT_SECRET", "test_secret")
	defer os.Unsetenv("JWT_SECRET")

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})

	signedToken, err := token.SignedString([]byte("test_secret"))
	if err != nil {
		t.Fatal(err)
	}

	err = RefreshTokenValidate(signedToken)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestRefreshTokenValidate_ExpiredToken(t *testing.T) {
	os.Setenv("JWT_SECRET", "test_secret")
	defer os.Unsetenv("JWT_SECRET")

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		ExpiresAt: time.Now().Add(-time.Hour).Unix(),
	})

	signedToken, err := token.SignedString([]byte("test_secret"))
	if err != nil {
		t.Fatal(err)
	}

	err = RefreshTokenValidate(signedToken)

	if err == nil {
		t.Error("Expected error for expired token, got nil")
	}
}

func TestRefreshTokenValidate_InvalidSignature(t *testing.T) {
	os.Setenv("JWT_SECRET", "test_secret")
	defer os.Unsetenv("JWT_SECRET")

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})

	signedToken, err := token.SignedString([]byte("wrong_secret"))
	if err != nil {
		t.Fatal(err)
	}

	err = RefreshTokenValidate(signedToken)

	if err == nil {
		t.Error("Expected error for invalid signature, got nil")
	}
}

func TestRefreshTokenValidate_WrongSigningMethod(t *testing.T) {
	os.Setenv("JWT_SECRET", "test_secret")
	defer os.Unsetenv("JWT_SECRET")

	signedToken := "invalid.rs256.token"

	err := RefreshTokenValidate(signedToken)

	if err == nil {
		t.Error("Expected error for wrong signing method, got nil")
	}
}

func TestRefreshTokenValidate_EmptyToken(t *testing.T) {
	os.Setenv("JWT_SECRET", "test_secret")
	defer os.Unsetenv("JWT_SECRET")

	err := RefreshTokenValidate("")

	if err == nil {
		t.Error("Expected error for empty token, got nil")
	}
}

func TestRefreshTokenValidate_MalformedToken(t *testing.T) {
	os.Setenv("JWT_SECRET", "test_secret")
	defer os.Unsetenv("JWT_SECRET")

	err := RefreshTokenValidate("invalid_token")

	if err == nil {
		t.Error("Expected error for malformed token, got nil")
	}
}

func TestCodeValidate_ValidCodes(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)

	err := CodeValidate(r, "12345", "12345")

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestCodeValidate_EmptyClientCode(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)

	err := CodeValidate(r, "", "12345")

	if err == nil {
		t.Error("Expected error for empty client code, got nil")
	}
}

func TestCodeValidate_CodesNotMatch(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)

	err := CodeValidate(r, "12345", "67890")

	if err == nil {
		t.Error("Expected error for non-matching codes, got nil")
	}
}

func TestCodeValidate_CaseSensitive(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)

	err := CodeValidate(r, "abcde", "ABCDE")

	if err == nil {
		t.Error("Expected error for case-sensitive mismatch, got nil")
	}
}

func TestCodeValidate_SpecialCharacters(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)

	err := CodeValidate(r, "!@#$%", "!@#$%")

	if err != nil {
		t.Errorf("Expected no error for special characters, got %v", err)
	}
}

func TestEmailValidate_ValidEmails(t *testing.T) {
	testCases := []string{
		"test@example.com",
		"user.name@domain.co.uk",
		"user+tag@example.org",
		"user123@test-domain.com",
		"a@b.co",
		"test.email.with+symbol@example.com",
	}

	for _, email := range testCases {
		err := EmailValidate(email)

		if err != nil {
			t.Errorf("Expected no error for email %s, got %v", email, err)
		}
	}
}

func TestEmailValidate_InvalidEmails(t *testing.T) {
	testCases := []string{
		"",
		"invalid",
		"@example.com",
		"test@",
		"test.example.com",
		"test@.com",
		"test@example.",
		"test@example..com",
		"test@@example.com",
		"test@example..com",
		"test@example.c",
		"test space@example.com",
		"test@example.com ",
		" test@example.com",
	}

	for _, email := range testCases {
		err := EmailValidate(email)

		if err == nil {
			t.Errorf("Expected error for email %s, got nil", email)
		}
	}
}

func TestEmailValidate_CyrillicEmail(t *testing.T) {
	err := EmailValidate("test@пример.com")

	if err == nil {
		t.Error("Expected error for Cyrillic domain, got nil")
	}
}

func TestPasswordValidate_ValidPasswords(t *testing.T) {
	testCases := []string{
		"pass",
		"password123",
		"пароль123",
		"Password123!",
		"test-password",
		"12345678",
		"пасс",
		"a1b2c3d4",
		"password-",
		"password)",
	}

	for _, password := range testCases {
		err := PasswordValidate(password)

		if err != nil {
			t.Errorf("Expected no error for password %s, got %v", password, err)
		}
	}
}

func TestPasswordValidate_InvalidPasswords(t *testing.T) {
	testCases := []string{
		"",
		"abc",
		"thisisaverylongpasswordthatexceedsthirtycharacters",
		"password(",
		"password[",
		"password{",
		"password}",
		"password]",
		"password|",
		"password\\",
		"password/",
		"password:",
		"password;",
		"password\"",
		"password'",
		"password<",
		"password>",
		"password?",
		"password.",
		"password,",
	}

	for _, password := range testCases {
		err := PasswordValidate(password)

		if err == nil {
			t.Errorf("Expected error for password %s, got nil", password)
		}
	}
}

func TestPasswordValidate_MinimumLength(t *testing.T) {
	testCases := []string{
		"abcd",
		"1234",
		"тест",
		"a1b2",
	}

	for _, password := range testCases {
		err := PasswordValidate(password)

		if err != nil {
			t.Errorf("Expected no error for minimum length password %s, got %v", password, err)
		}
	}
}

func TestPasswordValidate_MaximumLength(t *testing.T) {
	password := strings.Repeat("a", 30)

	err := PasswordValidate(password)

	if err != nil {
		t.Errorf("Expected no error for maximum length password, got %v", err)
	}
}

func TestResetTokenValidate_ValidToken(t *testing.T) {
	os.Setenv("JWT_SECRET", "test_secret")
	defer os.Unsetenv("JWT_SECRET")

	claims := &structs.PasswordResetTokenClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		},
		Email: "test@example.com",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte("test_secret"))
	if err != nil {
		t.Fatal(err)
	}

	result, err := ResetTokenValidate(signedToken)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if result.Email != "test@example.com" {
		t.Errorf("Expected email test@example.com, got %s", result.Email)
	}
}

func TestResetTokenValidate_ExpiredToken(t *testing.T) {
	os.Setenv("JWT_SECRET", "test_secret")
	defer os.Unsetenv("JWT_SECRET")

	claims := &structs.PasswordResetTokenClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(-time.Hour).Unix(),
		},
		Email: "test@example.com",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte("test_secret"))
	if err != nil {
		t.Fatal(err)
	}

	result, err := ResetTokenValidate(signedToken)

	if err == nil {
		t.Error("Expected error for expired token, got nil")
	}

	if result != nil {
		t.Errorf("Expected nil result for expired token, got %v", result)
	}
}

func TestResetTokenValidate_InvalidSignature(t *testing.T) {
	os.Setenv("JWT_SECRET", "test_secret")
	defer os.Unsetenv("JWT_SECRET")

	claims := &structs.PasswordResetTokenClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		},
		Email: "test@example.com",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte("wrong_secret"))
	if err != nil {
		t.Fatal(err)
	}

	result, err := ResetTokenValidate(signedToken)

	if err == nil {
		t.Error("Expected error for invalid signature, got nil")
	}

	if result != nil {
		t.Errorf("Expected nil result for invalid signature, got %v", result)
	}
}

func TestResetTokenValidate_WrongSigningMethod(t *testing.T) {
	os.Setenv("JWT_SECRET", "test_secret")
	defer os.Unsetenv("JWT_SECRET")

	signedToken := "invalid.rs256.token"

	result, err := ResetTokenValidate(signedToken)

	if err == nil {
		t.Error("Expected error for wrong signing method, got nil")
	}

	if result != nil {
		t.Errorf("Expected nil result for wrong signing method, got %v", result)
	}
}

func TestResetTokenValidate_EmptyToken(t *testing.T) {
	os.Setenv("JWT_SECRET", "test_secret")
	defer os.Unsetenv("JWT_SECRET")

	result, err := ResetTokenValidate("")

	if err == nil {
		t.Error("Expected error for empty token, got nil")
	}

	if result != nil {
		t.Errorf("Expected nil result for empty token, got %v", result)
	}
}

func TestResetTokenValidate_MalformedToken(t *testing.T) {
	os.Setenv("JWT_SECRET", "test_secret")
	defer os.Unsetenv("JWT_SECRET")

	result, err := ResetTokenValidate("invalid_token")

	if err == nil {
		t.Error("Expected error for malformed token, got nil")
	}

	if result != nil {
		t.Errorf("Expected nil result for malformed token, got %v", result)
	}
}

func TestResetTokenValidate_MissingEmailClaim(t *testing.T) {
	os.Setenv("JWT_SECRET", "test_secret")
	defer os.Unsetenv("JWT_SECRET")

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
	signedToken, err := token.SignedString([]byte("test_secret"))
	if err != nil {
		t.Fatal(err)
	}

	result, err := ResetTokenValidate(signedToken)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if result.Email != "" {
		t.Errorf("Expected empty email, got %s", result.Email)
	}
}

func TestRegexPatterns_LoginRegex(t *testing.T) {
	testCases := map[string]bool{
		"abc":                   true,
		"user123":               true,
		"TestUser":              true,
		"пользователь":          true,
		"Пользователь":          true,
		"user123ру":             true,
		"":                      false,
		"ab":                    false,
		"a!":                    false,
		"user@":                 false,
		"user space":            false,
		"user\ttest":            false,
		"user\nuser":            false,
		strings.Repeat("a", 30): true,
		strings.Repeat("a", 31): false,
	}

	for login, expected := range testCases {
		result := loginRegex.MatchString(login)
		if result != expected {
			t.Errorf("Expected %v for login %s, got %v", expected, login, result)
		}
	}
}

func TestRegexPatterns_EmailRegex(t *testing.T) {
	testCases := map[string]bool{
		"test@example.com":        true,
		"user.name@domain.co.uk":  true,
		"user+tag@example.org":    true,
		"user123@test-domain.com": true,
		"a@b.co":                  true,
		"":                        false,
		"invalid":                 false,
		"@example.com":            false,
		"test@":                   false,
		"test.example.com":        false,
		"test@.com":               false,
		"test@example.":           false,
		"test@example..com":       false,
		"test@@example.com":       false,
		"test space@example.com":  false,
		"test@example.com ":       false,
		" test@example.com":       false,
	}

	for email, expected := range testCases {
		result := emailRegex.MatchString(email)
		if result != expected {
			t.Errorf("Expected %v for email %s, got %v", expected, email, result)
		}
	}
}

func TestRegexPatterns_PasswordRegex(t *testing.T) {
	testCases := map[string]bool{
		"pass":                  true,
		"password123":           true,
		"пароль123":             true,
		"Password123!":          true,
		"test-password":         true,
		"12345678":              true,
		"пасс":                  true,
		"a1b2c3d4":              true,
		"password-":             true,
		"password)":             true,
		"":                      false,
		"abc":                   false,
		"password(":             false,
		"password[":             false,
		"password{":             false,
		"password}":             false,
		"password]":             false,
		"password|":             false,
		"password\\":            false,
		"password/":             false,
		"password:":             false,
		"password;":             false,
		"password\"":            false,
		"password'":             false,
		"password<":             false,
		"password>":             false,
		"password?":             false,
		"password.":             false,
		"password,":             false,
		strings.Repeat("a", 30): true,
		strings.Repeat("a", 31): false,
	}

	for password, expected := range testCases {
		result := passwordRegex.MatchString(password)
		if result != expected {
			t.Errorf("Expected %v for password %s, got %v", expected, password, result)
		}
	}
}
