// Package data предоставляет функции для работы с базой данных сессиями и cookie.
//
// Файл тестирует функции SetTemporaryIdInCookies, GetTemporaryIdFromCookies, ClearTemporaryIdInCookies и ClearCookiesDev.
package data

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gimaevra94/auth/app/consts"
)

// TestSetTemporaryIdInCookies_WithRememberMe проверяет установку cookie с флагом rememberMe.
// Ожидается: cookie с правильными свойствами и временем жизни 7 дней.
func TestSetTemporaryIdInCookies_WithRememberMe(t *testing.T) {
	w := httptest.NewRecorder()
	value := "test-temp-id"
	temporaryIdExp := 7 * 24 * 60 * 60
	rememberMe := true

	SetTemporaryIdInCookies(w, value, temporaryIdExp, rememberMe)

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Expected 1 cookie, got %d", len(cookies))
	}

	cookie := cookies[0]
	if cookie.Name != "temporaryId" {
		t.Errorf("Expected cookie name 'temporaryId', got '%s'", cookie.Name)
	}
	if cookie.Value != value {
		t.Errorf("Expected cookie value '%s', got '%s'", value, cookie.Value)
	}
	if cookie.Path != "/" {
		t.Errorf("Expected cookie path '/', got '%s'", cookie.Path)
	}
	if !cookie.HttpOnly {
		t.Error("Expected cookie to be HttpOnly")
	}
	if cookie.Secure {
		t.Error("Expected cookie Secure to be false")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("Expected SameSiteLaxMode, got %v", cookie.SameSite)
	}
	if cookie.MaxAge != temporaryIdExp {
		t.Errorf("Expected MaxAge %d, got %d", temporaryIdExp, cookie.MaxAge)
	}
}

// TestSetTemporaryIdInCookies_WithoutRememberMe проверяет установку cookie без флага rememberMe.
// Ожидается: cookie с временем жизни 24 часа.
func TestSetTemporaryIdInCookies_WithoutRememberMe(t *testing.T) {
	w := httptest.NewRecorder()
	value := "test-temp-id"
	temporaryIdExp := 7 * 24 * 60 * 60
	rememberMe := false

	SetTemporaryIdInCookies(w, value, temporaryIdExp, rememberMe)

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Expected 1 cookie, got %d", len(cookies))
	}

	cookie := cookies[0]
	expectedMaxAge := 24 * 60 * 60
	if cookie.MaxAge != expectedMaxAge {
		t.Errorf("Expected MaxAge %d (24 hours), got %d", expectedMaxAge, cookie.MaxAge)
	}
}

// TestSetTemporaryIdInCookies_EmptyValue проверяет установку cookie с пустым значением.
// Ожидается: cookie с пустым значением.
func TestSetTemporaryIdInCookies_EmptyValue(t *testing.T) {
	w := httptest.NewRecorder()
	value := ""
	temporaryIdExp := 7 * 24 * 60 * 60
	rememberMe := true

	SetTemporaryIdInCookies(w, value, temporaryIdExp, rememberMe)

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Expected 1 cookie, got %d", len(cookies))
	}

	cookie := cookies[0]
	if cookie.Value != "" {
		t.Errorf("Expected empty cookie value, got '%s'", cookie.Value)
	}
}

// TestSetTemporaryIdInCookies_ZeroExpiration проверяет установку cookie с нулевым временем жизни.
// Ожидается: cookie с MaxAge равным 0.
func TestSetTemporaryIdInCookies_ZeroExpiration(t *testing.T) {
	w := httptest.NewRecorder()
	value := "test-temp-id"
	temporaryIdExp := 0
	rememberMe := true

	SetTemporaryIdInCookies(w, value, temporaryIdExp, rememberMe)

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Expected 1 cookie, got %d", len(cookies))
	}

	cookie := cookies[0]
	if cookie.MaxAge != 0 {
		t.Errorf("Expected MaxAge 0, got %d", cookie.MaxAge)
	}
}

// TestGetTemporaryIdFromCookies_Success проверяет успешное получение cookie.
// Ожидается: успешное извлечение cookie с правильным значением.
func TestGetTemporaryIdFromCookies_Success(t *testing.T) {
	value := "test-temp-id"
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  "temporaryId",
		Value: value,
	})

	cookie, err := GetTemporaryIdFromCookies(req)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if cookie == nil {
		t.Fatal("Expected cookie, got nil")
	}
	if cookie.Value != value {
		t.Errorf("Expected cookie value '%s', got '%s'", value, cookie.Value)
	}
	if cookie.Name != "temporaryId" {
		t.Errorf("Expected cookie name 'temporaryId', got '%s'", cookie.Name)
	}
}

// TestGetTemporaryIdFromCookies_CookieNotFound проверяет обработку отсутствующего cookie.
// Ожидается: ошибка при отсутствии cookie.
func TestGetTemporaryIdFromCookies_CookieNotFound(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)

	cookie, err := GetTemporaryIdFromCookies(req)
	if err == nil {
		t.Error("Expected error, got nil")
	}
	if cookie != nil {
		t.Error("Expected nil cookie, got cookie")
	}
	if !strings.Contains(err.Error(), "cookie") && !strings.Contains(err.Error(), "named") {
		t.Errorf("Expected cookie not found error, got %v", err)
	}
}

// TestGetTemporaryIdFromCookies_EmptyValue проверяет обработку cookie с пустым значением.
// Ожидается: ошибка при пустом значении cookie.
func TestGetTemporaryIdFromCookies_EmptyValue(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  "temporaryId",
		Value: "",
	})

	cookie, err := GetTemporaryIdFromCookies(req)
	if err == nil {
		t.Error("Expected error for empty value, got nil")
	}
	if cookie != nil {
		t.Error("Expected nil cookie, got cookie")
	}
	if err.Error() != "temporaryId not exist" {
		t.Errorf("Expected 'temporaryId not exist' error, got %v", err)
	}
}

// TestGetTemporaryIdFromCookies_WrongCookieName проверяет обработку cookie с неверным именем.
// Ожидается: ошибка при неверном имени cookie.
func TestGetTemporaryIdFromCookies_WrongCookieName(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  "wrongCookie",
		Value: "some-value",
	})

	cookie, err := GetTemporaryIdFromCookies(req)
	if err == nil {
		t.Error("Expected error, got nil")
	}
	if cookie != nil {
		t.Error("Expected nil cookie, got cookie")
	}
}

// TestGetTemporaryIdFromCookies_MultipleCookies проверяет получение нужного cookie из нескольких.
// Ожидается: успешное извлечение правильного cookie.
func TestGetTemporaryIdFromCookies_MultipleCookies(t *testing.T) {
	value := "test-temp-id"
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  "otherCookie",
		Value: "other-value",
	})
	req.AddCookie(&http.Cookie{
		Name:  "temporaryId",
		Value: value,
	})
	req.AddCookie(&http.Cookie{
		Name:  "anotherCookie",
		Value: "another-value",
	})

	cookie, err := GetTemporaryIdFromCookies(req)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if cookie.Value != value {
		t.Errorf("Expected cookie value '%s', got '%s'", value, cookie.Value)
	}
}

// TestClearTemporaryIdInCookies проверяет очистку cookie.
// Ожидается: cookie с MaxAge -1 для удаления.
func TestClearTemporaryIdInCookies(t *testing.T) {
	w := httptest.NewRecorder()

	ClearTemporaryIdInCookies(w)

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Expected 1 cookie, got %d", len(cookies))
	}

	cookie := cookies[0]
	if cookie.Name != "temporaryId" {
		t.Errorf("Expected cookie name 'temporaryId', got '%s'", cookie.Name)
	}
	if cookie.Path != "/" {
		t.Errorf("Expected cookie path '/', got '%s'", cookie.Path)
	}
	if !cookie.HttpOnly {
		t.Error("Expected cookie to be HttpOnly")
	}
	if cookie.Secure {
		t.Error("Expected cookie Secure to be false")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("Expected SameSiteLaxMode, got %v", cookie.SameSite)
	}
	if cookie.MaxAge != -1 {
		t.Errorf("Expected MaxAge -1 for deletion, got %d", cookie.MaxAge)
	}
}

// TestClearTemporaryIdInCookies_MultipleCalls проверяет многократные вызовы очистки.
// Ожидается: несколько cookie с MaxAge -1.
func TestClearTemporaryIdInCookies_MultipleCalls(t *testing.T) {
	w := httptest.NewRecorder()

	ClearTemporaryIdInCookies(w)
	ClearTemporaryIdInCookies(w)

	cookies := w.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatalf("Expected 2 cookies, got %d", len(cookies))
	}

	for i, cookie := range cookies {
		if cookie.Name != "temporaryId" {
			t.Errorf("Cookie %d: Expected name 'temporaryId', got '%s'", i, cookie.Name)
		}
		if cookie.MaxAge != -1 {
			t.Errorf("Cookie %d: Expected MaxAge -1, got %d", i, cookie.MaxAge)
		}
	}
}

// TestClearCookiesDev_Success проверяет успешную очистку всех cookie в режиме разработки.
// Ожидается: HTTP 302, редирект на страницу регистрации.
func TestClearCookiesDev_Success(t *testing.T) {
	os.Setenv("LOGIN_STORE_SESSION_AUTH_KEY", "test-auth-key")
	os.Setenv("LOGIN_STORE_SESSION_ENCRYPTION_KEY", "test-encryption-key")
	os.Setenv("CAPTCHA_STORE_SESSION_SECRET_KEY", "test-captcha-key")
	defer os.Unsetenv("LOGIN_STORE_SESSION_AUTH_KEY")
	defer os.Unsetenv("LOGIN_STORE_SESSION_ENCRYPTION_KEY")
	defer os.Unsetenv("CAPTCHA_STORE_SESSION_SECRET_KEY")

	InitStore()

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)

	ClearCookiesDev(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("Expected status %d, got %d", http.StatusFound, resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	if location != consts.SignUpURL {
		t.Errorf("Expected redirect to '%s', got '%s'", consts.SignUpURL, location)
	}

	cookies := resp.Cookies()
	var tempIdCookie *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == "temporaryId" {
			tempIdCookie = cookie
			break
		}
	}
	if tempIdCookie != nil && tempIdCookie.MaxAge != -1 {
		t.Errorf("Expected temporaryId cookie to be deleted (MaxAge -1), got %d", tempIdCookie.MaxAge)
	}
}

// TestClearCookiesDev_SessionError проверяет обработку ошибок сессии при очистке.
// Ожидается: HTTP 302, редирект на страницу регистрации.
func TestClearCookiesDev_SessionError(t *testing.T) {
	os.Setenv("LOGIN_STORE_SESSION_AUTH_KEY", "test-auth-key")
	os.Setenv("LOGIN_STORE_SESSION_ENCRYPTION_KEY", "test-encryption-key")
	os.Setenv("CAPTCHA_STORE_SESSION_SECRET_KEY", "test-captcha-key")
	defer os.Unsetenv("LOGIN_STORE_SESSION_AUTH_KEY")
	defer os.Unsetenv("LOGIN_STORE_SESSION_ENCRYPTION_KEY")
	defer os.Unsetenv("CAPTCHA_STORE_SESSION_SECRET_KEY")

	InitStore()

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)

	ClearCookiesDev(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("Expected status %d, got %d", http.StatusFound, resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	if location != consts.SignUpURL {
		t.Errorf("Expected redirect to '%s', got '%s'", consts.SignUpURL, location)
	}
}

// TestClearCookiesDev_WithExistingCookies проверяет очистку при существующих cookie.
// Ожидается: HTTP 302, редирект на страницу регистрации.
func TestClearCookiesDev_WithExistingCookies(t *testing.T) {
	os.Setenv("LOGIN_STORE_SESSION_AUTH_KEY", "test-auth-key")
	os.Setenv("LOGIN_STORE_SESSION_ENCRYPTION_KEY", "test-encryption-key")
	os.Setenv("CAPTCHA_STORE_SESSION_SECRET_KEY", "test-captcha-key")
	defer os.Unsetenv("LOGIN_STORE_SESSION_AUTH_KEY")
	defer os.Unsetenv("LOGIN_STORE_SESSION_ENCRYPTION_KEY")
	defer os.Unsetenv("CAPTCHA_STORE_SESSION_SECRET_KEY")

	InitStore()

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	req.AddCookie(&http.Cookie{
		Name:  "temporaryId",
		Value: "some-value",
	})

	ClearCookiesDev(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("Expected status %d, got %d", http.StatusFound, resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	if location != consts.SignUpURL {
		t.Errorf("Expected redirect to '%s', got '%s'", consts.SignUpURL, location)
	}
}

// TestSetTemporaryIdInCookies_CookieProperties проверяет свойства устанавливаемого cookie.
// Ожидается: корректные свойства cookie без домена и даты истечения.
func TestSetTemporaryIdInCookies_CookieProperties(t *testing.T) {
	w := httptest.NewRecorder()
	value := "test-value"
	temporaryIdExp := 3600
	rememberMe := true

	SetTemporaryIdInCookies(w, value, temporaryIdExp, rememberMe)

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Expected 1 cookie, got %d", len(cookies))
	}

	cookie := cookies[0]
	if cookie.RawExpires != "" {
		t.Errorf("Expected empty RawExpires, got '%s'", cookie.RawExpires)
	}
	if cookie.Domain != "" {
		t.Errorf("Expected empty Domain, got '%s'", cookie.Domain)
	}
}

// TestGetTemporaryIdFromCookies_CookieProperties проверяет свойства получаемого cookie.
// Ожидается: корректные свойства cookie.
func TestGetTemporaryIdFromCookies_CookieProperties(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	testCookie := &http.Cookie{
		Name:  "temporaryId",
		Value: "test-value",
	}
	req.AddCookie(testCookie)

	cookie, err := GetTemporaryIdFromCookies(req)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if cookie.Name != testCookie.Name {
		t.Errorf("Expected name '%s', got '%s'", testCookie.Name, cookie.Name)
	}
	if cookie.Value != testCookie.Value {
		t.Errorf("Expected value '%s', got '%s'", testCookie.Value, cookie.Value)
	}
}

// TestClearTemporaryIdInCookies_CookieProperties проверяет свойства очищаемого cookie.
// Ожидается: cookie с пустыми значениями для удаления.
func TestClearTemporaryIdInCookies_CookieProperties(t *testing.T) {
	w := httptest.NewRecorder()

	ClearTemporaryIdInCookies(w)

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Expected 1 cookie, got %d", len(cookies))
	}

	cookie := cookies[0]
	if cookie.Value != "" {
		t.Errorf("Expected empty cookie value for deletion, got '%s'", cookie.Value)
	}
	if cookie.RawExpires != "" {
		t.Errorf("Expected empty RawExpires, got '%s'", cookie.RawExpires)
	}
	if cookie.Domain != "" {
		t.Errorf("Expected empty Domain, got '%s'", cookie.Domain)
	}
}
