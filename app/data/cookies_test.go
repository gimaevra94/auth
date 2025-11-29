package data

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gimaevra94/auth/app/consts"
)

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
