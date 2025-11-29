package data

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gimaevra94/auth/app/structs"
)

func TestInitStore(t *testing.T) {
	os.Setenv("LOGIN_STORE_SESSION_AUTH_KEY", "12345678901234567890123456789012")
	os.Setenv("LOGIN_STORE_SESSION_ENCRYPTION_KEY", "12345678901234567890123456789012")
	os.Setenv("CAPTCHA_STORE_SESSION_SECRET_KEY", "12345678901234567890123456789012")

	result := InitStore()
	if result != nil {
		t.Errorf("Expected nil, got %v", result)
	}

	if loginStore == nil {
		t.Error("loginStore should not be nil")
	}

	if captchaStore == nil {
		t.Error("captchaStore should not be nil")
	}

	if loginStore.Options.MaxAge != 30*60 {
		t.Errorf("Expected loginStore MaxAge 1800, got %d", loginStore.Options.MaxAge)
	}

	if captchaStore.Options.MaxAge != 30*24*60*60 {
		t.Errorf("Expected captchaStore MaxAge 2592000, got %d", captchaStore.Options.MaxAge)
	}

	if !loginStore.Options.HttpOnly {
		t.Error("loginStore should have HttpOnly set to true")
	}

	if !captchaStore.Options.HttpOnly {
		t.Error("captchaStore should have HttpOnly set to true")
	}

	if loginStore.Options.SameSite != http.SameSiteLaxMode {
		t.Errorf("Expected SameSiteLaxMode, got %v", loginStore.Options.SameSite)
	}

	if captchaStore.Options.Path != "/" {
		t.Errorf("Expected path '/', got %s", captchaStore.Options.Path)
	}
}

func TestSetCaptchaDataInSession(t *testing.T) {
	os.Setenv("LOGIN_STORE_SESSION_AUTH_KEY", "12345678901234567890123456789012")
	os.Setenv("LOGIN_STORE_SESSION_ENCRYPTION_KEY", "12345678901234567890123456789012")
	os.Setenv("CAPTCHA_STORE_SESSION_SECRET_KEY", "12345678901234567890123456789012")
	InitStore()

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	testCases := []struct {
		name  string
		key   string
		value interface{}
	}{
		{"captchaCounter", "captchaCounter", int64(5)},
		{"showCaptcha", "showCaptcha", true},
		{"showCaptchaFalse", "showCaptcha", false},
		{"stringValue", "testKey", "testValue"},
		{"intValue", "numberKey", 42},
		{"floatValue", "floatKey", 3.14},
		{"arrayValue", "arrayKey", []string{"item1", "item2"}},
		{"mapValue", "mapKey", map[string]interface{}{"nested": "value"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := SetCaptchaDataInSession(w, req, tc.key, tc.value)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			session, err := captchaStore.Get(req, "captchaStore")
			if err != nil {
				t.Errorf("Failed to get session: %v", err)
			}

			storedData, exists := session.Values[tc.key]
			if !exists {
				t.Errorf("Key %s not found in session", tc.key)
				return
			}

			jsonData, err := json.Marshal(tc.value)
			if err != nil {
				t.Errorf("Failed to marshal expected value: %v", err)
			}

			if string(jsonData) != string(storedData.([]byte)) {
				t.Errorf("Expected %v, got %v", tc.value, storedData)
			}
		})
	}
}

func TestSetAuthDataInSession(t *testing.T) {
	os.Setenv("LOGIN_STORE_SESSION_AUTH_KEY", "12345678901234567890123456789012")
	os.Setenv("LOGIN_STORE_SESSION_ENCRYPTION_KEY", "12345678901234567890123456789012")
	os.Setenv("CAPTCHA_STORE_SESSION_SECRET_KEY", "12345678901234567890123456789012")
	InitStore()

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	testUser := structs.User{
		UserId:                 "123",
		Login:                  "testuser",
		Email:                  "test@example.com",
		Password:               "hashedpassword",
		ServerCode:             "abc123",
		ServerCodeSendedConter: 0,
		UserAgent:              "Mozilla/5.0",
	}

	err := SetAuthDataInSession(w, req, testUser)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	session, err := loginStore.Get(req, "loginStore")
	if err != nil {
		t.Errorf("Failed to get session: %v", err)
	}

	storedData, exists := session.Values["user"]
	if !exists {
		t.Error("User data not found in session")
		return
	}

	var retrievedUser structs.User
	err = json.Unmarshal(storedData.([]byte), &retrievedUser)
	if err != nil {
		t.Errorf("Failed to unmarshal user data: %v", err)
	}

	if retrievedUser.UserId != testUser.UserId {
		t.Errorf("Expected UserId %s, got %s", testUser.UserId, retrievedUser.UserId)
	}

	if retrievedUser.Login != testUser.Login {
		t.Errorf("Expected Login %s, got %s", testUser.Login, retrievedUser.Login)
	}

	if retrievedUser.Email != testUser.Email {
		t.Errorf("Expected Email %s, got %s", testUser.Email, retrievedUser.Email)
	}

	if retrievedUser.Password != testUser.Password {
		t.Errorf("Expected Password %s, got %s", testUser.Password, retrievedUser.Password)
	}

	if retrievedUser.ServerCode != testUser.ServerCode {
		t.Errorf("Expected ServerCode %s, got %s", testUser.ServerCode, retrievedUser.ServerCode)
	}

	if retrievedUser.ServerCodeSendedConter != testUser.ServerCodeSendedConter {
		t.Errorf("Expected ServerCodeSendedConter %d, got %d", testUser.ServerCodeSendedConter, retrievedUser.ServerCodeSendedConter)
	}

	if retrievedUser.UserAgent != testUser.UserAgent {
		t.Errorf("Expected UserAgent %s, got %s", testUser.UserAgent, retrievedUser.UserAgent)
	}
}

func TestGetCaptchaCounterFromSession(t *testing.T) {
	os.Setenv("LOGIN_STORE_SESSION_AUTH_KEY", "12345678901234567890123456789012")
	os.Setenv("LOGIN_STORE_SESSION_ENCRYPTION_KEY", "12345678901234567890123456789012")
	os.Setenv("CAPTCHA_STORE_SESSION_SECRET_KEY", "12345678901234567890123456789012")
	InitStore()

	t.Run("valid counter", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()

		err := SetCaptchaDataInSession(w, req, "captchaCounter", int64(42))
		if err != nil {
			t.Errorf("Failed to set counter: %v", err)
		}

		counter, err := GetCaptchaCounterFromSession(req)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		if counter != 42 {
			t.Errorf("Expected counter 42, got %d", counter)
		}
	})

	t.Run("counter not exist", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)

		_, err := GetCaptchaCounterFromSession(req)
		if err == nil {
			t.Error("Expected error when counter doesn't exist")
		}

		if err.Error() != "captchaCounter not exist" {
			t.Errorf("Expected 'captchaCounter not exist', got %v", err)
		}
	})

	testValues := []int64{0, 1, -1, 999999999, -999999999}

	for _, testValue := range testValues {
		t.Run("counter value", func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			w := httptest.NewRecorder()

			err := SetCaptchaDataInSession(w, req, "captchaCounter", testValue)
			if err != nil {
				t.Errorf("Failed to set counter: %v", err)
			}

			counter, err := GetCaptchaCounterFromSession(req)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if counter != testValue {
				t.Errorf("Expected counter %d, got %d", testValue, counter)
			}
		})
	}
}

func TestGetShowCaptchaFromSession(t *testing.T) {
	os.Setenv("LOGIN_STORE_SESSION_AUTH_KEY", "12345678901234567890123456789012")
	os.Setenv("LOGIN_STORE_SESSION_ENCRYPTION_KEY", "12345678901234567890123456789012")
	os.Setenv("CAPTCHA_STORE_SESSION_SECRET_KEY", "12345678901234567890123456789012")
	InitStore()

	t.Run("show captcha true", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()

		err := SetCaptchaDataInSession(w, req, "showCaptcha", true)
		if err != nil {
			t.Errorf("Failed to set showCaptcha: %v", err)
		}

		showCaptcha, err := GetShowCaptchaFromSession(req)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		if !showCaptcha {
			t.Error("Expected showCaptcha to be true")
		}
	})

	t.Run("show captcha false", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()

		err := SetCaptchaDataInSession(w, req, "showCaptcha", false)
		if err != nil {
			t.Errorf("Failed to set showCaptcha: %v", err)
		}

		showCaptcha, err := GetShowCaptchaFromSession(req)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		if showCaptcha {
			t.Error("Expected showCaptcha to be false")
		}
	})

	t.Run("showCaptcha not exist", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)

		_, err := GetShowCaptchaFromSession(req)
		if err == nil {
			t.Error("Expected error when showCaptcha doesn't exist")
		}

		if err.Error() != "showCaptcha not exist" {
			t.Errorf("Expected 'showCaptcha not exist', got %v", err)
		}
	})
}

func TestGetAuthDataFromSession(t *testing.T) {
	os.Setenv("LOGIN_STORE_SESSION_AUTH_KEY", "12345678901234567890123456789012")
	os.Setenv("LOGIN_STORE_SESSION_ENCRYPTION_KEY", "12345678901234567890123456789012")
	os.Setenv("CAPTCHA_STORE_SESSION_SECRET_KEY", "12345678901234567890123456789012")
	InitStore()

	t.Run("valid user data", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()

		testUser := structs.User{
			UserId:                 "user123",
			Login:                  "testlogin",
			Email:                  "test@example.com",
			Password:               "hashedpass123",
			ServerCode:             "code456",
			ServerCodeSendedConter: 5,
			UserAgent:              "TestAgent/1.0",
		}

		err := SetAuthDataInSession(w, req, testUser)
		if err != nil {
			t.Errorf("Failed to set auth data: %v", err)
		}

		retrievedUser, err := GetAuthDataFromSession(req)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		if retrievedUser.UserId != testUser.UserId {
			t.Errorf("Expected UserId %s, got %s", testUser.UserId, retrievedUser.UserId)
		}

		if retrievedUser.Login != testUser.Login {
			t.Errorf("Expected Login %s, got %s", testUser.Login, retrievedUser.Login)
		}

		if retrievedUser.Email != testUser.Email {
			t.Errorf("Expected Email %s, got %s", testUser.Email, retrievedUser.Email)
		}

		if retrievedUser.Password != testUser.Password {
			t.Errorf("Expected Password %s, got %s", testUser.Password, retrievedUser.Password)
		}

		if retrievedUser.ServerCode != testUser.ServerCode {
			t.Errorf("Expected ServerCode %s, got %s", testUser.ServerCode, retrievedUser.ServerCode)
		}

		if retrievedUser.ServerCodeSendedConter != testUser.ServerCodeSendedConter {
			t.Errorf("Expected ServerCodeSendedConter %d, got %d", testUser.ServerCodeSendedConter, retrievedUser.ServerCodeSendedConter)
		}

		if retrievedUser.UserAgent != testUser.UserAgent {
			t.Errorf("Expected UserAgent %s, got %s", testUser.UserAgent, retrievedUser.UserAgent)
		}
	})

	t.Run("user not exist", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)

		_, err := GetAuthDataFromSession(req)
		if err == nil {
			t.Error("Expected error when user doesn't exist")
		}

		if err.Error() != "user not exist" {
			t.Errorf("Expected 'user not exist', got %v", err)
		}
	})

	testUsers := []structs.User{
		{UserId: "", Login: "", Email: "", Password: "", ServerCode: "", ServerCodeSendedConter: 0, UserAgent: ""},
		{UserId: "1", Login: "a", Email: "a@a.com", Password: "pass", ServerCode: "abc", ServerCodeSendedConter: 1, UserAgent: "agent"},
		{UserId: "user-with-special-chars_123", Login: "login.test", Email: "test.email+tag@example.com", Password: "hash$alt#salt@", ServerCode: "CODE-123-XYZ", ServerCodeSendedConter: 999, UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
	}

	for i, testUser := range testUsers {
		t.Run("user data", func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			w := httptest.NewRecorder()

			err := SetAuthDataInSession(w, req, testUser)
			if err != nil {
				t.Errorf("Failed to set auth data: %v", err)
			}

			retrievedUser, err := GetAuthDataFromSession(req)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if retrievedUser.UserId != testUser.UserId {
				t.Errorf("Test %d: Expected UserId %s, got %s", i, testUser.UserId, retrievedUser.UserId)
			}

			if retrievedUser.Login != testUser.Login {
				t.Errorf("Test %d: Expected Login %s, got %s", i, testUser.Login, retrievedUser.Login)
			}

			if retrievedUser.Email != testUser.Email {
				t.Errorf("Test %d: Expected Email %s, got %s", i, testUser.Email, retrievedUser.Email)
			}

			if retrievedUser.Password != testUser.Password {
				t.Errorf("Test %d: Expected Password %s, got %s", i, testUser.Password, retrievedUser.Password)
			}

			if retrievedUser.ServerCode != testUser.ServerCode {
				t.Errorf("Test %d: Expected ServerCode %s, got %s", i, testUser.ServerCode, retrievedUser.ServerCode)
			}

			if retrievedUser.ServerCodeSendedConter != testUser.ServerCodeSendedConter {
				t.Errorf("Test %d: Expected ServerCodeSendedConter %d, got %d", i, testUser.ServerCodeSendedConter, retrievedUser.ServerCodeSendedConter)
			}

			if retrievedUser.UserAgent != testUser.UserAgent {
				t.Errorf("Test %d: Expected UserAgent %s, got %s", i, testUser.UserAgent, retrievedUser.UserAgent)
			}
		})
	}
}

func TestEndAuthAndCaptchaSessions(t *testing.T) {
	os.Setenv("LOGIN_STORE_SESSION_AUTH_KEY", "12345678901234567890123456789012")
	os.Setenv("LOGIN_STORE_SESSION_ENCRYPTION_KEY", "12345678901234567890123456789012")
	os.Setenv("CAPTCHA_STORE_SESSION_SECRET_KEY", "12345678901234567890123456789012")
	InitStore()

	t.Run("end existing sessions", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()

		testUser := structs.User{UserId: "123", Login: "test", Email: "test@example.com", Password: "pass", ServerCode: "", ServerCodeSendedConter: 0, UserAgent: ""}
		err := SetAuthDataInSession(w, req, testUser)
		if err != nil {
			t.Errorf("Failed to set auth data: %v", err)
		}

		err = SetCaptchaDataInSession(w, req, "captchaCounter", int64(5))
		if err != nil {
			t.Errorf("Failed to set captcha data: %v", err)
		}

		err = EndAuthAndCaptchaSessions(w, req)
		if err != nil {
			t.Errorf("Unexpected error ending sessions: %v", err)
		}

		loginSession, err := loginStore.Get(req, "loginStore")
		if err != nil {
			t.Errorf("Failed to get login session: %v", err)
		}

		if loginSession.Options.MaxAge != -1 {
			t.Errorf("Expected login session MaxAge -1, got %d", loginSession.Options.MaxAge)
		}

		captchaSession, err := captchaStore.Get(req, "captchaStore")
		if err != nil {
			t.Errorf("Failed to get captcha session: %v", err)
		}

		if captchaSession.Options.MaxAge != -1 {
			t.Errorf("Expected captcha session MaxAge -1, got %d", captchaSession.Options.MaxAge)
		}

		_, err = GetAuthDataFromSession(req)
		if err == nil {
			t.Error("Expected error when getting auth data from ended session")
		}

		_, err = GetCaptchaCounterFromSession(req)
		if err == nil {
			t.Error("Expected error when getting captcha data from ended session")
		}
	})

	t.Run("end non-existent sessions", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()

		err := EndAuthAndCaptchaSessions(w, req)
		if err != nil {
			t.Errorf("Should handle non-existent sessions gracefully: %v", err)
		}
	})

	t.Run("multiple session operations", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()

		testUser := structs.User{UserId: "456", Login: "user2", Email: "user2@example.com", Password: "pass2", ServerCode: "code2", ServerCodeSendedConter: 2, UserAgent: "Agent2"}
		err := SetAuthDataInSession(w, req, testUser)
		if err != nil {
			t.Errorf("Failed to set auth data: %v", err)
		}

		err = SetCaptchaDataInSession(w, req, "showCaptcha", true)
		if err != nil {
			t.Errorf("Failed to set captcha data: %v", err)
		}

		retrievedUser, err := GetAuthDataFromSession(req)
		if err != nil {
			t.Errorf("Failed to get auth data before end: %v", err)
		}

		if retrievedUser.UserId != "456" {
			t.Errorf("Expected UserId 456, got %s", retrievedUser.UserId)
		}

		showCaptcha, err := GetShowCaptchaFromSession(req)
		if err != nil {
			t.Errorf("Failed to get captcha data before end: %v", err)
		}

		if !showCaptcha {
			t.Error("Expected showCaptcha to be true before end")
		}

		err = EndAuthAndCaptchaSessions(w, req)
		if err != nil {
			t.Errorf("Failed to end sessions: %v", err)
		}

		_, err = GetAuthDataFromSession(req)
		if err == nil {
			t.Error("Expected error after ending auth session")
		}

		_, err = GetShowCaptchaFromSession(req)
		if err == nil {
			t.Error("Expected error after ending captcha session")
		}
	})
}

func TestSessionIntegration(t *testing.T) {
	os.Setenv("LOGIN_STORE_SESSION_AUTH_KEY", "12345678901234567890123456789012")
	os.Setenv("LOGIN_STORE_SESSION_ENCRYPTION_KEY", "12345678901234567890123456789012")
	os.Setenv("CAPTCHA_STORE_SESSION_SECRET_KEY", "12345678901234567890123456789012")
	InitStore()

	t.Run("full auth flow", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()

		testUser := structs.User{
			UserId:                 "integration_user",
			Login:                  "integration_login",
			Email:                  "integration@example.com",
			Password:               "integration_hash",
			ServerCode:             "integration_code",
			ServerCodeSendedConter: 10,
			UserAgent:              "IntegrationAgent/1.0",
		}

		err := SetAuthDataInSession(w, req, testUser)
		if err != nil {
			t.Errorf("Failed to set auth data: %v", err)
		}

		err = SetCaptchaDataInSession(w, req, "captchaCounter", int64(3))
		if err != nil {
			t.Errorf("Failed to set captcha counter: %v", err)
		}

		err = SetCaptchaDataInSession(w, req, "showCaptcha", true)
		if err != nil {
			t.Errorf("Failed to set show captcha: %v", err)
		}

		retrievedUser, err := GetAuthDataFromSession(req)
		if err != nil {
			t.Errorf("Failed to retrieve user: %v", err)
		}

		if retrievedUser.UserId != testUser.UserId {
			t.Errorf("UserId mismatch: expected %s, got %s", testUser.UserId, retrievedUser.UserId)
		}

		counter, err := GetCaptchaCounterFromSession(req)
		if err != nil {
			t.Errorf("Failed to retrieve counter: %v", err)
		}

		if counter != 3 {
			t.Errorf("Counter mismatch: expected 3, got %d", counter)
		}

		showCaptcha, err := GetShowCaptchaFromSession(req)
		if err != nil {
			t.Errorf("Failed to retrieve show captcha: %v", err)
		}

		if !showCaptcha {
			t.Error("showCaptcha should be true")
		}

		err = EndAuthAndCaptchaSessions(w, req)
		if err != nil {
			t.Errorf("Failed to end sessions: %v", err)
		}

		_, err = GetAuthDataFromSession(req)
		if err == nil {
			t.Error("Expected error after session end")
		}

		_, err = GetCaptchaCounterFromSession(req)
		if err == nil {
			t.Error("Expected error after session end")
		}

		_, err = GetShowCaptchaFromSession(req)
		if err == nil {
			t.Error("Expected error after session end")
		}
	})
}
