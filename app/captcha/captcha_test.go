package captcha

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/gimaevra94/auth/app/data"
	"github.com/pkg/errors"
)

// roundTripFunc implements http.RoundTripper
type roundTripFunc struct {
	rt func(req *http.Request) (*http.Response, error)
}

func (r *roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return r.rt(req)
}

func TestShowCaptcha(t *testing.T) {
	t.Run("Отсутствует токен капчи", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/", nil)
		r.Form = url.Values{}
		err := ShowCaptcha(r)
		if err == nil {
			t.Error("Ожидалась ошибка при отсутствии токена капчи")
		}
		if !strings.Contains(err.Error(), "captchaToken not exist") {
			t.Errorf("Ожидалась ошибка 'captchaToken not exist', получено: %v", err)
		}
	})

	t.Run("Валидный токен капчи", func(t *testing.T) {
		os.Setenv("GOOGLE_CAPTCHA_SECRET", "test-secret")
		defer os.Unsetenv("GOOGLE_CAPTCHA_SECRET")

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			response := map[string]interface{}{"success": true}
			json.NewEncoder(w).Encode(response)
		}))
		defer server.Close()

		// Создаем кастомный HTTP клиент который перенаправляет запросы на наш тестовый сервер
		originalClient := httpClient
		defer func() { httpClient = originalClient }()

		// Создаем custom RoundTripper
		customTransport := &roundTripFunc{
			rt: func(req *http.Request) (*http.Response, error) {
				if req.URL.String() == "https://www.google.com/recaptcha/api/siteverify" {
					// Перенаправляем на наш тестовый сервер
					newReq, err := http.NewRequest("POST", server.URL, req.Body)
					if err != nil {
						return nil, err
					}
					return http.DefaultClient.Do(newReq)
				}
				return http.DefaultClient.Do(req)
			},
		}

		httpClient = &http.Client{
			Transport: customTransport,
		}

		r := httptest.NewRequest("POST", "/", nil)
		r.Form = url.Values{"g-recaptcha-response": {"valid-token"}}
		err := ShowCaptcha(r)
		if err != nil {
			t.Errorf("Ожидалось отсутствие ошибки для валидной капчи, получено: %v", err)
		}
	})

	t.Run("Невалидный ответ капчи", func(t *testing.T) {
		os.Setenv("GOOGLE_CAPTCHA_SECRET", "test-secret")
		defer os.Unsetenv("GOOGLE_CAPTCHA_SECRET")

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			response := map[string]interface{}{"success": false}
			json.NewEncoder(w).Encode(response)
		}))
		defer server.Close()

		originalClient := httpClient
		defer func() { httpClient = originalClient }()

		// Создаем custom RoundTripper
		customTransport := &roundTripFunc{
			rt: func(req *http.Request) (*http.Response, error) {
				if req.URL.String() == "https://www.google.com/recaptcha/api/siteverify" {
					newReq, err := http.NewRequest("POST", server.URL, req.Body)
					if err != nil {
						return nil, err
					}
					return http.DefaultClient.Do(newReq)
				}
				return http.DefaultClient.Do(req)
			},
		}

		httpClient = &http.Client{
			Transport: customTransport,
		}

		r := httptest.NewRequest("POST", "/", nil)
		r.Form = url.Values{"g-recaptcha-response": {"invalid-token"}}
		err := ShowCaptcha(r)
		if err == nil {
			t.Error("Ожидалась ошибка для невалидного ответа капчи")
		}
		if !strings.Contains(err.Error(), "reCAPTCHA verification failed") {
			t.Errorf("Ожидалась ошибка 'reCAPTCHA verification failed', получено: %v", err)
		}
	})

	t.Run("Некорректный JSON ответ", func(t *testing.T) {
		os.Setenv("GOOGLE_CAPTCHA_SECRET", "test-secret")
		defer os.Unsetenv("GOOGLE_CAPTCHA_SECRET")

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("invalid json"))
		}))
		defer server.Close()

		originalClient := httpClient
		defer func() { httpClient = originalClient }()

		// Создаем custom RoundTripper
		customTransport := &roundTripFunc{
			rt: func(req *http.Request) (*http.Response, error) {
				if req.URL.String() == "https://www.google.com/recaptcha/api/siteverify" {
					newReq, err := http.NewRequest("POST", server.URL, req.Body)
					if err != nil {
						return nil, err
					}
					return http.DefaultClient.Do(newReq)
				}
				return http.DefaultClient.Do(req)
			},
		}

		httpClient = &http.Client{
			Transport: customTransport,
		}

		r := httptest.NewRequest("POST", "/", nil)
		r.Form = url.Values{"g-recaptcha-response": {"token"}}
		err := ShowCaptcha(r)
		if err == nil {
			t.Error("Ожидалась ошибка для некорректного JSON ответа")
		}
	})

	t.Run("Ошибка HTTP запроса", func(t *testing.T) {
		os.Setenv("GOOGLE_CAPTCHA_SECRET", "test-secret")
		defer os.Unsetenv("GOOGLE_CAPTCHA_SECRET")

		originalClient := httpClient
		defer func() { httpClient = originalClient }()

		// Создаем custom RoundTripper
		customTransport := &roundTripFunc{
			rt: func(req *http.Request) (*http.Response, error) {
				return nil, errors.New("network error")
			},
		}

		httpClient = &http.Client{
			Transport: customTransport,
		}

		r := httptest.NewRequest("POST", "/", nil)
		r.Form = url.Values{"g-recaptcha-response": {"token"}}
		err := ShowCaptcha(r)
		if err == nil {
			t.Error("Ожидалась ошибка при сбое HTTP запроса")
		}
	})
}

func TestInitCaptchaState(t *testing.T) {
	os.Setenv("CAPTCHA_STORE_SESSION_SECRET_KEY", "test-secret-key")
	defer os.Unsetenv("CAPTCHA_STORE_SESSION_SECRET_KEY")
	data.InitStore()

	t.Run("Новая сессия - инициализация defaults", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()

		counter, showCaptcha, err := InitCaptchaState(w, r)
		if err != nil {
			t.Errorf("Ожидалось отсутствие ошибки, получено: %v", err)
		}
		if counter != 3 {
			t.Errorf("Ожидался счетчик 3, получено: %d", counter)
		}
		if showCaptcha != false {
			t.Errorf("Ожидалось showCaptcha false, получено: %v", showCaptcha)
		}
	})

	t.Run("Существующая сессия со значениями", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()

		data.SetCaptchaDataInSession(w, r, "captchaCounter", int64(1))
		data.SetCaptchaDataInSession(w, r, "showCaptcha", true)

		counter, showCaptcha, err := InitCaptchaState(w, r)
		if err != nil {
			t.Errorf("Ожидалось отсутствие ошибки, получено: %v", err)
		}
		if counter != 1 {
			t.Errorf("Ожидался счетчик 1, получено: %d", counter)
		}
		if showCaptcha != true {
			t.Errorf("Ожидалось showCaptcha true, получено: %v", showCaptcha)
		}
	})

	t.Run("Ошибка сессии на captchaCounter", func(t *testing.T) {
		originalGet := data.GetCaptchaCounterFromSession
		defer func() { data.GetCaptchaCounterFromSession = originalGet }()

		data.GetCaptchaCounterFromSession = func(r *http.Request) (int64, error) {
			return 0, errors.New("captchaCounter not exist")
		}

		r := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()

		counter, _, err := InitCaptchaState(w, r)
		if err != nil {
			t.Errorf("Ожидалось отсутствие ошибки, получено: %v", err)
		}
		if counter != 3 {
			t.Errorf("Ожидался счетчик 3, получено: %d", counter)
		}
	})

	t.Run("Ошибка сессии на showCaptcha", func(t *testing.T) {
		originalGet := data.GetShowCaptchaFromSession
		defer func() { data.GetShowCaptchaFromSession = originalGet }()

		data.GetShowCaptchaFromSession = func(r *http.Request) (bool, error) {
			return false, errors.New("showCaptcha not exist")
		}

		r := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()

		_, showCaptcha, err := InitCaptchaState(w, r)
		if err != nil {
			t.Errorf("Ожидалось отсутствие ошибки, получено: %v", err)
		}
		if showCaptcha != false {
			t.Errorf("Ожидалось showCaptcha false, получено: %v", showCaptcha)
		}
	})

	t.Run("Ошибка сохранения сессии", func(t *testing.T) {
		originalSet := data.SetCaptchaDataInSession
		defer func() { data.SetCaptchaDataInSession = originalSet }()

		data.SetCaptchaDataInSession = func(w http.ResponseWriter, r *http.Request, key string, value interface{}) error {
			return errors.New("save error")
		}

		originalGet := data.GetCaptchaCounterFromSession
		defer func() { data.GetCaptchaCounterFromSession = originalGet }()

		data.GetCaptchaCounterFromSession = func(r *http.Request) (int64, error) {
			return 0, errors.New("captchaCounter not exist")
		}

		r := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()

		_, _, err := InitCaptchaState(w, r)
		if err == nil {
			t.Error("Ожидалась ошибка при сохранении сессии")
		}
	})
}

func TestUpdateCaptchaState(t *testing.T) {
	os.Setenv("CAPTCHA_STORE_SESSION_SECRET_KEY", "test-secret-key")
	defer os.Unsetenv("CAPTCHA_STORE_SESSION_SECRET_KEY")
	data.InitStore()

	t.Run("Обновление только счетчика", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/", nil)
		w := httptest.NewRecorder()

		err := UpdateCaptchaState(w, r, 5, false)
		if err != nil {
			t.Errorf("Ожидалось отсутствие ошибки, получено: %v", err)
		}

		counter, _ := data.GetCaptchaCounterFromSession(r)
		if counter != 5 {
			t.Errorf("Ожидался счетчик 5, получено: %d", counter)
		}
	})

	t.Run("Счетчик <= 1 активирует капчу", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/", nil)
		w := httptest.NewRecorder()

		err := UpdateCaptchaState(w, r, 1, false)
		if err != nil {
			t.Errorf("Ожидалось отсутствие ошибки, получено: %v", err)
		}

		showCaptcha, _ := data.GetShowCaptchaFromSession(r)
		if showCaptcha != true {
			t.Errorf("Ожидалось showCaptcha true при счетчике <= 1, получено: %v", showCaptcha)
		}
	})

	t.Run("Счетчик = 0 активирует капчу", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/", nil)
		w := httptest.NewRecorder()

		err := UpdateCaptchaState(w, r, 0, false)
		if err != nil {
			t.Errorf("Ожидалось отсутствие ошибки, получено: %v", err)
		}

		showCaptcha, _ := data.GetShowCaptchaFromSession(r)
		if showCaptcha != true {
			t.Errorf("Ожидалось showCaptcha true при счетчике = 0, получено: %v", showCaptcha)
		}
	})

	t.Run("Счетчик > 1 не активирует капчу", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/", nil)
		w := httptest.NewRecorder()

		err := UpdateCaptchaState(w, r, 2, false)
		if err != nil {
			t.Errorf("Ожидалось отсутствие ошибки, получено: %v", err)
		}

		showCaptcha, _ := data.GetShowCaptchaFromSession(r)
		if showCaptcha != false {
			t.Errorf("Ожидалось showCaptcha false при счетчике > 1, получено: %v", showCaptcha)
		}
	})

	t.Run("Ошибка сохранения сессии на счетчике", func(t *testing.T) {
		originalSet := data.SetCaptchaDataInSession
		defer func() { data.SetCaptchaDataInSession = originalSet }()

		data.SetCaptchaDataInSession = func(w http.ResponseWriter, r *http.Request, key string, value interface{}) error {
			if key == "captchaCounter" {
				return errors.New("save error")
			}
			return originalSet(w, r, key, value)
		}

		r := httptest.NewRequest("POST", "/", nil)
		w := httptest.NewRecorder()

		err := UpdateCaptchaState(w, r, 5, false)
		if err == nil {
			t.Error("Ожидалась ошибка при сохранении сессии")
		}
	})

	t.Run("Ошибка сохранения сессии на showCaptcha", func(t *testing.T) {
		originalSet := data.SetCaptchaDataInSession
		defer func() { data.SetCaptchaDataInSession = originalSet }()

		data.SetCaptchaDataInSession = func(w http.ResponseWriter, r *http.Request, key string, value interface{}) error {
			if key == "showCaptcha" {
				return errors.New("save error")
			}
			return originalSet(w, r, key, value)
		}

		r := httptest.NewRequest("POST", "/", nil)
		w := httptest.NewRecorder()

		err := UpdateCaptchaState(w, r, 1, false)
		if err == nil {
			t.Error("Ожидалась ошибка при сохранении сессии")
		}
	})
}

func TestShowCaptchaMsg(t *testing.T) {
	t.Run("ShowCaptcha false", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/", nil)

		result := ShowCaptchaMsg(r, false)
		if result != false {
			t.Errorf("Ожидалось false когда showCaptcha false, получено: %v", result)
		}
	})

	t.Run("Отсутствует токен капчи", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/", nil)
		r.Form = url.Values{}

		result := ShowCaptchaMsg(r, true)
		if result != true {
			t.Errorf("Ожидалось true когда отсутствует токен капчи, получено: %v", result)
		}
	})

	t.Run("Валидный токен капчи", func(t *testing.T) {
		os.Setenv("GOOGLE_CAPTCHA_SECRET", "test-secret")
		defer os.Unsetenv("GOOGLE_CAPTCHA_SECRET")

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			response := map[string]interface{}{"success": true}
			json.NewEncoder(w).Encode(response)
		}))
		defer server.Close()

		originalClient := httpClient
		defer func() { httpClient = originalClient }()

		// Создаем custom RoundTripper
		customTransport := &roundTripFunc{
			rt: func(req *http.Request) (*http.Response, error) {
				if req.URL.String() == "https://www.google.com/recaptcha/api/siteverify" {
					newReq, err := http.NewRequest("POST", server.URL, req.Body)
					if err != nil {
						return nil, err
					}
					return http.DefaultClient.Do(newReq)
				}
				return http.DefaultClient.Do(req)
			},
		}

		httpClient = &http.Client{
			Transport: customTransport,
		}

		r := httptest.NewRequest("GET", "/", nil)
		r.Form = url.Values{"g-recaptcha-response": {"valid-token"}}

		result := ShowCaptchaMsg(r, true)
		if result != false {
			t.Errorf("Ожидалось false при валидной капче, получено: %v", result)
		}
	})

	t.Run("Невалидный ответ капчи", func(t *testing.T) {
		os.Setenv("GOOGLE_CAPTCHA_SECRET", "test-secret")
		defer os.Unsetenv("GOOGLE_CAPTCHA_SECRET")

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			response := map[string]interface{}{"success": false}
			json.NewEncoder(w).Encode(response)
		}))
		defer server.Close()

		originalClient := httpClient
		defer func() { httpClient = originalClient }()

		// Создаем custom RoundTripper
		customTransport := &roundTripFunc{
			rt: func(req *http.Request) (*http.Response, error) {
				if req.URL.String() == "https://www.google.com/recaptcha/api/siteverify" {
					newReq, err := http.NewRequest("POST", server.URL, req.Body)
					if err != nil {
						return nil, err
					}
					return http.DefaultClient.Do(newReq)
				}
				return http.DefaultClient.Do(req)
			},
		}

		httpClient = &http.Client{
			Transport: customTransport,
		}

		r := httptest.NewRequest("GET", "/", nil)
		r.Form = url.Values{"g-recaptcha-response": {"invalid-token"}}

		result := ShowCaptchaMsg(r, true)
		if result != true {
			t.Errorf("Ожидалось true при ошибке верификации капчи, получено: %v", result)
		}
	})

	t.Run("Ошибка HTTP запроса", func(t *testing.T) {
		os.Setenv("GOOGLE_CAPTCHA_SECRET", "test-secret")
		defer os.Unsetenv("GOOGLE_CAPTCHA_SECRET")

		originalClient := httpClient
		defer func() { httpClient = originalClient }()

		// Создаем custom RoundTripper
		customTransport := &roundTripFunc{
			rt: func(req *http.Request) (*http.Response, error) {
				return nil, errors.New("network error")
			},
		}

		httpClient = &http.Client{
			Transport: customTransport,
		}

		r := httptest.NewRequest("GET", "/", nil)
		r.Form = url.Values{"g-recaptcha-response": {"token"}}

		result := ShowCaptchaMsg(r, true)
		if result != false {
			t.Errorf("Ожидалось false при ошибке HTTP запроса, получено: %v", result)
		}
	})

	t.Run("Ошибка JSON unmarshal", func(t *testing.T) {
		os.Setenv("GOOGLE_CAPTCHA_SECRET", "test-secret")
		defer os.Unsetenv("GOOGLE_CAPTCHA_SECRET")

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("invalid json"))
		}))
		defer server.Close()

		originalClient := httpClient
		defer func() { httpClient = originalClient }()

		// Создаем custom RoundTripper
		customTransport := &roundTripFunc{
			rt: func(req *http.Request) (*http.Response, error) {
				if req.URL.String() == "https://www.google.com/recaptcha/api/siteverify" {
					newReq, err := http.NewRequest("POST", server.URL, req.Body)
					if err != nil {
						return nil, err
					}
					return http.DefaultClient.Do(newReq)
				}
				return http.DefaultClient.Do(req)
			},
		}

		httpClient = &http.Client{
			Transport: customTransport,
		}

		r := httptest.NewRequest("GET", "/", nil)
		r.Form = url.Values{"g-recaptcha-response": {"token"}}

		result := ShowCaptchaMsg(r, true)
		if result != false {
			t.Errorf("Ожидалось false при ошибке JSON unmarshal, получено: %v", result)
		}
	})
}

func TestInitCaptchaStateIntegration(t *testing.T) {
	os.Setenv("CAPTCHA_STORE_SESSION_SECRET_KEY", "test-secret-key")
	defer os.Unsetenv("CAPTCHA_STORE_SESSION_SECRET_KEY")
	data.InitStore()

	t.Run("Полный цикл с сохранением сессии", func(t *testing.T) {
		r1 := httptest.NewRequest("GET", "/", nil)
		w1 := httptest.NewRecorder()

		counter1, showCaptcha1, err1 := InitCaptchaState(w1, r1)
		if err1 != nil {
			t.Errorf("Ожидалось отсутствие ошибки при первом вызове, получено: %v", err1)
		}
		if counter1 != 3 || showCaptcha1 != false {
			t.Errorf("Ожидалось начальное состояние (3, false), получено: (%d, %v)", counter1, showCaptcha1)
		}

		cookies := w1.Result().Cookies()
		r2 := httptest.NewRequest("GET", "/", nil)
		for _, cookie := range cookies {
			r2.AddCookie(cookie)
		}
		w2 := httptest.NewRecorder()

		counter2, showCaptcha2, err2 := InitCaptchaState(w2, r2)
		if err2 != nil {
			t.Errorf("Ожидалось отсутствие ошибки при втором вызове, получено: %v", err2)
		}
		if counter2 != 3 || showCaptcha2 != false {
			t.Errorf("Ожидалось сохраненное состояние (3, false), получено: (%d, %v)", counter2, showCaptcha2)
		}
	})
}

func TestUpdateCaptchaStateIntegration(t *testing.T) {
	os.Setenv("CAPTCHA_STORE_SESSION_SECRET_KEY", "test-secret-key")
	defer os.Unsetenv("CAPTCHA_STORE_SESSION_SECRET_KEY")
	data.InitStore()

	t.Run("Уменьшение счетчика и активация капчи", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/", nil)
		w := httptest.NewRecorder()

		UpdateCaptchaState(w, r, 3, false)

		UpdateCaptchaState(w, r, 2, false)
		showCaptcha, _ := data.GetShowCaptchaFromSession(r)
		if showCaptcha != false {
			t.Error("Ожидалось showCaptcha false при счетчике 2")
		}

		UpdateCaptchaState(w, r, 1, false)
		showCaptcha, _ = data.GetShowCaptchaFromSession(r)
		if showCaptcha != true {
			t.Error("Ожидалось showCaptcha true при счетчике 1")
		}

		UpdateCaptchaState(w, r, 0, false)
		showCaptcha, _ = data.GetShowCaptchaFromSession(r)
		if showCaptcha != true {
			t.Error("Ожидалось showCaptcha true при счетчике 0")
		}
	})
}
