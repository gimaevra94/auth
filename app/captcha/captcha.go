// Package captcha предоставляет функции для проверки и управления Google reCAPTCHA.
//
// Файл содержит функции для:
//   - ShowCaptcha: верификация токена reCAPTCHA через Google API
//   - InitCaptchaState: инициализация состояния CAPTCHA в сессии
//   - UpdateCaptchaState: обновление состояния CAPTCHA в сессии
//   - ShowCaptchaMsg: проверка необходимости показа CAPTCHA
package captcha

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/gimaevra94/auth/app/data"
	"github.com/pkg/errors"
)

var httpClient = &http.Client{}

// SetHTTPClient устанавливает HTTP-клиент для запросов к Google reCAPTCHA API.
//
// Позволяет заменить стандартный клиент на кастомный для тестирования или конфигурации.
func SetHTTPClient(client *http.Client) {
	httpClient = client
}

// ShowCaptcha проверяет валидность токена reCAPTCHA через Google API.
//
// Извлекает токен из формы запроса и отправляет его на верификацию в Google.
// Возвращает ошибку, если токен отсутствует или верификация не пройдена.
func ShowCaptcha(r *http.Request) error {
	captchaToken := r.FormValue("g-recaptcha-response")
	if captchaToken == "" {
		err := errors.New("captchaToken not exist")
		wrappedErr := errors.WithStack(err)
		return wrappedErr
	}

	captchaURL := "https://www.google.com/recaptcha/api/siteverify"
	captchaParams := url.Values{
		"secret":   {os.Getenv("GOOGLE_CAPTCHA_SECRET")},
		"response": {captchaToken},
	}

	resp, err := httpClient.PostForm(captchaURL, captchaParams)
	if err != nil {
		return errors.WithStack(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	var result map[string]interface{}
	if err != nil {
		return errors.WithStack(err)
	}

	if err = json.Unmarshal(body, &result); err != nil {
		return errors.WithStack(err)
	}

	success, ok := result["success"].(bool)
	if !ok || !success {
		err := errors.New("reCAPTCHA verification failed")
		wrappedErr := errors.WithStack(err)
		return wrappedErr
	}

	return nil
}

// InitCaptchaState инициализирует состояние CAPTCHA из сессии.
//
// Получает значения счетчика CAPTCHA и флага показа из сессии пользователя.
// Если значения отсутствуют, устанавливает значения по умолчанию.
var InitCaptchaState=func (w http.ResponseWriter, r *http.Request) (captchaCounter int64, showCaptcha bool, err error) {
	captchaCounter, err = data.GetCaptchaCounterFromSession(r)
	if err != nil {
		if strings.Contains(err.Error(), "exist") {
			captchaCounter = 3
			if err := data.SetCaptchaDataInSession(w, r, "captchaCounter", captchaCounter); err != nil {
				return 0, false, errors.WithStack(err)
			}
		}
	}

	showCaptcha, err = data.GetShowCaptchaFromSession(r)
	if err != nil {
		if strings.Contains(err.Error(), "exist") {
			showCaptcha = false
			if err := data.SetCaptchaDataInSession(w, r, "showCaptcha", showCaptcha); err != nil {
				return 0, false, errors.WithStack(err)
			}
		}
	}

	return captchaCounter, showCaptcha, nil
}

// UpdateCaptchaState обновляет состояние CAPTCHA в сессии.
//
// Обновляет счетчик попыток и флаг показа CAPTCHA в зависимости от текущего состояния.
// Если счетчик достигает 1 или меньше, включает показ CAPTCHA.
var UpdateCaptchaState=func (w http.ResponseWriter, r *http.Request, captchaCounter int64, showCaptcha bool) error {
	if captchaCounter >= 0 {
		if err := data.SetCaptchaDataInSession(w, r, "captchaCounter", captchaCounter); err != nil {
			return errors.WithStack(err)
		}
	}

	if captchaCounter <= 1 {
		showCaptcha = true
		if err := data.SetCaptchaDataInSession(w, r, "showCaptcha", showCaptcha); err != nil {
			return errors.WithStack(err)
		}
	}

	return nil
}

// ShowCaptchaMsg определяет необходимость показа CAPTCHA пользователю.
//
// Проверяет флаг showCaptcha и при необходимости верифицирует токен reCAPTCHA.
// Возвращает true, если нужно показать сообщение об ошибке CAPTCHA.
var ShowCaptchaMsg= func (r *http.Request, showCaptcha bool) bool {
	if showCaptcha {
		if err := ShowCaptcha(r); err != nil {
			if strings.Contains(err.Error(), "captchaToken not exist") || strings.Contains(err.Error(), "reCAPTCHA verification failed") {
				return true
			}
			return false
		}
	}
	return false
}
