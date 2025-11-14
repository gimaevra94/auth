package tools

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/gimaevra94/auth/app/data"
	"github.com/pkg/errors"
)

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

	resp, err := http.PostForm(captchaURL, captchaParams)
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

func UpdateCaptchaState(w http.ResponseWriter, r *http.Request, captchaCounter int64, showCaptcha bool) error {
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
