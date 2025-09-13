package tools

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/pkg/errors"
)

func Captcha(r *http.Request) error {
	captchaToken := r.FormValue("g-recaptcha-response")
	if captchaToken == "" {
		return errors.WithStack(errors.New("captchaToken not exist"))
	}

	captchaURL := "https://www.google.com/recaptcha/api/siteverify"
	captchaParams := url.Values{
		"secret": {os.Getenv("GOOGLE_CAPTCHA_SECRET")},
		"response": {captchaToken},
	}

	resp, err := http.PostForm(captchaURL, captchaParams)
	if err != nil {
		return errors.WithStack(err)
	}

	body, err := io.ReadAll(resp.Body)
	var result map[string]interface{}
	if err != nil {
		return errors.WithStack(err)
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return errors.WithStack(err)
	}

	success, ok := result["success"].(bool)
	if !ok || !success {
		return errors.New("reCAPTCHA verification failed")
	}

	score, ok := result["score"].(float64)
	if !ok || score < 0.5 {
		return errors.New("reCAPTCHA score too low")
	}

	action, ok := result["action"].(string)
	if !ok || (action != "signup" && action != "signin") {
		return errors.New("reCAPTCHA action mismatch")
	}

	return nil
}
