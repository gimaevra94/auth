package tools

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/gimaevra94/auth/app/tmpls"
	"github.com/pkg/errors"
)

func Captcha(r *http.Request) error {
	captchaToken := r.FormValue("g-recaptcha-response")
	if captchaToken == "" {
		return errors.WithStack(errors.New("captchaToken: " + tmpls.NotExistErr))
	}

	captchaURL := "https://www.google.com/recaptcha/api/siteverify"
	captchaParams := url.Values{
		"secret": {os.Getenv("6LeTKHUrAAAAAOajSfcXlQSn-YYH4aCz2zTiwfa0")},
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
	if !ok {
		return errors.WithStack(errors.New("success: " + tmpls.NotExistErr))

	}

	if !success {
		return errors.WithStack(errors.New("success: false"))
	}

	return nil
}
