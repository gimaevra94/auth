package tools

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/structs"
	"github.com/pkg/errors"
)

func ShowCaptcha(r *http.Request) error {
	captchaToken := r.FormValue("g-recaptcha-response")
	if captchaToken == "" {
		return errors.WithStack(errors.New("captchaToken not exist"))
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

	err = json.Unmarshal(body, &result)
	if err != nil {
		return errors.WithStack(err)
	}

	success, ok := result["success"].(bool)
	if !ok || !success {
		return errors.New("reCAPTCHA verification failed")
	}

	return nil
}

func UpdateAndRenderCaptchaState(w http.ResponseWriter, r *http.Request, captchaCounter int64, ShowCaptcha bool) error {
	err := data.SetCaptchaDataInSession(w, r, "captchaCounter", captchaCounter)
	if err != nil {
		return errors.WithStack(err)
	}

	captchaCounter -= 1
	if captchaCounter == 0 {
		ShowCaptcha = true
	}

	err = data.SetCaptchaDataInSession(w, r, "ShowCaptcha", ShowCaptcha)
	if err != nil {
		return errors.WithStack(err)
	}

	err = TmplsRenderer(w, BaseTmpl, "SignUp", structs.SignUpPageData{Msg: ErrMsg["alreadyExist"].Msg, ShowCaptcha: ShowCaptcha})
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}
