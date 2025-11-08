package tools

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/gimaevra94/auth/app/consts"
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

	if err = json.Unmarshal(body, &result); err != nil {
		return errors.WithStack(err)
	}

	success, ok := result["success"].(bool)
	if !ok || !success {
		return errors.New("reCAPTCHA verification failed")
	}

	return nil
}

func UpdateAndRenderCaptchaState(w http.ResponseWriter, r *http.Request, captchaCounter int64, ShowCaptcha bool) error {
	var msgData structs.SignUpPageData

	if captchaCounter > 0 {
		if err := data.SetCaptchaDataInSession(w, r, "captchaCounter", captchaCounter); err != nil {
			return errors.WithStack(err)
		}
	}

	if captchaCounter == 0 {
		ShowCaptcha = true
	}

	if err := data.SetCaptchaDataInSession(w, r, "ShowCaptcha", ShowCaptcha); err != nil {
		return errors.WithStack(err)
	}

	if ShowCaptcha {
		captchaToken := r.FormValue("g-recaptcha-response")
		if captchaToken == "" {
			msgData = structs.SignUpPageData{Msg: consts.MsgForUser["captchaRequired"].Msg, ShowCaptcha: ShowCaptcha, Regs: nil}
		} else {
			msgData = structs.SignUpPageData{Msg: "", ShowCaptcha: ShowCaptcha, Regs: nil}
		}
		if err := TmplsRenderer(w, BaseTmpl, "signUp", msgData); err != nil {
			LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		}
	}

	return nil
}
