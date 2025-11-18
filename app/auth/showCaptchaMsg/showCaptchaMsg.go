package showCaptchaMsg

import (
	"net/http"
	"strings"

	"github.com/gimaevra94/auth/app/tools"
)

func ShowCaptchaMsg(r *http.Request, showCaptcha bool) bool {
	if showCaptcha {
		if err := tools.ShowCaptcha(r); err != nil {
			if strings.Contains(err.Error(), "captchaToken not exist") || strings.Contains(err.Error(), "reCAPTCHA verification failed") {
				return true
			}
			return false
		}
	}
	return false
}
