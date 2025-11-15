package errs

import (
	"log"
	"net/http"
	"strings"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/tools"
)

func LogAndRedirectIfErrNotNill(w http.ResponseWriter, r *http.Request, err error, url string) {
	log.Printf("%+v", err)
	if url == "" || url == "/" {
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	} else {
		http.Redirect(w, r, url, http.StatusFound)
		return
	}
}

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
