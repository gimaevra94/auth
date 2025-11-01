package data

import (
	"net/http"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/pkg/errors"
)

func SetTemporaryUserIdInCookies(w http.ResponseWriter, v string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "temporaryUserId",
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		Value:    v,
		MaxAge:   consts.TemporaryUserIdExp,
	})
}

func GetTemporaryUserIdFromCookies(r *http.Request) (*http.Cookie, error) {
	Cookies, err := r.Cookie("temporaryUserId")
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if Cookies.Value == "" {
		return nil, errors.New("temporaryUserId not exist")
	}

	return Cookies, nil
}

func ClearTemporaryUserIdFromCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "temporaryUserId",
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func ClearCookiesDev(w http.ResponseWriter, r *http.Request) {
	ClearTemporaryUserIdFromCookies(w)
	err := EndAuthSession(w, r)
	if err != nil {
		errors.WithStack(err)
	}
	err = CaptchaSessionEnd(w, r)
	if err != nil {
		errors.WithStack(err)
	}
	http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
}
