package data

import (
	"net/http"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/pkg/errors"
)

func SetTemporaryUserIdInCookie(w http.ResponseWriter, v string) {
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

func TemporaryUserIdCookiesClear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "temporaryUserId",
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func GetTemporaryUserIdFromCookie(r *http.Request) (*http.Cookie, error) {
	cookie, err := r.Cookie("temporaryUserId")
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if cookie.Value == "" {
		return nil, errors.New("temporaryUserId not exist")
	}

	return cookie, nil
}

func ClearCookiesDev(w http.ResponseWriter, r *http.Request) {
	TemporaryUserIdCookiesClear(w)
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
