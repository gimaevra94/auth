package data

import (
	"net/http"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/pkg/errors"
)

const temporaryIdExp = 30 * 24 * 60 * 60

func SetTemporaryIdInCookies(w http.ResponseWriter, v string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "temporaryId",
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		Value:    v,
		MaxAge:   temporaryIdExp,
	})
}

func GetTemporaryIdFromCookies(r *http.Request) (*http.Cookie, error) {
	Cookies, err := r.Cookie("temporaryId")
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if Cookies.Value == "" {
		return nil, errors.New("temporaryId not exist")
	}
	return Cookies, nil
}

func ClearTemporaryIdInCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "temporaryId",
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func ClearCookiesDev(w http.ResponseWriter, r *http.Request) {
	ClearTemporaryIdInCookies(w)
	if err := EndAuthSession(w, r); err != nil {
		errors.WithStack(err)
	}
	if err := EndCaptchaSession(w, r); err != nil {
		errors.WithStack(err)
	}
	http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
}
