package data

import (
	"net/http"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/pkg/errors"
)

func SetTemporaryIdInCookies(w http.ResponseWriter, value string, temporaryIdExp int, rememberMe bool) {
	temporaryIdExp24Hours := 24 * 60 * 60
	if !rememberMe {
		temporaryIdExp = temporaryIdExp24Hours
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "temporaryId",
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		Value:    value,
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
	if err := EndAuthAndCaptchaSessions(w, r); err != nil {
		errors.WithStack(err)
	}
	http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
}
