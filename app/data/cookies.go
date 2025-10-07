package data

import (
	"net/http"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/pkg/errors"
)

func TemporaryUserIDCookieSet(w http.ResponseWriter, v string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "temporaryUserID",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Value:    v,
		MaxAge:   consts.TemporaryUserIDExp,
	})
}

func TemporaryUserIDCookiesClear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "temporaryUserID",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

func TemporaryUserIDCookiesGet(r *http.Request) (*http.Cookie, error) {
	cookie, err := r.Cookie("temporaryUserID")
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if cookie.Value == "" {
		return nil, errors.New("temporaryUserID not exist")
	}

	return cookie, nil
}

func ClearCookiesDev(w http.ResponseWriter, r *http.Request) {
	TemporaryUserIDCookiesClear(w)
	http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
}
