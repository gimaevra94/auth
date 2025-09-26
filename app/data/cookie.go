package data

import (
	"net/http"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/pkg/errors"
)

func CookieAccessTokenSet(w http.ResponseWriter, v string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "accessToken",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Value:    v,
		MaxAge:   consts.AccessTokenExp15Min,
	})
}

func ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

func CookieIsExist(r *http.Request) (*http.Cookie, error) {
	cookie, err := r.Cookie("accessToken")
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if cookie.Value == "" {
		return nil, errors.New("accessToken not exist")
	}

	return cookie, nil
}

func ClearCookies(w http.ResponseWriter, r *http.Request) {
	ClearCookie(w)
	http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
}
