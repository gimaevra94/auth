package data

import (
	"net/http"

	"github.com/pkg/errors"
)

func CookieAccessTokenSet(w http.ResponseWriter, v string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Value:    v,
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

func CookieIsExist(r *http.Request) (string, error) {
	cookie, err := r.Cookie("token")
	if err != nil {
		return "", errors.WithStack(err)
	}

	if cookie.Value == "" {
		return "", errors.New("token not exist")
	}

	return cookie, nil
}

func ClearCookies(w http.ResponseWriter, r *http.Request) {
	ClearCookie(w)
	http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
}
