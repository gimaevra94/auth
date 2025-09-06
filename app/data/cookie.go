package data

import (
	"net/http"

	"github.com/pkg/errors"
)

func SetCookieWithToken(w http.ResponseWriter, v string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Value:    v,
	})
}

func SetCookieWithoutToken(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
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
		return "", err
	}

	if cookie.Value == "" {
		return "", errors.New("token not exist")
	}

	tokenValue:=cookie.Value
	return tokenValue, nil
}
