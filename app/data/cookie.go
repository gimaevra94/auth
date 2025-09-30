package data

import (
	"net/http"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/pkg/errors"
)

func UserPreferenceCookieSet(w http.ResponseWriter, v []byte) {
	http.SetCookie(w, &http.Cookie{
		Name:     "userPreference",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Value:    string(v),
		MaxAge:   consts.TemporaryUserIDExp,
	})
}

func ClearCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "userPreference",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

func GetCookies(r *http.Request) (*http.Cookie, error) {
	cookie, err := r.Cookie("userPreference")
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if cookie.Value == "" {
		return nil, errors.New("userPreference not exist")
	}

	return cookie, nil
}

func ClearCookiesDev(w http.ResponseWriter, r *http.Request) {
	ClearCookies(w)
	http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
}
