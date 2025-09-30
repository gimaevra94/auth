package auth

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/structs"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/pkg/errors"
)

var revocate structs.Revocate

func IsExpiredTokenMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var userPreferencesString string

		cookie, err := data.GetCookies(r)
		if err != nil {
			http.Redirect(w, r, consts.SignInURL, http.StatusFound)
			return
		}

		userPreferencesString = cookie.Value
		userPreferencesBytes := []byte(userPreferencesString)
		var userPreferences structs.UserPreferences

		err = json.Unmarshal([]byte(userPreferencesBytes), &userPreferences)
		if err != nil {
			log.Printf("%v", errors.WithStack(err))
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}

		permanentUserID, temporaryCancelled, err := data.MWUsernCheck(userPreferences.TemporaryUserID)
		if err != nil {
			log.Printf("%v", errors.WithStack(err))
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}

		if temporaryCancelled {
			Revocate(w, r, true, false, false)
			http.Redirect(w, r, consts.SignInURL, http.StatusFound)
			return
		}

		refreshToken, deviceInfo, tokenCancelled, err := data.RefreshTokenCheck(permanentUserID, r.UserAgent())
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				Revocate(w, r, true, true, false)
				http.Redirect(w, r, consts.SignInURL, http.StatusFound)
				return
			}

			log.Printf("%v", errors.WithStack(err))
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}

		revocate := structs.Revocate{}
		revocate.RefreshToken = refreshToken
		revocate.DeviceInfo = deviceInfo

		if deviceInfo != r.UserAgent() {
			Revocate(w, r, true, true, true)
			http.Redirect(w, r, consts.SignInURL, http.StatusFound)
			return
		}

		err = tools.RefreshTokenValidator(refreshToken)
		if err != nil {
			Revocate(w, r, true, true, true)
			http.Redirect(w, r, consts.SignInURL, http.StatusFound)
			return
		}

		if tokenCancelled {
			errors.WithStack(err)
			Revocate(w, r, true, true, false)
			//алерт на почту
			http.Redirect(w, r, consts.SignInURL, http.StatusFound)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func Logout(w http.ResponseWriter, r *http.Request) {
	err := data.SessionEnd(w, r)
	if err != nil {
		data.ClearCookies(w)
		http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
		return
	}
}

func SimpleLogout(w http.ResponseWriter, r *http.Request) {
	data.ClearCookies(w)
	http.Redirect(w, r, consts.SignInURL, http.StatusFound)
}

func Revocate(w http.ResponseWriter, r *http.Request, cookieClear, idCancel, tokenCancel bool) {
	if cookieClear {
		data.ClearCookies(w)
		return
	}

	if idCancel {
		err := data.TemporaryUserIDCancel(revocate.UserPreferences.TemporaryUserID)
		if err != nil {
			log.Printf("%v", errors.WithStack(err))
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}
	}

	if tokenCancel {
		err := data.TokenCancel(revocate.RefreshToken, revocate.DeviceInfo)
		if err != nil {
			log.Printf("%v", errors.WithStack(err))
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}
	}
}
