package auth

import (
	"log"
	"net/http"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/data"
	"github.com/pkg/errors"
)

func Logout(w http.ResponseWriter, r *http.Request) {
	Revocate(w, r, true, true, true)
	http.Redirect(w, r, consts.SignInURL, http.StatusFound)
}

func SimpleLogout(w http.ResponseWriter, r *http.Request) {
	Revocate(w, r, true, true, false)
	http.Redirect(w, r, consts.SignInURL, http.StatusFound)
}

func Revocate(w http.ResponseWriter, r *http.Request, cookieClear, idCancel, tokenCancel bool) {
	cookie, err := data.TemporaryUserIDCookiesGet(r)
	if err != nil {
		log.Printf("%v", errors.WithStack(err))
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}
	temporaryUserID := cookie.Value

	if cookieClear {
		data.TemporaryUserIDCookiesClear(w)
	}

	if idCancel {
		err := data.TemporaryUserIDCancel(temporaryUserID)
		if err != nil {
			log.Printf("%v", errors.WithStack(err))
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}
	}

	if tokenCancel {
		permanentUserID, _, err := data.MWUserCheck(temporaryUserID)
		if err != nil {
			log.Printf("%v", errors.WithStack(err))
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}

		refreshToken, deviceInfo, tokenCancelled, err := data.RefreshTokenCheck(permanentUserID, r.UserAgent())
		if err != nil {
			log.Printf("%v", errors.WithStack(err))
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}

		if deviceInfo != r.UserAgent() {
			err := errors.New("deviceInfo not match")
			log.Printf("%v", errors.WithStack(err))
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}

		if !tokenCancelled {
			err = data.TokenCancel(refreshToken, deviceInfo)
			if err != nil {
				log.Printf("%v", errors.WithStack(err))
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}
		}
	}
}
