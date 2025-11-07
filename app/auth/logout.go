package auth

import (
	"net/http"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/tools"
)

func Logout(w http.ResponseWriter, r *http.Request) {
	Revocate(w, r, true, true, true)
	http.Redirect(w, r, consts.SignInURL, http.StatusFound)
}

func SimpleLogout(w http.ResponseWriter, r *http.Request) {
	Revocate(w, r, true, true, false)
	http.Redirect(w, r, consts.SignInURL, http.StatusFound)
}

func Revocate(w http.ResponseWriter, r *http.Request, CookiesClear, temporaryIdCancel, refreshTokenCancel bool) {
	if CookiesClear {
		data.ClearTemporaryIdInCookies(w)
	}

	tx, err := data.Db.Begin()
	if err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	defer func() {
		if err := recover(); err != nil {
			tx.Rollback()
			panic(err)
		}
	}()

	Cookies, err := data.GetTemporaryIdFromCookies(r)
	if err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}
	temporaryId := Cookies.Value

	if temporaryIdCancel {
		if err := data.SetTemporaryIdCancelledInDbTx(tx, temporaryId); err != nil {
			tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}
	}

	if refreshTokenCancel {
		_, _, permanentId, _, err := data.GetAllUserKeysFromDb(temporaryId)
		if err != nil {
			tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}

		refreshToken, userAgent, refreshTokenCancelled, err := data.GetAllRefreshTokenKeysFromDb(permanentId, r.UserAgent())
		if err != nil {
			tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}

		if !refreshTokenCancelled {
			if err := data.SetRefreshTokenCancelledInDbTx(tx, refreshToken, userAgent); err != nil {
				tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}
		}
	}

	if err := tx.Commit(); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}
}
