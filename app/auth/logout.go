package auth

import (
	"net/http"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/errs"
)

func Logout(w http.ResponseWriter, r *http.Request) {
	Revocate(w, r, true, true, true)
	http.Redirect(w, r, consts.SignInURL, http.StatusFound)
}

func SimpleLogout(w http.ResponseWriter, r *http.Request) {
	Revocate(w, r, true, true, false)
	http.Redirect(w, r, consts.SignInURL, http.StatusFound)
}

func Revocate(w http.ResponseWriter, r *http.Request, cookieClear, temporaryUserIdCancel, refreshTokenCancel bool) {
	if cookieClear {
		data.TemporaryUserIdCookiesClear(w)
	}

	tx, err := data.DB.Begin()
	if err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	defer func() {
		if err := recover(); err != nil {
			tx.Rollback()
			panic(err)
		}
	}()

	cookie, err := data.GetTemporaryUserIdFromCookie(r)
	if err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}
	temporaryUserId := cookie.Value

	if temporaryUserIdCancel {
		if err := data.TemporaryUserIdCancelTx(tx, temporaryUserId); err != nil {
			errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}
	}

	if refreshTokenCancel {
		_, _, permanentUserId, _, err := data.MWUserCheck(temporaryUserId)
		if err != nil {
			errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}

		refreshToken, deviceInfo, refreshTokenCancelled, err := data.RefreshTokenCheck(permanentUserId, r.UserAgent())
		if err != nil {
			errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}

		if !refreshTokenCancelled {
			if err := data.TokenCancelTx(tx, refreshToken, deviceInfo); err != nil {
				errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}
		}
	}

	if err := tx.Commit(); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}
}
