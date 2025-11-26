package auth

import (
	"database/sql"
	"net/http"
	"strings"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/errs"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/pkg/errors"
)

func AuthGuardForSignUpAndSignInPath(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Cookies, err := data.GetTemporaryIdFromCookies(r)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		temporaryId := Cookies.Value
		if err := data.IsTemporaryIdCancelled(temporaryId); err != nil {
			if strings.Contains(err.Error(), "temporaryId cancelled") {
				next.ServeHTTP(w, r)
				return
			}
			errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}

		http.Redirect(w, r, consts.HomeURL, http.StatusFound)
	})
}

func AuthGuardForServerAuthCodeSendPath(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		user, err := data.GetAuthDataFromSession(r)
		if err != nil {
			http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
			return
		}

		if user.ServerCode == "" {
			http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func ResetTokenGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if token == "" {
			http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
			return
		}

		if _, err := tools.ResetTokenValidate(token); err != nil {
			http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
			return
		}

		if err := data.IsPasswordResetTokenCancelled(token); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
				return
			}
			errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func AuthGuardForHomePath(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		Cookies, err := data.GetTemporaryIdFromCookies(r)
		if err != nil {
			http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
			return
		}

		temporaryId := Cookies.Value

		permanentId, userAgent, err := data.GetTemporaryIdKeysFromDb(temporaryId)
		if err != nil {
			errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}

		email, err := data.GetEmailFromDb(permanentId)
		if err != nil {
			errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}

		if userAgent != r.UserAgent() {
			if err := tools.SuspiciousLoginEmailSend(email, r.UserAgent()); err != nil {
				errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}
			Logout(w, r)
			return
		}

		refreshToken, err := data.GetRefreshTokenFromDb(permanentId, userAgent)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				Logout(w, r)
				return
			}
			errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}

		if err := tools.RefreshTokenValidate(refreshToken); err != nil {
			Logout(w, r)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func Logout(w http.ResponseWriter, r *http.Request) {

	cookie, err := data.GetTemporaryIdFromCookies(r)
	if err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	temporaryId := cookie.Value

	permanentId, err := data.GetPermanentIdFromDbByTemporaryId(temporaryId)
	if err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	userAgent := r.UserAgent()

	tx, err := data.Db.Begin()
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

	if err := data.SetTemporaryIdCancelledInDbTx(tx, permanentId, userAgent); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if err := data.SetRefreshTokenCancelledInDbTx(tx, permanentId, userAgent); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if err = tx.Commit(); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	data.ClearTemporaryIdInCookies(w)

	http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
}
