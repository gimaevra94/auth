package auth

import (
	"database/sql"
	"net/http"

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
		userAgent := r.UserAgent()
		_, temporaryIdCancelled, _, err := data.GetTemporaryIdCancelledAndRefreshTokenCancelledFromDb(temporaryId, userAgent)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) || temporaryIdCancelled {
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

		if cancelled, err := data.GetResetTokenCancelledFromDb(token); err != nil || cancelled {
			http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
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
		email, permanentId, userAgent, yauth, err := data.GetAllUserKeysFromDb(temporaryId)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
				return
			}
			errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}

		if yauth {
			next.ServeHTTP(w, r)
			return
		}

		if userAgent != r.UserAgent() {
			if err := Logout(w, r, permanentId, userAgent); err != nil {
				errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}
			if err := tools.SuspiciousLoginEmailSend(email, r.UserAgent()); err != nil {
				errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}
			return
		}

		refreshToken, temporaryIdCancelled, refreshTokenCancelled, err := data.GetTemporaryIdCancelledAndRefreshTokenCancelledFromDb(permanentId, userAgent)
		if err != nil {
			errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}

		if temporaryIdCancelled || refreshTokenCancelled {
			if err := Logout(w, r, permanentId, userAgent); err != nil {
				errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}
			return
		}

		if err := tools.RefreshTokenValidate(refreshToken); err != nil {
			if err := Logout(w, r, permanentId, userAgent); err != nil {
				errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}
			return
		}

		next.ServeHTTP(w, r)
	})
}

func Logout(w http.ResponseWriter, r *http.Request) error {
	data.ClearTemporaryIdInCookies(w)
	temporaryIdCancelled, refreshTokenCancelled := true, true
	if err := data.SetTemporaryIdCancelledAndRefreshTokenCancelledInDb(permanentId, userAgent, temporaryIdCancelled, refreshTokenCancelled); err != nil {
		return errors.WithStack(err)
	}
	http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
	return nil
}
