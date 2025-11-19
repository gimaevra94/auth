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
		temporaryIdCancelled, _, err := data.GetTemporaryIdCancelledAndRefreshTokenCancelledFromDb(temporaryId, userAgent)
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
			http.Redirect(w, r, consts.GeneratePasswordResetLinkURL, http.StatusFound)
			return
		}

		if cancelled, err := data.GetResetTokenCancelledFromDb(token); err != nil || cancelled {
			http.Redirect(w, r, consts.GeneratePasswordResetLinkURL, http.StatusFound)
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

		email, permanentId, userAgent, err := data.GetAllUserKeysFromDb(Cookies.Value)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
				return
			}
			errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}

		temporaryId := Cookies.Value
		if userAgent != r.UserAgent() {
			data.ClearTemporaryIdInCookies(w)
			temporaryIdCancelled, refreshTokenCancelled := true, true
			if err := data.SetTemporaryIdCancelledAndRefreshTokenCancelledInDb(permanentId, userAgent, temporaryIdCancelled, refreshTokenCancelled); err != nil {
				errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}
			if err := tools.SuspiciousLoginEmailSend(email, r.UserAgent()); err != nil {
				errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}
			http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
			return
		}

		temporaryIdCancelled, refreshTokenCancelled, err := data.GetTemporaryIdRefreshTokenAndTheyCancelledFromDb(temporaryId, userAgent)
		if err != nil {
			errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}

		if temporaryIdCancelled || refreshTokenCancelled {
			data.ClearTemporaryIdInCookies(w)
			temporaryIdCancelled, refreshTokenCancelled := true, true
			if err := data.SetTemporaryIdCancelledAndRefreshTokenCancelledInDb(permanentId, userAgent, temporaryIdCancelled, refreshTokenCancelled); err != nil {
				errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}
			http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
			return
		}



		next.ServeHTTP(w, r)
	})
}
