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
		temporaryIdCancelled, refreshTokenCancelled, _, err := data.GetTemporaryIdCancelledRefreshTokenCancelledAndRefreshTokenFromDb(temporaryId, userAgent)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) || temporaryIdCancelled || refreshTokenCancelled {
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
		email, permanentId, userAgent, yauth, err := data.GetUserFromDb(temporaryId)
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
			Logout(w, r)
			if err := tools.SuspiciousLoginEmailSend(email, r.UserAgent()); err != nil {
				errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}
			return
		}

		temporaryIdCancelled, refreshTokenCancelled, refreshToken, err := data.GetTemporaryIdCancelledRefreshTokenCancelledAndRefreshTokenFromDb(permanentId, userAgent)
		if err != nil {
			errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}

		if temporaryIdCancelled || refreshTokenCancelled {
			Logout(w, r)
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

	temporaryIdCancelled, refreshTokenCancelled := true, true
	if err := data.SetTemporaryIdCancelledAndRefreshTokenCancelledInDb(permanentId, userAgent, temporaryIdCancelled, refreshTokenCancelled); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}
	data.ClearTemporaryIdInCookies(w)

	http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
}
