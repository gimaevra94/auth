package auth

import (
	"net/http"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/errs"
	"github.com/gimaevra94/auth/app/tools"
)

func AuthGuardForSignUpAndSignInPath(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Cookies, err := data.GetTemporaryIdFromCookies(r)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		temporaryId := Cookies.Value
		permanentId, temporaryIdCancelled, err := data.GetpermanentIdAndTemporaryIdCancelledFromDb(temporaryId)
		if err != nil || temporaryIdCancelled {
			next.ServeHTTP(w, r)
			return
		}

		_, _, refreshTokenCancelled, err := data.GetAllRefreshTokenKeysFromDb(permanentId, r.UserAgent())
		if err != nil || refreshTokenCancelled {
			next.ServeHTTP(w, r)
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

		temporaryId := Cookies.Value
		login, email, permanentId, temporaryIdCancelled, err := data.GetAllUserKeysFromDb(temporaryId)
		if err != nil {
			errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}

		if temporaryIdCancelled {
			Revocate(w, r, true, false, false)
			http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
			return
		}

		_, userAgent, refreshTokenCancelled, err := data.GetAllRefreshTokenKeysFromDb(permanentId, r.UserAgent())
		if err != nil {
			errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}

		if userAgent != r.UserAgent() || userAgent == "" {
			if err := tools.SuspiciousLoginEmailSend(email, login, r.UserAgent()); err != nil {
				errs.LogAndRedirectIfErrNotNill(w, r, err, consts.SignUpURL)
				return
			}
			Revocate(w, r, true, true, true)
			http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
			return
		}

		if refreshTokenCancelled {
			Revocate(w, r, true, true, false)
			userAgent := r.UserAgent()
			if err := tools.SuspiciousLoginEmailSend(email, login, userAgent); err != nil {
				errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}

			http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
			return
		}

		next.ServeHTTP(w, r)
	})
}
