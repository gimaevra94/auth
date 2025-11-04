package auth

import (
	"net/http"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/tools"
)

func AuthGuardForHomePath(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Cookies, err := data.GetTemporaryUserIdFromCookies(r)
		if err != nil {
			tools.LogAndRedirectIfErrNotNill(w, r, err, consts.SignUpURL)
			return
		}
		temporaryUserId := Cookies.Value

		login, email, permanentUserId, temporaryUserIdCancelled, err := data.GetAllUsersKeysFromDb(temporaryUserId)
		if err != nil {
			tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}

		if temporaryUserIdCancelled {
			Revocate(w, r, true, false, false)
			http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
			return
		}

		_, userAgent, refreshTokenCancelled, err := data.GetAllRefreshTokenKeysFromDb(permanentUserId, r.UserAgent())
		if err != nil {
			tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}

		if userAgent != r.UserAgent() {
			if err := tools.SendSuspiciousLoginEmail(email, login, r.UserAgent()); err != nil {
				tools.LogAndRedirectIfErrNotNill(w, r, err, consts.SignUpURL)
				return
			}

			Revocate(w, r, true, true, true)
			http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
			return
		}

		if refreshTokenCancelled {
			Revocate(w, r, true, true, false)
			if err := tools.SendSuspiciousLoginEmail(email, login, userAgent); err != nil {
				tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}

			http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func AuthGuardForSignInPath(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Cookies, err := data.GetTemporaryUserIdFromCookies(r)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		temporaryUserId := Cookies.Value
		permanentUserId, temporaryUserIdCancelled, err := data.GetPermanentUserIdAndTemporaryUserIdCancelledFlagFromDb(temporaryUserId)
		if err != nil || temporaryUserIdCancelled {
			next.ServeHTTP(w, r)
			return
		}

		_, _, refreshTokenCancelled, err := data.GetAllRefreshTokenKeysFromDb(permanentUserId, r.UserAgent())
		if err != nil || refreshTokenCancelled {
			next.ServeHTTP(w, r)
			return
		}

		http.Redirect(w, r, consts.HomeURL, http.StatusFound)
	})
}

func AuthGuardForSignUpPath(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := data.GetUserFromSession(r)
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
			http.Redirect(w, r, consts.PasswordResetURL, http.StatusFound)
			return
		}

		if _, err := tools.ValIdateResetToken(token); err != nil {
			http.Redirect(w, r, consts.PasswordResetURL, http.StatusFound)
			return
		}

		if cancelled, err := data.GetResetTokenCancelledFlagFromDb(token); err != nil || cancelled {
			http.Redirect(w, r, consts.PasswordResetURL, http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}
