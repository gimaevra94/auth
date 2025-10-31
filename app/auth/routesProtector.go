package auth

import (
	"net/http"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/errs"
	"github.com/gimaevra94/auth/app/tools"
)

func IsExpiredTokenMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := data.GetTemporaryUserIdFromCookie(r)
		if err != nil {
			errs.LogAndRedirectIfErrNotNill(w, r, err, consts.SignUpURL)
			return
		}
		temporaryUserId := cookie.Value

		login, email, permanentUserId, temporaryUserIdCancelled, err := data.MWUserCheck(temporaryUserId)
		if err != nil {
			errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}

		if temporaryUserIdCancelled {
			Revocate(w, r, true, false, false)
			http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
			return
		}

		_, deviceInfo, refreshTokenCancelled, err := data.RefreshTokenCheck(permanentUserId, r.UserAgent())
		if err != nil {
			errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}

		if deviceInfo != r.UserAgent() {
			err := tools.SendSuspiciousLoginEmail(email, login, r.UserAgent())
			if err != nil {
				errs.LogAndRedirectIfErrNotNill(w, r, err, consts.SignUpURL)
				return
			}

			Revocate(w, r, true, true, true)
			http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
			return
		}

		if refreshTokenCancelled {
			Revocate(w, r, true, true, false)
			err := tools.SendSuspiciousLoginEmail(email, login, deviceInfo)
			if err != nil {
				errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}

			http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func AlreadyAuthedRedirectMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := data.GetTemporaryUserIdFromCookie(r)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		temporaryUserId := cookie.Value
		_, _, permanentUserId, temporaryUserIdCancelled, err := data.MWUserCheck(temporaryUserId)
		if err != nil || temporaryUserIdCancelled {
			next.ServeHTTP(w, r)
			return
		}

		_, _, refreshTokenCancelled, err := data.RefreshTokenCheck(permanentUserId, r.UserAgent())
		if err != nil || refreshTokenCancelled {
			next.ServeHTTP(w, r)
			return
		}

		http.Redirect(w, r, consts.HomeURL, http.StatusFound)
	})
}

func SignUpFlowOnlyMW(next http.Handler) http.Handler {
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

// ResetTokenGuardMW обеспечивает доступ к установке нового пароля только через действительную ссылку сброса
func ResetTokenGuardMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if token == "" {
			http.Redirect(w, r, consts.PasswordResetURL, http.StatusFound)
			return
		}
		// Проверяем структуру JWT и срок действия
		if _, err := tools.ValIdateResetToken(token); err != nil {
			http.Redirect(w, r, consts.PasswordResetURL, http.StatusFound)
			return
		}
		// Проверяем наличие токена и отсутствие отмены в БД
		cancelled, err := data.ResetTokenCheck(token)
		if err != nil || cancelled {
			http.Redirect(w, r, consts.PasswordResetURL, http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}
