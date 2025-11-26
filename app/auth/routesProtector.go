package auth

import (
	"database/sql"
	"log"
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
		log.Printf("[DEBUG] AuthGuardForSignUpAndSignInPath called for path: %s", r.URL.Path)

		Cookies, err := data.GetTemporaryIdFromCookies(r)
		if err != nil {
			log.Printf("[DEBUG] No temporaryId cookie found, proceeding to next handler")
			next.ServeHTTP(w, r)
			return
		}

		temporaryId := Cookies.Value
		log.Printf("[DEBUG] Found temporaryId cookie: %s", temporaryId)

		if err := data.IsTemporaryIdCancelled(temporaryId); err != nil {
			if strings.Contains(err.Error(), "temporaryId cancelled") {
				log.Printf("[DEBUG] temporaryId %s is cancelled, proceeding to next handler", temporaryId)
				next.ServeHTTP(w, r)
				return
			}
			log.Printf("[ERROR] Error checking temporaryId cancellation status: %v", err)
			errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}

		log.Printf("[DEBUG] temporaryId %s is valid and not cancelled, redirecting to home", temporaryId)
		http.Redirect(w, r, consts.HomeURL, http.StatusFound)
	})
}

func AuthGuardForServerAuthCodeSendPath(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[DEBUG] AuthGuardForServerAuthCodeSendPath called for path: %s", r.URL.Path)

		user, err := data.GetAuthDataFromSession(r)
		if err != nil {
			log.Printf("[DEBUG] Error getting auth data from session: %v, redirecting to signup", err)
			http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
			return
		}

		if user.ServerCode == "" {
			log.Printf("[DEBUG] ServerCode is empty in session, redirecting to signup")
			http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
			return
		}

		log.Printf("[DEBUG] ServerCode exists in session, proceeding to next handler")
		next.ServeHTTP(w, r)
	})
}

func ResetTokenGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[DEBUG] ResetTokenGuard called for path: %s", r.URL.Path)

		token := r.URL.Query().Get("token")
		if token == "" {
			log.Printf("[DEBUG] No token in query parameters, redirecting to signup")
			http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
			return
		}

		log.Printf("[DEBUG] Found token in query: %s", token)

		if _, err := tools.ResetTokenValidate(token); err != nil {
			log.Printf("[DEBUG] Token validation failed: %v, redirecting to signup", err)
			http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
			return
		}

		if err := data.IsPasswordResetTokenCancelled(token); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				log.Printf("[DEBUG] Password reset token %s not found or cancelled, redirecting to signup", token)
				http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
				return
			}
			log.Printf("[ERROR] Error checking password reset token cancellation: %v", err)
			errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}

		log.Printf("[DEBUG] Password reset token %s is valid, proceeding to next handler", token)
		next.ServeHTTP(w, r)
	})
}

func AuthGuardForHomePath(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[DEBUG] AuthGuardForHomePath called for path: %s", r.URL.Path)

		Cookies, err := data.GetTemporaryIdFromCookies(r)
		if err != nil {
			log.Printf("[DEBUG] No temporaryId cookie found, redirecting to signup")
			http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
			return
		}

		temporaryId := Cookies.Value
		log.Printf("[DEBUG] Found temporaryId cookie: %s", temporaryId)

		permanentId, userAgent, err := data.GetTemporaryIdKeysFromDb(temporaryId)
		if err != nil {
			log.Printf("[ERROR] Error getting temporaryId keys from DB: %v, redirecting to signup", err)
			errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}
		log.Printf("[DEBUG] Found permanentId: %s and userAgent: %s for temporaryId: %s", permanentId, userAgent, temporaryId)

		email, yauth, err := data.GetEmailFromDb(permanentId)
		if err != nil {
			log.Printf("[ERROR] Error getting email from DB: %v, redirecting to signup", err)
			errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}
		log.Printf("[DEBUG] Found email: %s, yauth: %t for permanentId: %s", email, yauth, permanentId)

		if yauth {
			log.Printf("[DEBUG] User authenticated via Yandex, proceeding to next handler")
			next.ServeHTTP(w, r)
			return
		}

		if userAgent != r.UserAgent() {
			log.Printf("[DEBUG] UserAgent mismatch: stored: %s, current: %s, sending suspicious login email", userAgent, r.UserAgent())
			if err := tools.SuspiciousLoginEmailSend(email, r.UserAgent()); err != nil {
				log.Printf("[ERROR] Error sending suspicious login email: %v", err)
				errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}
			Logout(w, r)
			return
		}

		refreshToken, err := data.GetRefreshTokenFromDb(permanentId, userAgent)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				log.Printf("[DEBUG] Refresh token not found for permanentId: %s and userAgent: %s, calling logout", permanentId, userAgent)
				Logout(w, r)
				return
			}
			log.Printf("[ERROR] Error getting refresh token from DB: %v", err)
			errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}
		log.Printf("[DEBUG] Found refresh token for permanentId: %s and userAgent: %s", permanentId, userAgent)

		if err := tools.RefreshTokenValidate(refreshToken); err != nil {
			log.Printf("[DEBUG] Refresh token validation failed: %v, calling logout", err)
			Logout(w, r)
			return
		}

		log.Printf("[DEBUG] All checks passed, proceeding to next handler")
		next.ServeHTTP(w, r)
	})
}

func Logout(w http.ResponseWriter, r *http.Request) {
	log.Printf("[DEBUG] Logout called for path: %s", r.URL.Path)

	cookie, err := data.GetTemporaryIdFromCookies(r)
	if err != nil {
		log.Printf("[ERROR] Error getting temporaryId cookie: %v", err)
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	temporaryId := cookie.Value
	log.Printf("[DEBUG] Found temporaryId cookie to logout: %s", temporaryId)

	permanentId, err := data.GetPermanentIdFromDbByTemporaryId(temporaryId)
	if err != nil {
		log.Printf("[ERROR] Error getting permanentId by temporaryId: %v", err)
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}
	log.Printf("[DEBUG] Found permanentId: %s for temporaryId: %s", permanentId, temporaryId)

	userAgent := r.UserAgent()
	log.Printf("[DEBUG] Current userAgent: %s", userAgent)

	tx, err := data.Db.Begin()
	if err != nil {
		log.Printf("[ERROR] Error beginning transaction for logout: %v", err)
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}
	defer func() {
		if err := recover(); err != nil {
			log.Printf("[ERROR] Panic during logout transaction, rolling back: %v", err)
			tx.Rollback()
			panic(err)
		}
	}()

	if err := data.SetTemporaryIdCancelledInDbTx(tx, permanentId, userAgent); err != nil {
		log.Printf("[ERROR] Error setting temporaryId as cancelled in DB: %v", err)
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if err := data.SetRefreshTokenCancelledInDbTx(tx, permanentId, userAgent); err != nil {
		log.Printf("[ERROR] Error setting refreshToken as cancelled in DB: %v", err)
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if err = tx.Commit(); err != nil {
		log.Printf("[ERROR] Error committing transaction for logout: %v", err)
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	log.Printf("[DEBUG] Successfully cancelled temporaryId and refreshToken in DB for permanentId: %s, userAgent: %s", permanentId, userAgent)

	data.ClearTemporaryIdInCookies(w)
	log.Printf("[DEBUG] Cleared temporaryId cookie")

	http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
}