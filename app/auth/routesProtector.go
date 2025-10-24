package auth

import (
	"database/sql"
	"log"
	"net/http"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/pkg/errors"
)

func IsExpiredTokenMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("routesProtector: Request URL: %s", r.URL.Path)
		log.Printf("routesProtector: Received cookies: %+v", r.Cookies())
		cookie, err := data.TemporaryUserIDCookiesGet(r)
		if err != nil {
			log.Println("routesProtector: Redirecting to SignInURL because TemporaryUserID cookie not found or expired.")
			http.Redirect(w, r, consts.SignInURL, http.StatusFound)
			return
		}

		temporaryUserID := cookie.Value
		login, email, permanentUserID, temporaryCancelled, err := data.MWUserCheck(temporaryUserID)
		if err != nil {
			log.Printf("%v", errors.WithStack(err))
			log.Println("routesProtector: Redirecting to Err500URL because MWUserCheck failed.")
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}

		if temporaryCancelled {
			log.Println("routesProtector: Redirecting to SignInURL because temporaryUserID is cancelled.")
			Revocate(w, r, true, false, false)
			http.Redirect(w, r, consts.SignInURL, http.StatusFound)
			return
		}

		refreshToken, deviceInfo, tokenCancelled, err := data.RefreshTokenCheck(permanentUserID, r.UserAgent())
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				log.Println("routesProtector: RefreshToken not found for permanentUserID or UserAgent. Sending new device login alert and allowing request.")
				if mailErr := tools.SendNewDeviceLoginEmail(email, login, r.UserAgent()); mailErr != nil {
					log.Printf("%v", errors.WithStack(mailErr))
					log.Println("routesProtector: Redirecting to Err500URL because SendNewDeviceLoginEmail failed.")
					http.Redirect(w, r, consts.Err500URL, http.StatusFound)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			log.Printf("%v", errors.WithStack(err))
			log.Println("routesProtector: Redirecting to Err500URL because RefreshTokenCheck failed.")
			http.Redirect(w, r, consts.Err500URL, http.StatusFound)
			return
		}

		if deviceInfo != r.UserAgent() {
			log.Println("routesProtector: UserAgent mismatch. Sending suspicious login alert and allowing request.")
			if mailErr := tools.SendSuspiciousLoginEmail(email, login, r.UserAgent()); mailErr != nil {
				log.Printf("%v", errors.WithStack(mailErr))
				log.Println("routesProtector: Redirecting to Err500URL because SendSuspiciousLoginEmail failed.")
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		err = tools.RefreshTokenValidate(refreshToken)
		if err != nil {
			log.Println("routesProtector: Redirecting to SignInURL because RefreshToken is invalid or expired.")
			Revocate(w, r, true, true, true)
			http.Redirect(w, r, consts.SignInURL, http.StatusFound)
			return
		}

		if tokenCancelled {
			log.Println("routesProtector: Redirecting to SignInURL because RefreshToken is cancelled.")
			Revocate(w, r, true, true, false)
			err := tools.SendSuspiciousLoginEmail(email, login, deviceInfo)
			if err != nil {
				log.Printf("%v", errors.WithStack(err))
				log.Println("routesProtector: Redirecting to Err500URL because SendSuspiciousLoginEmail failed.")
				http.Redirect(w, r, consts.Err500URL, http.StatusFound)
				return
			}
			http.Redirect(w, r, consts.SignInURL, http.StatusFound)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// AlreadyAuthedRedirectMW redirects authenticated users away from public pages (e.g., sign-in/sign-up)
func AlreadyAuthedRedirectMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try to read auth cookie; if missing, user is not authed -> show public page
		cookie, err := data.TemporaryUserIDCookiesGet(r)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		temporaryUserID := cookie.Value
		_, _, permanentUserID, temporaryCancelled, err := data.MWUserCheck(temporaryUserID)
		if err != nil || temporaryCancelled {
			// Not a valid temporary session -> continue to public page
			next.ServeHTTP(w, r)
			return
		}

		refreshToken, deviceInfo, tokenCancelled, err := data.RefreshTokenCheck(permanentUserID, r.UserAgent())
		if err != nil || tokenCancelled || deviceInfo != r.UserAgent() {
			next.ServeHTTP(w, r)
			return
		}

		if err := tools.RefreshTokenValidate(refreshToken); err != nil {
			next.ServeHTTP(w, r)
			return
		}

		// User is authenticated -> redirect to Home
		http.Redirect(w, r, consts.HomeURL, http.StatusFound)
	})
}

// SignUpFlowOnlyMW allows access only when signup flow is in progress
// (session user exists and server code is generated). Otherwise redirects to SignUp.
func SignUpFlowOnlyMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := data.SessionUserGet(r)
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

// ResetTokenGuardMW ensures set-new-password is accessible only via a valid reset link
func ResetTokenGuardMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if token == "" {
			http.Redirect(w, r, consts.PasswordResetURL, http.StatusFound)
			return
		}
		// Validate JWT structure and expiry
		if _, err := tools.ValidateResetToken(token); err != nil {
			http.Redirect(w, r, consts.PasswordResetURL, http.StatusFound)
			return
		}
		// Check token presence and not cancelled in DB
		cancelled, err := data.ResetTokenCheck(token)
		if err != nil || cancelled {
			http.Redirect(w, r, consts.PasswordResetURL, http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}
