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
		temporaryIdCancelled, err := data.IsTemporaryIdCancelled(temporaryId, userAgent)
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

		isResetTokenCancelled, err := data.IsResetTokenCancelled(token, r.UserAgent())
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) || isResetTokenCancelled {
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
		permanentId, userAgent, cancelled, yauth, err := data.GetTemporaryIdKeys(temporaryId)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) || cancelled {
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
			email, err := data.GetEmailFromDb(permanentId)
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					http.Redirect(w, r, consts.SignUpURL, http.StatusFound)
					return
				}
				errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}

			if err := tools.SuspiciousLoginEmailSend(email, r.UserAgent()); err != nil {
				errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}
			Logout(w, r)
			return
		}

		refreshToken, refreshTokenCancelled, err := data.GetRefreshTokenFromDb(permanentId, userAgent)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) || refreshTokenCancelled {
				Logout(w, r)
				return
			}
			errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}

		if refreshTokenCancelled {
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
	permanentId, yauth, err := data.GetPermanentIdFromDbByTemporaryId(temporaryId)
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

	cancelled := true
	if err := data.SetTemporaryIdInDbTx(tx, permanentId, temporaryId, userAgent, cancelled, yauth); err != nil {
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
