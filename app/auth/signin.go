package auth

import (
	"database/sql"
	"net/http"
	"strings"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/structs"
	"github.com/gimaevra94/auth/app/tools"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

func ValidateSignInInput(w http.ResponseWriter, r *http.Request) {
	var user structs.User
	var ShowCaptcha bool
	login := r.FormValue("login")
	password := r.FormValue("password")
	user = structs.User{
		Login:    login,
		Password: password,
	}

	captchaCounter, err := data.GetCaptchaCounterFromSession(r)
	if err != nil {
		if strings.Contains(err.Error(), "exist") {
			captchaCounter = 3
			if err := data.SetCaptchaDataInSession(w, r, "captchaCounter", captchaCounter); err != nil {
				tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}
			return
		}
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	ShowCaptcha, err = data.GetShowCaptchaFromSession(r)
	if err != nil {
		if strings.Contains(err.Error(), "exist") {
			ShowCaptcha = false
			if err := data.SetCaptchaDataInSession(w, r, "ShowCaptcha", ShowCaptcha); err != nil {
				tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}
			return
		}
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if ShowCaptcha {
		if err := tools.ShowCaptcha(r); err != nil {
			if strings.Contains(err.Error(), "captchaToken not exist") {
				data := structs.SignInPageData{Msg: consts.MessagesForUser["captchaRequired"].Msg, ShowCaptcha: ShowCaptcha, Regs: nil}
				if err := tools.TmplsRenderer(w, tools.BaseTmpl, "SignIn", data); err != nil {
					tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
					return
				}
				return
			}
			tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}
	}

	if err := tools.InputValidate(r, user.Login, "", user.Password, true); err != nil {
		if strings.Contains(err.Error(), "login") || strings.Contains(err.Error(), "password") {
			if err := tools.UpdateAndRenderCaptchaState(w, r, captchaCounter, ShowCaptcha); err != nil {
				tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}
			return
		}
	}

	if err := data.SetAuthSessionData(w, r, user); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	CheckSignInUserInDb(w, r)
}

func CheckSignInUserInDb(w http.ResponseWriter, r *http.Request) {
	user, err := data.GetUserFromSession(r)
	if err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	captchaCounter, err := data.GetCaptchaCounterFromSession(r)
	if err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	ShowCaptcha, err := data.GetShowCaptchaFromSession(r)
	if err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	passwordHash, permanentId, err := data.GetPasswordHashAndpermanentIdFromDb(user.Login, user.Password)
	if err != nil {
		if strings.Contains(err.Error(), "password not found") || errors.Is(err, sql.ErrNoRows) || errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			if err := tools.UpdateAndRenderCaptchaState(w, r, captchaCounter, ShowCaptcha); err != nil {
				tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}
			return
		}
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if !passwordHash.Valid {
		if err := tools.UpdateAndRenderCaptchaState(w, r, captchaCounter, ShowCaptcha); err != nil {
			tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}
		return
	}

	if err = bcrypt.CompareHashAndPassword([]byte(passwordHash.String), []byte(user.Password)); err != nil {
		if err := tools.UpdateAndRenderCaptchaState(w, r, captchaCounter, ShowCaptcha); err != nil {
			tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}
		return
	}

	temporaryId := uuid.New().String()
	data.SetTemporaryIdInCookies(w, temporaryId)
	rememberMe := r.FormValue("rememberMe") != ""

	refreshToken, err := tools.GeneraterefreshToken(consts.RefreshTokenExp7Days, rememberMe)
	if err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	uniqueUserAgents, err := data.GetUniqueUserAgentsFromDb(permanentId)
	if err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
	} else {
		isNewDevice := true
		for _, userAgent := range uniqueUserAgents {
			if userAgent == r.UserAgent() {
				isNewDevice = false
				break
			}
		}

		if isNewDevice {
			if err := tools.SendNewDeviceLoginEmail(user.Login, user.Email, r.UserAgent()); err != nil {
				tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			}
		}
	}

	tx, err := data.Db.Begin()
	if err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	defer func() {
		if err := recover(); err != nil {
			tx.Rollback()
			panic(err)
		}
	}()

	temporaryIdCancelled := false
	if err = data.SetTemporaryIdInDbByEmailTx(tx, user.Login, temporaryId, temporaryIdCancelled); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	refreshTokenCancelled := false
	if err = data.SetRefreshTokenInDbTx(tx, permanentId, refreshToken, r.UserAgent(), refreshTokenCancelled); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if err = tx.Commit(); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	captchaCounter = 3
	if err = data.SetCaptchaDataInSession(w, r, "captchaCounter", captchaCounter); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return

	}

	ShowCaptcha = false
	if err = data.SetCaptchaDataInSession(w, r, "ShowCaptcha", ShowCaptcha); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if err = data.EndAuthSession(w, r); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	http.Redirect(w, r, consts.HomeURL, http.StatusFound)
}
