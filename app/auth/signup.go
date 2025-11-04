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
	"golang.org/x/crypto/bcrypt"

	"github.com/pkg/errors"
)

func ValIdateSignUpInput(w http.ResponseWriter, r *http.Request) {
	var user structs.User
	var ShowCaptcha bool
	login := r.FormValue("login")
	email := r.FormValue("email")
	password := r.FormValue("password")
	user = structs.User{
		Login:    login,
		Email:    email,
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
				if err := tools.TmplsRenderer(w, tools.BaseTmpl, "SignUp", structs.SignUpPageData{Msg: tools.MessagesForUser["captchaRequired"].Msg, ShowCaptcha: ShowCaptcha, Regs: nil}); err != nil {
					tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
					return
				}
				return
			}
			tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}
	}

	if err := tools.InputValIdate(r, user.Login, user.Email, user.Password, false); err != nil {
		if strings.Contains(err.Error(), "login") || strings.Contains(err.Error(), "email") || strings.Contains(err.Error(), "password") {
			if err := tools.UpdateAndRenderCaptchaState(w, r, captchaCounter, ShowCaptcha); err != nil {
				tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}
			tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
			return
		}
	}

	if err := data.SetAuthSessionData(w, r, user); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	CheckSignUpUserInDb(w, r)
}

func CheckSignUpUserInDb(w http.ResponseWriter, r *http.Request) {
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

	_, err = data.GetPermanentUserIdFromDb(user.Email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			CodeSend(w, r)
			return
		}
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if err := tools.UpdateAndRenderCaptchaState(w, r, captchaCounter-1, ShowCaptcha); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}
}

func CodeSend(w http.ResponseWriter, r *http.Request) {
	user, err := data.GetUserFromSession(r)
	if err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if user.ServerCode != "" {
		err := errors.New("code already sent")
		tracedErr := errors.WithStack(err)
		tools.LogAndRedirectIfErrNotNill(w, r, tracedErr, consts.CodeSendURL)
		return
	}

	serverCode, err := tools.AuthCodeSend(user.Email)
	if err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}
	user.ServerCode = serverCode

	if err := data.SetAuthSessionData(w, r, user); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if r.URL.Path != consts.CodeSendURL {
		http.Redirect(w, r, consts.CodeSendURL, http.StatusFound)
		return
	}
}

func SetUserInDb(w http.ResponseWriter, r *http.Request) {
	user, err := data.GetUserFromSession(r)
	if err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	clientCode := r.FormValue("clientCode")
	if err := tools.CodeValIdate(r, clientCode, user.ServerCode); err != nil {
		if strings.Contains(err.Error(), "exist") {
			if err := tools.TmplsRenderer(w, tools.BaseTmpl, "CodeSend", tools.MessagesForUser["userCode"]); err != nil {
				tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}
			return
		} else if strings.Contains(err.Error(), "match") {
			if err := tools.TmplsRenderer(w, tools.BaseTmpl, "CodeSend", tools.MessagesForUser["serverCode"]); err != nil {
				tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
				return
			}
			return
		}
	}

	rememberMe := r.FormValue("rememberMe") != ""
	refreshToken, err := tools.GenerateRefreshToken(consts.RefreshTokenExp7Days, rememberMe)
	if err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	tx, err := data.Db.Begin()
	if err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}
	defer func() {
		r := recover()
		if r != nil {
			tx.Rollback()
			panic(r)
		}
	}()

	temporaryUserId := uuid.New().String()
	data.SetTemporaryUserIdInCookies(w, temporaryUserId)
	permanentUserId := uuid.New().String()
	temporaryUserIdCancelled := false

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password),
		bcrypt.DefaultCost)
	if err != nil {
		return
	}

	if err := data.SetUserInDbTx(tx, user.Login, user.Email, permanentUserId, temporaryUserId, hashedPassword, temporaryUserIdCancelled); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	refreshTokenCancelled := false
	if err = data.SetUserRefreshTokenInDbTx(tx, permanentUserId, refreshToken, r.UserAgent(), refreshTokenCancelled); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if err = tx.Commit(); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if err = tools.SendNewDeviceLoginEmail(user.Email, user.Login, r.UserAgent()); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
	}

	captchaCounter := 3
	if err = data.SetCaptchaDataInSession(w, r, "captchaCounter", captchaCounter); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	ShowCaptcha := false
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
