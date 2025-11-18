package tmpls

import (
	"net/http"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/errs"
	"github.com/gimaevra94/auth/app/structs"
)

func SignUp(w http.ResponseWriter, r *http.Request) {
	if err := TmplsRenderer(w, BaseTmpl, "signUp", nil); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}
}

func SignIn(w http.ResponseWriter, r *http.Request) {
	if err := TmplsRenderer(w, BaseTmpl, "signIn", nil); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}
}

func ServerAuthCodeSend(w http.ResponseWriter, r *http.Request) {
	if err := TmplsRenderer(w, BaseTmpl, "serverAuthCodeSend", nil); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}
}

func Home(w http.ResponseWriter, r *http.Request) {
	cookies, err := data.GetTemporaryIdFromCookies(r)
	if err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	temporaryId := cookies.Value
	showSetPasswordButton := false
	passwordHash, err := data.GetPasswordHashFromDb(temporaryId)
	if err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if passwordHash.String == "" {
		showSetPasswordButton = true
	}

	data := struct{ ShowSetPasswordButton bool }{ShowSetPasswordButton: showSetPasswordButton}
	if err := TmplsRenderer(w, BaseTmpl, "home", data); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}
}

func Logout(w http.ResponseWriter, r *http.Request) {
	if err := TmplsRenderer(w, BaseTmpl, "logout", nil); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}
}

func GeneratePasswordResetLink(w http.ResponseWriter, r *http.Request) {
	msg := r.URL.Query().Get("msg")
	data := structs.MsgForUser{Msg: msg}
	if err := TmplsRenderer(w, BaseTmpl, "generatePasswordResetLink", data); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}
}

func SetNewPassword(w http.ResponseWriter, r *http.Request) {
	data := struct {
		Msg   string
		Token string
	}{Msg: r.URL.Query().Get("msg"), Token: r.URL.Query().Get("token")}
	if err := TmplsRenderer(w, BaseTmpl, "setNewPassword", data); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}
}

func SetFirstTimePassword(w http.ResponseWriter, r *http.Request) {
	data := struct {
		Msg  string
		Regs []string
	}{
		Msg:  r.URL.Query().Get("msg"),
		Regs: consts.PswrdReqs,
	}
	if err := TmplsRenderer(w, BaseTmpl, "setFirstTimePassword", data); err != nil {
		errs.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}
}

func Err500(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "../public/500.html")
}
