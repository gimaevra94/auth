package tmpls

import (
	"net/http"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/data"
	"github.com/gimaevra94/auth/app/structs"
	"github.com/gimaevra94/auth/app/tools"
)

const (
	templatesPath = "../public"
)

func SignUp(w http.ResponseWriter, r *http.Request) {
	if err := tools.TmplsRenderer(w, tools.BaseTmpl, "SignUp", nil); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}
}

func SignIn(w http.ResponseWriter, r *http.Request) {
	if err := tools.TmplsRenderer(w, tools.BaseTmpl, "SignIn", nil); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}
}

func CodeSend(w http.ResponseWriter, r *http.Request) {
	if err := tools.TmplsRenderer(w, tools.BaseTmpl, "CodeSend", nil); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}
}

func Home(w http.ResponseWriter, r *http.Request) {
	showSetPasswordButton := true
	cookies, err := data.GetTemporaryUserIdFromCookies(r)
	if err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	temporaryUserId := cookies.Value
	passwordHash, err := data.GetPasswordHashFromDb(temporaryUserId)
	if err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}

	if passwordHash.String != "" {
		showSetPasswordButton = false
	}

	data := struct{ ShowSetPasswordButton bool }{ShowSetPasswordButton: showSetPasswordButton}
	if err := tools.TmplsRenderer(w, tools.BaseTmpl, "Home", data); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}
}

func Logout(w http.ResponseWriter, r *http.Request) {
	if err := tools.TmplsRenderer(w, tools.BaseTmpl, "Logout", nil); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}
}

func PasswordReset(w http.ResponseWriter, r *http.Request) {
	message := r.URL.Query().Get("msg")
	data := structs.MessagesForUser{Msg: message}
	if err := tools.TmplsRenderer(w, tools.BaseTmpl, "PasswordReset", data); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}
}

func SetNewPassword(w http.ResponseWriter, r *http.Request) {
	data := struct {
		Msg   string
		Token string
	}{Msg: r.URL.Query().Get("msg"), Token: r.URL.Query().Get("token")}
	if err := tools.TmplsRenderer(w, tools.BaseTmpl, "SetNewPassword", data); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
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
	if err := tools.TmplsRenderer(w, tools.BaseTmpl, "SetFirstTimePassword", data); err != nil {
		tools.LogAndRedirectIfErrNotNill(w, r, err, consts.Err500URL)
		return
	}
}

func Err500(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, templatesPath+"/500.html")
}
