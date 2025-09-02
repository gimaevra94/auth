package htmls

import (
	"log"
	"net/http"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/tools"
)

const (
	templatesPath = "../../public"
)

func SignUp(w http.ResponseWriter, r *http.Request) {
	err := tools.TmplsRenderer(w, tools.BaseTmpl, "SignUp", nil)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}
}

func SignIn(w http.ResponseWriter, r *http.Request) {
	err := tools.TmplsRenderer(w, tools.BaseTmpl, "SignIn", nil)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}
}

func CodeSend(w http.ResponseWriter, r *http.Request) {
	err := tools.TmplsRenderer(w, tools.BaseTmpl, "CodeSend", nil)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}
}

func Home(w http.ResponseWriter, r *http.Request) {
	err := tools.TmplsRenderer(w, tools.BaseTmpl, "Home", nil)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}
}

func Logout(w http.ResponseWriter, r *http.Request) {
	err := tools.TmplsRenderer(w, tools.BaseTmpl, "Logout", nil)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}
}

func PasswordReset(w http.ResponseWriter, r *http.Request) {
	err := tools.TmplsRenderer(w, tools.BaseTmpl, "PasswordReset", nil)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, consts.Err500URL, http.StatusFound)
		return
	}
}

func Err500(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, templatesPath+"500.html")
}
