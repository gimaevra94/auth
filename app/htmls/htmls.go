package consts

import (
	"log"
	"net/http"

	"github.com/gimaevra94/auth/app/tools"
)

const (
	templatesPath = "C:Users/gimaevra94/Documents/git/auth/app/consts/trash"
)

func Home(w http.ResponseWriter, r *http.Request) {
	err := tools.TmplsRenderer(w, tools.BaseTmpl, "Home", nil)
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

func Err500(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, templatesPath+"500.html")
}

func CodeSend(w http.ResponseWriter, r *http.Request) {
	err := tools.TmplsRenderer(w, tools.BaseTmpl, "CodeSend", nil)
	if err != nil {
		log.Printf("%+v", err)
		http.Redirect(w, r, Err500URL, http.StatusFound)
		return
	}
}

func Logout(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, templatesPath+"logout.html")
}

func BadSignIn(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, templatesPath+"badSign-in.html")
}

func BadSignUp(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, templatesPath+"badSign-up.html")
}

func BadEmail(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, templatesPath+"badEmail.html")
}

func UserAllreadyExist(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, templatesPath+"userAllreadyExist.html")
}

func UserNotExist(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, templatesPath+"userNotExist.html")
}

func WrongCode(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, templatesPath+"wrongCode.html")
}

func SignUp(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, templatesPath+"signUp.html")
}
