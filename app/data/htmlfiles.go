package data

import (
	"io"
	"net/http"
	"os"
)

const (
	templatesPath = "C:/Users/gimaevra94/Documents/git/auth/app/templates/"
)

func SignUp(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, templatesPath+"signUp.html")
}

func SignIn(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, templatesPath+"signIn.html")
}

func Home(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, templatesPath+"home.html")
}

func RequestError(w http.ResponseWriter, r *http.Request) {
	referrer := r.Referer()
	if referrer == "" {
		f, err := os.Open(templatesPath + "pageNotFound.html")
		if err != nil {
			http.NotFound(w, r)
			return
		}

		defer f.Close()
		w.WriteHeader(http.StatusNotFound)
		io.Copy(w, f)
		return
	}

	http.ServeFile(w, r, templatesPath+"requestError.html")
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
