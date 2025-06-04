package data

import (
	"net/http"
)

func SignUp(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "signUp.html")
}

func SignIn(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "signIn.html")
}

func Home(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "home.html")
}

func RequestError(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "requestError.html")
}

func Logout(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "logout.html")
}

func BadSignIn(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "badSign-in.html")
}

func BadSignUp(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "badSign-up.html")
}

func UserAllreadyExist(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "userAllreadyExist.html")
}

func UserNotExist(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "userNotExist.html")
}

func WrongCode(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "wrongCode.html")
}
