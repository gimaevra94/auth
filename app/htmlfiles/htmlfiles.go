package htmlfiles

import (
	"net/http"
)

func SignUpLoginInput(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "signUpLoginInput.html")
}

func SignInLoginInput(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "signInLoginInput.html")
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
