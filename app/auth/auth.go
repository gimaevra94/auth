package sessionmanager

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/database"
	"github.com/gimaevra94/auth/app/mailsendler"
	"github.com/gimaevra94/auth/app/validator"
	"github.com/gorilla/sessions"
)

var store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET_KEY")))

func SignUpRouter() {
	http.HandleFunc(consts.SignUpURL, signUp)
	http.HandleFunc(consts.DataSendURL, CodeSend)
	http.HandleFunc(consts.CodeSendURL, codeCheck)
	http.HandleFunc(consts.HomeURL, Home)
}

func Home(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "home.html")
}

func signUp(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "sign-up.html")
}

func signIn(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "sign-in.html")
}

func CodeSend(w http.ResponseWriter, r *http.Request) {
	validatedLoginInput, err := validator.IsValidInput(w, r)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println("IsValidInput failed: ", err)
	}

	err = database.UserCheck(w, r, validatedLoginInput)
	if err != nil {
		if err == sql.ErrNoRows {
			email := validatedLoginInput.GetEmail()
			mscode, err := mailsendler.MailSendler(email)
			if err != nil {
				http.ServeFile(w, r, consts.RequestErrorHTML)
				log.Println("MailSendler failed: ", err)
			}

			session, _ := store.Get(r, "auth-session")

			session.Values["mscode"] = mscode
			err = session.Save(r, w)
			if err != nil {
				http.ServeFile(w, r, consts.RequestErrorHTML)
				log.Println("Saveing mscode in session failed", err)
			}

			jsonData, err := json.Marshal(validatedLoginInput)
			if err != nil {
				http.ServeFile(w, r, consts.RequestErrorHTML)
				log.Println("validatedLoginInput serialize failed", err)
			}

			session.Values["validatedLoginInput"] = string(jsonData)
			err = session.Save(r, w)
			if err != nil {
				http.ServeFile(w, r, consts.RequestErrorHTML)
				log.Println("Saveing validatedLoginInput in session failed")
			}

			http.Redirect(w, r, consts.CodeSendURL, http.StatusFound)
		}
	}

	http.ServeFile(w, r, "userallreadyexist.html")
	log.Println("User allready exist: ", err)
}

func codeCheck(w http.ResponseWriter, r *http.Request) {
	sessions, _ := store.Get(r, "auth-session")

	userCode := r.FormValue("code")
	mscode, ok := sessions.Values["mscode"].(string)
	if !ok {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println("mscode not found in session")
	}

	if userCode != mscode {
		http.ServeFile(w, r, "wrongcode.html")
		log.Println("userCode does not equal msCode")
	}

	jsonData, ok := sessions.Values["validatedLoginInput"].(string)
	if !ok {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println("validatedLoginInput not found in session")
	}

	var validatedLoginInput validator.Users
	err := json.Unmarshal([]byte(jsonData), validatedLoginInput)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println("validatedLoginInput deserialization failed")
	}

	err := database.UserAddInDB(w, r, validatedLoginInput)
	if err!=nil{
		http.ServeFile(w,r,consts.RequestErrorHTML)
		log.Println("")
	}
}
