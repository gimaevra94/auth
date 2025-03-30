package auth

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/gimaevra94/auth/app/constsandstructs"
	"github.com/gimaevra94/auth/app/database"
	"github.com/gimaevra94/auth/app/mailsendler"
	"github.com/gimaevra94/auth/app/validator"
	"github.com/gorilla/sessions"
)

var store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET_KEY")))

func SignUpRouter() {
	http.HandleFunc(constsandstructs.SignUpURL, signUp)
	http.HandleFunc(constsandstructs.DataSendURL, CodeSend)
	http.HandleFunc(constsandstructs.CodeSendURL, codeCheck)
	http.HandleFunc(constsandstructs.UserAddURL, userAdd)
	http.HandleFunc(constsandstructs.HomeURL, Home)
}

func Home(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "home.html")
}

func signUp(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "sign-up.html")
}

func CodeSend(w http.ResponseWriter, r *http.Request) {
	validatedLoginInput, err := validator.IsValidInput(w, r)
	if err != nil {
		http.ServeFile(w, r, constsandstructs.RequestErrorHTML)
		log.Println("IsValidInput failed: ", err)
	}

	err = database.UserCheck(w, r, validatedLoginInput)
	if err != nil {
		if err == sql.ErrNoRows {
			email := validatedLoginInput.GetEmail()
			mscode, err := mailsendler.MailSendler(email)
			if err != nil {
				http.ServeFile(w, r, constsandstructs.RequestErrorHTML)
				log.Println("MailSendler failed: ", err)
			}

			session, _ := store.Get(r, "auth-session")

			session.Values["mscode"] = mscode
			err = session.Save(r, w)
			if err != nil {
				http.ServeFile(w, r, constsandstructs.RequestErrorHTML)
				log.Println("Saveing mscode in session failed", err)
			}

			jsonData, err := json.Marshal(validatedLoginInput)
			if err != nil {
				http.ServeFile(w, r, constsandstructs.RequestErrorHTML)
				log.Println("validatedLoginInput serialize failed", err)
			}

			session.Values["validatedLoginInput"] = string(jsonData)
			err = session.Save(r, w)
			if err != nil {
				http.ServeFile(w, r, constsandstructs.RequestErrorHTML)
				log.Println("Saveing validatedLoginInput in session failed",err)
			}
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
		http.ServeFile(w, r, constsandstructs.RequestErrorHTML)
		log.Println("mscode not found in session")
	}

	if userCode != mscode {
		http.ServeFile(w, r, "wrongcode.html")
		log.Println("userCode does not equal msCode")
	}

	http.Redirect(w, r, constsandstructs.UserAddURL, http.StatusFound)
}

func userAdd(w http.ResponseWriter, r *http.Request) {
	jsonData, ok := sessions.Values["validatedLoginInput"].(string)
	if !ok {
		http.ServeFile(w, r, constsandstructs.RequestErrorHTML)
		log.Println("validatedLoginInput not found in session")
	}

	var validatedLoginInput constsandstructs.Users
	err := json.Unmarshal([]byte(jsonData), validatedLoginInput)
	if err != nil {
		http.ServeFile(w, r, constsandstructs.RequestErrorHTML)
		log.Println("validatedLoginInput deserialization failed")
	}

	err = database.UserAdd(w, r, validatedLoginInput)
	if err != nil {
		if err == sql.ErrNoRows {

		}

		http.ServeFile(w, r, constsandstructs.RequestErrorHTML)
		log.Println("")
	}
}
