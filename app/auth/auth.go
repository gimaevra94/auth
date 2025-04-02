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
	"github.com/gimaevra94/auth/app/tokenizer"
	"github.com/gimaevra94/auth/app/validator"
	"github.com/gorilla/sessions"
)

var store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET_KEY")))

func SignUpRouter() {
	http.HandleFunc(constsandstructs.SignUpURL, signUp)
	http.HandleFunc(constsandstructs.DataSendURL, CodeSend)
	http.HandleFunc(constsandstructs.CodeSendURL, codeCheckUserAdd)
	http.HandleFunc(constsandstructs.UserCheckURL, UserCheck)
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
				log.Println("Saveing validatedLoginInput in session failed", err)
			}
		}
	}
	http.ServeFile(w, r, "userallreadyexist.html")
	log.Println("User allready exist: ", err)
}

func codeCheckUserAdd(w http.ResponseWriter, r *http.Request) {
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
			rememberBool := r.FormValue("remember")
			if rememberBool == "" {
				http.ServeFile(w, r, constsandstructs.RequestErrorHTML)
				log.Println("value 'remember me' missing in FormValue")
			}
			err = tokenizer.TokenWriter(w, r,
				validatedLoginInput, rememberBool)
			if err != nil {
				http.ServeFile(w, r, constsandstructs.RequestErrorHTML)
				log.Println("Failed to sign the token")
			}
		}
	}
}

func UserCheck(w http.ResponseWriter, r *http.Request) {
	validatedUserInput, err := validator.IsValidInput(w, r)
	if err != nil {
		http.ServeFile(w, r, constsandstructs.RequestErrorHTML)
		log.Println("IsValidInput failed :", err)
	}

	err = database.UserCheck(w, r, validatedUserInput)
	if err != nil {
		if err == sql.ErrNoRows {
			http.ServeFile(w, r, "usernotexist.html")
			log.Println("User not exist: ", err)
		}
	}
	rememberBool := r.FormValue("remember")
	if rememberBool == "" {
		http.ServeFile(w, r, constsandstructs.RequestErrorHTML)
		log.Println("value 'remember' missing in FormValue")
	}
	err = tokenizer.TokenWriter(w, r, validatedUserInput, rememberBool)
	if err != nil {
		http.ServeFile(w, r, constsandstructs.RequestErrorHTML)
		log.Println("Failed to sign the token: ", err)
	}
}
