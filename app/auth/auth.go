package auth

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/database"
	"github.com/gimaevra94/auth/app/mailsendler"
	"github.com/gimaevra94/auth/app/tokenizer"
	"github.com/gimaevra94/auth/app/users"
	"github.com/gimaevra94/auth/app/validator"
	"github.com/gorilla/sessions"
)

var store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET_KEY")))
var userAddFromLogIn bool

func Router() {
	http.HandleFunc(consts.SignUpURL, signUpLoginInput)
	http.HandleFunc(consts.InputCheckURL, inputCheck)
	http.HandleFunc(consts.CodeSendURL, codeSend)
	http.HandleFunc(consts.UserAddURL, userAdd)

	http.HandleFunc(consts.SignInURL, signInLoginInput)
	http.HandleFunc(consts.LoginInURL, logIn)

	//LoginWithGoogleURL
}

func signUpLoginInput(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "signUploginInput.html")
}

func inputCheck(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "auth-session")
	if session.Values["validatedLoginInput"] != nil {
		http.Redirect(w, r, consts.CodeSendURL, http.StatusFound)
	}

	validatedLoginInput, err := validator.IsValidInput(w, r)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println("IsValidInput failed: ", err)
	}

	err = database.UserCheck(w, r, validatedLoginInput,
		userAddFromLogIn == false)
	if err != nil {
		if err == sql.ErrNoRows {
			jsonData, err := json.Marshal(validatedLoginInput)
			if err != nil {
				http.ServeFile(w, r, consts.RequestErrorHTML)
				log.Println("validatedLoginInput serialize failed", err)
			}

			session.Values["validatedLoginInput"] = string(jsonData)
			err = session.Save(r, w)
			if err != nil {
				http.ServeFile(w, r, consts.RequestErrorHTML)
				log.Println("Saveing validatedLoginInput in session failed", err)
			}

			http.Redirect(w, r, consts.CodeSendURL, http.StatusFound)
		}
	}
}
func codeSend(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "codeSend.html")
	session, _ := store.Get(r, "auth-session")

	jsonData, ok := session.Values["validatedLoginInput"].(string)
	if !ok {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println("validatedLoginInput not found in session")
	}

	var validatedLoginInput users.Users
	err := json.Unmarshal([]byte(jsonData), &validatedLoginInput)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println("validatedLoginInput deserialization failed")
	}

	email := validatedLoginInput.GetEmail()
	mscode, err := mailsendler.MailSendler(email)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println("MailSendler failed: ", err)
	}

	session.Values["mscode"] = mscode
	err = session.Save(r, w)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println("Saveing mscode in session failed", err)
	}
}

func userAdd(w http.ResponseWriter, r *http.Request) {
	rememberBool := r.FormValue("remember")
	if rememberBool == "" {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println("value 'remember me' missing in FormValue")
	}

	session, _ := store.Get(r, "auth-session")

	userCode := r.FormValue("code")
	mscode, ok := session.Values["mscode"].(string)
	if !ok {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println("mscode not found in session")
	}

	if userCode != mscode {
		http.ServeFile(w, r, "wrongcode.html")
		log.Println("userCode does not equal msCode")
	}

	jsonData, ok := session.Values["validatedLoginInput"].(string)
	if !ok {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println("validatedLoginInput not found in session")
	}

	var validatedLoginInput users.Users
	err := json.Unmarshal([]byte(jsonData), validatedLoginInput)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println("validatedLoginInput deserialization failed")
	}

	err = database.UserAdd(w, r, validatedLoginInput)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println("Adding users to database failed")
	}

	err = tokenizer.TokenWriter(w, r,
		validatedLoginInput, rememberBool)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println("Failed to sign the token")
	}

	http.ServeFile(w, r, consts.HomeURL)
}

func signInLoginInput(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "signInloginInput.html")
}

func logIn(w http.ResponseWriter, r *http.Request) {
	rememberBool := r.FormValue("remember")
	if rememberBool == "" {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println("value 'remember' missing in FormValue")
	}

	session, _ := store.Get(r, "auth-session")
	var validatedLoginInput users.Users

	if session.Values["validatedLoginInput"] != nil {
		jsonData, ok := session.Values["validatedLoginInput"].(string)
		if !ok {
			http.ServeFile(w, r, consts.RequestErrorHTML)
			log.Println("validatedLoginInput not found in session")
		}

		err := json.Unmarshal([]byte(jsonData), &validatedLoginInput)
		if err != nil {
			http.ServeFile(w, r, consts.RequestErrorHTML)
			log.Println("validatedLoginInput deserialization failed")
		}
	}

	validatedLoginInput, err := validator.IsValidInput(w, r)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println("IsValidInput failed :", err)
	}

	err = database.UserCheck(w, r, validatedLoginInput,
		userAddFromLogIn == true)
	if err != nil {
		if err == sql.ErrNoRows {
			http.ServeFile(w, r, "usernotexist.html")
			log.Println("User not exist: ", err)
		}
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println("Database query failed")
	}

	err = tokenizer.TokenWriter(w, r, validatedLoginInput, rememberBool)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println("Failed to sign the token: ", err)
	}
	http.ServeFile(w, r, consts.HomeURL)
}
