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

func Router() {
	http.HandleFunc(consts.SignUpPageURL, signUpPage)
	http.HandleFunc(consts.SignUpCodeSendURL, signUpCodeSend)
	http.HandleFunc(consts.SignUpUserAddURL, signUpUserAdd)

	http.HandleFunc(consts.SignInPageURL, signInPage)
	http.HandleFunc(consts.SignInURL, signIn)

	http.HandleFunc(consts.CodeNotArrivedURL, codeNotArrived)
	http.HandleFunc(consts.HomePageURL, HomePage)

	//LoginWithGoogleURL
}

func HomePage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "home.html")
}

func signUpPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "sign-up.html")
}

func signInPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "sign-in.html")
}

func signUpCodeSend(w http.ResponseWriter, r *http.Request) {
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
				log.Println("Saveing validatedLoginInput in session failed", err)
			}
		}
	}
	http.ServeFile(w, r, "userallreadyexist.html")
	log.Println("User allready exist: ", err)
}

func codeNotArrived(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "auth-session")

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

	email := validatedLoginInput.GetEmail()
	mscode, err := mailsendler.MailSendler(email)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println("MailSendler failed: ", err)
	}

	session.Values["mscode"] = mscode
	err = sessions.Save(r, w)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println("Saveing mscode in session failed", err)
	}
}

func signUpUserAdd(w http.ResponseWriter, r *http.Request) {
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
		if err == sql.ErrNoRows {
			rememberBool := r.FormValue("remember")
			if rememberBool == "" {
				http.ServeFile(w, r, consts.RequestErrorHTML)
				log.Println("value 'remember me' missing in FormValue")
			}
			err = tokenizer.TokenWriter(w, r,
				validatedLoginInput, rememberBool)
			if err != nil {
				http.ServeFile(w, r, consts.RequestErrorHTML)
				log.Println("Failed to sign the token")
			}

			http.ServeFile(w, r, consts.HomePageURL)
		}
	}
}

func signIn(w http.ResponseWriter, r *http.Request) {
	validatedUserInput, err := validator.IsValidInput(w, r)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
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
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println("value 'remember' missing in FormValue")
	}
	err = tokenizer.TokenWriter(w, r, validatedUserInput, rememberBool)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println("Failed to sign the token: ", err)
	}

	http.ServeFile(w, r, consts.HomePageURL)
}
