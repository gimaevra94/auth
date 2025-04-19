package auth

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/database"
	"github.com/gimaevra94/auth/app/logout"
	"github.com/gimaevra94/auth/app/mailsendler"
	"github.com/gimaevra94/auth/app/structs"
	"github.com/gimaevra94/auth/app/tokenizer"
	"github.com/gimaevra94/auth/app/validator"
	"github.com/go-chi/chi/v5"
	"github.com/gorilla/sessions"
)

var store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET_KEY")))
var userAddFromLogIn bool

func Router() *chi.Mux {
	r := chi.NewRouter()

	r.Get(consts.SignUpURL, signUpLoginInput)
	r.Post(consts.InputCheckURL, inputCheck)
	r.Get(consts.CodeSendURL, codeSend)
	r.Post(consts.UserAddURL, userAdd)

	r.Get(consts.SignInURL, signInLoginInput)
	r.Post(consts.LoginInURL, logIn)

	r.Use(logout.IsExpiredTokenMW(store))

	r.With(logout.IsExpiredTokenMW(store)).Get(consts.HomeURL, Home)
	r.With(logout.IsExpiredTokenMW(store)).Get(consts.LogoutURL, logout.Logout)

	//LoginWithGoogleURL
	return r
}

func signUpLoginInput(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "signUploginInput.html")
}

func inputCheck(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "auth")
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println("Failed to get session")
	}

	if session.Values["user"] != nil {
		http.Redirect(w, r, consts.CodeSendURL, http.StatusFound)
	}

	user, err := validator.IsValidInput(w, r)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println("IsValidInput failed: ", err)
	}

	err = database.UserCheck(w, r, user, !userAddFromLogIn)
	if err != nil {
		if err == sql.ErrNoRows {
			jsonData, err := json.Marshal(user)
			if err != nil {
				http.ServeFile(w, r, consts.RequestErrorHTML)
				log.Println("'user' serialize is failed", err)
			}

			session.Values["user"] = jsonData
			err = session.Save(r, w)
			if err != nil {
				http.ServeFile(w, r, consts.RequestErrorHTML)
				log.Println("Failed to save 'user' in session")
			}

			http.Redirect(w, r, consts.CodeSendURL, http.StatusFound)
		}
	}

	http.ServeFile(w, r, "userAllreadyExist.html")
}

func codeSend(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "codeSend.html")
	session, err := store.Get(r, "auth-session")
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println("Failed to get session")
	}

	jsonData, ok := session.Values["user"].([]byte)
	if !ok {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println("'user' is not exist in session")
	}

	var user structs.User
	err = json.Unmarshal([]byte(jsonData), &user)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println("'user' deserialize is failed", err)
	}

	email := user.GetEmail()
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
	session, err := store.Get(r, "auth-session")
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println("Failed to get session")
	}

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

	jsonData, ok := session.Values["user"].([]byte)
	if !ok {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println("user not found in session")
	}

	var user structs.User
	err = json.Unmarshal([]byte(jsonData), user)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println("user deserialization failed")
	}

	err = database.UserAdd(w, r, user)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println("Adding user to database failed")
	}

	tokenExp := r.FormValue("remember")
	err = tokenizer.TokenCreate(w, r, tokenExp, session)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println("Failed to get a new token")
	}

	lastActivity := time.Now().Add(3 * time.Hour)
	session.Values["lastActivity"] = lastActivity

	Home(w, r)
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

	session, err := store.Get(r, "auth-session")
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println("Failed to get session")
	}

	var user structs.User
	if session.Values["user"] != nil {
		jsonData, ok := session.Values["user"].(string)
		if !ok {
			http.ServeFile(w, r, consts.RequestErrorHTML)
			log.Println("user not found in session")
		}

		err := json.Unmarshal([]byte(jsonData), &user)
		if err != nil {
			http.ServeFile(w, r, consts.RequestErrorHTML)
			log.Println("user deserialization failed")
		}
	}

	user, err = validator.IsValidInput(w, r)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println("IsValidInput failed :", err)
	}

	err = database.UserCheck(w, r, user,
		userAddFromLogIn)
	if err != nil {
		if err == sql.ErrNoRows {
			http.ServeFile(w, r, "usernotexist.html")
			log.Println("User not exist: ", err)
		}
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println("Database query failed")
	}

	tokenExp := r.FormValue("remember")
	err = tokenizer.TokenCreate(w, r, tokenExp, session)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println("Failed to get a new token")
	}

	lastActivity := time.Now().Add(3 * time.Hour)
	session.Values["lastActivity"] = lastActivity
	http.Redirect(w, r, consts.HomeURL, http.StatusFound)
}

func Home(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "home.html")
}

func Logout(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "auth")
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println("Failed to get the session from the store")
	}

	delete(session.Values, "lastActivity")
	err = session.Save(r, w)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println("Session save is failed")
	}

	cookie := http.Cookie{
		Name:     "Authorization",
		Path:     "/set-token",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Value:    "",
		MaxAge:   -1,
	}
	http.SetCookie(w, &cookie)

	http.Redirect(w, r, consts.LogoutURL, http.StatusFound)
}
