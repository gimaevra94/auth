package router

import (
	"database/sql"
	"log"
	"net/http"

	"github.com/gimaevra94/auth/app/structs"
	"github.com/gimaevra94/auth/app/tokenizer"
	"github.com/gimaevra94/auth/app/validator"
)

//var rememberBool bool

func TokenRouter() {
	http.HandleFunc("/token_entry", TokenEntry)
	http.HandleFunc("/sign_in", SignIn)
	http.HandleFunc("/sign_in_data_sending", SignInDataSending)

	http.HandleFunc("/back_to_sign_in", SignIn)
	http.HandleFunc("/home", validator.IsValidToken(Home))
}



func SignUp_(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "sign_up.html")
}

func SignUpDataSending_(w http.ResponseWriter, r *http.Request) {
	login := r.FormValue("login")
	password := r.FormValue("password")
	if login == "" || password == "" {
		log.Println("r.FormValue err")
		http.ServeFile(w, r, "badreqsign-up.html")
	} else {
		if !validator.IsValidLogin(login) ||
			!validator.IsValidPassword(password) {
			http.ServeFile(w, r, "badsign-up.html")
			log.Println("!validator.IsValidLogin(login) ||" +
				"!validator.IsValidPassword(password) err")
		} else {
			db, err := database.DBConn(w, r)
			if err != nil {
				http.ServeFile(w, r, "badreqdb.html")
				log.Println("database.DBConn :", err)
			} else {
				remember := r.FormValue("remember")
				if remember != "" {
					rememberBool = true
				}
				err = database.SingUpCheckOrAdd(w, r, db, structs.TokenUsers{
					Login: login, Password: password}, rememberBool)
				if err != nil {
					if err.Error() == "user allready exist" {
						http.ServeFile(w, r, "userallreadyexist.html")
					} else {
						http.ServeFile(w, r, "badreqdb.html")
						log.Println("database.SingUpCheckOrAdd: ", err)
					}
				} else {
					err := tokenizer.TokenWriter(w, structs.TokenUsers{
						Login: login}, rememberBool)
					if err != nil {
						http.ServeFile(w, r, "sign-in.html")
						log.Println("tokenizer.TokenWriter", err)
					} else {
						http.Redirect(w, r, "/home?", http.StatusSeeOther)
					}
				}
			}
		}
	}
}

func SignIn(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "sign-in")
}

func SignInDataSending(w http.ResponseWriter, r *http.Request) {
	login := r.FormValue("login")
	password := r.FormValue("password")
	if !validator.IsValidLogin(login) || !validator.IsValidPassword(password) {
		http.ServeFile(w, r, "badsing_in.html")
	} else {
		db, err := database.DBConn(w, r)
		if err != nil {
			http.ServeFile(w, r, "badreqdb.html")
			log.Println("database.DBConn :", err)
		} else {
			err = database.SingInCheckOrLogIn(w, r, db, structs.TokenUsers{Login: login, Password: password})
			if err != nil {
				if err == sql.ErrNoRows {
					http.ServeFile(w, r, "usernotexist.html")
				} else {
					http.ServeFile(w, r, "badreqdb.html")
					log.Println("database.SingInCheckOrLogIn :", err)
				}
			} else {
				err := tokenizer.TokenWriter(w, structs.TokenUsers{
					Login: login}, rememberBool)
				if err != nil {
					http.ServeFile(w, r, "sign-in.html")
					log.Println("tokenizer.TokenWriter", err)
				} else {
					http.Redirect(w, r, "/home?", http.StatusSeeOther)
				}
			}
		}
	}
}

func Home(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "home.html")
}
