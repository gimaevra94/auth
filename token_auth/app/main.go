package main

import (
	"fmt"
	"net/http"

	"github.com/gimaevra94/auth/email_auth/app/database"
	"github.com/gimaevra94/auth/email_auth/app/mailsendler"
)

func main() {
	var email string

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/index.html")
	})

	http.HandleFunc("/email_send", func(w http.ResponseWriter, r *http.Request) {
		email = r.FormValue("email")
		mailsendler.MailSendler(email)
		http.ServeFile(w, r, "web/codesendform.html")
	})

	http.HandleFunc("/code_send", func(w http.ResponseWriter, r *http.Request) {
		code := r.FormValue("code")
		if code != mailsendler.Authcode_str {
			http.ServeFile(w, r, "web/wrongcode.html")
		} else {
			db, err := database.SqlConn()
			if err != nil {
				fmt.Printf("SqlConn: %v", err)
				return
			}

			database.EmailAdd(database.Users{Email: email}, db)
			http.ServeFile(w, r, "web/home.html")
		}
	})

	http.HandleFunc("/back_to_input", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/codesendform.html")
	})

	http.HandleFunc("/code_not_arrived", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/codesendform.html")
		mailsendler.MailSendler(email)
	})

	http.ListenAndServe(":8000", nil)
}
