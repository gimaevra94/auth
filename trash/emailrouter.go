package router

import (
	"log"
	"net/http"

	"github.com/gimaevra94/auth/app/mailsendler"
	"github.com/gimaevra94/auth/app/structs"
	"github.com/gimaevra94/auth/app/validator"
)

func EmailRouter() {
	// основные переходы
	http.HandleFunc("/email_entry", EmailEntry)
	http.HandleFunc("/email_send", CodeSend)
	http.HandleFunc("/code_input", CodeInput)
	http.HandleFunc("/code_send", CodeCheck)
	// кнопки возврата
	http.HandleFunc("/back_to_mail_input", EmailEntry)
	http.HandleFunc("/back_to_code_input", CodeInput)
	http.HandleFunc("/code_not_arrived", CodeInput)
}

func EmailEntry(w http.ResponseWriter, r *http.Request) {
	// юзер вводит почту
	http.ServeFile(w, r, "log-in.html")
}

func CodeSend(w http.ResponseWriter, r *http.Request) {
	// отправляется проверочный код
	email := r.FormValue("email")
	if email == "" {
		http.ServeFile(w, r, "badmailreq.html")
		log.Println("r.FormValue err")
	} else {
		if !validator.IsValidEmail(email) {
			http.ServeFile(w, r, "wrongmail.html")
			log.Println("validator.IsValidMail err")
		} else {
			mscode, err := mailsendler.MailSendler(w, r, email)
			if err != nil {
				http.ServeFile(w, r, "badmailreq.html")
				log.Println("mailsendler.MailSendler: ", err)
			} else {
				http.Redirect(w, r, "/code_input?email="+email+"&authcode="+mscode,
					http.StatusSeeOther)
			}
		}
	}
}

func CodeInput(w http.ResponseWriter, r *http.Request) {
	// юзер вводит код
	http.ServeFile(w, r, "codeinput.html")
}

func CodeCheck(w http.ResponseWriter, r *http.Request) {
	// код проверяется, юзер заносится в бд
	email := r.URL.Query().Get("email")
	mscode := r.URL.Query().Get("mscode")
	if email == "" || mscode == "" {
		http.ServeFile(w, r, "badmailreq.html")
		log.Println("r.URL.Query().Get err")
	} else {

		code := r.FormValue("code")
		if code == "" {
			http.ServeFile(w, r, "badcodereq.html")
			log.Println("r.FormValue err")
		}
		if code != mscode || !validator.IsValidCode(code) {
			http.ServeFile(w, r, "wrongcode.html")
			log.Println("code != mscode || !validator.IsValidCode err")
			
		} else {
			db, err := database.DBConn(w, r)
			if err != nil {
				http.ServeFile(w, r, "badreqdb.html")
				log.Println("database.DBConn: ", err)
			} else {
				err = database.EmailCheckAndAdd(structs.EmailUsers{Email: email}, w, r, db)
				if err != nil {
					http.ServeFile(w, r, "badreqdb.html")
					log.Println("database.EmailCheckAndAdd: ", err)
				} else {
					http.ServeFile(w, r, "home.html")
				}
			}
		}
	}
}
