package tools

import (
	"bytes"
	"html/template"
	"log"
	"math/rand"
	"net/smtp"
	"os"
	"strconv"
	"time"

	"github.com/pkg/errors"
)

func MailSendler(email string) (string, error) {
	random := rand.New(rand.NewSource(time.Now().UnixNano()))
	msCodeItn := random.Intn(9000) + 1000
	msCode := strconv.Itoa(msCodeItn)

	username := os.Getenv("MAIL_SENDER_EMAIL")
	password := os.Getenv("MAIL_PASSWORD")

	if username == "" || password == "" {
		log.Println("[ERROR] MAIL_SENDER_EMAIL or MAIL_PASSWORD is empty")
		return "", errors.New("missing email credentials")
	}

	host := "smtp.yandex.ru"
	auth := smtp.PlainAuth("", username, password, host)
	addr := "smtp.yandex.ru:587"

	tmplPath := "C:/Users/gimaevra94/Documents/git/auth/app/templates/mailCode.html"
	tmpl, err := template.ParseFiles(tmplPath)
	if err != nil {
		log.Printf("[ERROR] Failed to parse template: %v", err)
		return "", errors.WithStack(err)
	}

	var body bytes.Buffer
	err = tmpl.Execute(&body, struct{ Code string }{Code: msCode})
	if err != nil {
		log.Printf("[ERROR] Template execution failed: %v", err)
		return "", errors.WithStack(err)
	}

	subject := "Auth code"
	msg := []byte(
		"From: " + username + "\r\n" +
			"To: " + email + "\r\n" +
			"Subject: " + subject + "\r\n" +
			"MIME-Version: 1.0\r\n" +
			"Content-Type: text/html; charset=\"UTF-8\"\r\n" +
			"\r\n" +
			body.String(),
	)

	from := username
	to := []string{email}

	err = smtp.SendMail(addr, auth, from, to, msg)
	if err != nil {
		log.Printf("[ERROR] SMTP Error: %+v", err)
		return "", errors.WithStack(err)
	}

	log.Println("[SUCCESS] Email sent successfully")
	return msCode, nil
}
