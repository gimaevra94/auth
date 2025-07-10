package tools

import (
	"bytes"
	"math/rand"
	"net/smtp"
	"os"
	"strconv"
	"time"

	"github.com/pkg/errors"
)

func codeGenerator() string {
	random := rand.New(rand.NewSource(time.Now().UnixNano()))
	msCodeItn := random.Intn(9000) + 1000
	msCode := strconv.Itoa(msCodeItn)
	return msCode
}

func smtpAuth() (smtp.Auth, string) {
	username := os.Getenv("MAIL_SENDER_EMAIL")
	password := os.Getenv("MAIL_PASSWORD")
	host := "smtp.yandex.ru"
	auth := smtp.PlainAuth("", username, password, host)
	return auth, username
}

func CodeSender(email string) (string, error) {
	msCode := codeGenerator()
	auth, username := smtpAuth()

	var body bytes.Buffer
	err := BaseTmpl.ExecuteTemplate(&body, "mailCode", struct{ Code string }{Code: msCode})
	if err != nil {
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

	addr := "smtp.yandex.ru:587"
	err = smtp.SendMail(addr, auth, from, to, msg)
	if err != nil {
		return "", errors.WithStack(err)
	}

	return msCode, nil
}

func LinkSender(email string) (string, error) {

	return "", nil
}
