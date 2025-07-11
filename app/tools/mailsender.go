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

var (
	username         = os.Getenv("MAIL_SENDER_EMAIL")
	authCodeSubject  = "Auth code"
	resetLinkSubject = "Password reset link"
)

func codeGenerate() string {
	random := rand.New(rand.NewSource(time.Now().UnixNano()))
	msCodeItn := random.Intn(9000) + 1000
	msCode := strconv.Itoa(msCodeItn)
	return msCode
}

func smtpAuth(username string) smtp.Auth {
	password := os.Getenv("MAIL_PASSWORD")
	host := "smtp.yandex.ru"
	auth := smtp.PlainAuth("", username, password, host)
	return auth
}

func executeTmpl(username, email, subject string, data any) ([]byte, error) {
	var body bytes.Buffer
	err := BaseTmpl.ExecuteTemplate(&body, "mailCode", data)
	if err != nil {
		return []byte{}, errors.WithStack(err)
	}

	msg := []byte(
		"From: " + username + "\r\n" +
			"To: " + email + "\r\n" +
			"Subject: " + subject + "\r\n" +
			"MIME-Version: 1.0\r\n" +
			"Content-Type: text/html; charset=\"UTF-8\"\r\n" +
			"\r\n" +
			body.String(),
	)

	return msg, nil
}

func mailSend(username, email string, auth smtp.Auth, msg []byte) error {
	from := username
	to := []string{email}
	addr := "smtp.yandex.ru:587"

	err := smtp.SendMail(addr, auth, from, to, msg)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func AuthCodeSender(email string) (string, error) {
	msCode := codeGenerate()

	auth := smtpAuth(username)

	data := struct{ Code string }{Code: msCode}
	msg, err := executeTmpl(username, email, authCodeSubject, data)
	if err != nil {
		return "", err
	}

	err = mailSend(username, email, auth, msg)
	if err != nil {
		return "", err
	}

	return msCode, nil
}

func ResetLinkSender(email string) error {
	auth := smtpAuth(username)

	msg, err := executeTmpl(username, email, resetLinkSubject, nil)
	if err != nil {
		return err
	}

	err = mailSend(username, email, auth, msg)
	if err != nil {
		return err
	}

	return nil
}
