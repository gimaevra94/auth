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

func executeTmpl(msCode, username, email string) ([]byte, error) {
	var body bytes.Buffer
	err := BaseTmpl.ExecuteTemplate(&body, "mailCode", struct{ Code string }{Code: msCode})
	if err != nil {
		return []byte{}, errors.WithStack(err)
	}

	msg := []byte(
		"From: " + username + "\r\n" +
			"To: " + email + "\r\n" +
			"Subject: " + "Auth code" + "\r\n" +
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

func CodeSender(email string) (string, error) {
	msCode := codeGenerate()

	username := os.Getenv("MAIL_SENDER_EMAIL")
	auth := smtpAuth(username)

	msg, err := executeTmpl(msCode, username, email)
	if err != nil {
		return "", err
	}

	err = mailSend(username, email, auth, msg)
	if err != nil {
		return "", err
	}

	return msCode, nil
}

func LinkSender(email string) (string, error) {

	return "", nil
}
