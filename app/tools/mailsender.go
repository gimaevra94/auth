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
	senderEmail            string
	authCodeSubject        = "Auth code"
	suspiciousLoginSubject = "Suspicious login alert!"
	newDeviceLoginSubject  = "New device login"
	passwordResetSubject   = "Password reset request"
)

func codeGenerate() string {
	random := rand.New(rand.NewSource(time.Now().UnixNano()))
	msCodeItn := random.Intn(9000) + 1000
	msCode := strconv.Itoa(msCodeItn)
	return msCode
}

func SendNewDeviceLoginEmail(email, login, deviceInfo string) error {
	senderEmail = os.Getenv("MAIL_SENDER_EMAIL")
	auth := smtpAuth(senderEmail)

	data := struct {
		Login      string
		DeviceInfo string
	}{Login: login, DeviceInfo: deviceInfo}
	msg, err := executeTmpl(senderEmail, email, newDeviceLoginSubject, data)
	if err != nil {
		return errors.WithStack(err)
	}

	err = mailSend(senderEmail, email, auth, msg)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func smtpAuth(senderEmail string) smtp.Auth {
	senderPassword := os.Getenv("MAIL_PASSWORD")
	host := "smtp.yandex.ru"
	auth := smtp.PlainAuth("", senderEmail, senderPassword, host)
	return auth
}

func executeTmpl(senderEmail, email, subject string, data any) ([]byte, error) {
	var body bytes.Buffer

	switch subject {
	case authCodeSubject:
		err := BaseTmpl.ExecuteTemplate(&body, "mailCode", data)
		if err != nil {
			return []byte{}, errors.WithStack(err)
		}
	case suspiciousLoginSubject:
		err := BaseTmpl.ExecuteTemplate(&body, "suspiciousLoginMail", data)
		if err != nil {
			return []byte{}, errors.WithStack(err)
		}
	case newDeviceLoginSubject:
		err := BaseTmpl.ExecuteTemplate(&body, "newDeviceLoginMail", data)
		if err != nil {
			return []byte{}, errors.WithStack(err)
		}
	case passwordResetSubject:
		err := BaseTmpl.ExecuteTemplate(&body, "PasswordResetEmail", data)
		if err != nil {
			return []byte{}, errors.WithStack(err)
		}
	}

	msg := []byte(
		"From: " + senderEmail + "\r\n" +
			"To: " + email + "\r\n" +
			"Subject: " + subject + "\r\n" +
			"MIME-Version: 1.0\r\n" +
			"Content-Type: text/html; charset=\"UTF-8\"\r\n" +
			"\r\n" +
			body.String(),
	)

	return msg, nil
}

func mailSend(senderEmail, email string, auth smtp.Auth, msg []byte) error {
	from := senderEmail
	to := []string{email}
	addr := "smtp.yandex.ru:587"

	err := smtp.SendMail(addr, auth, from, to, msg)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func AuthCodeSend(email string) (string, error) {
	senderEmail = os.Getenv("MAIL_SENDER_EMAIL")
	msCode := codeGenerate()
	auth := smtpAuth(senderEmail)

	data := struct{ Code string }{Code: msCode}
	msg, err := executeTmpl(senderEmail, email, authCodeSubject, data)
	if err != nil {
		return "", err
	}

	err = mailSend(senderEmail, email, auth, msg)
	if err != nil {
		return "", err
	}

	return msCode, nil
}

func SendSuspiciousLoginEmail(email, login, deviceInfo string) error {
	senderEmail = os.Getenv("MAIL_SENDER_EMAIL")
	auth := smtpAuth(senderEmail)

	data := struct {
		Login      string
		DeviceInfo string
	}{Login: login, DeviceInfo: deviceInfo}
	msg, err := executeTmpl(senderEmail, email, suspiciousLoginSubject, data)
	if err != nil {
		return errors.WithStack(err)
	}

	err = mailSend(senderEmail, email, auth, msg)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func SendPasswordResetEmail(email, resetLink string) error {
	senderEmail = os.Getenv("MAIL_SENDER_EMAIL")
	auth := smtpAuth(senderEmail)

	data := struct{ ResetLink string }{ResetLink: resetLink}
	msg, err := executeTmpl(senderEmail, email, passwordResetSubject, data)
	if err != nil {
		return err
	}

	err = mailSend(senderEmail, email, auth, msg)
	if err != nil {
		return err
	}

	return nil
}
