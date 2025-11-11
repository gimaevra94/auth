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
	authCodeSubject        = "Auth code"
	suspiciousLoginSubject = "Suspicious login alert!"
	newDeviceLoginSubject  = "New device login"
	passwordResetSubject   = "Password reset request"
)

func serverAuthCodeGenerate() string {
	randomState := rand.New(rand.NewSource(time.Now().UnixNano()))
	AuthServerCodeItn := randomState.Intn(9000) + 1000
	AuthServerCode := strconv.Itoa(AuthServerCodeItn)
	return AuthServerCode
}

func SendNewDeviceLoginEmail(userEmail, login, userAgent string) error {
	serverEmail := os.Getenv("SERVER_EMAIL")
	sMTPServerAuthSubject, sMTPServerAddr := sMTPServerAuth(serverEmail)
	data := struct {
		login     string
		userAgent string
	}{login: login, userAgent: userAgent}

	msg, err := executeTmpl(serverEmail, userEmail, newDeviceLoginSubject, data)
	if err != nil {
		return errors.WithStack(err)
	}

	if err := mailSend(serverEmail, userEmail, sMTPServerAuthSubject, sMTPServerAddr, msg); err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func sMTPServerAuth(serverEmail string) (smtp.Auth, string) {
	serverPassword := os.Getenv("SERVER_EMAIL_PASSWORD")
	sMTPServerAddr := "smtp.yandex.ru"
	sMTPServerAuthSubject := smtp.PlainAuth("", serverEmail, serverPassword, sMTPServerAddr)
	return sMTPServerAuthSubject, sMTPServerAddr
}

func mailSend(serverEmail, userEmail string, sMTPServerAuthSubject smtp.Auth, sMTPServerAddr string, msg []byte) error {
	from := serverEmail
	to := []string{userEmail}
	addr := sMTPServerAddr + ":587"
	if err := smtp.SendMail(addr, sMTPServerAuthSubject, from, to, msg); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func executeTmpl(serverEmail, userEmail, emailSubject string, data any) ([]byte, error) {
	var body bytes.Buffer

	switch emailSubject {
	case authCodeSubject:
		if err := BaseTmpl.ExecuteTemplate(&body, "emailMsgWithServerAuthCode", data); err != nil {
			return []byte{}, errors.WithStack(err)
		}

	case suspiciousLoginSubject:
		if err := BaseTmpl.ExecuteTemplate(&body, "emailMsgAboutSuspiciousLoginEmail", data); err != nil {
			return []byte{}, errors.WithStack(err)
		}

	case newDeviceLoginSubject:
		if err := BaseTmpl.ExecuteTemplate(&body, "emailMsgAboutNewDeviceLoginEmail", data); err != nil {
			return []byte{}, errors.WithStack(err)
		}

	case passwordResetSubject:
		if err := BaseTmpl.ExecuteTemplate(&body, "generatePasswordResetLink", data); err != nil {
			return []byte{}, errors.WithStack(err)
		}
	}

	msg := []byte(
		"From: " + serverEmail + "\r\n" +
			"To: " + userEmail + "\r\n" +
			"Subject: " + emailSubject + "\r\n" +
			"MIME-Version: 1.0\r\n" +
			"Content-Type: text/html; charset=\"UTF-8\"\r\n" +
			"\r\n" +
			body.String(),
	)

	return msg, nil
}

func ServerAuthCodeSend(userEmail string) (string, error) {
	authServerCode := serverAuthCodeGenerate()
	serverEmail := os.Getenv("SERVER_EMAIL")
	sMTPServerAuthSubject, sMTPServerAddr := sMTPServerAuth(serverEmail)
	data := struct{ Code string }{Code: authServerCode}

	msg, err := executeTmpl(serverEmail, userEmail, authCodeSubject, data)
	if err != nil {
		return "", err
	}
	if err := mailSend(serverEmail, userEmail, sMTPServerAuthSubject, sMTPServerAddr, msg); err != nil {
		return "", err
	}

	return authServerCode, nil
}

func SuspiciousLoginEmailSend(userEmail, login, userAgent string) error {
	serverEmail := os.Getenv("SERVER_EMAIL")
	sMTPServerAuthSubject, sMTPServerAddr := sMTPServerAuth(serverEmail)
	data := struct {
		login     string
		userAgent string
	}{login: login, userAgent: userAgent}

	msg, err := executeTmpl(serverEmail, userEmail, suspiciousLoginSubject, data)
	if err != nil {
		return errors.WithStack(err)
	}
	if err := mailSend(serverEmail, userEmail, sMTPServerAuthSubject, sMTPServerAddr, msg); err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func PasswordResetEmailSend(userEmail, resetLink string) error {
	serverEmail := os.Getenv("SERVER_EMAIL")
	sMTPServerAuthSubject, sMTPServerAddr := sMTPServerAuth(serverEmail)
	data := struct{ ResetLink string }{ResetLink: resetLink}

	msg, err := executeTmpl(serverEmail, userEmail, passwordResetSubject, data)
	if err != nil {
		return err
	}
	if err := mailSend(serverEmail, userEmail, sMTPServerAuthSubject, sMTPServerAddr, msg); err != nil {
		return err
	}

	return nil
}
