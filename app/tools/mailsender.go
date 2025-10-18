package tools

import (
	"bytes"
	"fmt"
	"log"
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
	suspiciousLoginSubject = "Suspicious Login Alert!"
	passwordResetSubject   = "Password Reset Request"
)

type NewDeviceLoginData struct {
	Login      string
	Email      string // Хотя в шаблоне не используется напрямую, передаём для логики отправки
	DeviceInfo string
	Subject    string // Удобно передавать тему как параметр
}

// SendNewDeviceLoginEmail отправляет уведомление о входе с нового устройства.
func SendNewDeviceLoginEmail(login, email, deviceInfo string) error {
	senderEmail := os.Getenv("MAIL_SENDER_EMAIL")
	if senderEmail == "" {
		log.Println("MAIL_SENDER_EMAIL is not set, cannot send new device login email")
		return fmt.Errorf("MAIL_SENDER_EMAIL not configured")
	}

	subject := "New Device Login Alert"
	data := NewDeviceLoginData{
		Login:      login,
		Email:      email, // Используется в smtp.SendMail как recipient
		DeviceInfo: deviceInfo,
		Subject:    subject,
	}

	// Используем существующий шаблон (предполагая, что он обновлён как указано выше)
	tmpl := BaseTmpl.Lookup("suspiciousLoginMail")
	if tmpl == nil {
		return fmt.Errorf("template 'suspiciousLoginMail' not found")
	}

	var body bytes.Buffer
	if err := tmpl.Execute(&body, data); err != nil {
		return err // или errors.WithStack(err)
	}

	header := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n"
	fullMessage := fmt.Sprintf("To: %s\r\nSubject: %s\r\n%s\r\n%s", email, subject, header, body.String())

	auth := smtpAuth(senderEmail)
	err := smtp.SendMail("smtp.yandex.ru:587", auth, senderEmail, []string{email}, []byte(fullMessage))
	if err != nil {
		log.Printf("SendNewDeviceLoginEmail: Error sending email to %s: %v", email, err)
		return err // или errors.WithStack(err)
	}
	log.Printf("SendNewDeviceLoginEmail: Alert email sent successfully to %s for login from %s", email, deviceInfo)
	return nil
}

func codeGenerate() string {
	random := rand.New(rand.NewSource(time.Now().UnixNano()))
	msCodeItn := random.Intn(9000) + 1000
	msCode := strconv.Itoa(msCodeItn)
	return msCode
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
