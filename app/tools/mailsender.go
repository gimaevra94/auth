// Package tools предоставляет функции для валидации данных, геренации токенов и отправки email-уведомлений.
//
// Файл содержит функции для отправки email-уведомлений:
//   - SendNewDeviceLoginEmail: отправляет уведомление о входе с нового устройства
//   - SuspiciousLoginEmailSend: отправляет уведомление о подозрительном входе
//   - PasswordResetEmailSend: отправляет ссылку для сброса пароля
//   - ServerAuthCodeSend: отправляет код аутентификации сервера
package tools

import (
	"bytes"
	"math/rand"
	"net/smtp"
	"os"

	"strconv"
	"time"

	"github.com/gimaevra94/auth/app/tmpls"
	"github.com/pkg/errors"
)

var (
	authCodeSubject        = "Auth code"
	suspiciousLoginSubject = "Suspicious login alert!"
	newDeviceLoginSubject  = "New device login"
	passwordResetSubject   = "Password reset request"
)

// serverAuthCodeGenerate генерирует случайный 4-значный код аутентификации.
//
// Возвращает строку с кодом для серверной аутентификации.
func serverAuthCodeGenerate() string {
	randomState := rand.New(rand.NewSource(time.Now().UnixNano()))
	AuthServerCodeItn := randomState.Intn(9000) + 1000
	AuthServerCode := strconv.Itoa(AuthServerCodeItn)
	return AuthServerCode
}

// SendNewDeviceLoginEmail отправляет уведомление о входе с нового устройства.
//
// Принимает логин пользователя, email и User-Agent.
// Формирует и отправляет email с информацией о входе.
var SendNewDeviceLoginEmail = func(login, userEmail, userAgent string) error {
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

// sMTPServerAuth создает аутентификационные данные для SMTP-сервера.
//
// Принимает email сервера и возвращает объект аутентификации и адрес SMTP-сервера.
func sMTPServerAuth(serverEmail string) (smtp.Auth, string) {
	serverPassword := os.Getenv("SERVER_EMAIL_PASSWORD")
	sMTPServerAddr := "smtp.yandex.ru"
	sMTPServerAuthSubject := smtp.PlainAuth("", serverEmail, serverPassword, sMTPServerAddr)
	return sMTPServerAuthSubject, sMTPServerAddr
}

// mailSend отправляет email через SMTP-сервер.
//
// Принимает email отправителя, получателя, данные аутентификации, адрес сервера и сообщение.
// Выполняет отправку письма.
func mailSend(serverEmail, userEmail string, sMTPServerAuthSubject smtp.Auth, sMTPServerAddr string, msg []byte) error {
	from := serverEmail
	to := []string{userEmail}
	addr := sMTPServerAddr + ":587"
	if err := smtp.SendMail(addr, sMTPServerAuthSubject, from, to, msg); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

// executeTmpl формирует email-сообщение на основе шаблона.
//
// Принимает email отправителя, получателя, тему и данные для шаблона.
// Возвращает готовое email-сообщение в формате байтов.
func executeTmpl(serverEmail, userEmail, emailSubject string, data any) ([]byte, error) {
	var body bytes.Buffer

	switch emailSubject {
	case authCodeSubject:
		if err := tmpls.BaseTmpl.ExecuteTemplate(&body, "emailMsgWithServerAuthCode", data); err != nil {
			return []byte{}, errors.WithStack(err)
		}

	case suspiciousLoginSubject:
		if err := tmpls.BaseTmpl.ExecuteTemplate(&body, "emailMsgAboutSuspiciousLoginEmail", data); err != nil {
			return []byte{}, errors.WithStack(err)
		}

	case newDeviceLoginSubject:
		if err := tmpls.BaseTmpl.ExecuteTemplate(&body, "emailMsgAboutNewDeviceLoginEmail", data); err != nil {
			return []byte{}, errors.WithStack(err)
		}

	case passwordResetSubject:
		if err := tmpls.BaseTmpl.ExecuteTemplate(&body, "emailMsgWithPasswordResetLink", data); err != nil {
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

// SuspiciousLoginEmailSend отправляет уведомление о подозрительном входе.
//
// Принимает email пользователя и User-Agent.
// Формирует и отправляет email с предупреждением о подозрительной активности.
var SuspiciousLoginEmailSend = func(userEmail, userAgent string) error {
	serverEmail := os.Getenv("SERVER_EMAIL")
	sMTPServerAuthSubject, sMTPServerAddr := sMTPServerAuth(serverEmail)
	data := struct {
		UserAgent string
	}{UserAgent: userAgent}

	msg, err := executeTmpl(serverEmail, userEmail, suspiciousLoginSubject, data)
	if err != nil {
		return errors.WithStack(err)
	}
	if err := mailSend(serverEmail, userEmail, sMTPServerAuthSubject, sMTPServerAddr, msg); err != nil {
		return errors.WithStack(err)
	}

	return nil
}

// PasswordResetEmailSend отправляет ссылку для сброса пароля.
//
// Принимает email пользователя и ссылку для сброса.
// Формирует и отправляет email с инструкциями по сбросу пароля.
var PasswordResetEmailSend = func(userEmail, resetLink string) error {
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

// ServerAuthCodeSend отправляет код аутентификации сервера.
//
// Принимает email пользователя.
// Генерирует код и отправляет его на указанный email.
// Возвращает сгенерированный код и ошибку, если она возникла.
var ServerAuthCodeSend = func(userEmail string) (string, error) {
	authServerCode := serverAuthCodeGenerate()
	serverEmail := os.Getenv("SERVER_EMAIL")
	sMTPServerAuthSubject, sMTPServerAddr := sMTPServerAuth(serverEmail)
	data_ := struct{ Code string }{Code: authServerCode}

	msg, err := executeTmpl(serverEmail, userEmail, authCodeSubject, data_)
	if err != nil {
		return "", errors.WithStack(err)
	}

	if err := mailSend(serverEmail, userEmail, sMTPServerAuthSubject, sMTPServerAddr, msg); err != nil {
		return "", errors.WithStack(err)
	}

	return authServerCode, nil
}
