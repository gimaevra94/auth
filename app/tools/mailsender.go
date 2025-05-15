package tools

import (
	"log"
	"math/rand"
	"net/smtp"
	"os"
	"strconv"
	"time"
)

func MailSendler(email string) (string, error) {
	random := rand.New(rand.NewSource(time.Now().UnixNano()))
	msCodeItn := random.Intn(9000) + 1000
	msCode := strconv.Itoa(msCodeItn)
	msg := []byte("Access code: " + msCode)
	// работоспособность ящика под вопросом
	username := "gimaevra94@ya.ru"

	passwordFilePath := "/run/secrets/mail_password"
	password, err := os.ReadFile(passwordFilePath)
	if err != nil {
		log.Printf("%+v", err)
		return "", err
	}

	host := "smtp.yandex.ru"
	auth := smtp.PlainAuth("", username,
		string(password), host)
	addr := "smtp.yandex.ru:587"
	from := username
	to := []string{email}

	err = smtp.SendMail(addr, auth, from, to, msg)
	if err != nil {
		log.Printf("%+v", err)
		return "", err
	}

	return msCode, nil
}
