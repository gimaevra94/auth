package tools

import (
	"log"
	"math/rand"
	"net/smtp"
	"os"
	"strconv"
	"time"

	"github.com/gimaevra94/auth/app"
)

func MailSendler(email string) (string, error) {

	random := rand.New(rand.NewSource(time.Now().UnixNano()))
	msCodeItn := random.Intn(9000) + 1000
	msCode := strconv.Itoa(msCodeItn)
	msg := []byte("Access code: " + msCode)
	// работоспособность ящика под вопросом
	username := "gimaevra94@ya.ru"

	password, err := os.ReadFile(app.DBPasswordPathStr)
	if err != nil {
		log.Println(app.PasswordFileReadFailedErr, err)
		return "", err
	}

	host := app.SMTPHostStr
	auth := smtp.PlainAuth(app.EmptyValueStr, username,
		string(password), host)
	addr := app.SMTPAddrStr
	from := username
	to := []string{email}

	err = smtp.SendMail(addr, auth, from, to, msg)
	if err != nil {
		log.Println(app.AccessCodeSendFailedErr, err)
		return "", err
	}
	return msCode, err
}
