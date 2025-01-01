package mailsendler

import (
	"fmt"
	"math/rand"
	"net/smtp"
	"strconv"
)

var Authcode_str string

func MailSendler(email string) {
	authcode := rand.Intn(10000)
	Authcode_str = strconv.Itoa(authcode)
	msg := []byte("Код для входа: " + Authcode_str)

	username := "gimaev.vending@ya.ru"
	password := "gawgsryisrnimnmv"
	host := "smtp.yandex.ru"

	auth := smtp.PlainAuth("", username, password, host)
	addr := "smtp.yandex.ru:587"
	from := "gimaev.vending@ya.ru"
	to := []string{email}

	err := smtp.SendMail(addr, auth, from, to, msg)
	if err != nil {
		fmt.Printf("SendMail: %v", err)
		return
	}
}
