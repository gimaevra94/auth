package mailsendler

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
	mscodeItn := random.Intn(9000) + 1000
	mscode := strconv.Itoa(mscodeItn)
	msg := []byte("Код для входа: " + mscode)
	username := "gimaev.vending@ya.ru"

	password, err := os.ReadFile("db_password.txt")
	if err != nil {
		log.Println("db_password reading failed: ", err)
		return mscode, err
	}

	host := "smtp.yandex.ru"
	auth := smtp.PlainAuth("", username, string(password), host)
	addr := "smtp.yandex.ru:587"
	from := "gimaev.vending@ya.ru"
	to := []string{email}

	err = smtp.SendMail(addr, auth, from, to, msg)
	if err != nil {
		log.Println("Failed to send user verification email: ", err)
		return mscode, err
	}
	return mscode, err
}
