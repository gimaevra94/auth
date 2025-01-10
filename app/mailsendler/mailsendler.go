package mailsendler

import (
	"fmt"
	"log"
	"math/rand"
	"net/smtp"
	"os"
	"regexp"
	"strconv"
	"time"
)

var Authcode_str string
var r *rand.Rand

func init() {
	r = rand.New(rand.NewSource(time.Now().UnixNano()))
}

func MailSendler(input string) {
	authcode := r.Intn(9000) + 1000
	Authcode_str = strconv.Itoa(authcode)

	msg := []byte("Код для входа: " + Authcode_str)
	username := "gimaev.vending@ya.ru"

	password, err := os.ReadFile("db_password.txt")
	if err != nil {
		log.Fatal(err)
	}

	host := "smtp.yandex.ru"
	auth := smtp.PlainAuth("", username, string(password), host)

	addr := "smtp.yandex.ru:587"
	from := "gimaev.vending@ya.ru"
	to := []string{input}

	err = smtp.SendMail(addr, auth, from, to, msg)
	if err != nil {
		fmt.Printf("SendMail: %v", err)
		return
	}
}

func IsValidEmail(input string) bool {
	regex := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$`
	re := regexp.MustCompile(regex)
	return re.MatchString(input)
}

func IsValidCode(input string) bool {
	regex := `^\d{4}$`
	re := regexp.MustCompile(regex)
	return re.MatchString(input)
}
