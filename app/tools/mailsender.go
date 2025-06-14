package tools

import (
	"math/rand"
	"net/http"
	"net/smtp"
	"os"
	"strconv"
	"time"

	"github.com/gimaevra94/auth/app/errs"
)

func MailSendler(w http.ResponseWriter, r *http.Request, email string) (string, error) {
	random := rand.New(rand.NewSource(time.Now().UnixNano()))
	msCodeItn := random.Intn(9000) + 1000
	msCode := strconv.Itoa(msCodeItn)

	username := os.Getenv("MAIL_SENDER_EMAIL")
	password := os.Getenv("MAIL_PASSWORD")

	host := "smtp.yandex.ru"
	auth := smtp.PlainAuth("", username, string(password), host)
	addr := "smtp.yandex.ru:587"

	msg := []byte("Access code: " + msCode)
	from := username
	to := []string{email}

	err := smtp.SendMail(addr, auth, from, to, msg)
	if err != nil {
		return "", errs.OrigErrWrapPrintRedir(w, r, "", err)
	}

	return msCode, nil
}
