package mailsendler

import (
	"log"
	"math/rand"
	"net/smtp"
	"os"
	"strconv"
	"time"

	"github.com/gimaevra94/auth/app/consts"
)

func MailSendler(email string) (string, error) {

	random := rand.New(rand.NewSource(time.Now().UnixNano()))
	msCodeItn := random.Intn(9000) + consts.ThousandStr
	msCode := strconv.Itoa(msCodeItn)
	msg := []byte(consts.AccessCodeStr + msCode)
	username := consts.MailUserNameStr

	password, err := os.ReadFile(consts.DBPasswordPathStr)
	if err != nil {
		log.Println(consts.PasswordFileReadFailedErr, err)
		return msCode, err
	}

	host := consts.SMTPHostStr
	auth := smtp.PlainAuth(consts.EmptyValueStr, username,
		string(password), host)
	addr := consts.SMTPAddrStr
	from := consts.MailUserNameStr
	to := []string{email}

	err = smtp.SendMail(addr, auth, from, to, msg)
	if err != nil {
		log.Println(consts.AccessCodeSendFailedErr, err)
		return msCode, err
	}
	return msCode, err
}
