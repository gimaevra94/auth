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
	mscodeItn := random.Intn(9000) + 1000
	mscode := strconv.Itoa(mscodeItn)
	msg := []byte(consts.AccessCodeStr + mscode)
	username := consts.MailUserNameStr

	password, err := os.ReadFile(consts.DBPasswordPathStr)
	if err != nil {
		log.Println(consts.PasswordFileReadFailedErr, err)
		return mscode, err
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
		return mscode, err
	}
	return mscode, err
}
