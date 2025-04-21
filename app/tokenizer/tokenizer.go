package tokenizer

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/structs"
	"github.com/golang-jwt/jwt"
)

func TokenCreate(w http.ResponseWriter, r *http.Request, command string,
	user structs.User) error {

	var token *jwt.Token

	switch command {
	case consts.EmptyValueStr:
		exp := time.Now().Add(24 * time.Hour)
		user := user.GetLogin()
		token = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			consts.UserStr: user,
			consts.ExpStr:  exp,
		})

	case consts.OnValueStr:
		user := user.GetLogin()
		token = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			consts.UserStr: user,
		})

	case consts.TokenCommand3HoursStr:
		exp := time.Now().Add(3 * time.Hour)
		user := user.GetLogin()
		token = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			consts.UserStr: user,
			consts.ExpStr:  exp,
		})
	}

	SignedToken, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		log.Println(consts.TokenSignFailedErr, err)
		return err
	}

	cookie := http.Cookie{
		Name:     consts.AuthCookieNameStr,
		Path:     consts.AuthCookiePath,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Value:    SignedToken,
	}

	http.SetCookie(w, &cookie)

	return nil
}
