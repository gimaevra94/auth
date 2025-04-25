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
	value structs.User) error {

	var token *jwt.Token
	user := value.GetLogin()

	switch command {
	case consts.EmptyValueStr:
		exp := time.Now().Add(consts.TokenLifetime24HoursInt)
		token = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			consts.UserStr: user,
			consts.ExpStr:  exp,
		})

	case consts.OnValueStr:
		token = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			consts.UserStr: user,
		})

	case consts.TokenCommand3HoursStr:
		exp := time.Now().Add(consts.TokenLifetime3HoursInt)
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
		Name:     consts.CookieNameStr,
		Path:     consts.AuthCookiePath,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Value:    SignedToken,
	}

	http.SetCookie(w, &cookie)

	return nil
}
