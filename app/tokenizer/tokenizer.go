package tokenizer

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/structs"
	"github.com/golang-jwt/jwt"
	"github.com/gorilla/sessions"
)

func TokenCreate(w http.ResponseWriter, r *http.Request, command string,
	session *sessions.Session) error {

	jsonData, ok := session.Values[consts.UserStr].([]byte)
	if !ok {
		log.Println("'user' not exist in session")
		return errors.New("'user' not exist in session")
	}

	var user structs.User
	err := json.Unmarshal([]byte(jsonData), &user)
	if err != nil {
		log.Println(consts.UserDeserializeFailedErr, err)
		return err
	}

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
