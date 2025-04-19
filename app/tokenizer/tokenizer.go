package tokenizer

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gimaevra94/auth/app/structs"
	"github.com/golang-jwt/jwt"
	"github.com/gorilla/sessions"
)

func TokenCreate(w http.ResponseWriter, r *http.Request, command string,
	session *sessions.Session) error {

	jsonData, ok := session.Values["user"].([]byte)
	if !ok {
		log.Println("'user' not exist in session")
		return errors.New("'user' not exist in session")
	}

	var user structs.User
	err := json.Unmarshal([]byte(jsonData), &user)
	if err != nil {
		log.Println("'user' deserialize is failed", err)
		return err
	}

	var token *jwt.Token

	switch command {
	case "":
		exp := time.Now().Add(24 * time.Hour)
		user := user.GetLogin()
		token = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user": user,
			"exp":  exp,
		})

	case "on":
		user := user.GetLogin()
		token = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user": user,
		})

	case "expire_3_hours":
		exp := time.Now().Add(3 * time.Hour)
		user := user.GetLogin()
		token = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user": user,
			"exp":  exp,
		})
	}

	SignedToken, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		log.Println("Failed to sign a token")
		return err
	}

	cookie := http.Cookie{
		Name:     "Authorization",
		Path:     "/set-token",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Value:    SignedToken,
	}

	http.SetCookie(w, &cookie)

	return nil
}
