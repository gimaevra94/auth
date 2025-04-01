package tokenizer

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gimaevra94/auth/app/constsandstructs"
	"github.com/golang-jwt/jwt"
)

func authConf(w http.ResponseWriter,
	token string, exp time.Time) http.Cookie {
	return http.Cookie{
		Name:     "Authorization",
		Expires:  exp,
		Path:     "/set-token",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Value:    token,
	}
}

func authConfWithoutExp(w http.ResponseWriter,
	token string) http.Cookie {
	return http.Cookie{
		Name:     "Authorization",
		Path:     "/set-token",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Value:    token,
	}
}

// Функция для генерации JWT токена
func GenerateAndSignedToken(user string) (string, time.Time, error) {

	tokenLifeTime := 24 * time.Hour
	exp := time.Now().Add(tokenLifeTime)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user": user,
		"exp":  exp,
	})
	SignedToken, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	return SignedToken, exp, err
}

func GenerateAndSignedTokenWitoutExp(user string) (string, error) {

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user": user,
	})
	SignedToken, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	return SignedToken, err
}

func TokenWriter(w http.ResponseWriter, r *http.Request,
	users constsandstructs.Users,
	rememberBool string) error {
	login := users.GetLogin()

	if rememberBool != "on" {
		token, exp, err := GenerateAndSignedToken(login)
		if err != nil {
			http.ServeFile(w, r, constsandstructs.RequestErrorHTML)
			log.Println("Failed token signed: ", err)
		}

		w.Header().Set("Authorization", "Bearer"+token)
		w.Write([]byte(token))
		cookie := authConf(w, token, exp)
		http.SetCookie(w, &cookie)

		return err
	}

	token, err := GenerateAndSignedTokenWitoutExp(login)
	if err != nil {
		http.ServeFile(w, r, constsandstructs.RequestErrorHTML)
		log.Println("Failed token signed: ", err)
	}

	w.Header().Set("Authorization", "Bearer"+token)
	w.Write([]byte(token))
	cookie := authConfWithoutExp(w, token)
	http.SetCookie(w, &cookie)

	return err
}
