package tokenizer

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gimaevra94/auth/app/validator"
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
func GenerateAndSignedToken(user string,
	rememberBool bool) (string, time.Time, error) {
	var token *jwt.Token
	var tokenLifeTime time.Duration
	tokenLifeTime = 24 * time.Hour
	exp := time.Now().Add(tokenLifeTime)
	token = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user": user, // Имя пользователя
		"exp":  exp,  // Время истечения токена (24 часа)
	})
	SignedToken, err := token.SignedString([]byte(os.Getenv("JWT_SECRET"))) // Используем секретный ключ
	return SignedToken, exp, err
}

func GenerateAndSignedTokenWitoutExp(user string,
	rememberBool bool) (string, error) {
	var token *jwt.Token
	token = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user": user,
	})
	SignedToken, err := token.SignedString([]byte(os.Getenv("JWT_SECRET"))) // Используем секретный ключ
	return SignedToken, err
}

func TokenWriter(w http.ResponseWriter, users validator.Users,
	rememberBool bool) error {
	login := users.GetLogin()

	if !rememberBool {
		login := users.GetLogin()
		token, exp, err := GenerateAndSignedToken(login, rememberBool)
		if err != nil {
			log.Println("tokenizer.GenerateAndSignedToken: ", err)
		} else {
			w.Header().Set("Authorization", "Bearer"+token)
			w.Write([]byte(token))
			cookie := authConf(w, token, exp)
			http.SetCookie(w, &cookie)
		}
		return err
	} else {
		token, err := GenerateAndSignedTokenWitoutExp(login,
			rememberBool)
		if err != nil {
			log.Println("tokenizer.GenerateAndSignedToken: ", err)
		} else {
			w.Header().Set("Authorization", "Bearer"+token)
			w.Write([]byte(token))
			cookie := authConfWithoutExp(w, token)
			http.SetCookie(w, &cookie)
		}
		return err
	}
}
