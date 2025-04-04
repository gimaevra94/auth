package tokenizer

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/users"
	"github.com/golang-jwt/jwt"
)

func authConf(token string, exp time.Time) http.Cookie {
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

func authConfWithoutExp(token string) http.Cookie {
	return http.Cookie{
		Name:     "Authorization",
		Path:     "/set-token",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Value:    token,
	}
}

func generateAndSignedToken(user string) (string, time.Time, error) {

	tokenLifeTime := 24 * time.Hour
	exp := time.Now().Add(tokenLifeTime)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user": user,
		"exp":  exp,
	})
	SignedToken, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	return SignedToken, exp, err
}

func generateAndSignedTokenWitoutExp(user string) (string, error) {

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user": user,
	})
	SignedToken, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	return SignedToken, err
}

func GetJWTSecret(token *jwt.Token) (interface{}, error) {
	return []byte(os.Getenv("JWT_SECRET")), nil
}

func TokenWriter(w http.ResponseWriter, r *http.Request,
	users users.Users,
	rememberBool string) error {
	login := users.GetLogin()

	if rememberBool != "on" {
		token, exp, err := generateAndSignedToken(login)
		if err != nil {
			http.ServeFile(w, r, consts.RequestErrorHTML)
			log.Println("Failed to sign the token: ", err)
			return err
		}

		w.Header().Set("Authorization", "Bearer"+token)
		w.Write([]byte(token))
		cookie := authConf(token, exp)
		http.SetCookie(w, &cookie)

		return nil
	}

	token, err := generateAndSignedTokenWitoutExp(login)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println("Failed token signed: ", err)
		return err
	}

	w.Header().Set("Authorization", "Bearer"+token)
	w.Write([]byte(token))
	cookie := authConfWithoutExp(token)
	http.SetCookie(w, &cookie)

	return nil
}
