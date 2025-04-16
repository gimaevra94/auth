package tokenizer

import (
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/structs"
	"github.com/golang-jwt/jwt"
)

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
	signedToken, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	return signedToken, err
}

func GetNewTokegn(token *jwt.Token) error {
	claims := token.Claims.(jwt.MapClaims)
	expFloat := claims["exp"].(float64)
	exp := time.Unix(int64(expFloat), 0)
	if time.Now().After(exp) {
		log.Println("Token in expired")
		return errors.New("token in expired")
	}

	newExp := time.Now().Add(3 * time.Hour)
	newToken := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"user": claims["user"],
			"exp":  newExp.Unix(),
		})

	newiSngedToken, err := newToken.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		log.Println("Failed to sign token", err)
		return err
	}

	newCookie := http.Cookie{
		Name:     "Authorization",
		Path:     "/set-token",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Value:    newiSngedToken,
	}

	http.SetCookie(w, &newCookie)
}

func TokenWriter(w http.ResponseWriter, r *http.Request,
	users structs.Users,
	rememberBool string) (time.Time, error) {

	var exp time.Time
	login := users.GetLogin()

	if rememberBool != "on" {
		token, exp, err := generateAndSignedToken(login)
		if err != nil {
			http.ServeFile(w, r, consts.RequestErrorHTML)
			log.Println("Failed to sign the token: ", err)
			return exp, err
		}

		w.Header().Set("Authorization", "Bearer"+token)
		w.Write([]byte(token))

		cookie := http.Cookie{
			Name:     "Authorization",
			Expires:  exp,
			Path:     "/set-token",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			Value:    token,
		}

		http.SetCookie(w, &cookie)
		return exp, nil
	}

	token, err := generateAndSignedTokenWitoutExp(login)
	if err != nil {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println("Failed token signed: ", err)
		return exp, err
	}

	w.Header().Set("Authorization", "Bearer"+token)
	w.Write([]byte(token))

	cookie := http.Cookie{
		Name:     "Authorization",
		Path:     "/set-token",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Value:    token,
	}

	http.SetCookie(w, &cookie)
	return exp, nil
}

func GetNewToken(users structs.Users, command string) (string, error) {
	var token *jwt.Token

	switch command {
	case "Expire in 24 hours":
		exp := time.Now().Add(24 * time.Hour)
		user := users.GetLogin()
		token = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user": user,
			"exp":  exp,
		})

	case "Expire in 3 hours":

	case "No expiration":
	}

	SignedToken, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	return SignedToken, err
}
