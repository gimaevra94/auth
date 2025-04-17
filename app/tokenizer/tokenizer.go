package tokenizer

import (
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gimaevra94/auth/app/auth"
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

func TokenCreate(w http.ResponseWriter, r *http.Request,
	command string) error {

	var token *jwt.Token
	session, err := auth.Store.Get(r, "auth-session")
	if err != nil {
		log.Println("Failed to get 'auth-session'")
	}

	users:=session.Values[""]

	switch command {
	case "":
		exp := time.Now().Add(24 * time.Hour)
		user := users.GetLogin()
		token = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user": user,
			"exp":  exp,
		})

	case "on":
		user := users.GetLogin()
		token = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user": user,
		})

	case "expire_3_hours":
		exp := time.Now().Add(3 * time.Hour)
		user := users.GetLogin()
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
