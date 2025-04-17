package validator

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/structs"
	"github.com/golang-jwt/jwt"
)

func getKeyFromErr(err error) string {
	str := strings.SplitN(err.Error(), ":", 2)
	if len(str) != 0 {
		return strings.TrimSpace(str[0])
	}
	return "Failed to get the key"
}

func getJWTSecret(token *jwt.Token) (interface{}, error) {
	return []byte(os.Getenv("JWT_SECRET")), nil
}

func IsValidToken(r *http.Request) error {
	cookie, err := r.Cookie("Authorization")
	if err != nil {
		log.Println("Failed to get a cookie", err)
		return err
	}

	value := cookie.Value
	if value == "" {
		log.Println("Failed to get a token from the cookie", err)
		return err
	}

	token, err := jwt.Parse(value, getJWTSecret)
	if err != nil {
		log.Println("Failed to parse from token", err)
		return err
	}

	if !token.Valid {
		log.Println("Token is invalid", err)
		return err
	}
	return nil
}

func IsValidInput(w http.ResponseWriter,
	r *http.Request) (structs.Users, error) {

	var (
		errEmpty  = errors.New("value is empty")
		errValidr = errors.New("validation failed")
		errRegex  = errors.New("regex key not matching")
	)

	email := r.FormValue("email")
	if email == "" {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println("email missing in FormValue")
		return nil, errEmpty
	}

	login := r.FormValue("login")
	if login == "" {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println("login missing in FormValue")
		return nil, errEmpty
	}

	password := r.FormValue("password")
	if password == "" {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println("password missing in FormValue")
		return nil, errEmpty
	}

	validatedLoginInput := structs.NewUsers(
		email,
		login,
		password,
	)

	loginInput := map[string]string{
		"email":    email,
		"login":    login,
		"password": password,
	}

	regexes := map[string]string{
		"email":    consts.EmailRegex,
		"login":    consts.LoginRegex,
		"password": consts.PasswordRegex,
	}

	err := inputValidator(loginInput, regexes, errEmpty, errValidr,
		errRegex)
	if err != nil {
		if errors.Is(err, errEmpty) {
			http.ServeFile(w, r, consts.RequestErrorHTML)
			log.Println("Data loss when getting from: ", getKeyFromErr(err))
			return validatedLoginInput, err

		} else if errors.Is(err, errRegex) {
			http.ServeFile(w, r, consts.RequestErrorHTML)
			log.Println("Data loss when getting from: ", getKeyFromErr(err))
			return validatedLoginInput, err

		} else if errors.Is(err, errValidr) {
			http.ServeFile(w, r, "badsign-up.html")
			log.Printf("%s validation failed", getKeyFromErr(err))
			return validatedLoginInput, err
		}
	}
	return validatedLoginInput, err
}

func inputValidator(loginInput map[string]string,
	regexes map[string]string, errEmpty error, errValidr error,
	errRegex error) error {

	for key, value := range loginInput {
		if value == "" {
			return fmt.Errorf("%s: %w", key, errEmpty)
		}

		regex := regexes[key]
		if regex == "" {
			return fmt.Errorf("%s: %w", key, errRegex)
		}

		re := regexp.MustCompile(value)
		if !re.MatchString(value) {
			return fmt.Errorf("%s: %w", key, errValidr)
		}
	}
	return nil
}
