package validator

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/golang-jwt/jwt"
)

type users struct {
	Email    string `json:"email"`
	Login    string `json:"login"`
	Password string `json:"password"`
}

func NewUsers(email, login, password string) Users {
	return &users{
		Email:    email,
		Login:    login,
		Password: password,
	}
}

func (v *users) GetEmail() string {
	return v.Email
}

func (v *users) GetLogin() string {
	return v.Login
}

func (v *users) GetPassword() string {
	return v.Password
}

type Users interface {
	GetEmail() string
	GetLogin() string
	GetPassword() string
}

func IsValidToken(r *http.Request, cookie string) error {
	token := r.Header.Get("auth")
	if token == "" {
		return fmt.Errorf("token loss when got from header")
	}

	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims,

		func(token *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("JWT_SECRET")), nil
		})

	if err != nil {
		return err
	}
	return nil
}

func IsValidInput(w http.ResponseWriter, r *http.Request) (Users, error) {
	loginInput := map[string]string{
		"email":    r.FormValue("email"),
		"login":    r.FormValue("login"),
		"password": r.FormValue("password"),
	}

	regexes := map[string]string{
		"email":    consts.EmailRegex,
		"login":    consts.LoginRegex,
		"password": consts.PasswordRegex,
	}

	validatedLoginInput := NewUsers(
		loginInput["email"],
		loginInput["login"],
		loginInput["password"],
	)

	var (
		errEmpty  = errors.New("value is empty")
		errValidr = errors.New("validation failed")
		errRegex  = errors.New("regex key not matching")
	)

	err := inputValidator(loginInput, regexes, errEmpty, errValidr,
		errRegex)
	if err != nil {
		if errors.Is(err, errEmpty) {
			http.ServeFile(w, r, consts.RequestErrorHTML)
			log.Println("Data loss when getting from: ", err)
			return validatedLoginInput, err

		} else if errors.Is(err, errRegex) {
			http.ServeFile(w, r, consts.RequestErrorHTML)
			log.Println("Data loss when getting from: ", err)
			return validatedLoginInput, err

		} else if errors.Is(err, errValidr) {
			http.ServeFile(w, r, "badsign-up.html")
			log.Printf("%s validation failed", err)
			return validatedLoginInput, err
		}
	}
	return validatedLoginInput, err
}

func inputValidator(loginInput map[string]string,
	regexes map[string]string, errEmpty error, errValidr error,
	errRegex error) error {

	for field, value := range loginInput {
		if value == "" {
			return fmt.Errorf("%s: %w", field, errEmpty)
		}

		regex := regexes[field]
		if regex == "" {
			return fmt.Errorf("%s: %w", field, errRegex)
		}

		re := regexp.MustCompile(regex)
		if !re.MatchString(regex) {
			return fmt.Errorf("%s: %w", field, errValidr)
		}
	}
	return nil
}
