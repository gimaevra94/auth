package validator

import (
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/structs"
	"github.com/golang-jwt/jwt"
	"github.com/pkg/errors"
)

func getJWTSecret(token *jwt.Token) (interface{}, error) {
	secret := os.Getenv("JWT_SECRET")
	if secret == consts.EmptyValueStr {
		return nil, errors.New(consts.JWTSecretNotExistErr)
	}
	return []byte(os.Getenv("JWT_SECRET")), nil
}

func IsValidToken(r *http.Request) (*jwt.Token, error) {
	cookie, err := r.Cookie(consts.CookieNameStr)
	if err != nil {
		log.Println(consts.CookieGetFailedErr, err)
		return nil, err
	}

	value := cookie.Value
	if value == consts.EmptyValueStr {
		log.Println(consts.TokenGetFailedErr, err)
		return nil, errors.New(consts.TokenGetFailedErr)
	}

	token, err := jwt.Parse(value, getJWTSecret)
	if err != nil {
		log.Println(consts.ParseFromTokenFailedErr, err)
		return nil, err
	}

	if !token.Valid {
		log.Println(consts.InvalidTokenErr, err)
		return nil, errors.New(consts.TokenValidateFailedErr)
	}

	return token, nil
}

func IsValidInput(w http.ResponseWriter,
	r *http.Request) (structs.User, error) {

	var (
		errEmpty = errors.New(consts.EmptyValueErr)
		errValid = errors.New(consts.ValidationFailedErr)
		errRegex = errors.New(consts.RegexKeyNotMatchErr)
	)

	email := r.FormValue(consts.EmailStr)
	if email == consts.EmptyValueStr {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println(consts.EmailGetFromFormFailedErr)
		return nil, errEmpty
	}

	login := r.FormValue(consts.LoginStr)
	if login == consts.EmptyValueStr {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println(consts.LoginGetFromFormFailedErr)
		return nil, errEmpty
	}

	password := r.FormValue(consts.PasswordStr)
	if password == consts.EmptyValueStr {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println(consts.PasswordGetFromFormFailedErr)
		return nil, errEmpty
	}

	validatedLoginInput := structs.NewUser(
		email,
		login,
		password,
	)

	loginInput := map[string]string{
		consts.EmailStr:    email,
		consts.LoginStr:    login,
		consts.PasswordStr: password,
	}

	regexes := map[string]string{
		consts.EmailStr:    consts.EmailRegex,
		consts.LoginStr:    consts.LoginRegex,
		consts.PasswordStr: consts.PasswordRegex,
	}

	for key, value := range loginInput {
		regex := regexes[key]
		re := regexp.MustCompile(regex)
		if !re.MatchString(value) {
			return errors.Wrapf(errValidr, key)
		}
	return validatedLoginInput, nil
}