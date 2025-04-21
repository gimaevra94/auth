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

func getJWTSecret(token *jwt.Token) (interface{}, error) {
	return []byte(os.Getenv("JWT_SECRET")), nil
}

func IsValidToken(r *http.Request) (*jwt.Token, error) {
	cookie, err := r.Cookie(consts.AuthCookieNameStr)
	if err != nil {
		log.Println(consts.CookieGetFailedErr, err)
		return nil, err
	}

	value := cookie.Value
	if value == "" {
		log.Println(consts.TokenGetFailedErr, err)
		return nil, errors.New("failed to get the token")
	}

	token, err := jwt.Parse(value, getJWTSecret)
	if err != nil {
		log.Println(consts.ParseFromTokenFailedErr, err)
		return nil, err
	}

	if !token.Valid {
		log.Println(consts.InvalidTokenErr, err)
		return nil, errors.New("token is invalid")
	}

	return token, nil
}

func IsValidInput(w http.ResponseWriter,
	r *http.Request) (structs.User, error) {

	var (
		errEmpty  = errors.New(consts.EmptyValueErr)
		errValidr = errors.New(consts.ValidationFailedErr)
		errRegex  = errors.New(consts.RegexKEyNotMatchErr)
	)

	email := r.FormValue(consts.EmailStr)
	if email == consts.EmptyValueStr {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println(consts.EmailGetFromFormFailedErr, errEmpty)
		return nil, errEmpty
	}

	login := r.FormValue(consts.LoginStr)
	if login == consts.EmptyValueStr {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println(consts.LoginGetFromFormFailedErr, errEmpty)
		return nil, errEmpty
	}

	password := r.FormValue(consts.PasswordStr)
	if password == consts.EmptyValueStr {
		http.ServeFile(w, r, consts.RequestErrorHTML)
		log.Println(consts.PasswordGetFromFormFailedErr, errEmpty)
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

	err := inputValidator(loginInput, regexes, errEmpty, errValidr,
		errRegex)
	if err != nil {
		if errors.Is(err, errEmpty) {
			http.ServeFile(w, r, consts.RequestErrorHTML)
			log.Println(consts.DatGetFailed, getKeyFromErr(err))
			return validatedLoginInput, err

		} else if errors.Is(err, errRegex) {
			http.ServeFile(w, r, consts.RequestErrorHTML)
			log.Println(consts.DatGetFailed, getKeyFromErr(err))
			return validatedLoginInput, err

		} else if errors.Is(err, errValidr) {
			http.ServeFile(w, r, consts.BadSignUp)
			log.Printf("%s %s", getKeyFromErr(err), consts.ValidationFailedErr)
			return validatedLoginInput, err
		}
	}
	return validatedLoginInput, err
}

func getKeyFromErr(err error) string {
	str := strings.SplitN(err.Error(), ":", 2)
	if len(str) != 0 {
		return strings.TrimSpace(str[0])
	}
	return consts.KeyGetFailedErr
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
