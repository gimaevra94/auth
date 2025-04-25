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

	err := inputValidator(loginInput, regexes, errEmpty, errValid,
		errRegex)
	if err != nil {
		if errors.Is(err, errEmpty) {
			http.ServeFile(w, r, consts.RequestErrorHTML)
			log.Println(consts.EmptyValueErr, getKeyFromErr(err))
			return nil, err

		} else if errors.Is(err, errRegex) {
			http.ServeFile(w, r, consts.RequestErrorHTML)
			log.Println(consts.RegexKeyNotMatchErr, getKeyFromErr(err))
			return nil, err

		} else if errors.Is(err, errValid) {
			http.ServeFile(w, r, consts.BadSignUpHTML)
			log.Printf("%s: %s", getKeyFromErr(err), consts.ValidationFailedErr)
			return nil, err
		}
	}
	return validatedLoginInput, nil
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
		if value == consts.EmptyValueStr {
			return errors.Wrapf(errEmpty, "%s", key)
		}

		regex := regexes[key]
		if regex == consts.EmptyValueStr {
			return errors.Wrapf(errRegex, "%s", key)
		}

		re := regexp.MustCompile(regex)
		if !re.MatchString(value) {
			return errors.Wrapf(errValidr, "%s", key)
		}
	}
	return nil
}
