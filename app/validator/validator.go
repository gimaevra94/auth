package validator

import (
	"fmt"
	"log"
	"net/http"
	"regexp"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/structs"
	"github.com/golang-jwt/jwt"
	"github.com/pkg/errors"
)

const (
	emailRegex    = `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$`
	loginRegex    = `^[a-zA-Zа-яА-ЯёЁ0-9]{3,30}$`
	passwordRegex = `^(?=.*[a-zA-Zа-яА-ЯёЁ])(?=.*\d)(?=.*[!@#$%^&*])[\w!@#$%^&*]{3,30}$`
	pathRegex     = `^/[a-zA-Z0-9_/\\-]+$`
)

var validPathRegex = regexp.MustCompile(pathRegex)

func IsValidToken(w http.ResponseWriter, r *http.Request) (*jwt.Token, error) {
	cookie, err := r.Cookie("cookie")
	if err != nil {
		wrappedErr := LogTraceAndRedirectErr(w, r,
			consts.GetFailedErr, "cookie", "", false)
		return nil, wrappedErr
	}

	value := cookie.Value
	if value == "" {
		return nil, LogTraceAndRedirectErr(w, r,
			consts.EmptyValueErr, "token", "", false)
	}

	token, err := jwt.Parse(value, func(t *jwt.Token) (interface{}, error) {
		return []byte("my-super-secret-key"), nil
	})

	if err != nil {
		return nil, LogTraceAndRedirectErr(w, r, err, "", "", false)
	}

	if !token.Valid {
		return nil, LogTraceAndRedirectErr(w, r,
			consts.ValidationFailedErr, "token", "", false)
	}

	return token, nil
}

func IsValidInput(w http.ResponseWriter,
	r *http.Request) (structs.User, error) {

	data := []string{
		r.FormValue("email"),
		r.FormValue("login"),
		r.FormValue("password"),
		emailRegex,
		loginRegex,
		passwordRegex,
	}

	for i := 0; i < 3; i++ {
		if data[i] == "" {
			return nil, LogTraceAndRedirectErr(w, r,
				consts.EmptyValueErr, data[i], "", false)
		}
		re := regexp.MustCompile(data[i+3])
		if !re.MatchString(data[i]) {
			return nil, LogTraceAndRedirectErr(w, r,
				consts.ValidationFailedErr, data[i], "", false)
		}
	}

	validatedLoginInput := structs.NewUser(
		data[0],
		data[1],
		data[2],
	)
	return validatedLoginInput, nil
}

func LogTraceAndRedirectErr(w http.ResponseWriter, r *http.Request,
	err interface{}, key string, path string, isExternalCall bool) error {
	if err == nil || err == "" {
		log.Printf("'err' value is nil or empty")
		return nil
	}

	if isExternalCall {
		if e, ok := err.(error); ok {
			if !validPathRegex.MatchString(path) {
				log.Println("path format must be like '/sign_in'")
				return nil
			}

			log.Printf("%+v\n", e)
			http.Redirect(w, r, path, http.StatusFound)
			return nil
		}

		log.Printf("excpected 'error' type for 'err' when 'isExternalCall' = true, got: %T", err)
		return nil
	}

	switch e := err.(type) {
	case error, string:
		wrappedErr := errors.Wrapf(errors.New(fmt.Sprintf("%v", e)), key)
		log.Printf("%+v\n", wrappedErr)
		return wrappedErr
	}

	log.Printf("excpected 'error' or 'string' type for 'err' when 'isExternalCall' = false, got: %T", err)
	return nil
}
