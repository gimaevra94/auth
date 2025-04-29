package validator

import (
	"log"
	"net/http"
	"os"
	"regexp"

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
	cookie, err := r.Cookie("cookie")
	if err != nil {
		return nil, errors.Wrap(errors.New(consts.GetFailedErr), "cookie")
	}

	value := cookie.Value
	if value == "" {
		return nil, errors.Wrap(errors.New(consts.GetFailedErr), "token")
	}

	token, err := jwt.Parse(value, getJWTSecret)
	if err != nil {
		return nil, errors.Wrap(err, "")
	}

	if !token.Valid {
		log.Println(consts.InvalidTokenErr, err)
		return nil, errors.New(consts.TokenValidateFailedErr)
	}

	return token, nil
}

func IsValidInput(w http.ResponseWriter,
	r *http.Request) (structs.User, error) {

	data := []string{
		r.FormValue("email"),
		r.FormValue("login"),
		r.FormValue("password"),
		`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$`,
		`^[a-zA-Zа-яА-ЯёЁ0-9]{3,30}$`,
		`^(?=.*[a-zA-Zа-яА-ЯёЁ])(?=.*\d)(?=.*[!@#$%^&*])[\w!@#$%^&*]{3,30}$`,
	}

	for i := 0; i < 3; i++ {
		if data[i] == "" {
			wrappedErr := errors.Wrap(errors.New("empty value"), data[i])
			log.Printf("%+v\n", wrappedErr)
			return nil, wrappedErr
		}
		re := regexp.MustCompile(data[i+3])
		if !re.MatchString(data[i]) {
			wrappedErr := errors.Wrap(errors.New("validation failed"), data[i])
			log.Printf("%+v\n", wrappedErr)
			return nil, wrappedErr
		}
	}

	validatedLoginInput := structs.NewUser(
		data[0],
		data[1],
		data[2],
	)
	return validatedLoginInput, nil
} 