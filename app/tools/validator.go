package tools

import (
	"net/http"
	"regexp"

	"github.com/gimaevra94/auth/app"
	"github.com/golang-jwt/jwt"
)

var (
	emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$`)

	loginRegex = regexp.MustCompile(`^[a-zA-Zа-яА-ЯёЁ0-9]{3,30}$`)

	passwordRegex = regexp.MustCompile(`^(?=.*[a-zA-Zа-яА-ЯёЁ])(?=.*\d)(?=.[!@#$%^&*])[\w!@#$%^&*]{3,30}$`)
)

func IsValidToken(w http.ResponseWriter,
	r *http.Request) (*jwt.Token, error) {
	cookie, err := r.Cookie("cookie")
	if err != nil {
		return nil, logtraceredir.LogTraceRedir(w, r,
			app.GetFailedErr, "cookie", "", false)
	}

	value := cookie.Value
	if value == "" {
		return nil, logtraceredir.LogTraceRedir(w, r,
			app.EmptyValueErr, "token", "", false)
	}

	token, err := jwt.Parse(value, func(t *jwt.Token) (interface{},
		error) {
		return []byte("my-super-secret-key"), nil
	})

	if err != nil {
		return nil, logtraceredir.LogTraceRedir(w, r, err, "", "", false)
	}

	if !token.Valid {
		return nil, logtraceredir.LogTraceRedir(w, r,
			app.ValidationFailedErr, "token", "", false)
	}

	return token, nil
}

func IsValidInput(w http.ResponseWriter,
	r *http.Request) (app.User, error) {

	email := r.FormValue("email")
	login := r.FormValue("login")
	password := r.FormValue("password")

	if email == "" {
		return nil, logtraceredir.LogTraceRedir(w, r,
			app.EmptyValueErr, "email", "", false)
	}
	if !emailRegex.MatchString(email) {
		return nil, logtraceredir.LogTraceRedir(w, r,
			app.ValidationFailedErr, email, "", false)
	}

	if login == "" {
		return nil, logtraceredir.LogTraceRedir(w, r,
			app.EmptyValueErr, "login", "", false)
	}
	if !loginRegex.MatchString(login) {
		return nil, logtraceredir.LogTraceRedir(w, r,
			app.ValidationFailedErr, login, "", false)
	}

	if password == "" {
		return nil, logtraceredir.LogTraceRedir(w, r,
			app.EmptyValueErr, "password", "", false)
	}
	if !passwordRegex.MatchString(password) {
		return nil, logtraceredir.LogTraceRedir(w, r,
			app.ValidationFailedErr, password, "", false)
	}

	validatedLoginInput := app.NewUser(
		email,
		login,
		password,
	)
	return validatedLoginInput, nil
}
