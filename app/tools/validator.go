// Package tools предоставляет функции для валидации данных, геренации токенов и отправки email-уведомлений.
//
// Файл содержит функции для валидации различных типов данных:
//   - InputValidate: проверяет корректность логина, email и пароля
//   - RefreshTokenValidate: проверяет валидность refresh токена
//   - CodeValidate: сравнивает клиентский и серверный коды
//   - EmailValidate: проверяет корректность email
//   - PasswordValidate: проверяет корректность пароля
//   - ResetTokenValidate: проверяет и декодирует токен сброса пароля
package tools

import (
	"net/http"
	"os"
	"regexp"

	"github.com/gimaevra94/auth/app/structs"

	"github.com/golang-jwt/jwt"
	"github.com/pkg/errors"
)

var (
	loginRegex    = regexp.MustCompile(`^[a-zA-Zа-яА-ЯёЁ0-9]{3,30}$`)
	emailRegex    = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$`)
	passwordRegex = regexp.MustCompile(`^[a-zA-Zа-яА-ЯёЁ\d!@#$%^&*\-\)]{4,30}$`)
)

// InputValidate проверяет корректность введенных данных пользователя.
//
// Валидирует логин, пароль и email (только для регистрации).
// Возвращает ключ ошибки при невалидных данных.
var InputValidate = func(r *http.Request, login, email, password string, IsSignIn bool) (string, error) {
	var errMsgKey string
	if login == "" || !loginRegex.MatchString(login) {
		err := errors.New("loginInvalid")
		errMsgKey = "loginInvalid"
		return errMsgKey, errors.WithStack(err)
	}

	if password == "" || !passwordRegex.MatchString(password) {
		err := errors.New("passwordInvalid")
		errMsgKey = "passwordInvalid"
		return errMsgKey, errors.WithStack(err)
	}

	if !IsSignIn {
		if email == "" || !emailRegex.MatchString(email) {
			err := errors.New("emailInvalid")
			errMsgKey = "emailInvalid"
			return errMsgKey, errors.WithStack(err)
		}
	}

	return errMsgKey, nil
}

// RefreshTokenValidate проверяет валидность refresh токена.
//
// Декодирует JWT токен и проверяет его подпись и срок действия.
// Возвращает ошибку при невалидном токене.
var RefreshTokenValidate = func(refreshToken string) error {
	signedToken, err := jwt.ParseWithClaims(refreshToken, &jwt.StandardClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok || t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			err := errors.New("unexpected signing method")
			return nil, errors.WithStack(err)
		}
		jwtSecret := []byte(os.Getenv("JWT_SECRET"))
		return jwtSecret, nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	if !signedToken.Valid {
		err := errors.New("Refresh token invalid")
		return errors.WithStack(err)
	}

	return nil
}

// CodeValidate сравнивает клиентский и серверный коды.
//
// Проверяет наличие клиентского кода и его соответствие серверному.
// Используется для валидации кодов подтверждения (например, CAPTCHA).
var CodeValidate = func(r *http.Request, clientCode, serverCode string) error {
	if clientCode == "" {
		err := errors.New("clientCode not exist")
		return errors.WithStack(err)
	}

	if clientCode != serverCode {
		err := errors.New("codes not match")
		return errors.WithStack(err)
	}
	return nil
}

// EmailValidate проверяет корректность email адреса.
//
// Проверяет соответствие email формату с использованием регулярного выражения.
// Возвращает ошибку при невалидном email.
var EmailValidate = func(email string) error {
	if email == "" || !emailRegex.MatchString(email) {
		err := errors.New("email invalid")
		return errors.WithStack(err)
	}
	return nil
}

// PasswordValidate проверяет корректность пароля.
//
// Проверяет соответствие пароля требованиям безопасности с использованием регулярного выражения.
// Возвращает ошибку при невалидном пароле.
var PasswordValidate = func(password string) error {
	if password == "" || !passwordRegex.MatchString(password) {
		err := errors.New("password invalid")
		return errors.WithStack(err)
	}
	return nil
}

// ResetTokenValidate проверяет и декодирует токен сброса пароля.
//
// Валидирует JWT токен и извлекает из него claims с email пользователя.
// Возвращает структуру с данными токена при успешной валидации.
var ResetTokenValidate = func(signedToken string) (*structs.PasswordResetTokenClaims, error) {
	claims := &structs.PasswordResetTokenClaims{}

	tok, err := jwt.ParseWithClaims(signedToken, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	if err != nil {
		return nil, errors.WithStack(err)
	}

	if !tok.Valid {
		return nil, errors.New("token invalid")
	}

	return claims, nil
}
