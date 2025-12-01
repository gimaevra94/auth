// Package tools предоставляет функции для валидации данных, геренации токенов и отправки email-уведомлений.
//
// Файл содержит функции для генерации JWT токенов:
//   - GenerateRefreshToken: генерирует refresh токен для аутентификации
//   - GeneratePasswordResetLink: генерирует ссылку для сброса пароля с токеном
package tools

import (
	"os"
	"time"

	"github.com/gimaevra94/auth/app/structs"
	"github.com/golang-jwt/jwt"
	"github.com/pkg/errors"
)

// GenerateRefreshToken генерирует JWT refresh токен.
//
// Принимает время жизни токена и флаг "запомнить меня".
// Если флаг установлен в false, использует время жизни 24 часа по умолчанию.
// Возвращает подписанный JWT токен или ошибку.
var GenerateRefreshToken = func(refreshTokenExp int, rememberMe bool) (string, error) {
	refreshTokenExp24Hours := 24 * 60 * 60
	if !rememberMe {
		refreshTokenExp = refreshTokenExp24Hours
	}

	refreshTokenExpiresAt := time.Now().Unix() + int64(refreshTokenExp)
	refreshTokenIssuedAt := time.Now().Unix()
	standardClaims := jwt.StandardClaims{
		ExpiresAt: refreshTokenExpiresAt,
		IssuedAt:  refreshTokenIssuedAt,
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, standardClaims)
	jwtSecret := []byte(os.Getenv("JWT_SECRET"))
	signedrefreshToken, err := refreshToken.SignedString(jwtSecret)
	if err != nil {
		return "", errors.WithStack(err)
	}

	return signedrefreshToken, nil
}

// GeneratePasswordResetLink генерирует ссылку для сброса пароля с JWT токеном.
//
// Принимает email пользователя и базовый URL.
// Создает токен со сроком действия 15 минут, содержащий email.
// Возвращает полную ссылку для сброса пароля или ошибку.
var GeneratePasswordResetLink = func(email, baseURL string) (string, error) {
	passwordResetTokenExp15Minutes := time.Now().Add(15 * time.Minute)
	passwordResetTokenExp15MinutesExpiresAt := passwordResetTokenExp15Minutes.Unix()
	passwordResetTokenExp15MinutesIssuedAt := time.Now().Unix()
	passwordResetTokenClaims := structs.PasswordResetTokenClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: passwordResetTokenExp15MinutesExpiresAt,
			IssuedAt:  passwordResetTokenExp15MinutesIssuedAt,
		},
		Email: email,
	}

	resetToken := jwt.NewWithClaims(jwt.SigningMethodHS256, passwordResetTokenClaims)
	jwtSecret := []byte(os.Getenv("JWT_SECRET"))
	signedPasswordResetToken, err := resetToken.SignedString(jwtSecret)
	if err != nil {
		return "", errors.WithStack(err)
	}

	passwordResetLink := baseURL + "?token=" + signedPasswordResetToken
	return passwordResetLink, nil
}
