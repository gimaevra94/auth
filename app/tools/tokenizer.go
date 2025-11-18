package tools

import (
	"os"
	"time"

	"github.com/gimaevra94/auth/app/structs"
	"github.com/golang-jwt/jwt"
	"github.com/pkg/errors"
)

func GenerateRefreshToken(refreshTokenExp int, rememberMe bool) (string, error) {
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

func GeneratePasswordResetLink(email, baseURL string) (string, error) {
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
