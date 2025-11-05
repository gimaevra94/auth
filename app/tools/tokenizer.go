package tools

import (
	"os"
	"time"

	"github.com/gimaevra94/auth/app/structs"
	"github.com/golang-jwt/jwt"
	"github.com/pkg/errors"
)

func GenerateUserRefreshToken(userRefreshTokenExp int, rememberMe bool) (string, error) {
	userRefreshTokenExp24Hours := 24 * 60 * 60
	if !rememberMe {
		userRefreshTokenExp = userRefreshTokenExp24Hours
	}

	userRefreshTokenExpiresAt := time.Now().Unix() + int64(userRefreshTokenExp)
	userRefreshTokenIssuedAt := time.Now().Unix()
	standardClaims := jwt.StandardClaims{
		ExpiresAt: userRefreshTokenExpiresAt,
		IssuedAt:  userRefreshTokenIssuedAt,
	}

	userRefreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, standardClaims)
	jwtSecret := []byte(os.Getenv("JWT_SECRET"))
	signedUserRefreshToken, err := userRefreshToken.SignedString(jwtSecret)
	if err != nil {
		return "", errors.WithStack(err)
	}

	return signedUserRefreshToken, nil
}

func GeneratePasswordResetLink(userEmail, baseURL string) (string, error) {
	passwordResetTokenExp15Minutes := time.Now().Add(15 * time.Minute)
	passwordResetTokenExp15MinutesExpiresAt := passwordResetTokenExp15Minutes.Unix()
	passwordResetTokenExp15MinutesIssuedAt := time.Now().Unix()
	passwordResetTokenClaims := structs.PasswordResetTokenClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: passwordResetTokenExp15MinutesExpiresAt,
			IssuedAt:  passwordResetTokenExp15MinutesIssuedAt,
		},
		UserEmail: userEmail,
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
