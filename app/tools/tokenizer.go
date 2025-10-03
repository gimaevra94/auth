package tools

import (
	"os"
	"time"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/golang-jwt/jwt"
	"github.com/pkg/errors"
)

func GenerateRefreshToken(refreshTokenExp int, rememberMe bool) (string, error) {
	if !rememberMe {
		refreshTokenExp = consts.RefreshTokenExp24Hours
	}

	expiresAt := time.Duration(refreshTokenExp) * time.Second

	standardClaims := jwt.StandardClaims{
		ExpiresAt: time.Now().Add(expiresAt).Unix(),
		IssuedAt:  time.Now().Unix(),
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, standardClaims)
	jwtSecret := []byte(os.Getenv("JWT_SECRET"))
	signedRefreshToken, err := refreshToken.SignedString(jwtSecret)
	if err != nil {
		return "", errors.WithStack(err)
	}

	return signedRefreshToken, nil
}

func GenerateResetToken(email string) (string, time.Time, error) {
	expirationTime := time.Now().Add(15 * time.Minute)
	
	claims := jwt.StandardClaims{
		ExpiresAt: expirationTime.Unix(),
		IssuedAt:  time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	jwtSecret := []byte(os.Getenv("JWT_SECRET"))
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", time.Time{}, errors.Wrap(err, "failed to sign reset token")
	}

	return tokenString, expirationTime, nil
}

func GenerateResetLink(baseURL, token string) string {
	return baseURL + "?token=" + token
}
