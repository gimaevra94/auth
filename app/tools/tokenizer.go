package tools

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"time"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/golang-jwt/jwt"
	"github.com/pkg/errors"
)

type ResetClaims struct {
	jwt.StandardClaims
	Email string `json:"email"`
}

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

func GenerateResetLink(email, baseURL string) (string, error) {
	expirationTime := time.Now().Add(15 * time.Minute)

	claims := ResetClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
			IssuedAt:  time.Now().Unix(),
		},
		Email: email,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	jwtSecret := []byte(os.Getenv("JWT_SECRET"))
	signedToken, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", errors.WithStack(err)
	}

	resetLink := baseURL + "?token=" + signedToken
	return resetLink, nil
}

func ValidateResetToken(signedToken string) (*ResetClaims, error) {
	claims := &ResetClaims{}

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
		return nil, errors.New("token is invalid")
	}

	return claims, nil
}

func GenerateRandomKey(len int) (string, error) {
	rawKey := make([]byte, len)
	_, err := rand.Read(rawKey)
	if err != nil {
		return "", errors.WithStack(err)
	}
	encodedKey := base64.StdEncoding.EncodeToString(rawKey)
	return encodedKey, nil
}
