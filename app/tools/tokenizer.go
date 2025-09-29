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

/*func GenerateAccessToken(accessTokenExp int, userID string) (string, error) {
	expiresAt := time.Duration(accessTokenExp) * time.Second
	accessTokenClaims := &structs.AccessTokenClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(expiresAt).Unix(),
			IssuedAt:  time.Now().Unix(),
			Subject:   userID,
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessTokenClaims)
	jwtSecret := []byte(os.Getenv("JWT_SECRET"))
	signedAccessToken, err := accessToken.SignedString(jwtSecret)
	if err != nil {
		return "", errors.WithStack(err)
	}

	return signedAccessToken, nil
}*/
