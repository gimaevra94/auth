package tools

import (
	"os"
	"time"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/gimaevra94/auth/app/structs"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

func GenerateRefreshToken(user structs.User) (structs.User, error) {
	refreshTokenExp := consts.RefreshTokenExp
	if !user.RememberMe {
		refreshTokenExp = 24 * 60 * 60
	}

	jti := uuid.New().String()
	expiresAt := time.Duration(refreshTokenExp) * time.Second
	refreshTokenClaims := &structs.RefreshTokenClaims{
		UserID: user.UserID,
		JTI:    jti,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(expiresAt).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshTokenClaims)
	jwtSecret := []byte(os.Getenv("JWT_SECRET"))
	signedRefreshToken, err := refreshToken.SignedString(jwtSecret)
	if err != nil {
		return structs.User{}, errors.WithStack(err)
	}
	user.RefreshToken = signedRefreshToken

	expiresAtUnix := refreshTokenClaims.ExpiresAt
	expiresAtTime := time.Unix(expiresAtUnix, 0)
	user.RefreshExpiresAt = expiresAtTime

	return user, nil
}

func GenerateAccessToken(user structs.User) (structs.User, error) {
	expiresAt := time.Duration(consts.AccessTokenExp) * time.Second
	accessTokenClaims := &structs.AccessTokenClaims{
		UserID: user.UserID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(expiresAt).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessTokenClaims)
	jwtSecret := []byte(os.Getenv("JWT_SECRET"))
	signedAccessToken, err := accessToken.SignedString(jwtSecret)
	if err != nil {
		return structs.User{}, errors.WithStack(err)
	}
	user.AccessToken = signedAccessToken

	return user, nil
}
