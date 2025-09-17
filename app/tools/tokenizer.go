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

func GenerateAccessToken(user structs.User) (string, error) {
	expiresAt := time.Duration(consts.AccessTokenExp) * time.Second
	accessTokenClaims := &structs.AccessTokenClaims{
		UserID: user.UserID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(expiresAt).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodES256, accessTokenClaims)
	jwtSecret := []byte(os.Getenv("JWT_SECRET"))
	signedAccessToken, err := accessToken.SignedString(jwtSecret)
	if err != nil {
		return "", errors.WithStack(err)
	}
	return signedAccessToken, nil
}

func GenerateRefreshToken(rememberMe bool) (string, string, time.Time, error) {
	userID := uuid.New().String()
	refreshTokenExp := consts.RefreshTokenExp
	if !rememberMe {
		refreshTokenExp = 24 * 60 * 60
	}

	jti := uuid.New().String()
	expiresAt := time.Duration(refreshTokenExp) * time.Second
	refreshTokenClaims := &structs.RefreshTokenClaims{
		UserID: userID,
		JTI:    jti,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(expiresAt).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodES256, refreshTokenClaims)
	jwtSecret := []byte(os.Getenv("JWT_SECRET"))
	signedRefreshToken, err := refreshToken.SignedString(jwtSecret)
	if err != nil {
		return "", "", time.Time{}, errors.WithStack(err)
	}

	expiresAtUnix := refreshTokenClaims.ExpiresAt
	expiresAtTime := time.Unix(expiresAtUnix, 0)

	return signedRefreshToken, userID, expiresAtTime, nil
}
