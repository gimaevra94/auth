package tools

import (
	"os"
	"time"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

type AccessTokenClaims struct {
	UserID string `json:"user-id"`
	jwt.StandardClaims
}

type RefreshTokenClaims struct {
	UserID string `json:"user-id"`
	JTI    string `json:"jti"`
	jwt.StandardClaims
}

func GenerateAccessToken(userID string) (string, error) {
	expiresAt := time.Duration(consts.AccessTokenExp) * time.Second
	accessTokenClaims := &AccessTokenClaims{
		UserID: userID,
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

func GenerateRefreshToken(userID string, rememberMe bool) (string, error) {
	refreshTokenExp := consts.RefreshTokenExp
	if !rememberMe {
		refreshTokenExp = 24 * 60 * 60
	}

	jti := uuid.New().String()
	expiresAt := time.Duration(refreshTokenExp) * time.Second
	refreshTokenClaims := &RefreshTokenClaims{
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
		return "", errors.WithStack(err)
	}
	return signedRefreshToken, nil
}
