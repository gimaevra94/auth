package tools

import (
	"os"
	"time"

	"github.com/gimaevra94/auth/app/consts"
	"github.com/golang-jwt/jwt"
	"github.com/pkg/errors"
)

// ResetClaims добавляет permanentUserID и email к стандартным утверждениям JWT
type ResetClaims struct {
	jwt.StandardClaims
	PermanentUserID string `json:"permanent_user_id"`
	Email           string `json:"email"`
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

func GenerateResetLink(email, permanentUserID, baseURL string) (string, time.Time, string, error) {
	expirationTime := time.Now().Add(15 * time.Minute)

	claims := ResetClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
			IssuedAt:  time.Now().Unix(),
		},
		PermanentUserID: permanentUserID,
		Email:           email,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	jwtSecret := []byte(os.Getenv("JWT_SECRET"))
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", time.Time{}, "", errors.Wrap(err, "failed to sign reset token")
	}

	resetLink := baseURL + "?token=" + tokenString
	return resetLink, expirationTime, tokenString, nil
}

// ValidateResetToken извлекает и валидирует токен сброса пароля
func ValidateResetToken(tokenString string) (*ResetClaims, error) {
	claims := &ResetClaims{}

	tok, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	if err != nil {
		return nil, errors.Wrap(err, "failed to parse token")
	}

	if !tok.Valid {
		return nil, errors.New("token is invalid")
	}

	return claims, nil
}
