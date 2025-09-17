package structs

import (
	"time"

	"github.com/golang-jwt/jwt"
)

type User struct {
	UserID     string    `sql:"id" json:"user-id"`
	Login      string    `sql:"login" json:"login"`
	Email      string    `sql:"email" json:"email"`
	Password   string    `sql:"password" json:"password"`
	Token      string    `sql:"token" json:"token"`
	ExpiresAt  time.Time `sql:"expires-at" json:"expires-at"`
	DeviceInfo string    `sql:"deviceInfo" json:"deviceInfo"`
}

type AccessTokenClaims struct {
	UserID string `json:"user-id"`
	jwt.StandardClaims
}

type RefreshTokenClaims struct {
	UserID string `json:"user-id"`
	JTI    string `json:"jti"`
	jwt.StandardClaims
}
