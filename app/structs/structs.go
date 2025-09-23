package structs

import (
	"time"

	"github.com/golang-jwt/jwt"
)

type User struct {
	UserID     string    `sql:"userId" json:"userId"`
	Login      string    `sql:"login" json:"login"`
	Email      string    `sql:"email" json:"email"`
	Password   string    `sql:"password" json:"password"`
	Token      string    `sql:"token" json:"token"`
	ExpiresAt  time.Time `sql:"expiresAt" json:"expiresAt"`
	DeviceInfo string    `sql:"deviceInfo" json:"deviceInfo"`
}

type AccessTokenClaims struct {
	UserID string `json:"userId"`
	jwt.StandardClaims
}

type RefreshTokenClaims struct {
	UserID string `json:"userId"`
	JTI    string `json:"jti"`
	jwt.StandardClaims
}
