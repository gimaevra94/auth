package structs

import (
	"time"

	"github.com/golang-jwt/jwt"
)

type User struct {
	UserID             string    `sql:"userId" json:"userId"`
	Login              string    `sql:"login" json:"login"`
	Email              string    `sql:"email" json:"email"`
	Password           string    `sql:"password" json:"password"`
	RefreshToken       string    `sql:"refreshToken" json:"refreshToken"`
	AccessToken        string    `sql:"accessToken" json:"accessToken"`
	RefreshExpiresAt   time.Time `sql:"refreshExpiresAt" json:"refreshExpiresAt"`
	DeviceInfo         string    `sql:"deviceInfo" json:"deviceInfo"`
	RememberMe         bool
	AccessTokenClaims  AccessTokenClaims
	RefreshTokenClaims RefreshTokenClaims
}

type AccessTokenClaims struct {
	UserID string `json:"userID"`
	jwt.StandardClaims
}

type RefreshTokenClaims struct {
	UserID string `json:"userID"`
	JTI    string `json:"jti"`
	jwt.StandardClaims
}
