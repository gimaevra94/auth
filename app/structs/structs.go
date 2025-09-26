package structs

import (
	"time"

	"github.com/golang-jwt/jwt"
)

type User struct {
	Login            string    `sql:"login" json:"login"`                       //
	Email            string    `sql:"email" json:"email"`                       //
	Password         string    `sql:"password" json:"password"`                 //
	ServerCode       string    `sql:"serverCode" json:"serverCode"`             //
	UserID           string    `sql:"userId" json:"userId"`                     //
	RefreshToken     string    `sql:"refreshToken" json:"refreshToken"`         //
	RefreshExpiresAt time.Time `sql:"refreshExpiresAt" json:"refreshExpiresAt"` //
	AccessToken      string    `sql:"accessToken" json:"accessToken"`           //
	DeviceInfo       string    `sql:"deviceInfo" json:"deviceInfo"`             //
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
