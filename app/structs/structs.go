package structs

import (
	"github.com/golang-jwt/jwt"
)

type User struct {
	Login              string `sql:"login" json:"login"`               //
	Email              string `sql:"email" json:"email"`               //
	Password           string `sql:"password" json:"password"`         //
	ServerCode         string `sql:"serverCode" json:"serverCode"`     //
	UserID             string `sql:"userId" json:"userId"`             //
	RefreshToken       string `sql:"refreshToken" json:"refreshToken"` //
	DeviceInfo         string `sql:"deviceInfo" json:"deviceInfo"`     //
	RememberMe         bool   //
	RefreshTokenClaims RefreshTokenClaims
	AccessTokenClaims  AccessTokenClaims
}

type AccessTokenClaims struct {
	jwt.StandardClaims
}

type RefreshTokenClaims struct {
	jwt.StandardClaims
}
