package structs

import "github.com/golang-jwt/jwt"

type User struct {
	UserId                 string `sql:"userId"`
	Login                  string `sql:"login" json:"login"`
	Email                  string `sql:"email" json:"default_email"`
	Password               string `sql:"passwordHash"`
	ServerCode             string
	ServerCodeSendedConter int
	UserAgent              string
}

type MsgForUser struct {
	Msg                string
	ShowCaptcha        bool
	ShowForgotPassword bool
	Regs               []string
}

type PasswordResetTokenClaims struct {
	jwt.StandardClaims
	Email string `json:"email"`
}
