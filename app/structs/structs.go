package structs

import "github.com/golang-jwt/jwt"

type User struct {
	UserId      string `sql:"userId"`
	Login       string `sql:"login" json:"login"`
	Email       string `sql:"email" json:"default_email"`
	Password    string `sql:"passwordHash"`
	ServerCode  string
}

type MessagesForUser struct {
	Msg  string
	Regs []string
}

type SignUpPageData struct {
	Msg         string
	ShowCaptcha bool
	Regs        []string
}

type SignInPageData struct {
	Msg                string
	ShowForgotPassword bool
	ShowCaptcha        bool
	Regs               []string
	NoPassword         bool
}

type PasswordResetTokenClaims struct {
	jwt.StandardClaims
	Email string `json:"email"`
}
