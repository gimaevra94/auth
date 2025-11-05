package structs

import "github.com/golang-jwt/jwt"

type User struct {
	UserId          string `sql:"userId"`
	Login           string `sql:"login" json:"login"`
	Email           string `sql:"email" json:"default_email"`
	Password        string `sql:"passwordHash"`
	ServerCode      string
	TemporaryUserId string `sql:"temporaryUserId"`
	PermanentUserId string `sql:"permanentUserId"`
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
	UserEmail string `json:"userEmail"`
}
