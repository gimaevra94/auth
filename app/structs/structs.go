package structs

import "time"

type users struct {
	Email    string `json:"email"`
	Login    string `json:"login"`
	Password string `json:"password"`
}

type Users interface {
	GetEmail() string
	GetLogin() string
	GetPassword() string
}

func (v *users) GetEmail() string {
	return v.Email
}

func (v *users) GetLogin() string {
	return v.Login
}

func (v *users) GetPassword() string {
	return v.Password
}

func NewUsers(email, login, password string) Users {
	return &users{
		Email:    email,
		Login:    login,
		Password: password,
	}
}

type lastActivity struct {
	TokenExp    time.Time
	ActivityExp time.Time
}

type LastActivity interface {
	GetTokenExp() time.Time
	GetActivityExp() time.Time
	SetTokenExp(new_v time.Time)
	SetActivityExp(new_v time.Time)
}

func (v *lastActivity) GetTokenExp() time.Time {
	return v.TokenExp
}

func (v *lastActivity) GetActivityExp() time.Time {
	return v.ActivityExp
}

func (v *lastActivity) SetTokenExp(new_v time.Time) {
	v.TokenExp = new_v
}

func (v *lastActivity) SetActivityExp(new_v time.Time) {
	v.ActivityExp = new_v
}

func NewLastActivity(tokenExp time.Time) LastActivity {
	return &lastActivity{
		TokenExp:    tokenExp,
		ActivityExp: time.Now(),
	}
}
