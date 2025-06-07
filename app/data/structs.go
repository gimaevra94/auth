package data

import "net/http"

type user struct {
	ID       string `sql:"id" json:"id"`
	Login    string `sql:"login" json:"login"`
	Email    string `sql:"email" json:"email"`
	Password string `sql:"password" json:"password"`
}

func (v *user) GetLogin() string {
	return v.Login
}

func (v *user) GetEmail() string {
	return v.Email
}

func (v *user) GetPassword() string {
	return v.Password
}

type User interface {
	GetLogin() string
	GetEmail() string
	GetPassword() string
}

func NewUser(id, login, email, password string) User {
	return &user{
		ID:       id,
		Login:    login,
		Email:    email,
		Password: password,
	}
}

type cookie struct {
	cookie http.Cookie
}

func (c *cookie) GetValue() string {
	return c.cookie.Value
}
func (c *cookie) SetValue(v string) {
	c.cookie.Value = v
}
func (c *cookie) SetMaxAge(v int) {
	c.cookie.MaxAge = v
}
func (c *cookie) GetCookie() *http.Cookie {
	return &c.cookie
}

type Cookie interface {
	GetValue() string
	GetCookie() *http.Cookie
	SetValue(v string)
	SetMaxAge(v int)
}

func NewCookie() Cookie {
	return &cookie{
		cookie: http.Cookie{
			Name:     "auth",
			Path:     "/set-token",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		},
	}
}
