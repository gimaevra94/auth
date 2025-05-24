package app

type user struct {
	ID       string `json:"id"`
	Login    string `json:"login"`
	Email    string `json:"email"`
	Password string `json:"password"`
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
