package data

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
