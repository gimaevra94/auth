package structs

type user struct {
	Email    string `json:"email"`
	Login    string `json:"login"`
	Password string `json:"password"`
}

type User interface {
	GetEmail() string
	GetLogin() string
	GetPassword() string
}

func (v *user) GetEmail() string {
	return v.Email
}

func (v *user) GetLogin() string {
	return v.Login
}

func (v *user) GetPassword() string {
	return v.Password
}

func NewUser(email, login, password string) User {
	return &user{
		Email:    email,
		Login:    login,
		Password: password,
	}
}
