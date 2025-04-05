package users

type users struct {
	Email    string `json:"email"`
	Login    string `json:"login"`
	Password string `json:"password"`
}

func NewUsers(email, login, password string) Users {
	return &users{
		Email:    email,
		Login:    login,
		Password: password,
	}
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
