package app

type user struct {
	Email    string `json:"email"`
	Login    string `json:"login"`
	Password string `json:"password"`
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

type User interface {
	GetEmail() string
	GetLogin() string
	GetPassword() string
}

func NewUser(email, login, password string) User {
	return &user{
		Email:    email,
		Login:    login,
		Password: password,
	}
}

type yandexUser struct {
	ID    string `json:"id"`
	Login string `json:"login"`
	Email string `json:"default_email"`
}

func (v *yandexUser) GetID() string {
	return v.ID
}

func (v *yandexUser) GetLogin() string {
	return v.Login
}

func (v *yandexUser) GetEmail() string {
	return v.Email
}

type YandexUser interface {
	GetID() string
	GetLogin() string
	GetEmail() string
}

func NewYandexUser(id, login, email string) YandexUser {
	return &yandexUser{
		ID:    id,
		Login: login,
		Email: email,
	}
}
