package structs

type User struct {
	Login      string `sql:"login" json:"login"` //
	Email      string `sql:"email" json:"email"` //
	Password   string `sql:"password"`           //
	ServerCode string `sql:"serverCode"`         //
}

type UserPreferences struct {
	TemporaryUserID string
	RememberMe      bool
}
