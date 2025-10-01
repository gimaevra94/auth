package structs

type User struct {
	UserID          string `sql:"userId"`
	Login           string `sql:"login" json:"login"`
	Email           string `sql:"email" json:"email"`
	Password        string `sql:"passwordHash"`
	ServerCode      string
	TemporaryUserID string `sql:"temporaryUserID"`
	PermanentUserID string `sql:"permanentUserID"`
}

type RevocatePreference struct {
	RefreshToken    string
	DeviceInfo      string
	TemporaryUserID string
}
