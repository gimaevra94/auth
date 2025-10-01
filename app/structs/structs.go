package structs

type User struct {
	UserID          string `sql:"userId"`
	Login           string `sql:"login" json:"login"` //
	Email           string `sql:"email" json:"email"` //
	password        string `sql:"passwordHash"`       // Сделано неэкспортируемым и изменен тег sql
	ServerCode      string // Тег sql удален, так как не используется в БД
	TemporaryUserID string `sql:"temporaryUserID"`
	PermanentUserID string `sql:"permanentUserID"`
}

type RevocatePreference struct {
	RefreshToken    string
	DeviceInfo      string
	TemporaryUserID string
}
