package structs

type User struct {
	UserId          string `sql:"userId"`
	Login           string `sql:"login" json:"login"`
	Email           string `sql:"email" json:"default_email"`
	Password        string `sql:"passwordHash"`
	ServerCode      string
	TemporaryUserId string `sql:"temporaryUserId"`
	PermanentUserId string `sql:"permanentUserId"`
}

type RevocatePreference struct {
	RefreshToken    string
	DeviceInfo      string
	TemporaryUserId string
}

type ErrMsg struct {
	Msg  string
	Regs []string
}

type SignUpPageData struct {
	Msg         string
	ShowCaptcha bool
	Regs        []string
}

type SignInPageData struct {
	Msg                string
	ShowForgotPassword bool
	ShowCaptcha        bool
	Regs               []string
	NoPassword         bool
}
