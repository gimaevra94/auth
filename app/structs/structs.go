package structs

type User struct {
	UserID          string `sql:"userId"`
	Login           string `sql:"login" json:"login"`
	Email           string `sql:"email" json:"default_email"`
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

type ErrMsg struct {
	Msg  string
	Regs []string
}

type SignUpPageData struct {
	Msg         string
	CaptchaShow bool
	Regs        []string
}

type SignInPageData struct {
	Msg                string
	ShowForgotPassword bool
	CaptchaShow        bool
	Regs               []string
	NoPassword         bool
}
