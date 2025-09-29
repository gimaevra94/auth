package consts

const (
	SignUpURL           = "/sign-up"
	SignUpInputCheckURL = "/sign-up-input-check"
	CodeSendURL         = "/code-send"
	UserAddURL          = "/user-add"

	SignInURL           = "/sign-in"
	SignInInputCheckURL = "/sign-in-input-check"

	HomeURL   = "/home"
	LogoutURL = "/logout"
	Err500URL = "/500"

	TemporaryUserIDExp     = 30 * 24 * 60 * 60
	RefreshTokenExp7Days   = 7 * 24 * 60 * 60
	RefreshTokenExp24Hours = 24 * 60 * 60
)
