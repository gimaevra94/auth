package consts

const (
	SignUpURL           = "/sign-up"
	SignUpInputCheckURL = "/sign-up-input-check"
	CodeSendURL         = "/code-send"
	UserAddURL          = "/user-add"

	SignInURL           = "/sign-in"
	SignInInputCheckURL = "/sign-in-input-check"

	HomeURL               = "/home"
	LogoutURL             = "/logout"
	SimpleLogoutURL       = "/simple-logout"
	Err500URL             = "/500"
	YandexCallbackURL     = "/ya_callback"
	YandexCallbackFullURL = "http://localhost:8080/ya_callback"

	PasswordResetURL      = "/password-reset"
	PasswordResetEmailURL = "/password-reset-email"
	SetNewPasswordURL     = "/set-new-password"

	TemporaryUserIDExp     = 30 * 24 * 60 * 60
	RefreshTokenExp7Days   = 7 * 24 * 60 * 60
	RefreshTokenExp24Hours = 24 * 60 * 60
)

const (
	UserInsertQuery         = "insert into user (login,email,passwordHash,temporaryUserID,permanentUserID,temporaryCancelled) values(?,?,?,?,?,?)"
	RefreshTokenInsertQuery = "insert into refresh_token (permanentUserID,refreshToken,deviceInfo,tokenCancelled) values (?,?,?,?)"
	YauthInsertQuery        = "insert into user (login,email, temporaryUserID, permanentUserID, temporaryCancelled) values(?,?,?,?,?)"
	ResetTokenInsertQuery   = "insert into reset_token  (token, cancelled) values (?, ?)"

	UserSelectQuery               = "select passwordHash, permanentUserID from user where login = ? limit 1"
	PasswordResetEmailSelectQuery = "select permanentUserID from user where email = ?"
	RefreshTokenSelectQuery       = "select refreshToken,deviceInfo,tokenCancelled from refresh_token where permanentUserID =? and deviceInfo =? limit 1"
	YauthSelectQuery              = "select permanentUserID from user where login = ? limit 1"
	MWUserSelectQuery             = "select login, email, permanentUserID, temporaryCancelled from user where temporaryUserID = ? limit 1"
	ResetTokenSelectQuery         = "select cancelled from reset_token where token = ?"

	TemporaryIDUpdateQuery     = "update user set temporaryUserID = ?, temporaryCancelled = ? where login = ?"
	RefreshtokenUpdateQuery    = "update refresh_token set tokenCancelled =? where refreshToken =? and deviceInfo =?"
	TemporaryUserIDUpdateQuery = "update user set temporaryCancelled =? where temporaryUserID =?"
	PasswordUpdateQuery        = "update user set passwordHash = ? where email = ?"
	ResetTokenUpdateQuery      = "update reset_token  set cancelled = TRUE where token = ?"
)
