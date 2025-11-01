package consts

const (
	SignUpURL              = "/sign-up"
	ValIdateSignUpInputURL = "/valIdate-sign-up-input"
	CodeSendURL            = "/code-send"
	SetUserInDbURL         = "/set-user-in-db"

	SignInURL              = "/sign-in"
	ValIdateSignInInputURL = "/valIdate-sign-in-input"

	YandexCallbackURL     = "/ya_callback"
	YandexCallbackFullURL = "http://localhost:8080/ya_callback"

	PasswordResetURL      = "/password-reset"
	PasswordResetEmailURL = "/password-reset-email"
	SetNewPasswordURL     = "/set-new-password"
	SetPasswordURL        = "/set-password"
	SubmitPasswordURL     = "/submit-password"

	HomeURL         = "/home"
	LogoutURL       = "/logout"
	SimpleLogoutURL = "/simple-logout"
	Err500URL       = "/500"
)

const (
	TemporaryUserIdExp     = 30 * 24 * 60 * 60
	RefreshTokenExp7Days   = 7 * 24 * 60 * 60
	RefreshTokenExp24Hours = 24 * 60 * 60
)

const (
	UserAgents                    = "select distinct device_info FROM refresh_tokens WHERE permanentUserId = $1 AND refreshTokenCancelled = false;"
	UserAgentSelectQuery          = "select distinct deviceInfo FROM refresh_token WHERE permanentUserId = ?"
	SignUpUserSelectQuery         = "select email from user where login = ? limit 1"
	SignInUserSelectQuery         = "select passwordHash, permanentUserId from user where login = ? limit 1"
	PasswordResetEmailSelectQuery = "select permanentUserId from user where email = ?"
	RefreshTokenSelectQuery       = "select refreshToken,deviceInfo,refreshTokenCancelled from refresh_token where permanentUserId =? and deviceInfo =? AND refreshTokenCancelled = FALSE limit 1"
	YauthSelectQuery              = "select permanentUserId from user where login = ? limit 1"
	MWUserSelectQuery             = "select login, email, permanentUserId, temporaryUserIdCancelled from user where temporaryUserId = ? limit 1"
	ResetTokenSelectQuery         = "select cancelled from reset_token where token = ?"

	UserInsertQuery         = "insert into user (login,email,passwordHash,temporaryUserId,permanentUserId,temporaryUserIdCancelled) values(?,?,?,?,?,?)"
	RefreshTokenInsertQuery = "insert into refresh_token (permanentUserId,refreshToken,deviceInfo,refreshTokenCancelled) values (?,?,?,?)"
	YauthInsertQuery        = "insert into user (login,email, temporaryUserId, permanentUserId, temporaryUserIdCancelled) values(?,?,?,?,?)"
	ResetTokenInsertQuery   = "insert into reset_token  (token, cancelled) values (?, ?)"
	PasswordSetQuery        = `select login, email, permanentUserId from user where temporaryUserId = ? AND passwordHash IS NULL`

	TemporaryIdUpdateQuery           = "update user set temporaryUserId = ?, temporaryUserIdCancelled = ? where login = ?"
	TemporaryIdUpdateByEmailQuery    = "update user set temporaryUserId = ?, temporaryUserIdCancelled = ? where email = ?"
	RefreshtokenUpdateQuery          = "update refresh_token set refreshTokenCancelled =? where refreshToken =? and deviceInfo =?"
	TemporaryUserIdUpdateQuery       = "update user set temporaryUserIdCancelled =? where temporaryUserId =?"
	PasswordUpdateQuery              = "update user set passwordHash = ? where email = ?"
	ResetTokenUpdateQuery            = "update reset_token  set cancelled = TRUE where token = ?"
	PasswordUpdateByPermanentIdQuery = "update user set passwordHash = ? where permanentUserId = ?"
)
