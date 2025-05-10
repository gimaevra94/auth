package consts

const (
	SelectQuery = "select password from users where email = ? limit 1"
	InsertQuery = "insert into users (email,login,password) values(?,?,?)"
)

const (
	SignUpURL          = "/sign_up"
	InputCheckURL      = "/input_check"
	CodeSendURL        = "/code_send"
	UserAddURL         = "/user_add"
	SignInURL          = "/sign_in"
	LogInURL           = "/log_in"
	SendCodeAgainURL   = "/send_code_again"
	HomeURL            = "/home"
	LogoutURL          = "/log_out"
	LoginWithGoogleURL = "/login_with_google"
	RequestErrorURL    = "/request_error"
	RedirectURL        = "http://localhost:8080/home"
	AuthURL            = "https://oauth.yandex.ru/authorize"
	TokenURL           = "https://oauth.yandex.ru/token"
	UserInfoURL        = "https://login.yandex.ru/info"
	YandexAuthURL      = "/yandex"
	YandexCallbackURL  = "/yandex/callback"
)

const (
	DBPingFailedErr      = "DB.Ping failed"
	MailSendlerFailedErr = "mailSendler failed"

	UserGetFromSessionErr = "'userGetFromSession' failed"
	UserSetFromSessionErr = "'userSetFromSession' failed"

	UserAllreadyExistErr = "'user' allready exist"
	RegexKeyNotMatchErr  = "regex key not matching: "

	InvalidTokenErr            = "token is invalid"
	UserNotExistErr            = "'user' is not exist"
	MscodeNotExistInSessionErr = "'msCode' is not exist in the session"
	AuthCodeNotFoundErr        = "Auth code: 'CodeStr' not found in the auth url: 'authURLWithParamsUrl'"

	CodesNotMatchErr = "the 'userCode' does not match the 'msCode'"

	UserSaveInSessionFailedErr   = "failed to save the 'user' in the session"
	MscodeSaveInSessionFailedErr = "failed to save the msCode in the session"

	DBStartServerFailedErr = "failed to start the server"
	DBStartFailedErr       = "failed to start the database"

	InputValidateFailedErr = "failed to validate the input in 'IsValidInput'  when called from 'inputCheck'"
	UserSerializeFailedErr = "failed to serialize the 'user'"

	UserDeserializeFailedErr  = "failed to deserialize the 'user'"
	ParseFromTokenFailedErr   = "failed to parse from token"
	TokenValidateFailedErr    = "failed to validate the token"
	TokenCreateFailedErr      = "failed to create the token"
	UserAddInDBFailedErr      = "failed to add the 'user' in db"
	PasswordFileReadFailedErr = "failed to read 'db_password.txt'"
	PasswordHashingFailedErr  = "failed to hash the password"
	AccessCodeSendFailedErr   = "failed to send access code fron user email"
	TokenSignFailedErr        = "failed to sign the token"

	DataGetFailedErr    = "failed to get the data from: "
	TokenGetFailedErr   = "failed to get the token"
	CookieGetFailedErr  = "failed to get the cookie"
	KeyGetFailedErr     = "failed to get the key"
	SessionGetFailedErr = "session get failed"
	ClaimsGetFailedErr  = "failed to get the claims"

	EmailGetFromFormFailedErr    = "failed to get 'email' from the FormValue"
	LoginGetFromFormFailedErr    = "failed to get 'login' from the FormValue"
	PasswordGetFromFormFailedErr = "failed to get the 'password' from the FormValue"
	RememberGetInFormFailedErr   = "failed to get the 'remember' from the FormValue"
	YandexTokenGetFailedErr      = "failed to get the token from the 'getAccessToken'"
	UserInfoGetFailedErr         = "failed to get the user info from the 'getUserInfo'"

	GetFailedErr        = "get failed"
	ValidationFailedErr = "validation failed"
	EmptyValueErr       = "empty value"
)

const (
	LoginStr              = "login"
	EmailStr              = "email"
	UserStr               = "user"
	MscodeStr             = "mscode"
	UserCodeStr           = "code"
	SessionNameStr        = "auth"
	RememberStr           = "remember"
	EmptyValueStr         = ""
	CookieNameStr         = "Authorization"
	AuthCookiePath        = "/set-token"
	PasswordStr           = "password"
	DBPasswordPathStr     = "/run/secrets/db_password"
	DBNameDriverStr       = "mysql"
	TokenCommand3HoursStr = "expire_3_hours"
	ExpStr                = "exp"
	AccessCodeStr         = "Access code: "
	MailUserNameStr       = "gimaev.vending@ya.ru"
	SMTPHostStr           = "smtp.yandex.ru"
	SMTPAddrStr           = "smtp.yandex.ru:587"
	OnValueStr            = "on"
	BearerStr             = "Bearer"
	ServerPortStr         = ":8080"
	SlashStr              = "/"
	GrandTypeStr          = "grant_type"
	AuthCodeStr           = "authorization_code"
	CodeStr               = "code"
	ClientIDStr           = "client_id"
	ClientSecret          = "client_secret"
	RedirectUrlStr        = "redirect_uri"
	ClientIDCodeStr       = "0c0c69265b9549b7ae1b994a2aecbcfb"
	ClientSecretCodeStr   = "a72af8c056c647c99d6b0ab470569b0b"
	ResponseTypeStr       = "response_type"
	QuestionMarkStr       = "?"
	TokenStr              = "access_token"
)
