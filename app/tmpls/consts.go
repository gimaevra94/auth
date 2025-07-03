package tmpls

type User struct {
	ID       string `sql:"id" json:"id"`
	Login    string `sql:"login" json:"login"`
	Email    string `sql:"email" json:"email"`
	Password string `sql:"password" json:"password"`
}

const (
	CodeSendURL     = "/code_send"
	SignInURL       = "/sign_in"
	HomeURL         = "/home"
	UserAddURL      = "/user_add"
	LogoutURL       = "/logout"
	BadSignInURL    = "/bad_sign_in"
	BadSignUpURL    = "/bad_sign_up"
	BadEmailURL     = "/bad_email"
	UserNotExistURL = "/user_not_exist"
	WrongCodeURL    = "/wrong_code"
	AlreadyExistURL = "/already_exist"
	Err500URL       = "/500"
	InputCheckURL   = "/input_check"

	NotExistErr = "not exist"
	InvalidErr  = "invalid"

	NoExpiration = 253402300799.0
)

var (
	LoginReqs = []string{
		"3-30 characters long",
		"Latin or Cyrillic letters",
		"Numbers 0-9",
	}
	EmailReqs = []string{
		"Must contain Latin letters, numbers and allowed special characters: . _ % + -",
		"Must contain exactly one '@' symbol",
		"Domain must be valid and end with .com, .org, etc.",
	}
	PswrdReqs = []string{
		"8-30 characters long",
		"Latin letters only",
		"Numbers 0-9",
		"Special symbols: !@#$%^&*",
	}

	LoginMsg            = "Login invalid"
	EmailMsg            = "Email invalid"
	PasswrdMsg          = "Password invalid"
	UserAlreadyExistMsg = "User already exist"
	MsCodeMsg           = "Wrong code"
)
