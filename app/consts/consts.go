package consts

const (
	SelectQuery = "select password from users where email = ? limit 1"
	InsertQuery = "insert into users (email,login,password) values(?,?,?)"

	EmailRegex    = `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$`
	LoginRegex    = `^[a-zA-Zа-яА-ЯёЁ0-9]{3,30}$`
	PasswordRegex = `^(?=.*[a-zA-Zа-яА-ЯёЁ])(?=.*\d)(?=.*[!@#$%^&*])[\w!@#$%^&*]{3,30}$`

	SignUpURL          = "/sign_up"
	InputCheckURL      = "/input_check"
	CodeSendURL        = "/code_send"
	UserAddURL         = "/user_add"
	SignInURL          = "/sign_in"
	LoginInURL         = "/log_in"
	SendCodeAgain      = "/send_code_again"
	HomeURL            = "/home"
	LoginWithGoogleURL = "/login_with_google"
	
	RequestErrorHTML   = "requesterror.html"
)
