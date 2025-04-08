package consts

const (
	SelectQuery = "select password from users where email = ? limit 1"
	InsertQuery = "insert into users (email,login,password) values(?,?,?)"

	EmailRegex    = `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$`
	LoginRegex    = `^[a-zA-Zа-яА-ЯёЁ0-9]{3,30}$`
	PasswordRegex = `^(?=.*[a-zA-Zа-яА-ЯёЁ])(?=.*\d)(?=.*[!@#$%^&*])[\w!@#$%^&*]{3,30}$`

	SignUpLoginInputURL = "/sign_up_login_input"
	InputCheckURL       = "/input_check"
	CodeSendURL         = "/code_send"
	UserAddURL          = "/user_add"

	SignInLoginInputURL       = "/sign_in_login_input"
	LoginInputCheckUserAddURL = "/input_check_user_add"

	SendCodeAgain      = "/send_code_again"
	HomeURL            = "/home"
	LoginWithGoogleURL = "/login_with_google"

	RequestErrorHTML = "requesterror.html"
)
