package consts

const (
	SelectQuery = "select * from users where email = ? limit 1"
	InsertQuery = "insert into users (email,login,password) values(?,?,?)"

	EmailRegex    = `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$`
	LoginRegex    = `^[a-zA-Zа-яА-ЯёЁ0-9]{3,30}$`
	PasswordRegex = `^(?=.*[a-zA-Zа-яА-ЯёЁ])(?=.*\d)(?=.*[!@#$%^&*])[\w!@#$%^&*]{3,30}$`

	SignUpPageURL       = "/sign_up_page"
	SignUpCodeSendURL   = "/sign_up_code_send"
	SignUpUserAddURL    = "/sign_up_user_add"
	SignInPageURL       = "/sign_in_page"
	SignInURL           = "/sign_in"
	CodeNotArrivedURL   = "/code_not_arrived"
	HomePageURL         = "/home_page"

	LoginWithGoogleURL = "/login_with_google"

	RequestErrorHTML = "requesterror.html"
)
