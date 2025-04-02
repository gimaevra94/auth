package constsandstructs

const (
	MailSelectQuery = "select * from users where email = ? limit 1"
	MailInsertQuery = "insert into users (email) values (?)"

	TokenSelectQuery = "select * from users where login = ? limit 1"
	TokenInsertQuery = "insert into users (login,password) values (?,?)"

	EmailRegex    = `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$`
	LoginRegex    = `^[a-zA-Zа-яА-ЯёЁ0-9]{3,30}$`
	PasswordRegex = `^(?=.*[a-zA-Zа-яА-ЯёЁ])(?=.*\d)(?=.*[!@#$%^&*])[\w!@#$%^&*]{3,30}$`

	HomeURL          = "/home"
	SignUpURL        = "/sign_up"
	SignInURL        = "/sign_in"
	DataSendURL      = "/data_send"
	CodeSendURL      = "/code_send"
	UserAddURL       = "/user_add"
	UserCheckURL     = "/user_check"
	RequestErrorHTML = "requesterror.html"
)

type users struct {
	Email    string `json:"email"`
	Login    string `json:"login"`
	Password string `json:"password"`
}

func NewUsers(email, login, password string) Users {
	return &users{
		Email:    email,
		Login:    login,
		Password: password,
	}
}

type Users interface {
	GetEmail() string
	GetLogin() string
	GetPassword() string
}

func (v *users) GetEmail() string {
	return v.Email
}

func (v *users) GetLogin() string {
	return v.Login
}

func (v *users) GetPassword() string {
	return v.Password
}
