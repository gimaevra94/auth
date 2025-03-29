package consts

const (
	MailSelectQuery = "select * from users where email = ? limit 1"
	MailInsertQuery = "insert into users (email) values (?)"

	TokenSelectQuery = "select * from users where login = ? limit 1"
	TokenInsertQuery = "insert into users (login,password) values (?,?)"

	EmailRegex    = `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$`
	LoginRegex    = `^[a-zA-Zа-яА-ЯёЁ0-9]{3,30}$`
	PasswordRegex = `^(?=.*[a-zA-Zа-яА-ЯёЁ])(?=.*\d)(?=.*[!@#$%^&*])[\w!@#$%^&*]{3,30}$`

	SignUpURL   = "/sign_up"
	SignInURL   = "/sign_in"
	DataSendURL = "/data_send"
	CodeSendURL = "/code_send"
	HomeURL     = "/home"

	RequestErrorHTML = "requesterror.html"
)
