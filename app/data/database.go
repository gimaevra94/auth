package data

import (
	"database/sql"
	"os"

	"github.com/go-sql-driver/mysql"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"

	"github.com/gimaevra94/auth/app/consts"
)

var DB *sql.DB

// GetAllUserAgentsForUser возвращает список уникальных User-Agent'ов,
// связанных с активными refresh-токенами для данного пользователя.
func GetAllUserAgentsForUser(permanentUserID string) ([]string, error) {
	// Запрос выбирает уникальные deviceInfo (User-Agent) для активных токенов пользователя
	query := `SELECT DISTINCT deviceInfo FROM refresh_token WHERE permanentUserID = ? AND tokenCancelled = FALSE;`
	rows, err := DB.Query(query, permanentUserID)
	if err != nil {
		// Оберните ошибку для лучшей отладки, если используете pkg/errors
		return nil, err // или errors.WithStack(err)
	}
	defer rows.Close()

	var userAgents []string
	for rows.Next() {
		var ua string
		if err := rows.Scan(&ua); err != nil {
			// Оберните ошибку
			return nil, err // или errors.WithStack(err)
		}
		userAgents = append(userAgents, ua)
	}

	// Проверьте, были ли ошибки при итерации rows
	if err = rows.Err(); err != nil {
		return nil, err // или errors.WithStack(err)
	}

	return userAgents, nil
}

func DBConn() error {
	dbPassword := []byte(os.Getenv("DB_PASSWORD"))

	cfg := mysql.Config{
		User:   "root",
		Passwd: string(dbPassword),
		Net:    "tcp",
		Addr:   "localhost:3306",
		DBName: "db",
	}

	var err error
	DB, err = sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return errors.WithStack(err)
	}

	err = DB.Ping()
	if err != nil {
		DB.Close()
		return errors.WithStack(err)
	}

	return nil
}

func DBClose() {
	if DB != nil {
		DB.Close()
	}
}

func SignUpUserCheck(login, password string) error {
	row := DB.QueryRow(consts.SignUpUserSelectQuery, login)
	var DbLogin string
	var DbEmail string

	err := row.Scan(&DbLogin, &DbEmail)
	if err != nil {
		if err == sql.ErrNoRows {
			return errors.WithStack(err)
		}
		return errors.WithStack(err)
	}

	if DbLogin != "" || DbEmail != "" {
		err = errors.New("user already exist")
		return errors.WithStack(err)
	}

	return nil
}

func PasswordResetEmailCheck(email string) error {
	row := DB.QueryRow(consts.PasswordResetEmailSelectQuery, email)
	var permanentUserID string
	err := row.Scan(&permanentUserID)
	if err != nil {
		if err == sql.ErrNoRows {
			return errors.WithStack(err)
		}
		return errors.WithStack(err)
	}
	return nil
}

func RefreshTokenCheck(permanentUserID, userAgent string) (string, string, bool, error) {
	row := DB.QueryRow(consts.RefreshTokenSelectQuery, permanentUserID, userAgent)
	var refreshToken string
	var deviceInfo string
	var tokenCancelled bool

	err := row.Scan(&refreshToken, &deviceInfo, &tokenCancelled)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", "", false, errors.WithStack(err)
		}
		return "", "", false, errors.WithStack(err)
	}
	return refreshToken, deviceInfo, tokenCancelled, nil
}

func YauthUserCheck(login string) (string, error) {
	row := DB.QueryRow(consts.YauthSelectQuery, login)
	var permanentUserID string
	err := row.Scan(&permanentUserID)

	if err != nil {
		if err == sql.ErrNoRows {
			return "", errors.WithStack(err)
		}
		return "", errors.WithStack(err)
	}

	return permanentUserID, nil
}

func MWUserCheck(key string) (string, string, string, bool, error) {
	row := DB.QueryRow(consts.MWUserSelectQuery, key)
	var login string
	var email string
	var permanentUserID string
	var temporaryUserID bool
	err := row.Scan(&login, &email, &permanentUserID, &temporaryUserID)
	if err != nil {
		return "", "", "", false, errors.WithStack(err)
	}
	return login, email, permanentUserID, temporaryUserID, nil
}

func ResetTokenCheck(signedToken string) (bool, error) {
	row := DB.QueryRow(consts.ResetTokenSelectQuery, signedToken)
	var cancelled bool
	err := row.Scan(&cancelled)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, errors.New("reset token not found or invalid")
		}
		return false, errors.WithStack(err)
	}
	return cancelled, nil
}

func UserAddTx(tx *sql.Tx, login, email, password, temporaryUserID, permanentUserID string, temporaryCancelled bool) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password),
		bcrypt.DefaultCost)
	if err != nil {
		return errors.WithStack(err)
	}

	_, err = tx.Exec(consts.UserInsertQuery, login, email, hashedPassword, temporaryUserID, permanentUserID, temporaryCancelled)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func TemporaryUserIDAddTx(tx *sql.Tx, login, temporaryUserID string, temporaryCancelled bool) error {
	_, err := tx.Exec(consts.TemporaryIDUpdateQuery, temporaryUserID, temporaryCancelled, login)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func TemporaryUserIDAddByEmailTx(tx *sql.Tx, email, temporaryUserID string, temporaryCancelled bool) error {
	_, err := tx.Exec(consts.TemporaryIDUpdateByEmailQuery, temporaryUserID, temporaryCancelled, email)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func RefreshTokenAddTx(tx *sql.Tx, permanentUserID, refreshToken, deviceInfo string, tokenCancelled bool) error {
	_, err := tx.Exec(consts.RefreshTokenInsertQuery, permanentUserID, refreshToken, deviceInfo, tokenCancelled)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func YauthUserAddTx(tx *sql.Tx, login, email, temporaryUserID, permanentUserID string, temporaryCancelled bool) error {
	_, err := tx.Exec(consts.YauthInsertQuery, login, email, temporaryUserID, permanentUserID, temporaryCancelled)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func ResetTokenAddTx(tx *sql.Tx, resetToken string) error {
	_, err := tx.Exec(consts.ResetTokenInsertQuery, resetToken, false)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func TokenCancelTx(tx *sql.Tx, refreshToken, deviceInfo string) error {
	_, err := tx.Exec(consts.RefreshtokenUpdateQuery, true, refreshToken, deviceInfo)
	if err != nil {
		return errors.WithStack(err)
	}
	return err
}

func TemporaryUserIDCancelTx(tx *sql.Tx, temporaryUserID string) error {
	_, err := tx.Exec(consts.TemporaryUserIDUpdateQuery, true, temporaryUserID)
	if err != nil {
		return errors.WithStack(err)
	}
	return err
}

func ResetTokenCancelTx(tx *sql.Tx, tokenString string) error {
	_, err := tx.Exec(consts.ResetTokenUpdateQuery, tokenString)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func UpdatePasswordTx(tx *sql.Tx, email, newPassword string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword),
		bcrypt.DefaultCost)
	if err != nil {
		return errors.WithStack(err)
	}

	_, err = tx.Exec(consts.PasswordUpdateQuery, hashedPassword, email)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func UpdatePasswordByPermanentIDTx(tx *sql.Tx, permanentUserID, newPassword string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return errors.WithStack(err)
	}

	_, err = tx.Exec(consts.PasswordUpdateByPermanentIDQuery, hashedPassword, permanentUserID)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}
