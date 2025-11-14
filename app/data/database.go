package data

import (
	"database/sql"
	"os"

	"github.com/go-sql-driver/mysql"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

const (
	permanentIdSelectQuery                        = "select permanentId from user where email = ?"
	allUserKeysSelectQuery                        = "select login, email, permanentId, temporaryIdCancelled from user where temporaryId = ? limit 1"
	passwordHashAndPermanentIdSelectQuery         = "select passwordHash, permanentId from user where login = ? limit 1"
	passwordHashSelectQuery                       = "select passwordHash from user where temporaryId = ? limit 1"
	permanentIdAndTemporaryIdCancelledSelectQuery = "select permanentId, temporaryIdCancelled from user where temporaryId = ? limit 1"
	uniqueUserAgentsSelectQuery                   = "select distinct userAgent FROM refresh_token WHERE permanentId = ?"
	allRefreshTokenKeysSelectQuery                = "select refreshToken, userAgent, refreshTokenCancelled from refresh_token where permanentId = ? and userAgent = ? AND refreshTokenCancelled = FALSE limit 1"
	resetTokenCancelledSelectQuery                = "select cancelled from reset_token where token = ?"

	userInsertQuery               = "insert into user (login, email, passwordHash, temporaryId, permanentId, temporaryIdCancelled) values (?, ?, ?, ?, ?, ?)"
	yauthUserInsertQuery          = "insert into user (login, email, temporaryId, permanentId, temporaryIdCancelled) values (?, ?, ?, ?, ?)"
	refreshTokenInsertQuery       = "insert into refresh_token (permanentId, refreshToken, userAgent, refreshTokenCancelled) values (?, ?, ?, ?)"
	passwordResetTokenInsertQuery = "insert into reset_token (token, cancelled) values (?, ?)"

	passwordInDbByEmailUpdateQuery         = "update user set passwordHash = ? where email = ?"
	passwordInDbByPermanentIdUpdateQuery   = "update user set passwordHash = ? where temporaryId = ?"
	temporaryIdInDbByLoginUpdateQuery      = "update user set temporaryId = ?, temporaryIdCancelled = ? where login = ?"
	temporaryIdInDbByEmailUpdateQuery      = "update user set temporaryId = ?, temporaryIdCancelled = ? where email = ?"
	refreshTokenCancelledUpdateQuery       = "update refresh_token set refreshTokenCancelled = ? where refreshToken = ? and userAgent = ?"
	temporaryIdCancelledUpdateQuery        = "update user set temporaryIdCancelled = ? where temporaryId = ?"
	passwordResetTokenCancelledUpdateQuery = "update reset_token set cancelled = TRUE where token = ?"
)

var Db *sql.DB

func DbConn() error {
	DbPassword := []byte(os.Getenv("DB_PASSWORD"))
	cfg := mysql.Config{
		User:   "root",
		Passwd: string(DbPassword),
		Net:    "tcp",
		Addr:   "localhost:3306",
		DBName: "db",
	}
	var err error

	Db, err = sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return errors.WithStack(err)
	}
	if err = Db.Ping(); err != nil {
		Db.Close()
		return errors.WithStack(err)
	}
	return nil
}

func DbClose() {
	if Db != nil {
		Db.Close()
	}
}

func GetPermanentIdFromDb(Email string) (string, error) {
	var permanentId string
	row := Db.QueryRow(permanentIdSelectQuery, Email)
	err := row.Scan(&permanentId)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", errors.WithStack(err)
		}
		return "", errors.WithStack(err)
	}
	return permanentId, nil
}

func GetPasswordFromDb(temporaryId string) (string, error) {
	var passwordHash sql.NullString
	row := Db.QueryRow(passwordInDbByPermanentIdUpdateQuery, temporaryId)
	err := row.Scan(&passwordHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", errors.WithStack(err)
		}
		return "", errors.WithStack(err)
	}
	return passwordHash.String, nil
}

func GetAllUserKeysFromDb(temporaryId string) (string, string, string, bool, error) {
	var login string
	var email string
	var permanentId string
	var temporaryIdCancelled bool
	row := Db.QueryRow(allUserKeysSelectQuery, temporaryId)
	err := row.Scan(&login, &email, &permanentId, &temporaryIdCancelled)
	if err != nil {
		return "", "", "", false, errors.WithStack(err)
	}
	return login, email, permanentId, temporaryIdCancelled, nil
}

func GetPasswordHashFromDb(temporaryId string) (sql.NullString, error) {
	var passwordHash sql.NullString
	row := Db.QueryRow(passwordHashSelectQuery, temporaryId)
	err := row.Scan(&passwordHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return sql.NullString{}, errors.WithStack(err)
		}
		return sql.NullString{}, errors.WithStack(err)
	}
	return passwordHash, nil
}

func GetPasswordHashAndPermanentIdFromDb(login, password string) (sql.NullString, string, error) {
	var passwordHash sql.NullString
	var permanentId string
	row := Db.QueryRow(passwordHashAndPermanentIdSelectQuery, login)
	err := row.Scan(&passwordHash, &permanentId)
	if err != nil {
		if err == sql.ErrNoRows {
			return sql.NullString{}, "", errors.WithStack(err)
		}
		return sql.NullString{}, "", errors.WithStack(err)
	}
	return passwordHash, permanentId, nil
}

func GetpermanentIdAndTemporaryIdCancelledFromDb(temporaryId string) (string, bool, error) {
	var permanentId string
	var temporaryIdCancelled bool
	row := Db.QueryRow(permanentIdAndTemporaryIdCancelledSelectQuery, temporaryId)
	err := row.Scan(&permanentId, &temporaryIdCancelled)
	if err != nil {
		return "", false, errors.WithStack(err)
	}
	return permanentId, temporaryIdCancelled, nil
}

func GetUniqueUserAgentsFromDb(permanentId string) ([]string, error) {
	rows, err := Db.Query(uniqueUserAgentsSelectQuery, permanentId)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer rows.Close()

	var userAgents []string
	for rows.Next() {
		var userAgent string
		if err := rows.Scan(&userAgent); err != nil {
			return nil, errors.WithStack(err)
		}
		userAgents = append(userAgents, userAgent)
	}

	if err = rows.Err(); err != nil {
		return nil, errors.WithStack(err)
	}

	return userAgents, nil
}

func GetAllRefreshTokenKeysFromDb(permanentId, userAgent string) (string, string, bool, error) {
	var refreshToken string
	var dbUserAgent string
	var refreshTokenCancelled bool
	row := Db.QueryRow(allRefreshTokenKeysSelectQuery, permanentId, userAgent)
	err := row.Scan(&refreshToken, &dbUserAgent, &refreshTokenCancelled)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", "", false, errors.WithStack(err)
		}
		return "", "", false, errors.WithStack(err)
	}
	return refreshToken, dbUserAgent, refreshTokenCancelled, nil
}

func GetResetTokenCancelledFromDb(signedToken string) (bool, error) {
	var cancelled bool
	row := Db.QueryRow(resetTokenCancelledSelectQuery, signedToken)
	err := row.Scan(&cancelled)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, errors.New("reset token not found or invalid")
		}
		return false, errors.WithStack(err)
	}
	return cancelled, nil
}

func SetUserInDbTx(tx *sql.Tx, login, email, permanentId, temporaryId string, hashedPassword []byte, temporaryIdCancelled bool) error {
	_, err := tx.Exec(userInsertQuery, login, email, hashedPassword, temporaryId, permanentId, temporaryIdCancelled)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func SetYauthUserInDbTx(tx *sql.Tx, login, email, temporaryId, permanentId string, temporaryIdCancelled bool) error {
	_, err := tx.Exec(yauthUserInsertQuery, login, email, temporaryId, permanentId, temporaryIdCancelled)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func SetPasswordInDbByEmailTx(tx *sql.Tx, email, newPassword string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword),
		bcrypt.DefaultCost)
	if err != nil {
		return errors.WithStack(err)
	}
	_, err = tx.Exec(passwordInDbByEmailUpdateQuery, hashedPassword, email)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func SetPasswordInDbByTemporaryId(temporaryId string, hashedPassword []byte) error {
	_, err := Db.Exec(passwordInDbByPermanentIdUpdateQuery, hashedPassword, temporaryId)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func SetTemporaryIdInDbByLoginTx(tx *sql.Tx, login, temporaryId string, temporaryIdCancelled bool) error {
	_, err := tx.Exec(temporaryIdInDbByLoginUpdateQuery, temporaryId, temporaryIdCancelled, login)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func SetTemporaryIdInDbByEmailTx(tx *sql.Tx, email, temporaryId string, temporaryIdCancelled bool) error {
	_, err := tx.Exec(temporaryIdInDbByEmailUpdateQuery, temporaryId, temporaryIdCancelled, email)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func SetRefreshTokenInDbTx(tx *sql.Tx, permanentId, refreshToken, userAgent string, refreshTokenCancelled bool) error {
	_, err := tx.Exec(refreshTokenInsertQuery, permanentId, refreshToken, userAgent, refreshTokenCancelled)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func SetPasswordResetTokenInDbTx(tx *sql.Tx, resetToken string) error {
	_, err := tx.Exec(passwordResetTokenInsertQuery, resetToken, false)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func SetRefreshTokenCancelledInDbTx(tx *sql.Tx, refreshToken, userAgent string) error {
	_, err := tx.Exec(refreshTokenCancelledUpdateQuery, true, refreshToken, userAgent)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func SetTemporaryIdCancelledInDbTx(tx *sql.Tx, temporaryId string) error {
	_, err := tx.Exec(temporaryIdCancelledUpdateQuery, true, temporaryId)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func SetPasswordResetTokenCancelledInDbTx(tx *sql.Tx, resetToken string) error {
	_, err := tx.Exec(passwordResetTokenCancelledUpdateQuery, resetToken)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}
