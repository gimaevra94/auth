package data

import (
	"database/sql"
	"os"

	"github.com/go-sql-driver/mysql"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

const (
	PermanentUserIdSelectQuery                                = "select permanentUserId from user where email = ?"
	UserPasswordSelectQuery                                   = "select passwordHash from user where temporaryUserId = ?"
	AllUsersKeysSelectQuery                                   = "select login, email, permanentUserId, temporaryUserIdCancelled from user where temporaryUserId = ? limit 1"
	PasswordHashAndPermanentUserIdSelectQuery                 = "select passwordHash, permanentUserId from user where login = ? limit 1"
	PermanentUserIdAndTemporaryUserIdCancelledFlagSelectQuery = "select permanentUserId, temporaryUserIdCancelled from user where temporaryUserId = ? limit 1"
	UniqueUserAgentsSelectQuery                               = "select distinct userAgent FROM refresh_token WHERE permanentUserId = ?"
	AllRefreshTokenKeysSelectQuery                            = "select refreshToken, userAgent, refreshTokenCancelled from refresh_token where permanentUserId = ? and userAgent = ? AND refreshTokenCancelled = FALSE limit 1"
	ResetTokenCancelledFlagSelectQuery                        = "select cancelled from reset_token where token = ?"

	UserInsertQuery                            = "insert into user (login, email, passwordHash, temporaryUserId, permanentUserId, temporaryUserIdCancelled) values (?, ?, ?, ?, ?, ?)"
	YauthUserInsertQuery                       = "insert into user (login, email, temporaryUserId, permanentUserId, temporaryUserIdCancelled) values (?, ?, ?, ?, ?)"
	UserRefreshTokenInsertQuery                = "insert into refresh_token (permanentUserId, refreshToken, userAgent, refreshTokenCancelled) values (?, ?, ?, ?)"
	PasswordResetTokenInsertQuery              = "insert into reset_token (token, cancelled) values (?, ?)"

	UserPasswordInDbByEmailUpdateQuery         = "update user set passwordHash = ? where email = ?"
	UserPasswordInDbByPermanentIdUpdateQuery   = "update user set passwordHash = ? where temporaryUserId = ?"
	TemporaryUserIdInDbByLoginUpdateQuery      = "update user set temporaryUserId = ?, temporaryUserIdCancelled = ? where login = ?"
	TemporaryUserIdInDbByEmailUpdateQuery      = "update user set temporaryUserId = ?, temporaryUserIdCancelled = ? where email = ?"
	RefreshTokenCancelledFlagUpdateQuery       = "update refresh_token set refreshTokenCancelled = ? where refreshToken = ? and userAgent = ?"
	TemporaryUserIdCancelledFlagUpdateQuery    = "update user set temporaryUserIdCancelled = ? where temporaryUserId = ?"
	PasswordResetTokenCancelledFlagUpdateQuery = "update reset_token set cancelled = TRUE where token = ?"
)

var Db *sql.DB

func DbConn() error {
	DbPassword := []byte(os.Getenv("Db_PASSWORD"))
	cfg := mysql.Config{
		User:   "root",
		Passwd: string(DbPassword),
		Net:    "tcp",
		Addr:   "localhost:3306",
		DBName: "Db",
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

func GetPermanentUserIdFromDb(userEmail string) (string, error) {
	var permanentUserId string
	row := Db.QueryRow(PermanentUserIdSelectQuery, userEmail)
	err := row.Scan(&permanentUserId)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", errors.WithStack(err)
		}
		return "", errors.WithStack(err)
	}
	return permanentUserId, nil
}

func GetUserPasswordFromDb(temporaryUserId string) (string, error) {
	var passwordHash sql.NullString
	row := Db.QueryRow(UserPasswordSelectQuery, temporaryUserId)
	err := row.Scan(&passwordHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", errors.WithStack(err)
		}
		return "", errors.WithStack(err)
	}
	return passwordHash.String, nil
}

func GetAllUsersKeysFromDb(temporaryUserId string) (string, string, string, bool, error) {
	var login string
	var email string
	var permanentUserId string
	var temporaryUserIdCancelled bool
	row := Db.QueryRow(AllUsersKeysSelectQuery, temporaryUserId)
	err := row.Scan(&login, &email, &permanentUserId, &temporaryUserIdCancelled)
	if err != nil {
		return "", "", "", false, errors.WithStack(err)
	}
	return login, email, permanentUserId, temporaryUserIdCancelled, nil
}

func GetPasswordHashAndPermanentUserIdFromDb(userLogin, userPassword string) (sql.NullString, string, error) {
	var passwordHash sql.NullString
	var permanentUserId string
	row := Db.QueryRow(PasswordHashAndPermanentUserIdSelectQuery, userLogin)
	err := row.Scan(&passwordHash, &permanentUserId)
	if err != nil {
		if err == sql.ErrNoRows {
			return sql.NullString{}, "", errors.WithStack(err)
		}
		return sql.NullString{}, "", errors.WithStack(err)
	}
	return passwordHash, permanentUserId, nil
}

func GetPermanentUserIdAndTemporaryUserIdCancelledFlagFromDb(temporaryUserId string) (string, bool, error) {
	var permanentUserId string
	var temporaryUserIdCancelled bool
	row := Db.QueryRow(PermanentUserIdAndTemporaryUserIdCancelledFlagSelectQuery, temporaryUserId)
	err := row.Scan(&permanentUserId, &temporaryUserIdCancelled)
	if err != nil {
		return "", false, errors.WithStack(err)
	}
	return permanentUserId, temporaryUserIdCancelled, nil
}

func GetUniqueUserAgentsFromDb(permanentUserId string) ([]string, error) {
	rows, err := Db.Query(UniqueUserAgentsSelectQuery, permanentUserId)
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

func GetAllRefreshTokenKeysFromDb(permanentUserId, userAgent string) (string, string, bool, error) {
	var refreshToken string
	var dbUserAgent string
	var refreshTokenCancelled bool
	row := Db.QueryRow(AllRefreshTokenKeysSelectQuery, permanentUserId, userAgent)
	err := row.Scan(&refreshToken, &dbUserAgent, &refreshTokenCancelled)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", "", false, errors.WithStack(err)
		}
		return "", "", false, errors.WithStack(err)
	}
	return refreshToken, dbUserAgent, refreshTokenCancelled, nil
}

func GetResetTokenCancelledFlagFromDb(signedToken string) (bool, error) {
	var cancelled bool
	row := Db.QueryRow(ResetTokenCancelledFlagSelectQuery, signedToken)
	err := row.Scan(&cancelled)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, errors.New("reset token not found or invalId")
		}
		return false, errors.WithStack(err)
	}
	return cancelled, nil
}

func SetUserInDbTx(tx *sql.Tx, login, email, temporaryUserId, permanentUserId string, hashedPassword []byte, temporaryUserIdCancelled bool) error {
	_, err := tx.Exec(UserInsertQuery, login, email, hashedPassword, temporaryUserId, permanentUserId, temporaryUserIdCancelled)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func SetYauthUserInDbTx(tx *sql.Tx, login, email, temporaryUserId, permanentUserId string, temporaryUserIdCancelled bool) error {
	_, err := tx.Exec(YauthUserInsertQuery, login, email, temporaryUserId, permanentUserId, temporaryUserIdCancelled)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func SetUserPasswordInDbByEmailTx(tx *sql.Tx, userEmail, newPassword string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword),
		bcrypt.DefaultCost)
	if err != nil {
		return errors.WithStack(err)
	}
	_, err = tx.Exec(UserPasswordInDbByEmailUpdateQuery, hashedPassword, userEmail)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func SetUserPasswordInDbByTemporaryUserId(temporaryUserId string, hashedPassword []byte) error {
	_, err := Db.Exec(UserPasswordInDbByPermanentIdUpdateQuery, hashedPassword, temporaryUserId)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func SetTemporaryUserIdInDbByLoginTx(tx *sql.Tx, login, temporaryUserId string, temporaryUserIdCancelled bool) error {
	_, err := tx.Exec(TemporaryUserIdInDbByLoginUpdateQuery, temporaryUserId, temporaryUserIdCancelled, login)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func SetTemporaryUserIdInDbByEmailTx(tx *sql.Tx, email, temporaryUserId string, temporaryUserIdCancelled bool) error {
	_, err := tx.Exec(TemporaryUserIdInDbByEmailUpdateQuery, temporaryUserId, temporaryUserIdCancelled, email)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func SetUserRefreshTokenInDbTx(tx *sql.Tx, permanentUserId, refreshToken, userAgent string, refreshTokenCancelled bool) error {
	_, err := tx.Exec(UserRefreshTokenInsertQuery, permanentUserId, refreshToken, userAgent, refreshTokenCancelled)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func SetPasswordResetTokenInDbTx(tx *sql.Tx, resetToken string) error {
	_, err := tx.Exec(PasswordResetTokenInsertQuery, resetToken, false)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func SetRefreshTokenCancelledFlagFromDbTx(tx *sql.Tx, userRefreshToken, userAgent string) error {
	_, err := tx.Exec(RefreshTokenCancelledFlagUpdateQuery, true, userRefreshToken, userAgent)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func SetTemporaryUserIdCancelledFlagFromDbTx(tx *sql.Tx, temporaryUserId string) error {
	_, err := tx.Exec(TemporaryUserIdCancelledFlagUpdateQuery, true, temporaryUserId)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func SetPasswordResetTokenCancelledFlagFromDbTx(tx *sql.Tx, resetToken string) error {
	_, err := tx.Exec(PasswordResetTokenCancelledFlagUpdateQuery, resetToken)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}
