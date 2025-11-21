package data

import (
	"database/sql"
	"os"

	"github.com/go-sql-driver/mysql"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

const (
	allUserKeysSelectQuery                        = "select login, email, permanentId, temporaryIdCancelled from user where temporaryId = ? limit 1"
	passwordHashAndPermanentIdSelectQuery         = "select passwordHash, permanentId from user where login = ? limit 1"
	passwordHashSelectQuery                       = "select passwordHash from user where temporaryId = ? limit 1"
	permanentIdAndTemporaryIdCancelledSelectQuery = "select permanentId, temporaryIdCancelled from user where temporaryId = ? limit 1"
	uniqueUserAgentsSelectQuery                   = "select distinct userAgent FROM refresh_token WHERE permanentId = ?"
	allRefreshTokenKeysSelectQuery                = "select refreshToken, userAgent, refreshTokenCancelled from refresh_token where permanentId = ? AND userAgent = ? AND refreshTokenCancelled = FALSE limit 1"
	resetTokenCancelledSelectQuery                = "select resetTokenCancelled from reset_token where resetToken = ?"

	userInsertQuery               = "insert into user (login, email, passwordHash, permanentId) values (?, ?, ?, ?)"
	yauthUserInsertQuery          = "insert into user (login, email, temporaryId, permanentId, temporaryIdCancelled) values (?, ?, ?, ?, ?)"
	refreshTokenInsertQuery       = "insert into refresh_token (permanentId, refreshToken, userAgent, refreshTokenCancelled) values (?, ?, ?, ?)"
	temporaryIdInsertQuery        = "insert into temporary_id (permanentId, temporaryId, userAgent, temporaryIdCancelled) values (?, ?, ?, ?)"
	passwordResetTokenInsertQuery = "insert into reset_token (resetToken, resetTokenCancelled) values (?, ?)"

	getOldPasswordHashAndPermanentIdFromUserTxSelectQuery = "select passwordHash, permanentId from user where email = ?"             //
	setOldPasswordHashInHistoryTxInsertQuery              = "insert into password_history (permanentId, passwordHash) values (?, ?)" //
	setNewPasswordHashInUserTxUpdateQuery                 = "update user set passwordHash = ? where email = ?"                       //

	passwordInDbBytemporaryIdUpdateQuery   = "update user set passwordHashCancelled = ? where temporaryId = ? and passwordHashCancelled = false; insert into user (passwordHash, passwordHashCancelled) values (?,?)"
	temporaryIdInDbByLoginUpdateQuery      = "update user set temporaryIdCancelled = ? where login = ? and temporaryIdCancelled = false; insert into user (temporaryId, temporaryIdCancelled) values (?,?)"
	temporaryIdInDbByEmailUpdateQuery      = "update user set temporaryIdCancelled = ? where email = ? and temporaryIdCancelled = false; insert into user (temporaryId, temporaryIdCancelled) values (?,?)"
	refreshTokenCancelledUpdateQuery       = "update refresh_token set refreshTokenCancelled = ? where refreshToken = ?"
	temporaryIdCancelledUpdateQuery        = "update user set temporaryIdCancelled = ? where temporaryId = ?"
	passwordResetTokenCancelledUpdateQuery = "update reset_token set resetTokenCancelled = ? where resetToken = ?"

	/////////////////////////////////////////////////////////////////////////
	permanentIdSelectQuery  = "select Id, cancelled from email where email = ?"
	loginInsertQuery        = "insert into login (Id, login, cancelled) values (?, ?, ?)"
	emailInsertQuery        = "insert into email (Id, email, cancelled) values (?, ?, ?)"
	passwordHashInsertQuery = "insert into password_hash (Id, hash, cancelled) values (?, ?, ?)"
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

func GetOldPasswordHashAndPermanentIdFromUserTx(tx *sql.Tx, email string) ([]byte, string, error) {
	var passwordHash []byte
	var permanentId string
	row := tx.QueryRow(getOldPasswordHashAndPermanentIdFromUserTxSelectQuery, email)
	err := row.Scan(&passwordHash, &permanentId)
	if err != nil {
		return nil, "", errors.WithStack(err)
	}
	return passwordHash, permanentId, nil
}

func SetOldPasswordHashInHistoryTx(tx *sql.Tx, permamentId string, passwordHash []byte) error {
	_, err := tx.Exec(setOldPasswordHashInHistoryTxInsertQuery, permamentId, passwordHash)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func SetNewPasswordHashInUserTx(tx *sql.Tx, hashedPassword []byte, email string) error {
	_, err := tx.Exec(setNewPasswordHashInUserTxUpdateQuery, hashedPassword, email)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func SetPasswordResetTokenCancelledInDb(token string, cancelled bool) error {
	_, err := Db.Exec(passwordResetTokenInsertQuery, token, cancelled)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func SetPasswordResetTokenCancelledInDbTx(tx *sql.Tx, token string, cancelled bool) error {
	_, err := tx.Exec(passwordResetTokenCancelledUpdateQuery, cancelled, token)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func GetPermanentIdFromDbByTemporaryId(temporaryId string) (string, error) {
	var permanentId string
	row := Db.QueryRow(permanentIdSelectQuery, temporaryId)
	err := row.Scan(&permanentId)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", errors.WithStack(err)
		}
		return "", errors.WithStack(err)
	}
	return permanentId, nil
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

func SetUserInDbTx(tx *sql.Tx, login, email, permanentId string, hashedPassword []byte, yauth bool) error {
	_, err := tx.Exec(userInsertQuery, login, email, permanentId, hashedPassword, yauth)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func SetTemporaryIdAndRefreshTokenInDbTx(tx *sql.Tx, permanentId, temporaryId, userAgent string, refreshToken string, temporaryIdCancelled, refreshTokenCancelled bool) error {
	_, err := tx.Exec(temporaryIdInsertQuery, permanentId, temporaryId, userAgent, temporaryIdCancelled)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
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

func GetUserFromDb(temporaryId string) (string, string, string, bool, error) {
	var email string
	var permanentId string
	var userAgent string
	var yauth bool
	row := Db.QueryRow(allUserKeysSelectQuery, temporaryId)
	err := row.Scan(&email, &permanentId, &userAgent, &yauth)
	if err != nil {
		return "", "", "", false, errors.WithStack(err)
	}
	return email, permanentId, userAgent, yauth, nil
}

func GetTemporaryIdCancelledRefreshTokenCancelledAndRefreshTokenFromDb(permanentId, userAgent string) (bool, bool, string, error) {
	var temporaryIdCancelled bool
	var refreshTokenCancelled bool
	var refreshToken string
	row := Db.QueryRow(permanentIdAndTemporaryIdCancelledSelectQuery, permanentId, userAgent)
	err := row.Scan(&temporaryIdCancelled, &refreshTokenCancelled, &refreshToken)
	if err != nil {
		return false, false, "", errors.WithStack(err)
	}
	return temporaryIdCancelled, refreshTokenCancelled, refreshToken, nil
}

func SetTemporaryIdCancelledAndRefreshTokenCancelledInDb(permanentId, userAgent string, temporaryIdCancelled, refreshTokenCancelled bool) error {
	_, err := Db.Exec(temporaryIdCancelledUpdateQuery, temporaryIdCancelled, permanentId)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func GetYauthFromDb(yauth bool) (string, error) {
	var permanentId string
	row := Db.QueryRow(yauthSelectQuery, yauth)
	err := row.Scan(&permanentId)
	if err != nil {
		return "", errors.WithStack(err)
	}
	return permanentId, nil
}

///////////////////////////////////////////////////////////////////////

func GetPermanentIdFromEmailDb(email string) (string, error) {
	var Id string
	var cancelled bool
	row := Db.QueryRow(permanentIdSelectQuery, email)
	err := row.Scan(&Id, &cancelled)
	if err != nil {
		if err == sql.ErrNoRows {
			err := errors.New("user not found")
			traceErr := errors.WithStack(err)
			return "", errors.WithStack(traceErr)
		}
		return "", errors.WithStack(err)
	}
	if cancelled {
		err := errors.New("user not found")
		traceErr := errors.WithStack(err)
		return "", errors.WithStack(traceErr)
	}
	return Id, nil
}

func SetLoginInDbTx(tx *sql.Tx, permanentId, login string) error {
	_, err := tx.Exec(loginInsertQuery, permanentId, login, true)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func SetEmailInDbTx(tx *sql.Tx, permanentId, email string) error {
	_, err := tx.Exec(emailInsertQuery, permanentId, email, true)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func SetPasswordInDbTx(tx *sql.Tx, Id, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password),
		bcrypt.DefaultCost)
	if err != nil {
		return errors.WithStack(err)
	}
	_, err = tx.Exec(passwordHashInsertQuery, Id, hash, true)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}
