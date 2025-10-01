package data

import (
	"database/sql"
	"os"

	"github.com/go-sql-driver/mysql"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

const (
	userInsertQuery  = "insert into user (userId,login,email,passwordHash,temporaryUserID,permanentUserID,temporaryCancelled) values(?,?,?,?,?,?,?)"
	tokenInsertQuery = "insert into token (userId,token,deviceInfo,tokenCancelled) values (?,?,?,?)"
	yauthInsertQuery = "insert into user (login, temporaryUserID, permanentUserID, temporaryCancelled) values(?,?,?,?)"

	userSelectQuery   = "select passwordHash, permanentUserID from user where %s = ? limit 1"
	tokenSelectQuery  = "select refreshToken,tokenCancelled,deviceInfo from token where permanentUserID =? and deviceInfo =? limit 1"
	yauthSelectQuery  = "select * from user where login = ? limit 1"
	mwUserSelectQuery = "select permanentUserID from user where %s = ? limit 1"

	temporaryIDUpdateQuery = "update user set temporaryUserID = ? where login = ?"
	tokenUpdateQuery       = "update token set tokenCancelled =? where refreshToken =? and deviceInfo =?"
	temporaryUserIDQuery   = "update user set tokenCancelled =? where temporaryUserID =?"
)

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
	db, err = sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return errors.WithStack(err)
	}

	err = db.Ping()
	if err != nil {
		db.Close()
		return errors.WithStack(err)
	}

	return nil
}

func DBClose() {
	if db != nil {
		db.Close()
	}
}

func UserCheck(login, password string) (string, error) {
	row := db.QueryRow(userSelectQuery, login)
	var passwordHash string
	var permanentUserID string
	err := row.Scan(&passwordHash, &permanentUserID)

	if err != nil {
		if err == sql.ErrNoRows {
			return "", errors.WithStack(err)
		}
		return "", errors.WithStack(err)
	}

	err = bcrypt.CompareHashAndPassword([]byte(passwordHash),
		[]byte(password))
	if err != nil {
		return "", errors.WithStack(err)
	}

	return permanentUserID, nil
}

func RefreshTokenCheck(permanentUserID, userAgent string) (string, string, bool, error) {
	row := db.QueryRow(tokenSelectQuery, permanentUserID)
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

func YauthUserCheck(login string) (string, string, string, error) {
	row := db.QueryRow(yauthSelectQuery, login)
	var email string
	var password string
	var permanentUserID string
	err := row.Scan(&email, &password, &permanentUserID)

	if err != nil {
		if err == sql.ErrNoRows {
			return "", "", "", errors.WithStack(err)
		}
		return "", "", "", errors.WithStack(err)
	}

	return email, password, permanentUserID, nil
}

func MWUsernCheck(key string) (string, bool, error) {
	row := db.QueryRow(mwUserSelectQuery, key)
	var permanentUserID string
	var temporaryUserID bool
	err := row.Scan(&permanentUserID, &temporaryUserID)
	if err != nil {
		return "", false, errors.WithStack(err)
	}
	return permanentUserID, temporaryUserID, nil
}

func UserAdd(login, email, password, temporaryUserID, permanentUserID string, temporaryCancelled bool) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password),
		bcrypt.DefaultCost)
	if err != nil {
		return errors.WithStack(err)
	}

	_, err = db.Exec(userInsertQuery, login, email, hashedPassword, temporaryUserID, permanentUserID, temporaryCancelled)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func TemporaryUserIDAdd(login, temporaryUserID string) error {
	_, err := db.Exec(temporaryIDUpdateQuery, temporaryUserID, login)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func RefreshTokenAdd(permanentUserID, refreshToken, deviceInfo string, tokenCancelled bool) error {
	_, err := db.Exec(tokenInsertQuery, permanentUserID, refreshToken, deviceInfo, tokenCancelled)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func YauthUserAdd(login, temporaryUserID, permanentUserID string, temporaryCancelled bool) error {
	_, err := db.Exec(yauthInsertQuery, login, temporaryUserID, permanentUserID, temporaryCancelled)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func TokenCancel(refreshToken, deviceInfo string) error {
	_, err := db.Exec(tokenUpdateQuery, true)
	if err != nil {
		return errors.WithStack(err)
	}
	return err
}

func TemporaryUserIDCancel(temporaryUserID string) error {
	_, err := db.Exec(temporaryUserIDQuery, true)
	if err != nil {
		return errors.WithStack(err)
	}
	return err
}
