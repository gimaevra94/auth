package data

import (
	"database/sql"
	"fmt"
	"os"

	"github.com/go-sql-driver/mysql"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

const (
	userInsertQuery  = "insert into user (userId,login,email,passwordHash) values(?,?,?,?)"
	tokenInsertQuery = "insert into token (userId,token,deviceInfo) values (?,?,?)"
	tokenSelectQuery = "select refreshToken from token where userID =? limit 1"
	yauthSelectQuery = "select email from user where email = ? limit 1"
	yauthInsertQuery = "insert into user (login,email) values(?,?)"
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

func query(s string) string {
	return fmt.Sprintf("select passwordHash, userID from user where %s = ? limit 1", s)
}

func UserCheck(queryValue string, login, password string) (string, error) {
	row := db.QueryRow(query(queryValue), login)
	var passwordHash string
	var userID string
	err := row.Scan(&passwordHash, &userID)

	if err != nil {
		if err == sql.ErrNoRows {
			return userID, errors.WithStack(err)
		}
		return userID, errors.WithStack(err)
	}

	err = bcrypt.CompareHashAndPassword([]byte(passwordHash),
		[]byte(password))
	if err != nil {
		return userID, errors.WithStack(err)
	}

	return userID, nil
}

func UserAdd(login, email, password, userID string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password),
		bcrypt.DefaultCost)
	if err != nil {
		return errors.WithStack(err)
	}

	_, err = db.Exec(userInsertQuery, userID, login, email, hashedPassword)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func RefreshTokenCheck(userID string) (string, error) {
	row := db.QueryRow(tokenSelectQuery, userID)
	var refreshToken string
	err := row.Scan(&refreshToken)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", errors.WithStack(err)
		}
		return "", errors.WithStack(err)
	}
	return refreshToken, nil
}

func RefreshTokenAdd(userID, refreshToken, deviceInfo string) error {
	_, err := db.Exec(tokenInsertQuery, userID, refreshToken, deviceInfo)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func YauthUserCheck(email string) error {
	row := db.QueryRow(yauthSelectQuery, email)
	var existingEmail string
	err := row.Scan(&existingEmail)

	if err != nil {
		if err == sql.ErrNoRows {
			return errors.WithStack(err)
		}
		return errors.WithStack(err)
	}

	return nil
}

func YauthUserAdd(login, email string) error {
	_, err := db.Exec(yauthInsertQuery, login, email)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func DBClose() {
	if db != nil {
		db.Close()
	}
}
