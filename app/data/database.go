package data

import (
	"database/sql"
	"fmt"
	"os"

	"github.com/gimaevra94/auth/app/structs"
	"github.com/go-sql-driver/mysql"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

const (
	userInsertQuery  = "insert into user (user-id,login,email,passwordHash) values(?,?,?,?)"
	tokenInsertQuery = "insert into token (user-id,token,expires-at,device-info) values (?,?,?,?)"
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
	return fmt.Sprintf("select passwordHash from user where %s = ? limit 1", s)
}

func UserCheck(queryValue string, usrValue string, pswrd string) error {
	row := db.QueryRow(query(queryValue), usrValue)
	var passwordHash string
	err := row.Scan(&passwordHash)

	if err != nil {
		if err == sql.ErrNoRows {
			return errors.WithStack(err)
		}
		return errors.WithStack(err)
	}

	err = bcrypt.CompareHashAndPassword([]byte(passwordHash),
		[]byte(pswrd))
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func UserAdd(user structs.User) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password),
		bcrypt.DefaultCost)
	if err != nil {
		return errors.WithStack(err)
	}

	_, err = db.Exec(userInsertQuery, user.UserID, user.Login, user.Email, hashedPassword)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func RefreshTokenAdd(user structs.User) error {
	_, err := db.Exec(tokenInsertQuery, user.UserID, user.Token, user.ExpiresAt, user.DeviceInfo)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func YauthUserCheck(user structs.User) error {
	row := db.QueryRow(yauthSelectQuery, user.Email)
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

func YauthUserAdd(user structs.User) error {
	_, err := db.Exec(yauthInsertQuery, user.Login, user.Email)
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
