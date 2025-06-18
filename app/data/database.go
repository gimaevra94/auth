package data

import (
	"database/sql"
	"net/http"
	"os"

	"github.com/go-sql-driver/mysql"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

var DB *sql.DB

const (
	selectQuery      = "select passwordHash from user where email = ? limit 1"
	insertQuery      = "insert into user (email,login,passwordHash) values(?,?,?)"
	yauthSelectQuery = "select email from user where email = ? limit 1"
	yauthInsertQuery = "insert into user (email,login) values(?,?)"
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

func UserCheck(w http.ResponseWriter, r *http.Request, user User) error {
	if err := DB.Ping(); err != nil {
		return errors.WithStack(err)
	}

	row := DB.QueryRow(selectQuery, user.Email)
	var passwordHash string
	err := row.Scan(&passwordHash)

	if err != nil {
		if err == sql.ErrNoRows {
			return errors.WithStack(err)

		}
		
		return errors.WithStack(err)
	}

	err = bcrypt.CompareHashAndPassword([]byte(passwordHash),
		[]byte(user.Password))
	if err != nil {
		return errors.WithStack(err)
	}

	return nil

}

func UserAdd(w http.ResponseWriter, r *http.Request, user User) error {
	if err := DB.Ping(); err != nil {
		return errors.WithStack(err)
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password),
		bcrypt.DefaultCost)
	if err != nil {
		return errors.WithStack(err)
	}

	_, err = DB.Exec(insertQuery, user.Login, user.Email, hashedPassword)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func YauthUserCheck(w http.ResponseWriter, r *http.Request, user User) error {
	if err := DB.Ping(); err != nil {
		return errors.WithStack(err)
	}

	row := DB.QueryRow(yauthSelectQuery, user.Email)
	var existingEmail string
	err := row.Scan(&existingEmail)

	if err != nil {
		if err == sql.ErrNoRows {
			return errors.WithStack(errors.New("user: " + NotExistErr))
		}
		return errors.WithStack(err)
	}

	return nil
}

func YauthUserAdd(w http.ResponseWriter, r *http.Request, user User) error {
	_, err := DB.Exec(yauthInsertQuery, user.Login, user.Email)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}
