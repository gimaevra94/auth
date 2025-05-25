package app

import (
	"database/sql"
	"log"
	"net/http"
	"os"

	"github.com/go-sql-driver/mysql"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

var DB *sql.DB

const (
	selectQuery = "select email,passwordHash from users where email = ? and passwordHash = ? limit 1"
	insertQuery = "insert into users (email,login,passwordHash) values(?,?,?)"
)

const (
	dbStartFailedErr = "failed to start the database"
)

func DBConn() error {
	passwordFilePath := "/run/secrets/db_password"
	password, err := os.ReadFile(passwordFilePath)
	if err != nil {
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		return wrappedErr
	}

	defer func() {
		for i := range password {
			password[i] = 0
		}
	}()

	cfg := mysql.Config{
		User:   "root",
		Passwd: string(password),
		Net:    "tcp",
		Addr:   "db:3306",
		DBName: "db",
	}

	DB, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		return wrappedErr
	}

	err = DB.Ping()
	if err != nil {
		DB.Close()
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		return wrappedErr
	}

	return nil
}

func UserCheck(w http.ResponseWriter, r *http.Request,
	user User, userCheckFromLogIn bool) error {

	if err := DB.Ping(); err != nil {
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		log.Fatal(wrappedErr)
	}

	inputEmail := user.GetEmail()
	inputPassword := user.GetPassword()

	row := DB.QueryRow(selectQuery, inputEmail, inputPassword)
	var email, passwordHash string
	err := row.Scan(&email)
	if err != nil {
		if err == sql.ErrNoRows {
			newErr := errors.New(NotExistErr)
			wrappedErr := errors.Wrap(newErr, "user")
			log.Printf("%+v", wrappedErr)
			return wrappedErr
		}

		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		return wrappedErr
	}

	if userCheckFromLogIn {
		err := row.Scan(&passwordHash)
		if err != nil {
			if err == sql.ErrNoRows {
				newErr := errors.New("invalid password")
				wrappedErr := errors.WithStack(newErr)
				log.Printf("%+v", wrappedErr)
				return wrappedErr
			}

			wrappedErr := errors.WithStack(err)
			log.Printf("%+v", wrappedErr)
			return wrappedErr
		}

		inputPassword := user.GetPassword()
		err = bcrypt.CompareHashAndPassword([]byte(passwordHash),
			[]byte(inputPassword))
		if err != nil {
			wrappedErr := errors.WithStack(err)
			log.Printf("%+v", wrappedErr)
			return wrappedErr
		}
	}

	return nil
}

func UserAdd(w http.ResponseWriter, r *http.Request,
	user User) error {
	if err := DB.Ping(); err != nil {
		log.Fatal(dbStartFailedErr)
	}

	email := user.GetEmail()
	login := user.GetLogin()
	password := user.GetPassword()

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password),
		bcrypt.DefaultCost)
	if err != nil {
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		return wrappedErr
	}

	_, err = DB.Exec(insertQuery, email, login, hashedPassword)
	if err != nil {
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		return wrappedErr
	}

	return nil
}
