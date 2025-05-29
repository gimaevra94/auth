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
	dbPassword := []byte(os.Getenv("DB_PASSWORD"))
	if len(dbPassword) == 0 {
		newErr := errors.New(NotExistErr)
		wrappedErr := errors.Wrapf(newErr, "dbPassword")
		log.Printf("%+v", wrappedErr)
		return wrappedErr
	}

	defer func() {
		for i := range dbPassword {
			dbPassword[i] = 0
		}
	}()

	cfg := mysql.Config{
		User:   "root",
		Passwd: string(dbPassword),
		Net:    "tcp",
		Addr:   "localhost:3306",
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
	var email string

	err := row.Scan(&email, nil)
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
		var passwordHash string
		err := row.Scan(nil, &passwordHash)
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

	login := user.GetLogin()
	email := user.GetEmail()
	password := user.GetPassword()

	if password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password),
			bcrypt.DefaultCost)
		if err != nil {
			wrappedErr := errors.WithStack(err)
			log.Printf("%+v", wrappedErr)
			return wrappedErr
		}

		_, err = DB.Exec(insertQuery, login, email, hashedPassword)
		if err != nil {
			wrappedErr := errors.WithStack(err)
			log.Printf("%+v", wrappedErr)
			return wrappedErr
		}
	}

	_, err := DB.Exec(insertQuery, login, email, password)
	if err != nil {
		wrappedErr := errors.WithStack(err)
		log.Printf("%+v", wrappedErr)
		return wrappedErr
	}

	return nil
}
