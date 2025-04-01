package database

import (
	"database/sql"
	"log"
	"net/http"
	"os"

	"github.com/gimaevra94/auth/app/constsandstructs"
	"github.com/go-sql-driver/mysql"
)

var DB *sql.DB

func dBConnConf(password []byte) mysql.Config {
	return mysql.Config{
		User:   "root",
		Passwd: string(password),
		Net:    "tcp",
		Addr:   "db:3306",
		DBName: "db",
	}
}

func DBConn() error {
	password, err := os.ReadFile("/run/secrets/db_password")
	if err != nil {
		log.Println("db_password reading error: ", err)
		return err
	}

	cfg := dBConnConf(password)
	DB, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		log.Println("sql.Open: ", err)
		return err
	}

	err = DB.Ping()
	if err != nil {
		log.Println("db.Ping: ", err)
		DB.Close()
		return err
	}

	return nil
}

func UserCheck(w http.ResponseWriter, r *http.Request,
	users constsandstructs.Users) error {

	if DB == nil {
		log.Fatal("Failed to start database")
	}

	query := "select * from users where email = ? limit 1"
	email := users.GetEmail()
	row := DB.QueryRow(query, email)
	var emailContainer string
	err := row.Scan(&emailContainer)
	if err != nil {
		if err == sql.ErrNoRows {
			return err
		}
		return err
	}
	return nil
}

func UserAdd(w http.ResponseWriter, r *http.Request,
	users constsandstructs.Users) error {

	err := UserCheck(w, r, users)
	if err != nil {
		if err == sql.ErrNoRows {
			query := "insert into users (email,login,password) values(?,?,?)"
			email := users.GetEmail()
			login := users.GetLogin()
			password := users.GetPassword()

			_, err = DB.Exec(query, email, login, password)
			if err != nil {
				http.ServeFile(w, r, constsandstructs.RequestErrorHTML)
				log.Println("Adding user to database failed", err)
				return err
			}
		}
		return err
	}
	return nil
}
