package database

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/go-sql-driver/mysql"
)

type Users struct {
	ID    int64
	Email string
}

func SqlConn() (*sql.DB, error) {
	password, err := os.ReadFile("/run/secrets/db_password")
	if err != nil {
		log.Fatal(err)
	}

	cfg := mysql.Config{
		User:   "root",
		Passwd: strings.TrimSpace(string(password)),
		Net:    "tcp",
		Addr:   "db:3306",
		DBName: "db",
	}

	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		log.Fatal(err)
	}

	if err := db.Ping(); err != nil {
		log.Fatal(err)
	}

	return db, nil
}

func EmailAdd(users Users, db *sql.DB) {
	row := db.QueryRow("SELECT * FROM users WHERE email LIKE %v LIMIT 1;", users.Email)
	if row == nil {
		result, err := db.Exec("insert into users (email) values (?)", users.Email)
		if err != nil {
			fmt.Printf("EmailAdd: %v", err)
			return
		} else {
			fmt.Print(result)
		}
	} else {
		fmt.Print("Такой пользователь уже есть")
	}
}
