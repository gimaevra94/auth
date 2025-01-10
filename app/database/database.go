package database

import (
	"database/sql"
	"fmt"
	"log"
	"os"

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
		Passwd: string(password),
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
	row := db.QueryRow("SELECT * FROM users WHERE email = ? LIMIT 1", users.Email)
	var email string
	err := row.Scan(&email)

	if err != nil {
		if err == sql.ErrNoRows {
			result, err := db.Exec("INSERT INTO users (email) VALUES (?)", users.Email)
			if err != nil {
				fmt.Printf("EmailAdd: %v", err)
				return
			} else {
				fmt.Println(result)
			}
		} else {
			fmt.Printf("QueryRow error: %v", err)
			return
		}
	} else {
		fmt.Println("Такой пользователь уже есть")
	}
}
