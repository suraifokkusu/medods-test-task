package db

import (
	"database/sql"
	"fmt"
	"log"

	"medods-authservice/internal/config"

	_ "github.com/lib/pq"
)

func SetupDB(cfg config.Config) *sql.DB {
	// создаем строку подключения на основе данных из конфигурации
	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		cfg.DBHost, cfg.DBPort, cfg.DBUser, cfg.DBPassword, cfg.DBName)
	
	// открываем подключение к базе данных
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err) // критическая ошибка, если не удалось подключиться
	}

	// проверяем, установлено ли успешное соединение
    err = db.Ping()
	if err != nil {
		log.Fatal(err) // завершаем работу, если не удалось подключиться
	}

	return db
}
