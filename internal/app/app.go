package app

import (
	"database/sql"
	"medods-authservice/internal/config"
	"medods-authservice/internal/db"
)

// структура приложения, тут хранится подключение к БД и секретный ключ
type App struct {
	DB         *sql.DB          // подключение к базе данных
	SecretKey  []byte           // секретный ключ для токенов
	UserEmails map[string]string // тут будем хранить мапу с email'ами пользователей
}

// функция для инициализации приложения
func NewApp(cfg *config.Config) *App {
	// создаем подключение к базе через функцию SetupDB
	database := db.SetupDB(*cfg)

	// возвращаем объект приложения с базой и секретным ключом
	return &App{
		DB:         database,
		SecretKey:  cfg.SecretKey,
		UserEmails: make(map[string]string), // создаем пустую мапу для email'ов
	}
}
