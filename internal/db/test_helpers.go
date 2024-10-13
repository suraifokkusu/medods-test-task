package db

import (
	"database/sql"
	"log"

	_ "github.com/lib/pq"
)

func SetupTestDB(connStr string) *sql.DB {
	// открываем подключение к тестовой базе данных
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err) // завершаем выполнение при ошибке подключения
	}

	// очищаем таблицу refresh_tokens перед запуском тестов
	_, err = db.Exec("TRUNCATE TABLE refresh_tokens RESTART IDENTITY CASCADE")
	if err != nil {
		log.Fatal(err) // если очистка таблицы не удалась, тесты не могут продолжаться
	}

	return db // возвращаем подключение к базе данных
}
