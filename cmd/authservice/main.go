package main

import (
	"log"
	"net/http"

	"medods-authservice/internal/app"
	"medods-authservice/internal/config"
)

func main() {
	// загружаем конфигурацию из config
	cfg := config.LoadConfig()

	// создаем приложение с настройками из конфигурации
	application := app.NewApp(&cfg)

	// регистрируем обработчики для маршрутов
	mux := http.NewServeMux()
	mux.HandleFunc("/token", application.TokenHandler)   // этот маршрут выдаёт access и refresh токены
	mux.HandleFunc("/refresh", application.RefreshHandler) // этот маршрут обновляет токены

	// запускаем HTTP сервер на порту 8080
	log.Println("Server started on :8080")
	err := http.ListenAndServe(":8080", mux) // если возникнет ошибка запуска сервера, выводим лог
	if err != nil {
		log.Fatalf("Could not start server: %s\n", err.Error()) // фатальная ошибка, если сервер не запустился
	}
}
