package config

import (
	"os"
)

type Config struct {
	DBHost     string
	DBPort     string
	DBUser     string
	DBPassword string
	DBName     string
	SecretKey  []byte
}

// загружаем конфигурацию из переменных окружения, если переменной нет — используем значение по умолчанию
func LoadConfig() Config {
	return Config{
		DBHost:     getEnv("DB_HOST", "localhost"),
		DBPort:     getEnv("DB_PORT", "5432"),
		DBUser:     getEnv("DB_USER", "postgres"),
		DBPassword: getEnv("DB_PASSWORD", "1111"),
		DBName:     getEnv("DB_NAME", "authservice_db"),
		SecretKey:  []byte(getEnv("SECRET_KEY", "medods")),
	}
}

// вспомогательная функция для получения переменной окружения с возможностью указания значения по умолчанию
func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}
