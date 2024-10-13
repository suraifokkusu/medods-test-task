package models_test

import (
	"testing"
	"time"

	"medods-authservice/internal/models"
)

func TestTokenData(t *testing.T) {
	// задаем тестовые данные для проверки структуры TokenData
	userID := "test-user-id"
	ip := "127.0.0.1"
	expiration := time.Now().Add(15 * time.Minute)

	// инициализируем структуру TokenData
	tokenData := models.TokenData{
		UserID:     userID,
		IP:         ip,
		Expiration: expiration.Unix(),
	}

	// проверяем, что поле UserID инициализировано корректно
	if tokenData.UserID != userID {
		t.Errorf("Expected UserID %s, got %s", userID, tokenData.UserID)
	}

	// проверяем, что поле IP инициализировано корректно
	if tokenData.IP != ip {
		t.Errorf("Expected IP %s, got %s", ip, tokenData.IP)
	}

	// проверяем, что поле Expiration содержит ожидаемое значение
	if tokenData.Expiration != expiration.Unix() {
		t.Errorf("Expected Expiration %v, got %v", expiration, tokenData.Expiration)
	}
}
