package app_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"medods-authservice/internal/app"
	"medods-authservice/internal/config"
	"medods-authservice/internal/db"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func setupTestApplication(t *testing.T) *app.App {
	t.Helper()

	// устанавливаем переменные окружения для тестов, как в обычной среде
	os.Setenv("TEST_MODE", "true")
	os.Setenv("DB_HOST", "db")
	os.Setenv("DB_PORT", "5432")
	os.Setenv("DB_USER", "postgres")
	os.Setenv("DB_PASSWORD", "postgres")
	os.Setenv("DB_NAME", "medods_db")
	os.Setenv("SECRET_KEY", "test-secret-key")

	cfg := config.LoadConfig()

	// коннектимся к тестовой бд
	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		cfg.DBHost, cfg.DBPort, cfg.DBUser, cfg.DBPassword, cfg.DBName)

	// настраиваем тестовую бд
	testDB := db.SetupTestDB(connStr)

	// возвращаем приложение с тестовой бд и секретным ключом
	return &app.App{
		DB:         testDB,
		SecretKey:  cfg.SecretKey,
		UserEmails: make(map[string]string),
	}
}

func teardownTestApplication(app *app.App) {
	if app.DB != nil {
		app.DB.Close() // всегда нужно закрывать подключение к базе после тестов
	}
}

func TestTokenHandler_Success(t *testing.T) {
	application := setupTestApplication(t)
	defer teardownTestApplication(application)

	// использую фиксированный UUID для того, чтобы результат был предсказуем
	userID := "123e4567-e89b-12d3-a456-426614174000"

	// создаю тестовый HTTP-запрос
	req, err := http.NewRequest("GET", "/token?user_id="+userID, nil)
	if err != nil {
		t.Fatal(err)
	}

	// задаю IP-адрес клиента для теста
	req.RemoteAddr = "127.0.0.1:12345"

	// создаю recorder для получения ответа
	rr := httptest.NewRecorder()

	// вызываю обработчик
	handler := http.HandlerFunc(application.TokenHandler)
	handler.ServeHTTP(rr, req)

	// проверяю статус ответа
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// проверяю, что в ответе есть access_token и refresh_token
	var response map[string]string
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	if err != nil {
		t.Errorf("Unable to parse response body: %v", err)
	}

	if _, ok := response["access_token"]; !ok {
		t.Errorf("Expected access_token in response")
	}

	if _, ok := response["refresh_token"]; !ok {
		t.Errorf("Expected refresh_token in response")
	}
}

func TestTokenHandler_MissingUserID(t *testing.T) {
	application := setupTestApplication(t)
	defer teardownTestApplication(application)

	req, err := http.NewRequest("GET", "/token", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(application.TokenHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusBadRequest)
	}

	expected := "user_id is required\n"
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v", rr.Body.String(), expected)
	}
}

func TestTokenHandler_DBConnectionError(t *testing.T) {
	application := &app.App{
		DB:         nil, 
		SecretKey:  []byte("test-secret-key"),
		UserEmails: make(map[string]string),
	}

	userID := "123e4567-e89b-12d3-a456-426614174000"

	req, err := http.NewRequest("GET", "/token?user_id="+userID, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.RemoteAddr = "127.0.0.1:12345"

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(application.TokenHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusInternalServerError {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusInternalServerError)
	}

	expected := "Database connection error\n"
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v", rr.Body.String(), expected)
	}
}

func TestRefreshHandler_Success(t *testing.T) {
	application := setupTestApplication(t)
	defer teardownTestApplication(application)

	userID := "123e4567-e89b-12d3-a456-426614174000"
	ip := "127.0.0.1"

	application.UserEmails[userID] = "alisa@example.com"

	accessToken, refreshToken := generateTokensForTesting(t, application, userID, ip)

	requestBody, err := json.Marshal(map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("POST", "/refresh", bytes.NewBuffer(requestBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = ip + ":12345"

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(application.RefreshHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	var response map[string]string
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	if err != nil {
		t.Errorf("Unable to parse response body: %v", err)
	}

	if _, ok := response["access_token"]; !ok {
		t.Errorf("Expected access_token in response")
	}

	if _, ok := response["refresh_token"]; !ok {
		t.Errorf("Expected refresh_token in response")
	}
}

func TestRefreshHandler_InvalidAccessToken(t *testing.T) {
	application := setupTestApplication(t)
	defer teardownTestApplication(application)

	userID := "123e4567-e89b-12d3-a456-426614174000"
	ip := "127.0.0.1"

	application.UserEmails[userID] = "test@example.com"

	_, refreshToken := generateTokensForTesting(t, application, userID, ip)

	accessToken := "invalid-access-token"

	requestBody, err := json.Marshal(map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("POST", "/refresh", bytes.NewBuffer(requestBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = ip + ":12345"

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(application.RefreshHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusUnauthorized)
	}

	expected := "Invalid access token\n"
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v", rr.Body.String(), expected)
	}
}

func TestRefreshHandler_InvalidRefreshToken(t *testing.T) {
	application := setupTestApplication(t)
	defer teardownTestApplication(application)

	userID := "123e4567-e89b-12d3-a456-426614174000"
	ip := "127.0.0.1"

	application.UserEmails[userID] = "test@example.com"

	accessToken, _ := generateTokensForTesting(t, application, userID, ip)

	refreshToken := "invalid-refresh-token"

	requestBody, err := json.Marshal(map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("POST", "/refresh", bytes.NewBuffer(requestBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = ip + ":12345"

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(application.RefreshHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusUnauthorized)
	}

	expected := "Invalid refresh token\n"
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v", rr.Body.String(), expected)
	}
}

func TestRefreshHandler_IPChanged(t *testing.T) {
	application := setupTestApplication(t)
	defer teardownTestApplication(application)

	userID := "123e4567-e89b-12d3-a456-426614174000"
	originalIP := "127.0.0.1"
	newIP := "192.168.1.1"

	application.UserEmails[userID] = "test@example.com"

	accessToken, refreshToken := generateTokensForTesting(t, application, userID, originalIP)

	var logBuffer bytes.Buffer
	log.SetOutput(&logBuffer)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	requestBody, err := json.Marshal(map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("POST", "/refresh", bytes.NewBuffer(requestBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = newIP + ":54321"

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(application.RefreshHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	logOutput := logBuffer.String()
	expectedLogMessage := fmt.Sprintf("Sending email warning to %s: IP address has changed for user %s", "test@example.com", userID)
	if !strings.Contains(logOutput, expectedLogMessage) {
		t.Errorf("Expected log message '%s', got '%s'", expectedLogMessage, logOutput)
	}
}

func TestRefreshHandler_DBConnectionError(t *testing.T) {
	application := &app.App{
		DB:         nil, 
		SecretKey:  []byte("test-secret-key"),
		UserEmails: make(map[string]string),
	}

	requestBody, err := json.Marshal(map[string]string{
		"access_token":  "some-token",
		"refresh_token": "some-refresh-token",
	})
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("POST", "/refresh", bytes.NewBuffer(requestBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:12345"

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(application.RefreshHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusInternalServerError {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusInternalServerError)
	}

	expected := "Database connection error\n"
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v", rr.Body.String(), expected)
	}
}

func TestSendEmailWarning(t *testing.T) {
	userID := "123e4567-e89b-12d3-a456-426614174000"

	application := &app.App{
		UserEmails: map[string]string{
			userID: "alisa@example.com",
		},
	}

	var logBuffer bytes.Buffer
	log.SetOutput(&logBuffer)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	application.SendEmailWarning(userID)

	logOutput := logBuffer.String()
	expectedLogMessage := fmt.Sprintf("Sending email warning to %s: IP address has changed for user %s", "test@example.com", userID)
	if !strings.Contains(logOutput, expectedLogMessage) {
		t.Errorf("Expected log message '%s', got '%s'", expectedLogMessage, logOutput)
	}
}

func generateTokensForTesting(t *testing.T, application *app.App, userID, ip string) (string, string) {
	t.Helper()

	claims := jwt.MapClaims{
		"user_id": userID,
		"ip":      ip,
		"exp":     time.Now().Add(15 * time.Minute).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	accessToken, err := token.SignedString(application.SecretKey)
	if err != nil {
		t.Fatal(err)
	}

	refreshTokenBytes := make([]byte, 32)
	_, err = rand.Read(refreshTokenBytes)
	if err != nil {
		t.Fatal(err)
	}
	refreshToken := base64.URLEncoding.EncodeToString(refreshTokenBytes)

	hashedToken, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}

    if application.DB != nil {
		_, err = application.DB.Exec(
			"INSERT INTO refresh_tokens (user_id, token_hash) VALUES ($1, $2)",
			userID, string(hashedToken),
		)
		if err != nil {
			t.Fatal(err)
		}
	}

	return accessToken, refreshToken
}
