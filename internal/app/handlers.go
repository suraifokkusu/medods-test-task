package app

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"medods-authservice/internal/models"
)

func (app *App) TokenHandler(w http.ResponseWriter, r *http.Request) {
	// получаем userID из параметров запроса
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		http.Error(w, "user_id is required", http.StatusBadRequest)
		return
	}
	log.Printf("Attempting to save refresh token for userID: %s", userID)

	// проверяем подключение к базе данных
	if app.DB == nil {
		log.Println("Database connection is nil")
		http.Error(w, "Database connection error", http.StatusInternalServerError)
		return
	}

	// получаем ip-адрес клиента
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, "Unable to get IP address", http.StatusInternalServerError)
		return
	}

	// создаем данные для токена, указываем время жизни
	tokenData := models.TokenData{
		UserID:     userID,
		IP:         ip,
		Expiration: time.Now().Add(15 * time.Minute).Unix(), // токен будет валиден 15 минут
	}

	// создаем jwt-токен с нужными полями
	claims := jwt.MapClaims{
		"user_id": tokenData.UserID,
		"ip":      tokenData.IP,
		"exp":     tokenData.Expiration,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	accessToken, err := token.SignedString(app.SecretKey)
	if err != nil {
		http.Error(w, "Error generating access token", http.StatusInternalServerError)
		return
	}

	// создаем случайный refresh-токен
	refreshTokenBytes := make([]byte, 32)
	_, err = rand.Read(refreshTokenBytes)
	if err != nil {
		http.Error(w, "Error generating refresh token", http.StatusInternalServerError)
		return
	}
	refreshToken := base64.URLEncoding.EncodeToString(refreshTokenBytes)

	// хешируем refresh-токен для хранения в базе
	hashedToken, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error hashing refresh token", http.StatusInternalServerError)
		return
	}

	// сохраняем хеш refresh-токена в базе
	refreshTokenModel := models.RefreshToken{
		UserID:    userID,
		TokenHash: string(hashedToken),
		ExpiredAt: time.Now(),
	}
	_, err = app.DB.Exec(
		"INSERT INTO refresh_tokens (user_id, token_hash, created_at) VALUES ($1, $2, $3)",
		refreshTokenModel.UserID, refreshTokenModel.TokenHash, refreshTokenModel.ExpiredAt,
	)
	if err != nil {
		log.Printf("Error saving refresh token: %v", err)
		http.Error(w, "Error saving refresh token", http.StatusInternalServerError)
		return
	}

	// отправляем клиенту токены
	response := map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (app *App) RefreshHandler(w http.ResponseWriter, r *http.Request) {
	// проверяем подключение к базе
	if app.DB == nil {
		log.Println("Database connection is nil")
		http.Error(w, "Database connection error", http.StatusInternalServerError)
		return
	}

	type RefreshRequest struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}

	// разбираем запрос
	var req RefreshRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// валидируем Access-токен
	token, err := jwt.Parse(req.AccessToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return app.SecretKey, nil
	})
	if err != nil || !token.Valid {
		http.Error(w, "Invalid access token", http.StatusUnauthorized)
		return
	}

	// получаем user_id и ip из токена
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(w, "Invalid token claims", http.StatusUnauthorized)
		return
	}
	tokenUserID, ok := claims["user_id"].(string)
	if !ok {
		http.Error(w, "Invalid user_id in token", http.StatusUnauthorized)
		return
	}
	tokenIP, ok := claims["ip"].(string)
	if !ok {
		http.Error(w, "Invalid ip in token", http.StatusUnauthorized)
		return
	}

	// проверяем хеш refresh-токена в базе
	var storedTokenHash string
	err = app.DB.QueryRow("SELECT token_hash FROM refresh_tokens WHERE user_id = $1", tokenUserID).Scan(&storedTokenHash)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Refresh token not found", http.StatusUnauthorized)
		} else {
			http.Error(w, "Database error", http.StatusInternalServerError)
		}
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(storedTokenHash), []byte(req.RefreshToken))
	if err != nil {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	// получаем текущий IP клиента
	currentIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, "Unable to get IP address", http.StatusInternalServerError)
		return
	}

	// если IP изменился, шлем уведомление
	if tokenIP != currentIP {
		app.SendEmailWarning(tokenUserID)
	}

	// удаляем старый refresh-токен из базы
	_, err = app.DB.Exec("DELETE FROM refresh_tokens WHERE user_id = $1", tokenUserID)
	if err != nil {
		http.Error(w, "Error deleting old refresh token", http.StatusInternalServerError)
		return
	}

	// создаем новую пару токенов
	newClaims := jwt.MapClaims{
		"user_id": tokenUserID,
		"ip":      currentIP,
		"exp":     time.Now().Add(15 * time.Minute).Unix(),
	}
	newToken := jwt.NewWithClaims(jwt.SigningMethodHS512, newClaims)
	newAccessToken, err := newToken.SignedString(app.SecretKey)
	if err != nil {
		http.Error(w, "Error generating access token", http.StatusInternalServerError)
		return
	}

	// генерируем новый refresh-токен
	refreshTokenBytes := make([]byte, 32)
	_, err = rand.Read(refreshTokenBytes)
	if err != nil {
		http.Error(w, "Error generating refresh token", http.StatusInternalServerError)
		return
	}
	newRefreshToken := base64.URLEncoding.EncodeToString(refreshTokenBytes)

	// хешируем новый refresh-токен
	hashedToken, err := bcrypt.GenerateFromPassword([]byte(newRefreshToken), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error hashing refresh token", http.StatusInternalServerError)
		return
	}

	// сохраняем новый refresh-токен в базе
	_, err = app.DB.Exec("INSERT INTO refresh_tokens (user_id, token_hash) VALUES ($1, $2)", tokenUserID, string(hashedToken))
	if err != nil {
		http.Error(w, "Error saving refresh token", http.StatusInternalServerError)
		return
	}

	// отправляем клиенту новые токены
	response := map[string]string{
		"access_token":  newAccessToken,
		"refresh_token": newRefreshToken,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (app *App) SendEmailWarning(userID string) {
	// если мыло юзера не указано, шлем на дефолтное
	email, ok := app.UserEmails[userID]
	if !ok {
		email = "alisa@example.com"
	}
	log.Printf("Sending email warning to %s: IP address has changed for user %s", email, userID)
}
