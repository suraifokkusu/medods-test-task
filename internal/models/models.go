package models

import "time"

// структура TokenData хранит информацию о токене
type TokenData struct {
	UserID     string
	IP         string
	Expiration int64
}

// конструктор для создания нового экземпляра TokenData
func NewTokenData(userID, ip string, exp int64) *TokenData {
	return &TokenData{
		UserID:     userID,
		IP:         ip,
		Expiration: exp,
	}
}

// структура RefreshToken хранит информацию о refresh токене
type RefreshToken struct {
	UserID    string
	TokenHash string
	ExpiredAt time.Time
}
