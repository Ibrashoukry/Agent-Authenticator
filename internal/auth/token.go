package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

/* Creating JWT token */
func CreateToken(agentID string, privateKey []byte) (string, error) {
	key, err := jwt.ParseRSAPrivateKeyFromPEM(privateKey)
	if err != nil {
		return "", err
	}

	claims := jwt.MapClaims{
		"id":     agentID,
		"exp":    time.Now().Add(24 * time.Hour).Unix(),
		"issued": time.Now().Unix,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(key)
}
