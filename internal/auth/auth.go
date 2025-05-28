package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

/* JWT token verification */
func VerifyToken(publicKey []byte, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		key, err := jwt.ParseRSAPublicKeyFromPEM(publicKey)
		if err != nil {
			http.Error(w, "Invalid public key", http.StatusInternalServerError)
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return key, nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Context key for agent ID
var agentIDKey = &struct{}{}

// ExtractAgentIDFromJWT parses the JWT, verifies it with the correct public key, and returns the agent ID (sub claim)
func ExtractAgentIDFromJWT(tokenString string, agentKeys map[string]string) (string, error) {
	var agentID string
	var pubKeyPath string
	var found bool

	// Parse JWT without verifying to get the sub claim
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return "", err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("invalid claims")
	}
	sub, ok := claims["sub"].(string)
	if !ok {
		return "", errors.New("missing sub claim")
	}
	agentID = sub
	pubKeyPath, found = agentKeys[agentID]
	if !found {
		return "", errors.New("unknown agent")
	}
	pubKey, err := ioutil.ReadFile(pubKeyPath)
	if err != nil {
		return "", err
	}
	// Now verify the token
	verifiedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return jwt.ParseRSAPublicKeyFromPEM(pubKey)
	})
	if err != nil || !verifiedToken.Valid {
		return "", errors.New("invalid token signature")
	}
	return agentID, nil
}

// WithAgentID sets the agent ID in the context
func WithAgentID(ctx context.Context, agentID string) context.Context {
	return context.WithValue(ctx, agentIDKey, agentID)
}

// GetAgentID retrieves the agent ID from the context
func GetAgentID(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(agentIDKey).(string)
	return id, ok
}

// GenerateAndRotateKey generates a new RSA key pair and writes to disk, returns PEM-encoded private and public keys
func GenerateAndRotateKey(agentID, keyDir string) (privPEM, pubPEM []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	privBytes := x509.MarshalPKCS1PrivateKey(key)
	privPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})
	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	pubPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	// Write to disk
	privPath := keyDir + "/" + agentID + ".key"
	pubPath := keyDir + "/" + agentID + ".pub"
	if err := os.WriteFile(privPath, privPEM, 0600); err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(pubPath, pubPEM, 0644); err != nil {
		return nil, nil, err
	}
	return privPEM, pubPEM, nil
}

// TODO: Add background job for periodic key rotation and cleanup
