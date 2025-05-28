package auth

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestCreateAndVerifyToken(t *testing.T) {
	// Simulate agent registration
	agent := Agent{
		AgentID:    "agent-001",
		Registered: time.Now(),
	}

	// Load private key (PEM) for signing
	privateKey, err := os.ReadFile("../../configs/keys/agent-001.key")
	if err != nil {
		t.Fatalf("failed to read private key: %v", err)
	}

	// Create JWT token for agent
	token, err := CreateToken(agent.AgentID, privateKey)
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	// Load public key (PEM) for verification
	publicKey, err := os.ReadFile("../../configs/keys/agent-001.pub")
	if err != nil {
		t.Fatalf("failed to read public key: %v", err)
	}

	// Prepare a test HTTP request with the JWT in the Authorization header
	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	// Use your VerifyToken middleware
	handler := VerifyToken(publicKey, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", rr.Code)
	}
}
