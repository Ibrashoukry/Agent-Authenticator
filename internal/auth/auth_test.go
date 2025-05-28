package auth

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

type agentYAML struct {
	AgentID      string  `yaml:"AgentID"`
	PublicKey    string  `yaml:"PublicKey"`
	Registered   string  `yaml:"Registered"`
	LastActive   string  `yaml:"LastActive"`
	RateLimit    int     `yaml:"RateLimit"`
	AnomalyScore float64 `yaml:"AnomalyScore"`
}

type agentsList struct {
	Agents []agentYAML `yaml:"agents"`
}

func TestCreateAndVerifyToken(t *testing.T) {
	// Load agents from YAML file
	yamlPath := "../../configs/agents.yaml"
	data, err := os.ReadFile(yamlPath)
	if err != nil {
		t.Fatalf("failed to read agents.yaml: %v", err)
	}

	var agents agentsList
	if err := yaml.Unmarshal(data, &agents); err != nil {
		t.Fatalf("failed to unmarshal agents.yaml: %v", err)
	}

	for _, a := range agents.Agents {
		t.Run(a.AgentID, func(t *testing.T) {
			agent := Agent{
				AgentID: a.AgentID,
			}

			keyDir := "../../configs/keys"
			privPath := filepath.Join(keyDir, agent.AgentID+".key")
			pubPath := filepath.Join(keyDir, agent.AgentID+".pub")

			privateKey, err := os.ReadFile(privPath)
			if err != nil {
				t.Skipf("skipping %s: missing private key: %v", agent.AgentID, err)
			}

			token, err := CreateToken(agent.AgentID, privateKey)
			if err != nil {
				t.Errorf("failed to create token for %s: %v", agent.AgentID, err)
				return
			}

			publicKey, err := os.ReadFile(pubPath)
			if err != nil {
				t.Skipf("skipping %s: missing public key: %v", agent.AgentID, err)
			}

			req := httptest.NewRequest("GET", "/protected", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			rr := httptest.NewRecorder()

			handler := VerifyToken(publicKey, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("expected 200 OK for %s, got %d", agent.AgentID, rr.Code)
			}
		})
	}
}
