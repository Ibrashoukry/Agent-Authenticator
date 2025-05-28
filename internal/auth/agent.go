package auth

import (
	"time"
)

/* Agent Registration */
type Agent struct {
	AgentID      string    // unique agent id
	PublicKey    string    // PEM-encoded RSA public key
	Registered   time.Time // registration timestamp
	LastActive   time.Time // last active timestamp
	RateLimit    int       // requests per time window
	AnomalyScore float64   // for anomaly detection
}
