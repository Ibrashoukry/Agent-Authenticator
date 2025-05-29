package monitor

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

type AgentStatus struct {
	AgentID    string    `json:"agent_id"`
	LastActive time.Time `json:"last_active"`
	Requests   int       `json:"requests"`
	Anomalies  []string  `json:"anomalies"`
}

type DashboardData struct {
	Agents    []AgentStatus `json:"agents"`
	Timestamp time.Time     `json:"timestamp"`
}

var (
	dashboardMu   sync.Mutex
	dashboardData = DashboardData{Timestamp: time.Now()}
)

// UpdateAgentStatus is called by middleware to update agent stats
func UpdateAgentStatus(agentID string, lastActive time.Time, anomalyTags []string) {
	dashboardMu.Lock()
	defer dashboardMu.Unlock()
	found := false
	for i, a := range dashboardData.Agents {
		if a.AgentID == agentID {
			dashboardData.Agents[i].LastActive = lastActive
			dashboardData.Agents[i].Requests++
			if len(anomalyTags) > 0 {
				// Merge new anomaly tags, avoid duplicates
				tagsMap := make(map[string]struct{})
				for _, t := range dashboardData.Agents[i].Anomalies {
					tagsMap[t] = struct{}{}
				}
				for _, t := range anomalyTags {
					tagsMap[t] = struct{}{}
				}
				merged := make([]string, 0, len(tagsMap))
				for t := range tagsMap {
					merged = append(merged, t)
				}
				dashboardData.Agents[i].Anomalies = merged
			}
			found = true
			break
		}
	}
	if !found {
		dashboardData.Agents = append(dashboardData.Agents, AgentStatus{
			AgentID:    agentID,
			LastActive: lastActive,
			Requests:   1,
			Anomalies:  anomalyTags,
		})
	}
	dashboardData.Timestamp = time.Now()
}

// Handler for /monitor endpoint
func DashboardHandler(w http.ResponseWriter, r *http.Request) {
	dashboardMu.Lock()
	data := dashboardData
	dashboardMu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}
