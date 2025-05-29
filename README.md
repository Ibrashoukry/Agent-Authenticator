# AI Agent Auth Gateway (Zero-Trust Authentication for AI Agents)

This project is a secure, zero-trust authentication gateway for AI agents.

## Tech Stack
- **Go** (Golang) for backend, middleware, and monitoring
- **Bootstrap 5** for dashboard UI
- **Chart.js** for live charts
- **YAML** for agent config
- **JWT (RS256)** for authentication

## Quick Start
1. **Install Go** (if not already): https://go.dev/dl/
2. **Run the server:**
   ```zsh
   go run cmd/server/main.go
   ```
3. **Generate a JWT for an agent:**
   ```zsh
   go run gen_token.go agent001
   ```
4. **Test authentication:**
   ```zsh
   curl -H "Authorization: Bearer <PASTE_JWT_HERE>" http://localhost:8080/agent
   ```
5. **View the dashboard:**
   Open [http://localhost:8080/dashboard/](http://localhost:8080/dashboard/) in your browser.

## Prototype Tests
- **Valid/invalid JWTs**: Try with and without a valid token.
- **Rate limiting**: Send >10 requests/minute for an agent to trigger rate limiting.
- **Anomaly detection**: Send rapid requests, request spikes, or use multiple IPs to see anomaly tags in the dashboard.
- **Live monitoring**: All agent activity, requests, and anomalies are visible in real time on the dashboard.

See `test-scenarios.md` and `test-anomalies.md` for more detailed test cases and curl scripts.

---

**Note:** This is a prototype for research and demonstration. For production, use persistent storage, secure key management, and production-grade JWT validation.
