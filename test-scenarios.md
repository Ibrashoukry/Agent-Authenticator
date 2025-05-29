# Agent Gateway Test Scenarios

This file describes test cases and provides curl commands/scripts to simulate different agent activities, rate limiting, and anomaly detection for your AI Agent Auth Gateway.

---

## 1. Valid Agent Authentication

Generate a JWT for `agent001`:

```
go run gen_token.go agent001
```

Use the output token in the following curl command:

```
curl -v -H "Authorization: Bearer <PASTE_JWT_HERE>" http://localhost:8080/agent
```

Expected: HTTP 200, response contains `Authenticated agent: agent001`.

---

## 2. Invalid JWT (wrong signature)

Edit the JWT (change a character) and try:

```
curl -v -H "Authorization: Bearer <PASTE_BROKEN_JWT_HERE>" http://localhost:8080/agent
```

Expected: HTTP 401, response contains `Invalid token`.

---

## 3. Missing Authorization Header

```
curl -v http://localhost:8080/agent
```

Expected: HTTP 401, response contains `Missing Bearer token`.

---

## 4. Rate Limiting (exceed limit)

Generate a JWT for `agent002`:

```
go run gen_token.go agent002
```

Send 11 requests in quick succession (limit is 10/min):

```
for i in {1..11}; do curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer <PASTE_JWT_HERE>" http://localhost:8080/agent; done
```

Expected: First 10 requests return 200, 11th returns 429 (rate limit exceeded).

---

## 5. Anomaly Detection (rapid requests)

Generate a JWT for `agent003`:

```
go run gen_token.go agent003
```

Send 2 requests with less than 100ms between them:

```
curl -H "Authorization: Bearer <PASTE_JWT_HERE>" http://localhost:8080/agent
curl -H "Authorization: Bearer <PASTE_JWT_HERE>" http://localhost:8080/agent
```

Expected: Second request is flagged as anomaly (see logs and dashboard).

---

## 6. Dashboard Monitoring

Visit:

```
http://localhost:8080/dashboard/
```

You should see agent activity, requests, anomalies, and raw data update in real time as you run the above tests.

---

## 7. Multiple Agents

Generate tokens for `agent004` and `agent005` and repeat the above tests to see dashboard updates for multiple agents.

---

## 8. Invalid Agent (not in YAML)

Generate a JWT for a non-existent agent (e.g., `agent999`):

```
go run gen_token.go agent999
```

Try a request:

```
curl -v -H "Authorization: Bearer <PASTE_JWT_HERE>" http://localhost:8080/agent
```

Expected: HTTP 401, response contains `Invalid token`.

---

## 9. Expired Token

(Manually edit the `exp` claim in the JWT payload to a past timestamp, re-sign if needed, and try the request.)

Expected: HTTP 401, response contains `Invalid token`.

---

## 10. Raw Data Debugging

After running tests, check the Raw Data section in the dashboard for agent stats and anomalies.

---

**Tip:**
- Use the logs for detailed anomaly and authentication traces.
- Use the dashboard for a live view of agent activity and anomalies.
