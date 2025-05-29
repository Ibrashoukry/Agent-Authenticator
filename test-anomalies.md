# Extended Anomaly Test Scenarios

This file describes how to test all supported anomaly tags in the dashboard. For each scenario, use the appropriate JWT and curl commands. (Replace `<PASTE_JWT_HERE>` with a valid token for the agent.)

---

## 1. Rapid Requests ("Rapid requests")
Send two requests <100ms apart:

```
go run gen_token.go agent001
curl -H "Authorization: Bearer <PASTE_JWT_HERE>" http://localhost:8080/agent
curl -H "Authorization: Bearer <PASTE_JWT_HERE>" http://localhost:8080/agent
```

---

## 2. Frequent Rate Limit Violations ("Frequent rate limit violations")
Send more requests than allowed in a minute (limit is 10/min):

```
go run gen_token.go agent002
for i in {1..12}; do curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer <PASTE_JWT_HERE>" http://localhost:8080/agent; done
```

---

## 3. Request Spike Detected ("Request spike detected")
Send a burst of requests (e.g., 5+ in 1 second):

```
go run gen_token.go agent003
for i in {1..6}; do curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer <PASTE_JWT_HERE>" http://localhost:8080/agent & done; wait
```

---

## 4. Repeated Auth Failures ("Repeated auth failures")
Send several requests with an invalid JWT:

```
for i in {1..5}; do curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer invalidtoken" http://localhost:8080/agent; done
```

---

## 5. Multiple IPs Detected ("Multiple IPs detected")
Send requests for the same agent from two different machines or use curl with --interface to spoof IPs (if supported):

```
# On two different machines or using two different network interfaces:
curl -H "Authorization: Bearer <PASTE_JWT_HERE>" http://localhost:8080/agent
# (repeat from another IP)
```

---

## 6. Suspicious Payload ("Suspicious payload")
Send a request with an unexpected payload (e.g., POST with weird data):

```
curl -X POST -H "Authorization: Bearer <PASTE_JWT_HERE>" -d '{"foo": "bar", "unexpected": 12345}' http://localhost:8080/agent
```

---

## 7. Inactivity Burst Anomaly ("Inactivity burst anomaly")
Wait 3+ minutes without requests, then send several requests quickly:

```
# Wait 3+ minutes, then:
for i in {1..3}; do curl -H "Authorization: Bearer <PASTE_JWT_HERE>" http://localhost:8080/agent; done
```



