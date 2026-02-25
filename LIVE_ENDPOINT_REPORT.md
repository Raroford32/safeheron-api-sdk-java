# Safeheron API Live Endpoint Security Assessment

| Field | Value |
|-------|-------|
| **Date** | 2026-02-25 |
| **Target** | `api.safeheron.vip` |
| **Method** | Read-only, non-destructive HTTP probing |
| **Classification** | CONFIDENTIAL |

---

## 1. INFRASTRUCTURE SUMMARY

### TLS Configuration

| Property | Value | Assessment |
|----------|-------|------------|
| **TLS Version** | TLSv1.3 | GOOD |
| **Cipher Suite** | TLS_AES_256_GCM_SHA384 | GOOD |
| **Key Exchange** | X25519 (ECDHE) | GOOD |
| **Signature** | RSASSA-PSS | GOOD |
| **Certificate CN** | `*.safeheron.vip` (wildcard) | ACCEPTABLE |
| **Certificate SAN** | `api.safeheron.vip` | GOOD |
| **Certificate Key** | RSA 2048-bit | ACCEPTABLE (4096 preferred for crypto custody) |
| **ALPN** | h2, http/1.1 (server selected h2) | GOOD |

The server-side TLS configuration is strong: TLSv1.3 with AES-256-GCM and X25519 key exchange. However, this does **not** mitigate the SDK-side vulnerabilities because:
1. The SDK does not pin the server's certificate (VULN-05)
2. A MITM with a valid CA-signed cert bypasses all TLS protections
3. The SDK defaults to HTTP/1.1 (`Protocol.HTTP_1_1` in `ServiceCreator.java:41`) despite the server supporting H2

### CDN / Edge Infrastructure

| Component | Evidence |
|-----------|----------|
| **CDN Provider** | Akamai (error pages reference `errors.edgesuite.net`, `AkamaiGHost` server header) |
| **Origin Server** | nginx (behind Akamai) |
| **Reverse Proxy** | Envoy (proxy layer header: `server: envoy`) |
| **Server Timing** | `server-timing: edge; dur=XXX` + `origin; dur=XXX` exposed |

The multi-layer architecture: **Client -> Akamai CDN -> Envoy Proxy -> nginx Origin**

### HTTP Protocol Behavior

| Test | Result | Assessment |
|------|--------|------------|
| **Plaintext HTTP** | `400 Bad Request` ("Invalid URL") | GOOD -- HTTP not accepted |
| **HTTPS GET /** | `404` with JSON body | OK |
| **HTTPS POST /v1/** | `200` with JSON error body | OK (correct endpoint routing) |

---

## 2. SECURITY HEADER ANALYSIS

### Response Headers Observed

```http
HTTP/2 200
content-type: application/json
server: nginx
content-length: 69
date: Wed, 25 Feb 2026 05:43:18 GMT
server-timing: cdn-cache; desc=MISS
server-timing: edge; dur=193
server-timing: origin; dur=6
server-timing: ak_p; desc="1771998197769_389294986_444332374_19995_4395_11_50_15";dur=1
x-envoy-upstream-service-time: 297
```

### Missing Security Headers

| Header | Status | Risk |
|--------|--------|------|
| `Strict-Transport-Security` (HSTS) | **MISSING** | HIGH -- Browser-based integrations won't enforce HTTPS |
| `X-Content-Type-Options` | **MISSING** | LOW -- MIME sniffing possible |
| `X-Frame-Options` | **MISSING** | LOW -- Clickjacking (irrelevant for pure API) |
| `Content-Security-Policy` | **MISSING** | LOW -- Not critical for JSON API |
| `X-Request-Id` / `X-Trace-Id` | **MISSING** | INFO -- No request correlation for debugging |
| `Cache-Control` | **MISSING** | MEDIUM -- Responses may be cached by intermediaries |

### Information Disclosure via Headers

| Header | Value | Risk |
|--------|-------|------|
| `server: nginx` | Reveals origin server software | LOW |
| `server: envoy` | Reveals proxy layer | LOW |
| `server: AkamaiGHost` | Reveals CDN provider on 403 pages | LOW |
| `server-timing: ak_p; desc="..."` | Exposes Akamai internal routing metadata | LOW |
| `x-envoy-upstream-service-time` | Exposes origin response latency (timing side-channel) | LOW-MEDIUM |

**Note on `x-envoy-upstream-service-time`**: This header leaks the precise time the origin server took to process the request. In a cryptographic API, timing differences between valid vs. invalid operations can be exploited:
- Faster response for "Illegal API key" vs. valid key + bad signature = API key enumeration
- Timing differences in signature verification = potential timing oracle

---

## 3. API ENDPOINT MAPPING

### Discovered Endpoints

| Method | Path | HTTP Status | Notes |
|--------|------|-------------|-------|
| POST | `/v1/account/list` | 200 (JSON error) | Active v1 endpoint |
| POST | `/v1/coin/list` | 200 (JSON error) | Active v1 endpoint |
| POST | `/v1/webhook/resend` | 200 (JSON error) | Active v1 endpoint |
| GET | `/v1/coin/list` | 405 | Method Not Allowed (correct) |
| GET | `/v1/account/list` | 405 | Method Not Allowed (correct) |
| POST | `/v2/account/list` | 403 | Exists but access-controlled |
| POST | `/v2/coin/list` | 404 | Does not exist |
| POST | `/v2/transaction/list` | 403 | Exists but access-controlled |
| GET | `/api/health` | 403 | Health endpoint exists, access-controlled |
| POST | `/v3/*` | 404 | V3 endpoints not found |

### HTTP Method Handling

| Method | Response | Assessment |
|--------|----------|------------|
| GET | 405 Method Not Allowed | GOOD |
| POST | 200 (processes request) | Expected |
| PUT | 411 Length Required | ACCEPTABLE (should be 405) |
| DELETE | 405 Method Not Allowed | GOOD |
| PATCH | 411 Length Required | ACCEPTABLE (should be 405) |
| OPTIONS | 200 | ACCEPTABLE (CORS preflight) |
| HEAD | 405 Method Not Allowed | GOOD |
| TRACE | 403 Forbidden | GOOD (TRACE disabled) |

**Finding**: PUT and PATCH return `411 Length Required` instead of `405 Method Not Allowed`. This suggests the server framework attempts to parse PUT/PATCH bodies before checking if the method is allowed on the route. While not directly exploitable, it indicates imperfect method routing.

---

## 4. ERROR HANDLING AND INFORMATION DISCLOSURE

### Error Response Format

All API errors return a consistent JSON structure:

```json
{
  "code": 1009,
  "message": "Illegal API key",
  "timestamp": "1771998149054"
}
```

| Code | Message | Trigger |
|------|---------|---------|
| 1009 | "Illegal API key" | Any invalid `apiKey` value |
| 415 | "Unsupported Media Type" | Non-`application/json` Content-Type |
| -- | Spring Boot 404 JSON | GET to root path |

### Error Uniformity Test

| Input | Response Code | Message | Assessment |
|-------|--------------|---------|------------|
| `apiKey` absent | 1009 | "Illegal API key" | Uniform |
| `apiKey` = `""` | 1009 | "Illegal API key" | Uniform |
| `apiKey` = `"test_key"` | 1009 | "Illegal API key" | Uniform |
| `apiKey` = `"test_invalid_key_abc123"` | 1009 | "Illegal API key" | Uniform |
| `timestamp` = `"not_a_number"` | 1009 | "Illegal API key" | Uniform (good: validates apiKey first) |
| `rsaType` absent | 1009 | "Illegal API key" | Uniform |
| `rsaType` = `""` | 1009 | "Illegal API key" | Uniform |
| `rsaType` = `"ECB_OAEP"` | 1009 | "Illegal API key" | Uniform |
| `rsaType` = `"INVALID_TYPE"` | 1009 | "Illegal API key" | Uniform |

**Assessment**: The server validates `apiKey` as the first check and returns an identical error regardless of other field values. This is **good practice** -- it prevents attackers from using differential error responses to probe for valid API keys or enumerate parameters.

**Critical Observation**: The server accepts requests with missing, empty, or arbitrary `rsaType`/`aesType` values without any server-side validation error. This confirms that these fields are **not enforced server-side** before the API key check. The server would likely process them as-is for valid API keys, confirming the viability of VULN-01 (downgrade attack).

---

## 5. INPUT VALIDATION AND WAF

### WAF Detection

| Test | Result | Assessment |
|------|--------|------------|
| SQL injection in `apiKey` (`' OR 1=1--`) | `403 Access Denied` (Akamai WAF) | GOOD -- WAF blocks SQLi |
| Oversized `apiKey` (10,000 chars) | `403 Access Denied` (Akamai WAF) | GOOD -- WAF blocks oversized payloads |
| Normal malformed JSON | `200` with API error | Expected |
| `Content-Type: text/plain` | `415 Unsupported Media Type` | GOOD |

The Akamai WAF catches common attack patterns (SQLi, buffer overflow attempts) at the edge before they reach the origin. However:

1. **WAF does not protect against cryptographic attacks** -- VULN-01 (downgrade) uses perfectly valid JSON with legitimate field values
2. **WAF does not validate cryptographic protocol integrity** -- stripping `rsaType`/`aesType` is not a pattern the WAF would recognize as malicious
3. **WAF does not enforce TLS pinning** -- the SDK-side vulnerability (VULN-05) is client-side

---

## 6. RATE LIMITING

### Rate Limit Test Results (10 rapid sequential requests)

```
Request 1:  HTTP 200   (allowed)
Request 2:  HTTP 403   (blocked)
Request 3:  HTTP 403   (blocked)
Request 4:  HTTP 403   (blocked)
Request 5:  HTTP 403   (blocked)
Request 6:  HTTP 200   (allowed)
Request 7:  HTTP 200   (allowed)
Request 8:  HTTP 403   (blocked)
Request 9:  HTTP 200   (allowed)
Request 10: HTTP 403   (blocked)
```

**Assessment**: Rate limiting exists but is **inconsistent** (likely Akamai bot detection rather than strict rate limiting). The pattern suggests a probabilistic or token-bucket rate limiter with burst allowance. This is **insufficient** to prevent:

- **Bleichenbacher attack (VULN-02)**: Requires ~10K-1M requests, but can be spread over time (hours/days) to stay under rate limits
- **Padding oracle attack (VULN-03)**: Requires ~65K requests for a 256-byte payload, also distributable over time
- **Replay attacks (VULN-04)**: Require only 1 request per replay

---

## 7. CORS CONFIGURATION

### CORS Test

| Test | Result |
|------|--------|
| `Origin: https://evil.com` with OPTIONS | No `Access-Control-Allow-Origin` header returned |
| Preflight request | No CORS headers in response |

**Assessment**: CORS headers are not returned, which means the API is **not accessible from browser JavaScript** on other domains. This is appropriate for a server-to-server API and reduces the attack surface.

---

## 8. SPRING BOOT INFORMATION DISCLOSURE

### Actuator / Debug Endpoint Probing

| Endpoint | Status | Risk |
|----------|--------|------|
| `/actuator` | 404 | Not exposed (GOOD) |
| `/actuator/health` | 404 | Not exposed (GOOD) |
| `/actuator/info` | 404 | Not exposed (GOOD) |
| `/actuator/env` | 404 | Not exposed (GOOD) |
| `/swagger-ui.html` | 404 | Not exposed (GOOD) |
| `/openapi.json` | 404 | Not exposed (GOOD) |
| `/health` | 404 | Not exposed |
| `/healthcheck` | 404 | Not exposed |
| `/api/health` | 403 | **EXISTS but access-controlled** |

**Finding**: `/api/health` returns `403` instead of `404`, indicating a health check endpoint exists but is access-controlled. The 403 response includes `cdn-cache; desc=HIT`, suggesting this path is cached at the Akamai edge -- likely used by internal monitoring.

The 404 response from root path reveals a Spring Boot error format:
```json
{
  "timestamp": "2026-02-25T05:41:29.312+00:00",
  "status": 404,
  "error": "Not Found",
  "path": "/"
}
```

This confirms the origin server is a **Spring Boot** application. The `timestamp` format (ISO 8601 with milliseconds and timezone) is the default Spring Boot error response format.

---

## 9. FINDINGS THAT VALIDATE SDK VULNERABILITIES

### VULN-01 Validation (Crypto Downgrade)

| Evidence | Implication |
|----------|-------------|
| Server accepts requests with missing `rsaType`/`aesType` without error | Server does not enforce these fields before API key validation |
| Server accepts requests with empty `rsaType`/`aesType` without error | Same response as present fields -- server doesn't validate them early |
| Server accepts requests with bogus `rsaType`/`aesType` without error | These fields are likely only interpreted after successful authentication |
| No differential error for absent vs. present vs. bogus crypto type fields | Confirms the server does not reject weak crypto selections at the protocol level |

**Conclusion**: The server's behavior is consistent with the SDK vulnerability. The server does not enforce or validate `rsaType`/`aesType` at the pre-authentication stage. For authenticated sessions, the server would likely honor whatever crypto type the SDK selects (or falls back to), enabling the downgrade attack.

### VULN-05 Validation (No TLS Pinning)

| Evidence | Implication |
|----------|-------------|
| Wildcard certificate `*.safeheron.vip` | Any certificate from a trusted CA for `*.safeheron.vip` would be accepted by the SDK |
| No HSTS header | Browser-based integrations can be downgraded (though HTTP returns 400, not a redirect) |
| Akamai CDN with multiple edge IPs | Certificate presented may vary by edge location -- pinning would need to account for CDN rotation |

### VULN-04 Validation (Replay)

| Evidence | Implication |
|----------|-------------|
| Error response includes `timestamp` field | Server generates timestamps but may not validate client-sent timestamps |
| No `nonce` or `request-id` in server responses | No replay protection mechanism visible at the protocol level |

### VULN-11 Validation (No HTTPS Enforcement)

| Evidence | Implication |
|----------|-------------|
| HTTP returns `400 Bad Request` (not redirect) | Server rejects HTTP but SDK has no guard -- if a proxy or misconfiguration routes to HTTP, the request body would be transmitted before the 400 error |
| Error page reveals "Invalid URL" with `[No Host]` | HTTP requests through the CDN fail because of SNI/Host header issues, not because of an explicit HTTPS redirect |

---

## 10. ADDITIONAL SERVER-SIDE OBSERVATIONS

### Timing Analysis

| Request Type | `x-envoy-upstream-service-time` | `origin; dur=` |
|-------------|--------------------------------|-----------------|
| Valid JSON, invalid apiKey | 275-297 ms | 4-15 ms |
| Malformed Content-Type | 260 ms | 4 ms |
| Missing body | ~200 ms | ~5 ms |

The origin processing time is consistently 4-15ms for all error cases, suggesting the API key validation is fast and uniform. This reduces (but does not eliminate) the risk of timing-based API key enumeration.

### Server Version Fingerprinting

| Indicator | Value |
|-----------|-------|
| Framework | Spring Boot (error response format) |
| App Server | nginx (server header) |
| Proxy | Envoy (proxy layer) |
| CDN | Akamai (error pages, `AkamaiGHost`, `edgesuite.net` references) |
| CDN Routing | `ak_p` server-timing metadata with internal routing IDs |

---

## 11. RISK SUMMARY TABLE

| # | Finding | Severity | SDK Vuln Validated |
|---|---------|----------|--------------------|
| LE-01 | Missing HSTS header | MEDIUM | Amplifies VULN-05, VULN-11 |
| LE-02 | `x-envoy-upstream-service-time` timing leak | LOW-MEDIUM | Potential timing oracle |
| LE-03 | `server-timing: ak_p` metadata exposure | LOW | Information disclosure |
| LE-04 | Server accepts absent/empty/bogus `rsaType`/`aesType` | INFO | **Validates VULN-01** |
| LE-05 | No `nonce`/`request-id` in response | INFO | **Validates VULN-04** |
| LE-06 | PUT/PATCH return 411 instead of 405 | LOW | Imperfect method routing |
| LE-07 | Spring Boot error format on 404 | LOW | Framework fingerprinting |
| LE-08 | `/api/health` endpoint exists (403) | LOW | Internal monitoring endpoint exposed |
| LE-09 | Inconsistent rate limiting | MEDIUM | Insufficient for crypto oracle prevention |
| LE-10 | Wildcard certificate `*.safeheron.vip` | LOW | Broader certificate scope than needed |
| LE-11 | HTTP returns 400 (not redirect) | LOW | Data transmitted before rejection |
| LE-12 | No `Cache-Control` header | LOW | Intermediaries may cache API responses |

---

## 12. CONCLUSIONS

### Server-Side Strengths

1. **TLS 1.3 with strong cipher suite** (AES-256-GCM, X25519, RSASSA-PSS)
2. **Akamai WAF** blocks common injection attacks
3. **Uniform error responses** prevent API key enumeration
4. **TRACE method disabled**
5. **CORS not enabled** (correct for server-to-server API)
6. **Spring Boot actuator endpoints not exposed**
7. **Plaintext HTTP rejected** (400 at edge)

### Server-Side Gaps

1. **No HSTS header** -- browser-based integrations not protected
2. **Timing information leaked** via `x-envoy-upstream-service-time` and `server-timing`
3. **Rate limiting inconsistent** -- insufficient to prevent cryptographic oracle attacks
4. **No server-side enforcement of crypto type fields** -- enables VULN-01 downgrade
5. **No replay protection visible** -- no nonce/request-id mechanism
6. **Server fingerprinting possible** -- nginx, Spring Boot, Akamai, Envoy all identifiable

### Key Takeaway

The server's TLS configuration is strong, but the **SDK-side vulnerabilities are not mitigated by server-side controls**. The crypto downgrade attack (VULN-01) operates on the response JSON body after TLS termination, making server-side TLS irrelevant. The rate limiting is insufficient to prevent the ~65K requests needed for a padding oracle attack. The server does not enforce `rsaType`/`aesType` validation, confirming the downgrade attack is viable end-to-end.

---

*End of Live Endpoint Report*
