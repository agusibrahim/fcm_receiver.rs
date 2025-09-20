# Building an FCM Receiver from Scratch (Unofficial Flow)

This document explains, end to end, how to build an FCM (Firebase Cloud Messaging) client that can receive messages and subscribe to topics without the Firebase SDK. The flow mirrors what the legacy Play Services implementation does internally. Every step includes why it is required, the exact requests, and the expected responses so you can reproduce it in any language.

---
## 1. Device Emulation & Check-In

FCM expects devices to identify themselves using Android device metadata. The first step is to perform an **Android Check-In**, which yields an `androidId` and `securityToken`. You will use them later for all authenticated requests.

### Request
- **URL**: `https://android.clients.google.com/checkin`
- **Method**: `POST`
- **Headers**: `Content-Type: application/x-protobuf`
- **Body**: serialize an `AndroidCheckinRequest` proto. Key fields:
  - `checkin.type` = 3 (device)
  - `checkin.build.device`, `checkin.build.product`, `checkin.build.version.sdk` – supply realistic Android build info (e.g. model `samsung/a21s`, SDK `29`).
  - `locale` (`en_US`), `timezone` (`GMT`), `logging_id` (optional).
  - If this is the first run, leave `androidId` and `securityToken` zeroed.

> **Implementation tip**: You can craft this payload manually (proto definitions are public) or reuse existing encoders. The server expects a valid proto; otherwise you receive `400` or no response.

### Response
- **Content-Type**: `application/x-protobuf`
- **Message**: `AndroidCheckinResponse`
- **Fields of interest**:
  - `androidId` (`uint64`)
  - `securityToken` (`uint64`)
  - `digest` (resource version hints; optional)

Store `androidId` and `securityToken`. They are the credentials you will use later with the `AidLogin` scheme.

---
## 2. Obtain an FCM Registration Token

Next, register the device with GCM/FCM. This returns the token that downstream messages target.

### Request
- **URL**: `https://android.clients.google.com/c2dm/register3`
- **Method**: `POST`
- **Headers**:
  - `Authorization: AidLogin <androidId>:<securityToken>`  (values from step 1)
  - `Content-Type: application/x-www-form-urlencoded`
- **Body** (URL-encoded key/value pairs). Required fields:
  - `X-subtype` – for legacy use, set to project sender ID; for headless receivers we can use the Firebase `appId` or a placeholder.
  - `sender` – either the same ID as subtype, or the 65-byte public key when emulating Chrome. For simplicity, use the same value as `X-subtype`.
  - `device` – the `androidId` from check-in.
  - `app` – package name; if you do not impersonate a real APK, use `org.chromium.linux` or similar.
  - `cert` – SHA1 fingerprint of the signing certificate; optional for headless usage. When omitted, Google still accepts the request.
  - `app_ver`, `X-app_ver` – version numbers (use `1`).
  - `X-gms_app_id` – the Firebase `appId` you target (`1:<project-number>:android:<hash>`).
  - Noise parameters to mimic Play Services (recommended but not mandatory):
    - `X-osv=29`, `X-cliv=fiid-21.1.1`, `X-gmsv=220217001`, `X-scope=*`, `X-Firebase-Client=<detailed fingerprint>`, `X-Firebase-Client-Log-Type=1`, `X-app_ver_name=1`, `target_ver=31`.

Example curl:
```bash
curl -s "https://android.clients.google.com/c2dm/register3" \
  -H "Authorization: AidLogin <ANDROID_ID>:<SECURITY_TOKEN>" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "X-subtype=<SENDER_ID_OR_APPID>" \
  --data-urlencode "sender=<SENDER_ID_OR_APPID>" \
  --data-urlencode "device=<ANDROID_ID>" \
  --data-urlencode "app=org.chromium.linux" \
  --data-urlencode "app_ver=1" \
  --data-urlencode "X-gms_app_id=<APP_ID>" \
  --data-urlencode "X-osv=29" \
  --data-urlencode "X-cliv=fiid-21.1.1" \
  --data-urlencode "X-gmsv=220217001"
```

### Response
- Success: `token=<FCM_TOKEN>`
- Failure: `Error=<ERROR_CODE>`

Persist the returned `FCM_TOKEN`. You will receive messages and manage topics using this token.

---
## 3. Establish the MCS (Mobile Client Server) Connection

FCM pushes messages over a persistent socket called MCS (Mobile Client Server). You must implement the binary protocol (protobuf-based) and keep the connection alive.

### 3.1. TLS Connection
- Connect to `mtalk.google.com` on port `5228` (fallback ports `443`, `5230`, etc.).
- Wrap in TLS (no client certificate).
- **Example (Python)**
  ```python
  import socket
  import ssl

  def open_mcs_socket(host="mtalk.google.com", port=5228):
      raw = socket.create_connection((host, port))
      context = ssl.create_default_context()
      return context.wrap_socket(raw, server_hostname=host)

  sock = open_mcs_socket()
  ```

### 3.2. MCS Framing
MCS uses version-prefixed frames:
1. A single byte `version` (usually `41`, but accept `38` for backward compatibility).
2. A single byte `tag` (message type).
3. Varint `size` (payload length).
4. `size` bytes of protobuf payload, depending on `tag`.
- **Example (Python helper)**
  ```python
  def encode_frame(version, tag, payload):
      def encode_varint(value):
          out = bytearray()
          while True:
              byte = value & 0x7F
              value >>= 7
              if value:
                  out.append(byte | 0x80)
              else:
                  out.append(byte)
                  return bytes(out)
      return bytes([version]) + bytes([tag]) + encode_varint(len(payload)) + payload

  frame = encode_frame(41, 7, payload_bytes)  # 41 = version, 7 = LoginRequest
  sock.sendall(frame)
  ```

### 3.3. Login Handshake
- After establishing TLS, send `LoginRequest` (proto defined in `mcs.proto`). Important fields:
  - `auth_token`: `oauth2:<securityToken>` (example: `oauth2:2161691940600792139`).
  - `username`: the decimal `androidId` (example: `5164734579307925461`).
  - `id`: random session identifier (string).
  - `device_id`, `user`: `androidId` string with `android-` prefix.
  - `account_id`: `androidId` as string.
  - `setting`: include heartbeat interval, network type, etc.
 - **Example (Python + dynamic protobuf)**
  ```python
  import os
  from google.protobuf.internal import builder as _builder

  LOGIN_REQUEST_SCHEMA = """
  syntax = \"proto2\";

  message LoginRequest {
    optional string id = 7;
    optional string domain = 3;
    optional string user = 4;
    optional string resource = 5;
    optional string auth_token = 2;
    optional string device_id = 11;
    optional string account_id = 12;
    optional int32 network_type = 18;
    message Setting {
      optional string name = 1;
      optional string value = 2;
    }
    repeated Setting setting = 13;
  }
  """

  file_desc, _ = _builder._BuildFile(LOGIN_REQUEST_SCHEMA)
  proto_module = _builder.BuildModule(file_desc, __name__)
  LoginRequest = proto_module.LoginRequest

  def build_login_request(android_id, security_token):
      req = LoginRequest()
      req.id = os.urandom(4).hex()
      req.domain = "mcs.android.com"
      req.user = str(android_id)
      req.resource = str(android_id)
      req.device_id = f"android-{android_id:x}"
      req.network_type = 1  # WIFI
      req.auth_token = f"oauth2:{security_token}"
      req.account_id = str(android_id)
      setting = req.setting.add()
      setting.name = "client_alive_interval_ms"
      setting.value = str(5 * 60 * 1000)
      return req

  login = build_login_request(android_id=0x47A2F3EAF0E0D8B5, security_token=0x1DE5D3019342794B)
  payload = login.SerializeToString()

  def send_frame(sock, tag, data):
      version = b"\x29"  # 41 decimal
      tag_byte = bytes([tag])
      def encode_varint(value):
          out = bytearray()
          while True:
              byte = value & 0x7F
              value >>= 7
              if value:
                  out.append(byte | 0x80)
              else:
                  out.append(byte)
                  return bytes(out)
      frame = version + tag_byte + encode_varint(len(data)) + data
      sock.sendall(frame)

  send_frame(sock, tag=7, data=payload)  # 7 = LoginRequest

  def read_varint(sock):
      shift = 0
      result = 0
      while True:
          byte = sock.recv(1)
          if not byte:
              raise IOError("EOF")
          byte = byte[0]
          result |= (byte & 0x7F) << shift
          if not (byte & 0x80):
              return result
          shift += 7

  def recv_frame(sock):
      version = sock.recv(1)
      if not version:
          return None
      tag = sock.recv(1)[0]
      size = read_varint(sock)
      payload = sock.recv(size)
      return version[0], tag, payload

  _, tag, login_response = recv_frame(sock)
  assert tag == 8  # LoginResponse
  ```
- Wait for `LoginResponse`. This will confirm the session and may adjust heartbeat intervals.

### 3.4. Heartbeats
- Send `HeartbeatPing` periodically (default every 5 minutes).
- Upon receiving `HeartbeatAck`, update timestamp. If ack is missing beyond a threshold, reconnect.

### 3.5. Data Messages
- Incoming payloads arrive as `DataMessageStanza`:
  - Inspect `persistent_id` to deduplicate.
  - `app_data` contains metadata (key/value). Encrypted messages have `crypto-key` and `encryption` entries.
  - `raw_data` holds encrypted or plaintext payload bytes.
- After processing, schedule removal of `persistent_id` after its TTL to allow replays if necessary.

### 3.6. Acknowledging Messages
- Optionally send `Ack` (SelectiveAck / StreamAck) to confirm receipt. FCM tolerates clients that only maintain `persistent_id` cache, but acking is good practice.

---
## 4. Decryption of WebPush-Style Payloads

When `app_data` includes `crypto-key` and `encryption` values:
1. Extract `dh=` (Base64 URL) to obtain the sender’s ephemeral P-256 public key.
2. Extract `salt=` from the encryption string.
3. Perform ECDH using your stored private key (generated alongside FCM registration) to derive the shared secret.
4. Run HKDF to produce the content-encryption key and nonce (per RFC 8188).
5. Decrypt `raw_data` using AES256-GCM (`12-byte nonce`, `16-byte tag`).

Use libraries such as `ece`, `http_ece`, or implement AES-GCM + HKDF manually.

---
## 5. Topic Subscription (Without OAuth)

To bind the existing `FCM_TOKEN` to a topic, reuse the `register3` endpoint with slightly altered parameters.

### 5.1. Subscribe
- Same URL and headers as registration.
- Body differences:
  - `X-subtype=<FCM_TOKEN>`
  - `sender=<FCM_TOKEN>`
  - `X-gcm.topic=/topics/<name>`
  - `X-scope=/topics/<name>`
  - `X-subscription=<FCM_TOKEN>`
  - `X-kid=|ID|<random>|`
  - Optional `app`, `cert`, etc.; include all base parameters (`device`, `app_ver`, etc.) as before.

Example:
```bash
curl -s "https://android.clients.google.com/c2dm/register3" \
  -H "Authorization: AidLogin <ANDROID_ID>:<SECURITY_TOKEN>" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "X-subtype=<FCM_TOKEN>" \
  --data-urlencode "sender=<FCM_TOKEN>" \
  --data-urlencode "device=<ANDROID_ID>" \
  --data-urlencode "app=org.chromium.linux" \
  --data-urlencode "app_ver=1" \
  --data-urlencode "X-gms_app_id=<APP_ID>" \
  --data-urlencode "X-gcm.topic=/topics/news" \
  --data-urlencode "X-scope=/topics/news" \
  --data-urlencode "X-subscription=<FCM_TOKEN>" \
  --data-urlencode "X-kid=|ID|123456|"
```

- Response `token=|ID|...|:` indicates success.
- `Error=...` indicates failure (retry/backoff as needed).

### 5.2. Unsubscribe
- Same as subscribe, plus:
  - `delete=1`
  - `X-delete=1`

Example:
```bash
curl -s "https://android.clients.google.com/c2dm/register3" \
  -H "Authorization: AidLogin <ANDROID_ID>:<SECURITY_TOKEN>" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "X-subtype=<FCM_TOKEN>" \
  --data-urlencode "sender=<FCM_TOKEN>" \
  --data-urlencode "device=<ANDROID_ID>" \
  --data-urlencode "delete=1" \
  --data-urlencode "X-delete=1" \
  --data-urlencode "X-gcm.topic=/topics/news" \
  --data-urlencode "X-scope=/topics/news" \
  --data-urlencode "X-subscription=<FCM_TOKEN>" \
  --data-urlencode "X-kid=|ID|987654|"
```

---
## 6. Persistent Storage

Maintain durable storage containing:
- `androidId` and `securityToken`
- `FCM_TOKEN` and (optional) `GCM_TOKEN`
- Private key + auth secret for decrypting payloads
- Optional local cache of subscribed topics (for UI only; server keeps authoritative state)

Ensure you reload these on restart before attempting to reconnect or subscribe to topics.

---
## 7. Error Handling & Retry Strategy

- **Check-In**: Retry on network failures. If the device already has credentials, you can reuse them instead of re-checking in.
- **Register/subscribe/unsubscribe**: Implement exponential backoff for `SERVICE_NOT_AVAILABLE`. Treat `INVALID_PARAMETERS` as validation failures (fix input and retry manually).
- **MCS**: Reconnect if heartbeat ACKs aren’t received in time or you get a `Close` stanza. Re-run the login handshake after reconnecting.
- **Decryption**: If `crypto-key`/`encryption` headers are missing, treat message as plaintext. If decryption fails, report error but continue listening.

---
## 8. Implementation Checklist

1. Generate/install proto definitions (`checkin.proto`, `mcs.proto`) so you can serialize/deserialize messages.
2. Implement check-in request/response handling.
3. Implement register3 requests (token fetch, subscribe, unsubscribe) with dynamic payload composition.
4. Manage TLS socket to `mtalk.google.com` with framing for `LoginRequest`, heartbeats, and message stanzas.
5. Build decryption helper using P-256 key pair + HKDF + AESGCM.
6. Persist all long-lived secrets (Android ID, security token, keys, FCM token).
7. Provide callbacks for decrypted data and raw message handling.
8. Add topic subscribe/unsubscribe API on top of the register3 helper, normalizing topic names to `/topics/<name>`.

Following this blueprint, you can build a fully functional FCM receiver capable of:
- Generating device credentials
- Receiving direct token-targeted messages
- Subscribing/unsubscribing to topics
- Decrypting WebPush-style payloads
- Maintaining the MCS connection for real-time delivery

Everything can be implemented in any language with HTTPS, TLS, and protobuf support.
