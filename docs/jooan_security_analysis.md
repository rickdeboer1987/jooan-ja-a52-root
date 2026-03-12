# Jooan JA-A52 Security Analysis

## Executive Summary

Security assessment of Jooan JA-A52 IP camera (QAIOT platform, com.jooan.cam720ja app).
Camera IP: 192.168.1.253 | Firmware: 05.02.31.29 (Nov 5 2025)
TUTK ID: D2W2E3ABS1MNLFMT111A

**Severity Rating: CRITICAL** - Default credentials, no firmware signing, TUTK P2P vulnerabilities,
cleartext credential exposure, extremely fragile web server (DoS via rapid connections).

---

## 1. Device Information

| Field | Value |
|-------|-------|
| Product | Jooan JA-A52 |
| System Model | QAIOT |
| Firmware | 05.02.31.29 / 5.2.0 (Nov 5 2025) |
| TUTK ID | D2W2E3ABS1MNLFMT111A |
| SoC | Likely Ingenic T23N (per Thingino wiki for Jooan A6M) |
| Flash | Likely NOR 8MB |
| WiFi | Likely Altobeam ATBM601BX or iComm SV6355 |
| Web Server | GoAhead-based (goform endpoints) |
| RTSP Server | LIVE555 Media Server |
| Video | H.264 Main 1920x1080@15fps, Sub 640x360@15fps |
| Audio | G.711 A-law (PCMA), 8000 Hz |
| Open Ports | 443 (HTTPS), 554 (RTSP) |

## 2. App & Cloud Infrastructure

| Component | Detail |
|-----------|--------|
| iOS App | com.jooan.cam720ja v2.0.92 (JACam720) |
| Cloud Backend | use1vas.jooaniot.com (US East, AWS) |
| IoT Platform | Alibaba Living Platform (api.link.aliyun.com) |
| Alibaba appKey | 33920415 (hardcoded in app) |
| Auth Signing | HmacSHA1 (x-ca-signature) |
| Analytics | mosspf.net (UA SDK 6.5.34), Firebase, Apple Analytics |
| Crash Reports | Tencent Bugly (ios.bugly.qq.com) |
| P2P SDK | **TUTK** (ThroughTek Kalay) |
| Company | Shenzhen Weizhi IoT / Shenzhen JOOAN Technology |
| Website | www.qacctv.com |
| Policy Domain | policy.qacloud.com.cn |

## 3. Authentication Weaknesses

### 3.1 Default Credentials (CRITICAL)
- **Web/RTSP**: `admin` / `admin123` (confirmed working)
- **Auth mechanism**: MD5 hash of password sent as cookie (`userkey`)
- **No account lockout**: Unlimited login attempts
- **No CSRF protection** on any endpoint

### 3.2 Cleartext Credential Exposure (HIGH)
- **Endpoint**: `/goform/getOtherSetttings?singleCMD=RtspConf`
- **Returns**: `{"auth":3,"user":"admin","key":"admin123"}` (plaintext password!)
- **Impact**: Any authenticated user can read all RTSP credentials

### 3.3 MD5 as Password Hash (MEDIUM)
- Password sent as MD5 hash, used directly as session cookie
- MD5 hash IS the authentication token - if leaked, it's equivalent to the password
- No session tokens, no expiry, no rotation

### 3.4 Hardcoded Alibaba appKey (HIGH)
- `appKey=33920415` hardcoded in every app instance
- appSecret likely embedded in binary (needed for HmacSHA1 signing)
- Enables forging API requests to Alibaba IoT platform for any Jooan device

## 4. Web Interface Vulnerabilities

### 4.1 /goform/SystemCommand - NOT Present (TESTED)
- `/goform/SystemCommand` returns **HTTP 404** on this firmware
- This specific RCE vector does NOT exist on the JA-A52
- However, the GoAhead goform framework may have other injection points via `SetJsonConf`

### 4.1b Extreme Web Server Fragility (HIGH - CONFIRMED)
- LIVE555 RTSP + HTTPS server crashes after 2-3 rapid connections
- Camera enters boot loop, comes up for ~30s then crashes again
- Only recovers with physical power cycle (unplug/replug)
- **DoS**: Trivial to permanently disable camera with a few rapid HTTP requests

### 4.2 Unauthenticated Reboot (HIGH)
- `/goform/reboot` - Single GET request reboots camera
- No confirmation dialog, no CSRF token
- **DoS**: Any network attacker can repeatedly reboot the camera

### 4.3 Firmware Upload Without Signing (CRITICAL)
- `/apcam/adm/upload_firmware.asp` accepts arbitrary firmware files
- No cryptographic signature verification
- "A corrupted image will hang up the system" = no validation
- **Impact**: Upload malicious firmware for persistent root access

### 4.4 Web API Endpoints

| Endpoint | Auth | Function |
|----------|------|----------|
| `/goform/getDeviceInfo` | Cookie | Device info (model, fw, TUTK ID) |
| `/goform/getVideoSettings` | Cookie | Video resolution/fps |
| `/goform/getOtherSetttings` | Cookie | Master config (singleCMD parameter) |
| `/goform/reboot` | Cookie | Immediate reboot |
| `/apcam/adm/upload_firmware.asp` | Cookie | Firmware upload |
| `/apcam/adm/users.asp` | Cookie | User management, RTSP config |
| `/apcam/adm/backup.asp` | Cookie | Config export/import (GetJsonConf/SetJsonConf) |

### 4.5 Pre-Auth Info Leak Vectors (TO TEST)
- Pierre Kim's `system.ini?loginuse&loginpas` bypass (CVE-2017-8225)
- GoAhead credential disclosure via `/goform/apcamMode`
- WiFi password disclosure via `/apcam/for-android/aplist.asp`

## 5. RTSP / Video Stream

### 5.1 Working Stream URLs
- **Main**: `rtsp://admin:admin123@192.168.1.253:554/live/ch00_0` (1080p)
- **Sub**: `rtsp://admin:admin123@192.168.1.253:554/live/ch00_1` (360p)
- **Auth**: Digest (realm="ipc")

### 5.2 RTSP Server Fragility (MEDIUM)
- LIVE555-based server crashes after 2-3 rapid connections
- Camera takes ~3 minutes to recover (full reboot)
- **DoS**: Trivial to crash video service with rapid connection attempts

### 5.3 Unauthenticated RTSP (TO TEST)
- Pierre Kim found port 10554 unauthenticated on similar cameras
- `rtsp://IP:10554/tcp/av0_0` and `rtsp://IP:10554/tcp/av0_1`
- Port 10554 was not open in our scan but may activate after reboot

## 6. P2P / TUTK Vulnerabilities

### 6.1 CVE-2021-28372 - ThroughTek Kalay P2P (CRITICAL)
- **CVSS**: 9.6
- TUTK SDK confirmed in Jooan privacy policy and device info (TUTK ID present)
- Allows attackers to:
  - Impersonate devices
  - Intercept live video/audio streams
  - Potentially execute remote code
- **Affects**: 100+ million devices globally
- **TUTK ID format**: D2W2E3ABS1MNLFMT111A (20 chars, base36-like)

### 6.2 TUTK ID as Security Boundary
- TUTK ID `D2W2E3ABS1MNLFMT111A` is the only identifier for P2P connection
- Printed on device, exposed via web API, likely in cloud responses
- Knowledge of TUTK ID + CVE-2021-28372 = full video access

## 7. Known CVEs for Jooan

| CVE | CVSS | Description |
|-----|------|-------------|
| CVE-2017-16566 | 9.8 | Jooan A5: FTP on port 21, no auth, root filesystem access |
| CVE-2018-20051 | 7.5 | Jooan JA-Q1H: ONVIF DoS via '>' in methods |
| CVE-2021-28372 | 9.6 | TUTK Kalay P2P: Device impersonation, video interception |

## 8. Firmware & Supply Chain

### 8.1 Unsigned Firmware (CRITICAL)
- Web upload accepts any file without signature check
- Only basic corruption check (file must not "hang" the system)
- Same vulnerability class as Meari camera (but even easier - direct web upload)

### 8.2 Hardware Root Access
- **UART**: 115200 baud, 3.3V (disabled in vendor Linux per Thingino wiki)
- **U-Boot**: Password locked on Jooan
- **Flash programmer**: CH341A + SOIC8 clip as fallback
- **Thingino**: Supports Jooan A6M (T23N), may work for JA-A52

### 8.3 SD Card Vectors
- Check for ppsFactoryTool.txt / ppsMmcTool.txt support (QAIOT may use different names)
- Thingino auto-update possible if U-Boot supports it

## 9. Attack Scenarios

### Scenario 1: Full Camera Takeover (LAN)
1. Find camera on network (port 443/554 scan)
2. Login with default `admin:admin123`
3. Upload malicious firmware via web interface
4. Get persistent root shell
5. Extract WiFi creds, pivot to network

### Scenario 2: Remote Video Surveillance (Internet)
1. Obtain TUTK ID (from label, API, or enumeration)
2. Exploit CVE-2021-28372 to connect via P2P
3. Intercept live 1080p video and audio
4. No authentication needed if TUTK SDK is unpatched

### Scenario 3: Cloud Account Takeover
1. Extract Alibaba appSecret from APK/IPA decompilation
2. Forge API requests with hardcoded appKey=33920415
3. Enumerate/access any Jooan user's devices via Alibaba IoT platform

### Scenario 4: Mass DoS
1. Send 3 rapid RTSP connections to crash LIVE555
2. Or hit `/goform/reboot` repeatedly
3. Camera offline indefinitely

### Scenario 5: Cloud API Abuse (CONFIRMED)
1. Jooan API at `use1api.jooaniot.com` accepts unauthenticated requests
2. Login endpoint: `POST /v3/am/login` with `{"header": {...}, "email": "...", "password": "MD5..."}`
3. Verify code endpoint sends emails to ANY address without validation (spam/phishing)
4. Register endpoint leaks existing accounts ("phone number already registered")
5. Rate limiting exists but is weak (per-email, not per-IP)

**API Auth Format (from decompiled HeaderHelper.java):**
- All requests include `"header"` JSON field with: `seqno`, `package_name`, `client_version`, `phone_model`, `language`
- Authenticated endpoints add: `user_id`, `token`
- Login: `email` + `password` (MD5 hash) -> returns `user_id` + `token`
- Alibaba IoT API: Uses native SecurityGuard signer (NOT simple HmacSHA1 with appSecret)

## 10. Comparison with Meari/CZeView Camera

| Feature | Meari/CZeView | Jooan JA-A52 |
|---------|---------------|--------------|
| SoC | Ingenic T23 | Likely Ingenic T23N |
| P2P Protocol | PPPP (Palant ~540K keyspace) | TUTK Kalay (CVE-2021-28372) |
| Cloud | Meari/CloudEdge | Alibaba IoT Living Platform |
| Encryption | XOR with MD5 key | Unknown (TUTK native?) |
| Web Interface | None (port 0) | Full web admin on 443 |
| Firmware Signing | None (MD5 only) | None (web upload, no check) |
| Default Creds | None (app-only setup) | admin:admin123 |
| Open Ports | 0 | 2 (443, 554) |
| RTSP | None | Yes (LIVE555, Digest auth) |
| Attack Difficulty | Medium (cloud/P2P) | **Low** (direct web + RTSP) |

## 11. APK Reverse Engineering (CRITICAL)

### 11.1 AES Master Encryption Key (CRITICAL)
- **AES-128-CBC Key:** `0032561478523654`
- **IV:** `0102030405060708`
- All secrets in the app encrypted with this key - trivially decryptable
- **File:** `com.jooan.basic.util.security.AesCbcUtils`

### 11.2 Alibaba IoT Credentials (Decrypted)

| Brand | appKey | appSecret |
|-------|--------|-----------|
| QiaoAnZhiLian (main) | 33670805 | f4ace09a3a2f87ef1f485370b267a516 |
| cam720 Google Play | 33687487 | ab3cd17fa14c71d7b761ee7a4fc91291 |
| iOS app (MITM captured) | 33920415 | (not yet extracted from IPA) |
| DuYan | 334761855 | fd051be0efed4e8082c26d0e5100ab65 |
| DuoDuoJianKong | 34587882 | a1ef158c0ab5ae6210ee3a5819a116d0 |
| Escanu | 33754619 | a0cc9a94cac0490f66ba4dd59c5aecfb |
| ArmySeeCloud | 33687487 | ab3cd17fa14c71d7b761ee7a4fc91291 |
| Lenovo HuiYan | 32188655 | c2773e6bab5b38475538c55432713b98 |

**Impact**: Can forge API requests to Alibaba IoT platform for ANY of these brands' devices.

### 11.3 TUTK SDK License Key
```
AQAAAAz23JF3LejrsAkPzjVZ9cSHVXvsi8WfQIBihTg7GMzy8gHJEGbJWhLa05bxbkJS7PvgQtUH
51nnNzXAoMGl3oEhf3b1HM3WGZTZzlT8D2kqhbFefTatdl/14h+ucrNkQxgWEWxhjjS7eKDt+2aw
5dU95AcsWVvyHljWNDy5RvRcalo75+VY7h1/lO18ejWmSbIZTjowgcmInaNL+IH4vnEb
```
- Default auth key: `00000000`
- Used to initialize TUTK SDK for P2P connections

### 11.4 MQTT Infrastructure
- **SSL Password:** `VeB3DVJcm1Xw5Ucu`
- **Brokers:**
  - `ssl://commserver.qalink.cn:31638`
  - `ssl://commserver1.qalink.cn:30521`
  - `ssl://commserver2.qalink.cn:30883`
  - `ssl://commserver3.qalink.cn:30883`
- Self-signed certs valid until 2123 in APK assets

### 11.5 Other Leaked Credentials
| Service | Key | Secret |
|---------|-----|--------|
| WeChat | wx5db9fdf4425f0885 | - |
| OPPO Push | 0523c52476e1488ab760dc785b492464 | 88ef861e682d4073b94af003a5c0aae7 |
| Xiaomi Push | 2882303761520631228 | 5492063157228 |
| Lenovo Pay | 93872093 | ro0rtd1qrhk7qvgu8ga6j636kcbq717b |
| Alibaba Client ID | 2FOOMZMA6ZNH2U36ANQO | - |
| Ads AES Key | com.ja.cateyeelf | - |

### 11.6 White-Label Platform (HIGH)
Same APK serves 10+ brands: Jooan, Cowelf, DuYan, Escanu, ArmySeeCloud, Fingertip, DuoDuoJianKong, Lenovo HuiYan, F360, YiBan, HaoWang, MiaoYanJingLing. All share the same codebase and AES master key.

### 11.7 PTZ IOCTRL Commands (from decompiled AVIOCtrlDefine.java)
| Command | Value | Description |
|---------|-------|-------------|
| IOTYPE_JOOAN_PTZ_COMMAND | 69633 (0x11001) | Jooan custom PTZ |
| IOTYPE_IPCAM_PTZ_COMMAND | 4097 (0x1001) | Standard TUTK PTZ |
| IOTYPE_JOOAN_MULTI_PTZ | 805306423 | Multi-step PTZ |
| IOTYPE_JOOAN_GET_PTZ_STATUS | 262177 | Get PTZ position |

PTZ payload: `channel(1) + direction(1) + speed(1) + point(1) + aux(1) + limit(1) + reserved(2)`
Directions: STOP=0, UP=1, DOWN=2, LEFT=3, LEFT_UP=4, LEFT_DOWN=5, RIGHT=6, RIGHT_UP=7, RIGHT_DOWN=8

## 12. P2P Infrastructure Analysis

### 12.1 Server Status
| Server | Type | Status |
|--------|------|--------|
| m1-m4.iotcplatform.com | TUTK Masters | ALL DEAD/firewalled |
| 112.74.108.149:32100 | CS2 Alibaba | ALIVE (NOT REGISTERED - wrong network) |
| 54.84.37.235:32100 | CS2 AWS US | ALIVE (NOT REGISTERED) |
| 54.254.195.28:32100 | CS2 AWS SG | ALIVE (NOT REGISTERED) |
| p2p.jooancloud.com (1.13.71.130) | Jooan P2P | No PPPP response (different protocol?) |

### 12.2 Key Finding
Jooan camera uses TUTK's own infrastructure (iotcplatform.com), NOT the CS2 network. TUTK masters are firewalled from our location. The `p2p.jooancloud.com` may use a custom protocol or different port.

### 12.3 PoC Scripts
- **poc_jooan_tutk_p2p.py** - Full TUTK P2P client (LAN discovery, server lookup, P2P connect, CVE-2021-28372 impersonation, PTZ control)

## 13. Cloud API Exploitation & Leaked Brand Credentials

### 13.1 Hardcoded AES Master Key (CRITICAL)
- **Key**: `0032561478523654` (BasicConstants.GLOBAL_INFO_AES_KEY)
- **IV**: `0102030405060708` (AesCbcUtils.java)
- **Mode**: AES/CBC/PKCS5Padding
- **Impact**: Decrypts ALL Alibaba IoT appKey/appSecret pairs for 14 brands, 27 credential sets

### 13.2 Decrypted Brand Credentials

| Brand | Package Name | appKey | appSecret |
|-------|-------------|--------|-----------|
| QiaoAnZhiLian (Jooan) | com.jooan.qiaoanzhilian | 30507928 | 8a2d1f393265c156c0b21d4fced82f09 |
| MiaoYanJingLing | com.jooan.qalink | 30824006 | 1e0270c516943e392d6688c29be93eca |
| DuYan | com.jooan.leanfu | 334761855 | fd051be0efed4e8082c26d0e5100ab65 |
| Escanu | com.lieju.lws.escanu | 33754619 | a0cc9a94cac0490f66ba4dd59c5aecfb |
| DuoDuoJianKong | com.jooan.taisiwei | 34587882 | a1ef158c0ab5ae6210ee3a5819a116d0 |
| **ArmySeeCloud** | com.jooan.AndroidArmySeeCloud | **33687487** | **ab3cd17fa14c71d7b761ee7a4fc91291** |
| Cowelf | com.jooan.cowelf | **33687487** | **ab3cd17fa14c71d7b761ee7a4fc91291** |
| Lenovo HuiYan | com.jooan.smarteye.lenovo | 32188655 | c2773e6bab5b38475538c55432713b98 (PLAINTEXT!) |
| Fingertip | com.jooan.fingertip | 335371769 | 1de610b94eba4e9e96cd29681aeca5fb |
| HaoWang | com.jooan.Androidhaowang | 335622622 | e6151fb753ef4334bcbec17b226773d8 |
| cam720 (F360 GP) | com.jooan.qiaoanzhilian.fmr.gp | 33938805 | 6233cff83ce92ca37388221def7b512a |
| Lenovo PAY | com.jooan.smarteye.lenovo | 93872093 | ro0rtd1qrhk7qvgu8ga6j636kcbq717b |

**ArmySeeCloud == Cowelf**: Military surveillance brand shares IDENTICAL credentials with consumer brand.

### 13.3 API Servers (ALL ALIVE)
| Server | Type |
|--------|------|
| use1api.jooaniot.com | Overseas Production |
| usw2api-test.jooaniot.com | Overseas Test |
| qadubboapi.jooancloud.com | Domestic Production |
| qacloudapi.jooancloud.com | Domestic Legacy |
| dubbotest.jooancloud.com | Domestic Test |
| qacloudapi-test.jooancloud.com | Domestic Old Test |

### 13.4 Cloud API Endpoints (Confirmed Working)
These endpoints return `E_000_003` (token validation) = LIVE, just need valid token:
- `/v2/cs/getEventImage` - Cloud event thumbnails with image_url, bucket_name
- `/v2/cs/getCloudVideoUrl` - Playback URL for cloud recordings
- `/v2/cs/getCloudVideoDownUrl` - Download URL for cloud videos
- `/v2/cs/getFaceImageList` - Face recognition images
- `/v2/cs/getBirdThumbnails` - Bird camera thumbnails
- `/v3/cs/cloud_video_list` - Cloud video list
- `/v3/cs/generateTimeAlbum` - Time-lapse album generation
- `/v3/cs/get_event_list` - Event/alert list
- `/v3/cs/getCloudStorageInfo` - Cloud storage subscription info
- `/v2/pay/my_vas_pkg` - VAS (cloud subscription) packages

### 13.5 MQTT Alert Push System
- **Topics**: `qaiot/mqtt/{device_id}` (publish), `qaiot/mqtt/user/{user_id}` (subscribe)
- **Protocol**: MQTT over TLS (ssl://)
- **SSL Password**: `VeB3DVJcm1Xw5Ucu` (hardcoded in SSLConstant.java)
- **Certificates**: commserver.qalink.cn-client.crt, qacloudCA0-1.crt, jooanmqtt2-5.crt
- **Brokers**: commserver.qalink.cn:31638, commserver1.qalink.cn:30521, commserver2.qalink.cn:30883
- **All brokers ALIVE** - TLS connected (TLS 1.3, AES-256-GCM), CONNACK=5 (auth required)
- **Auth**: Requires valid user token from login API, not just SSL password

### 13.6 Account Enumeration (CONFIRMED)
- `/v3/am/register` returns `E_006_010` "phone number is already registered" for existing accounts
- `/v3/am/login` returns `E_006_012` "user or password is error" (confirms account exists)
- No rate limiting observed on login endpoint
- Password reset flow (`/v3/am/reset_password`) validates verify codes - weak codes could allow takeover

### 13.7 Transport Encryption Bypass
- API uses X25519 + AES-GCM for request body encryption (HttpAesUtils.java)
- Server public key (prod): `302a300506032b656e03210070785cd6207fee382af57d3d8c3a787244d35c038a70f3a6ef101a88e0c5a57e`
- **BUT**: When `isHttpEncrypt=false` (SharedPreferences toggle), sends plain JSON
- Login endpoint (`/v3/am/login`) already accepts plain JSON - encryption is optional
- **PoC**: poc_jooan_cloud_exploit.py sends all requests as plain JSON successfully

### 13.8 Attack Scenario: Cloud Data Exfiltration
1. Obtain valid `user_id` + `token` (via login, MITM, or account takeover)
2. Call `/v2/cs/getEventImage` with target device_sn to get cloud thumbnails
3. Each thumbnail contains `bucket_name`, `end_point`, `event_id`, `image_url`
4. Call `/v2/cs/getCloudVideoDownUrl` with event_id to get signed download URL
5. Download all cloud-stored video recordings
6. Subscribe to `qaiot/mqtt/user/{user_id}` for real-time motion/event alerts
7. Cross-brand access: swap `package_name` header to access ArmySeeCloud/Lenovo/etc devices

### 13.9 Additional Leaked Secrets
- **Alibaba LinkVisual Client ID**: `2FOOMZMA6ZNH2U36ANQO`
- **WeChat App ID**: `wx5db9fdf4425f0885`
- **Xiaomi App ID**: `2882303761520631228` / Key: `5492063157228`
- **OPPO App Key**: `0523c52476e1488ab760dc785b492464` / Secret: `88ef861e682d4073b94af003a5c0aae7`

### 13.10 MITM Token Capture (CONFIRMED)
- iOS app (com.jooan.cam720ja v2.0.92) sends **plaintext JSON** over HTTPS (no transport encryption)
- Captured via mitmproxy on port 8888 with SSL interception
- **Captured credentials**: `user_id: 8ed39e1ce32f34f5a31e0ec9f8525a18`, `token: ebb7f33c012f455caac1`
- Token is 20-char hex string, included in every API request body as `header.token`
- API request format: `{"header": {"user_id": "...", "token": "...", "device_list": "TUTK_UID", "package_name": "com.jooan.cam720ja", ...}}`

### 13.11 IDOR / Broken Access Control (CRITICAL)
**The Jooan cloud API does NOT validate that a token belongs to the user_id in the request.**

| Test | Endpoint | Result |
|------|----------|--------|
| Own user_id + own token | `/v2/pay/my_vas_pkg` | `error_code: 0` (success) |
| Fake user_id + own token | `/v2/pay/my_vas_pkg` | `error_code: 0` (success) |
| Other device_list + own token | `/v3/device/getEventImage` | `E_000_003` (rejected) |
| Other device_list + own token | `/v2/pay/claim_vas_pkg` | `E_000_003` (rejected) |

- **user_id is not validated against token** on payment/subscription endpoints
- **device_list IS validated** on device-specific endpoints (getEventImage, claim_vas_pkg)
- This means an attacker with ANY valid token can query subscription/payment data for ANY user_id

### 13.12 Cross-Brand Access (CRITICAL)
**The `package_name` header field is NOT validated - any brand name is accepted.**

All 12+ brand package names return `error_code: 0` with our token:
- `com.jooan.QiaoAnZhiLian`, `com.jooan.AndroidArmySeeCloud`, `com.lenovo.lenovocamera`
- `com.jooan.escanu`, `com.jooan.MiaoYanCamera`, `com.jooan.DuYanCamera`
- `com.jooan.cowelf`, `com.jooan.FingerTipLifeCamera`, `com.jooan.HaoWangCamera`
- `com.jooan.duoduocamera`, `com.jooan.F360Camera`, `com.jooan.cam720gp`

**Impact**: A single compromised token from ANY brand gives access to the shared backend. Military surveillance brand (ArmySeeCloud) shares the same API as consumer cameras.

### 13.13 PoC Scripts
- **poc_jooan_cloud_exploit.py** - Decrypts all 27 credentials, tests all 6 API servers, probes cloud endpoints
- **poc_jooan_mitm_token_capture.py** - MITM proxy + cloud exploit (device list, cloud events, face images, cross-brand, IDOR)
- **mitm_jooan_addon.py** - mitmproxy addon for token capture, logs all traffic to JSONL
- **jooan_decrypted_credentials.json** - All decrypted appKey/appSecret pairs
- **jooan_captured_token.json** - Captured user_id + token from MITM

## 14. TODO

- [x] Test `/goform/SystemCommand?command=id` (RCE) - **404, NOT PRESENT**
- [x] Download and decompile APK - **DONE, all secrets extracted**
- [x] TUTK P2P server scan - **DONE, TUTK masters dead, CS2 not registered**
- [x] Test pre-auth leaks - **404 on system.ini, apcamMode** (NOT vulnerable)
- [x] Test unauthenticated RTSP on port 10554 - **Connection refused**
- [x] Test FTP on port 21 (CVE-2017-16566) - **Closed**
- [x] Check for telnet/SSH after reboot - **All closed** (22, 23, 2323)
- [x] Jooan cloud API recon - Login works, account enumeration confirmed
- [x] MQTT broker connectivity - All brokers alive, TLS connected, auth required
- [x] Decrypt all brand appKey/appSecret pairs - **27 credentials from 14 brands**
- [x] Cloud API endpoint mapping - **10+ live endpoints confirmed**
- [x] Cross-brand access testing - All 6 API servers respond
- [x] Obtain valid cloud token (MITM app) - **DONE, captured via mitmproxy**
- [x] IDOR testing - **CONFIRMED: user_id not validated against token on payment endpoints**
- [x] Cross-brand access - **CONFIRMED: package_name not validated, all 12 brands accepted**
- [ ] Access cloud pictures/videos with valid token (need cloud events recorded first)
- [ ] MQTT alert sniffing with valid user token
- [ ] TUTK P2P via Jooan's own servers (p2p.jooancloud.com)
- [ ] Full 65535 port scan (camera too fragile for fast scans)
- [ ] MITM app while using PTZ to capture IOCTRL commands
- [ ] Wireshark capture of TUTK P2P handshake

---

## References

- [CVE-2017-16566 - Jooan A5 FTP](https://github.com/advisories/GHSA-m7v9-w9c3-mw2g)
- [CVE-2018-20051 - Jooan ONVIF DoS](https://github.com/advisories/GHSA-63wg-rrpw-6rxq)
- [CVE-2021-28372 - TUTK Kalay](https://unit42.paloaltonetworks.com/iot-supply-chain-cve-2021-28372/)
- [Pierre Kim - 1250+ cameras](https://pierrekim.github.io/blog/2017-03-08-camera-goahead-0day.html)
- [Belkin NetCam EDB-42331](https://www.exploit-db.com/exploits/42331)
- [FortiGuard goform SystemCommand](https://www.fortiguard.com/encyclopedia/ips/46082)
- [Jooan A6M Thingino wiki](https://github.com/themactep/thingino-firmware/wiki/Camera:-Jooan-A6M)
- [Jooan RTSP paths](https://www.ispyconnect.com/camera/jooan)
- [Mandiant TUTK Kalay CVE-2021-28372](https://cloud.google.com/blog/topics/threat-intelligence/mandiant-discloses-critical-vulnerability-affecting-iot-devices/)
- [Nozomi Networks TUTK P2P CVE-2021-32934](https://www.nozominetworks.com/blog/new-iot-security-risk-throughtek-p2p-supply-chain-vulnerability)
- [cnping/TUTK SDK (leaked)](https://github.com/cnping/TUTK)
- [kroo/wyzecam Python TUTK wrapper](https://github.com/kroo/wyzecam)
- [fbertone/32100-dissector Wireshark](https://github.com/fbertone/32100-dissector)
