# SecureVault AP Mode — Architecture & Implementation Notes

> **Status:** Implemented in firmware v5.4. The hotspot only runs when the user explicitly selects AP MODE from the mode menu — it is NOT always-on.

## TL;DR

AP MODE turns the SecureVault into a self-contained admin unit: it brings up a WPA2-secured hotspot, serves a captive-portal webapp at `http://192.168.4.1/` (or any hostname — the DNS hijack makes them all resolve to 192.168.4.1), and lets you add / edit / delete vault entries from your phone's browser. All traffic is end-to-end encrypted with the same ECDH P-256 + AES-256-GCM stack that powers Dashboard Mode over USB-CDC.

The "6-layer protection" from SecureGen is fully ported. The "dynamic password per session" from SecureKey is fully ported. The hotspot only runs while you're in AP mode — exit the mode (BACK button, idle timeout, or auto-lock) and WiFi + DNS + the web server all tear down cleanly and BLE is restored.

---

## How to use it

1. **Unlock the device** with your vault PIN (same as always).
2. **Tap the mode badge** (top-right of the vault list screen, shows "BLE").
3. **Tap AP MODE** (third item in the 5-item mode menu).
4. The TFT shows:
   - **WiFi:** `SecureVault-<last4hex>` (e.g. `SecureVault-a1b2`)
   - **Password:** 8 random chars (regenerated every AP session)
   - **Code:** 6-digit code (regenerated every AP session)
   - **BACK** button (bottom-left)
5. **On your phone:**
   - Join the WiFi network shown on the TFT (use the WPA2 password shown).
   - The captive-portal sheet should pop up automatically. If it doesn't, open `http://192.168.4.1/` in a browser.
   - Enter the 6-digit code from the TFT.
   - The vault list loads. Add / edit / delete entries as needed.
6. **To exit:** tap BACK on the device, OR wait 5 minutes with no activity (auto-off), OR auto-lock fires.

---

## The 6 layers (ported from SecureGen)

SecureGen's `security_model.md` enumerates 6 web-protection layers (L3–L8 in their numbering; L1–L2 are device-security layers we already have). All 6 are now ported to firmware_patched:

| # | Layer | firmware_patched file(s) | Purpose |
|---|---|---|---|
| 1 | Web Auth + CSRF | `include/web_auth_manager.h` + `src/web_auth_manager.cpp` | Per-session 16-byte session ID + 32-byte CSRF token. HttpOnly+SameSite=Strict cookie. Constant-time comparison. |
| 2 | Transport Encryption (ECDH + AES-256-GCM) | `include/secure_layer_manager.h` + `src/secure_layer_manager.cpp` | ECDH P-256 key exchange over HTTP, HKDF-SHA256 session key derivation, AES-256-GCM per-message encryption with per-session replay counters. |
| 3 | URL Obfuscation | `include/url_obfuscation_manager.h` + `src/url_obfuscation_manager.cpp` | Maps real API paths (`/api/vault/list`) to random 12-char hex paths (`/x/abcdef123456`), regenerated per AP session. |
| 4 | Method Tunneling | `include/method_tunneling_manager.h` + `src/method_tunneling_manager.cpp` | Tunnels PUT/DELETE through `POST /api/tunnel` with XOR-encoded `X-Real-Method` header. (Mirrors SecureGen exactly, including the documented XOR weakness — see caveat below.) |
| 5 | Traffic Obfuscation (Decoy) | `include/traffic_obfuscation_manager.h` + `src/traffic_obfuscation_manager.cpp` | Emits fake HTTP-like UDP packets every 20–60s to random `192.168.4.x` addresses (local subnet only — diverges from SecureGen which sends to `8.8.8.8` etc.). |
| 6 | Header Obfuscation | `include/header_obfuscation_manager.h` + `src/header_obfuscation_manager.cpp` | Renames `X-Client-ID` → `X-Req-UUID` and `X-Secure-Request` → `X-Security-Level`. Adds 5 fake decoy headers (`X-Browser-Engine`, etc.) with random hex values. |

### Foundation layer

The 6 layers depend on a shared crypto foundation in `include/web_crypto_utils.h` + `src/web_crypto_utils.cpp`:
- Base64 encode/decode (for transporting ECDH pubkeys + AES-GCM ciphertext + tags over JSON)
- SHA-256, HMAC-SHA256, HKDF-SHA256
- Device key derivation (mirrors SecureGen's `DeviceStaticKey` — deterministic per chip, NOT a true secret)
- Constant-time comparison (for session IDs + CSRF tokens)
- Hex encode/decode

The existing `crypto_utils.h` (PBKDF2, AES-256-GCM, `secureRandom`, `secureZero`) is reused as-is.

---

## The dynamic password (ported from SecureKey)

Every time you enter AP mode, two fresh credentials are generated via `esp_random()` (hardware RNG):

1. **WPA2 password** — 8 chars from a 31-char "no-confusable" alphabet (`ABCDEFGHJKLMNPQRSTUVWXYZ23456789` — no `O`/`0`/`I`/`1`). Gates who can even reach the HTTP server. ~39.7 bits of entropy — sufficient for `max_clients=1` + 5-min window.

2. **6-digit code** — `esp_random() % 1000000`, formatted as a zero-padded 6-digit string. Acts as a Pre-Shared Key mixed into the HKDF session key derivation (same construction as the existing serial Dashboard Mode — see `secure_session.h`). The code never crosses the wire in plaintext; the webapp sends `SHA-256(code)` as the `codeProof` field in `/api/login` and `/api/secure/hello`.

Both are displayed on the TFT, both are zeroed with `secureZero()` on AP-mode exit, and both are regenerated on the next AP-mode entry. There is no persistent state — every AP session starts with a clean slate.

---

## Stability mitigations (also from SecureKey)

These patterns from SecureKey's `wifi_portal.ino` are ported to avoid the documented ESP32 WiFi+BLE pitfalls:

- **`max_clients=1`** on `WiFi.softAP()` — single-client assumption, reduces attack surface + memory pressure.
- **`WiFi.setTxPower(WIFI_POWER_8_5dBm)`** — phone is inches away for a captive portal, doesn't need the default 19.5 dBm blast. Avoids current-spike resets on battery.
- **BLE suspended before AP start, restored on stop** — WiFi + BLE share one 2.4 GHz radio. Leaving BLE on causes coexistence arbitration resets. Implemented via the new `BleKeyboardManager::end()` + `resume()` methods (added in v5.4).
- **5-minute idle auto-off** — matches `SEC_SESSION_TIMEOUT_MS` on the serial side. Consistent timeout across both network modes.
- **Deferred DB reload** — vault DB changes go through `VaultManager::addEntry/updateEntry/deleteEntry` which already do incremental on-disk writes (no full re-encryption). No deferred-reload flag needed — the existing vault implementation is already AP-mode-safe.

---

## Request lifecycle (all 6 layers)

A typical vault list request from the phone:

```
Phone browser → POST /x/abcdef123456   (the obfuscated /api/vault/list path — Layer 3)
   Headers:
     Cookie: SecureVault=session=<32-hex>           ← Layer 1
     X-CSRF-Token: <64-hex>                          ← Layer 1
     X-Req-UUID: <32-hex clientId>                   ← Layer 6 (obfuscated X-Client-ID)
     X-Security-Level: true                          ← Layer 6 (obfuscated X-Secure-Request)
     X-Browser-Engine: <random hex>                  ← Layer 6 (fake decoy header)
     X-Request-Time: <random hex>                    ← Layer 6 (fake decoy header)
     ...3 more fake headers...
   Body (AES-256-GCM encrypted, Layer 2):
     { "counter": 1, "iv": "<b64>", "ct": "<b64>", "tag": "<b64>" }

  ┌──────────────────────────────────────────────────────────────────┐
  │ AsyncWebServer dispatches to the obfuscated-path handler        │
  │                                                                  │
  │  Step 1 (Layer 3): deobfuscateURL → /api/vault/list            │
  │  Step 2 (Layer 1): isAuthenticated(request)                     │
  │          └─ Cookie session=... matches an active session        │
  │          └─ Session not expired (5-min TTL)                     │
  │  Step 3 (Layer 1): verifyCsrfToken(request)                     │
  │          └─ X-CSRF-Token header == session.csrfToken            │
  │  Step 4 (Layer 6): getClientId(request)                         │
  │          └─ tries X-Client-ID, falls back to X-Req-UUID         │
  │  Step 5 (Layer 2): decryptRequest(clientId, body)               │
  │          └─ find SecureSession by clientId                      │
  │          └─ check counter > rxCounter (replay protection)       │
  │          └─ AES-256-GCM auth_decrypt with sessionKey            │
  │  Step 6: dispatch to _handleVaultList → vault.entryAt(i) for i  │
  │  Step 7 (Layer 2): encryptResponseJSON(clientId, responseBody)  │
  │          └─ AES-256-GCM encrypt with sessionKey                 │
  │          └─ { counter, iv, ct, tag }                            │
  └──────────────────────────────────────────────────────────────────┘
Phone ← 200 OK, application/json
   Body: { "counter": 1, "iv": "<b64>", "ct": "<b64>", "tag": "<b64>" }

Meanwhile in loop():  TrafficObfuscationManager::tick()   ← Layer 5
                      └─ every 20–60s, fire 1 decoy UDP packet
                         to a random 192.168.4.x address
```

For state-changing operations (edit, delete), the webapp additionally uses Layer 4: it POSTs to `/api/tunnel` with `X-Real-Method: <XOR-encoded PUT or DELETE>` and the inner endpoint + data encrypted inside the Layer 2 body.

---

## Captive portal detection routes

These are registered on the AsyncWebServer so the phone's captive-portal sheet pops automatically when the user joins the SecureVault WiFi:

| Route | Platform | Behavior |
|---|---|---|
| `/generate_204` | Android | Expects HTTP 204; we 302 to `/` |
| `/hotspot-detect.html` | Apple (iOS + macOS) | Expects a specific success HTML; we 302 to `/` |
| `/ncsi.txt` | Windows | Expects "Microsoft NCSI"; we 302 to `/` |
| `/fwlink` | Legacy Microsoft | We 302 to `/` |
| 404 (any other path) | Catch-all | 302 to `/` |

The 302-to-`/` redirect is what makes the phone's browser open the captive portal page automatically — the OS detects "this network intercepts HTTP" and pops the sign-in sheet.

---

## File map (new files added in v5.4)

```
firmware_patched/
├── include/
│   ├── ap_mode_manager.h          # APModeManager — SoftAP lifecycle
│   ├── web_auth_manager.h         # Layer 1: WebAuth + CSRF
│   ├── secure_layer_manager.h     # Layer 2: ECDH + AES-256-GCM
│   ├── url_obfuscation_manager.h  # Layer 3: URL obfuscation
│   ├── method_tunneling_manager.h # Layer 4: Method tunneling
│   ├── traffic_obfuscation_manager.h # Layer 5: Decoy traffic
│   ├── header_obfuscation_manager.h  # Layer 6: Header obfuscation
│   ├── web_crypto_utils.h         # Foundation: base64, SHA-256, HKDF, HMAC
│   ├── web_vault_server.h         # AsyncWebServer + route handlers
│   └── portal_html.h              # Single-page webapp (PROGMEM HTML+CSS+JS)
└── src/
    ├── ap_mode_manager.cpp
    ├── web_auth_manager.cpp
    ├── secure_layer_manager.cpp
    ├── url_obfuscation_manager.cpp
    ├── method_tunneling_manager.cpp
    ├── traffic_obfuscation_manager.cpp
    ├── header_obfuscation_manager.cpp
    ├── web_crypto_utils.cpp
    └── web_vault_server.cpp
```

## Files modified in v5.4

| File | Change |
|---|---|
| `platformio.ini` | Added `esphome/ESPAsyncWebServer-esp8266` + `AsyncTCP-esp8266` to lib_deps; added AP-mode note to build_flags |
| `src/CMakeLists.txt` | Added `esp_wifi`, `esp_netif`, `esp_timer` to REQUIRES |
| `include/ui_screens.h` | Added `AP_INFO` to `Screen` enum, `AP` to `HidMode` enum, `_apPin` + AP screen method decls, `#include "ap_mode_manager.h"` |
| `src/ui_screens.cpp` | Expanded mode menu to 5 items (BLE / DASHBOARD / AP / SETTINGS / CANCEL), added `drawApInfoScreen()` + `handleApInfoTouch()` + `updateApInfoScreen()`, wired AP start/stop into `handleModeMenuTouch()`, added AP-mode tick + auto-lock teardown |
| `include/ble_keyboard_manager.h` | Added `end()` + `resume()` method decls + `_deviceName[32]` cache member |
| `src/ble_keyboard_manager.cpp` | Implemented `end()` (NimBLE deinit) + `resume()` (re-init with cached name); `begin()` now caches the device name |

---

## Known caveats (carried over from SecureGen)

These are documented in `study_securegen_layers.md` §5 and reproduced here for completeness:

1. **Layer 4 uses XOR, not AES.** SecureGen's `MethodTunnelingManager` uses XOR with a deterministic key derived from the public clientId — this is NOT cryptographic, just obfuscation. We mirror the same construction to stay faithful to the source. The cryptographic defense comes from Layer 2 (ECDH + AES-256-GCM on the body), not from this layer. This layer's value is purely traffic-pattern obfuscation: it makes every state-changing request look identical on the wire (POST `/api/tunnel`, no method-distinguishing URL or verb).

2. **Layer 5 diverges from SecureGen.** SecureGen sends decoy UDP packets to public DNS IPs (`8.8.8.8`, `1.1.1.1`, `9.9.9.9`). In AP mode there's no internet uplink — those packets would be dropped by the AP-side netif (no route to internet), generating noise in AP logs and wasting battery for zero effect. We send decoys to the local subnet (`192.168.4.x` + `192.168.4.255` broadcast) instead — same effect (traffic-pattern obfuscation against a passive sniffer on the same AP), no unreachable-destination waste.

3. **Device key derivation is NOT a secret.** `deriveDeviceStaticKey()` (in `web_crypto_utils.cpp`) produces a deterministic key from chip MAC + flash identifiers. An attacker with one device of the same model can derive a similar key for another device. This is a wrapping convenience to make the ECDH handshake opaque to passive observers, not a true key-extraction protection. (Same caveat as SecureGen — see `study_securegen_layers.md` caveat #6.)

4. **No mutex on the session map (SecureGen caveat #1) — FIXED.** SecureGen's `SecureLayerManager` had a known race condition: the `std::map<String, SecureSession> sessions` map had no mutex, relying on AsyncWebServer's single-event-loop serialization. Our port adds a FreeRTOS mutex (`SemaphoreHandle_t _mutex`) to both `WebAuthManager` and `SecureLayerManager`. Costs ~10 bytes per session in RAM, eliminates the latent bug.

---

## Threat model

| Threat | Mitigation |
|---|---|
| Passive WiFi sniffer on the same AP | Layer 2 (ECDH + AES-256-GCM) — all vault data is encrypted end-to-end |
| Active MITM substituting ECDH pubkeys | 6-digit code acts as a PSK mixed into the HKDF — MITM can't derive the session key without it |
| Brute-force the 6-digit code | `max_clients=1` (only one phone can connect at a time) + 5-min idle auto-off + per-session code rotation |
| CSRF (cross-site request forgery) | Layer 1: CSRF token + SameSite=Strict cookie + HttpOnly flag |
| Session hijack via stolen cookie | Layer 1: 5-min TTL + per-session CSRF token + cookie not readable from JS (HttpOnly) |
| API surface enumeration from captured traffic | Layer 3: obfuscated URL paths (`/x/abcdef123456`) rotated per session |
| HTTP method fingerprinting | Layer 4: all state-changing ops tunneled through `POST /api/tunnel` |
| Traffic timing analysis | Layer 5: decoy UDP packets every 20–60s |
| Header fingerprinting by automated scanners | Layer 6: real headers renamed + 5 fake decoy headers with random values |
| Plaintext vault at rest | Already mitigated — `VaultManager` uses AES-256-GCM with PBKDF2-derived key (existing since v3) |

---

## Troubleshooting

**AP mode won't start (tap AP MODE, nothing happens or returns to vault list):**
- Check the serial monitor for `[AP]` log lines — `APModeManager::start()` returns false on softAP failure
- Make sure BLE was successfully initialized at boot (the BLE suspend step requires a valid `_ble` pointer)
- If the build fails on `WiFi.h` not found, verify `esp_wifi` is in `src/CMakeLists.txt` REQUIRES

**Captive portal doesn't pop up on the phone:**
- Some Android phones don't trigger the captive-portal sheet reliably — open `http://192.168.4.1/` manually in a browser
- iOS is most reliable — the `/hotspot-detect.html` route works consistently
- If the page loads but looks unstyled, hard-refresh (the page is served from PROGMEM, caching shouldn't be an issue but a stale browser cache can cause it)

**Login fails with "code_mismatch":**
- The 6-digit code on the TFT rotates per AP session. If you exit and re-enter AP mode, a new code is generated — make sure you're reading the current code, not a stale photo
- The code proof is `SHA-256(code)` — if you mistype a digit, the proof won't match. Re-enter the code carefully

**ECDH handshake fails ("code_proof_mismatch_or_ecdh_failed"):**
- Same as above — most likely a mistyped code
- If the code is definitely correct, the ECDH keypair may have failed to generate (very rare — check serial log for `[SL]` errors)
- Exit and re-enter AP mode to regenerate everything from scratch

**BLE doesn't work after exiting AP mode:**
- `BleKeyboardManager::resume()` re-inits with the cached device name — your phone should reconnect automatically
- If it doesn't, toggle Bluetooth off/on on your phone, or forget and re-pair the device
- Bonding info is persisted in NVS by NimBLE, so re-pairing should be rare

**Vault edits don't persist:**
- `WebVaultServer` calls `vault.addEntry(e, _pin)` etc. — the PIN must be valid for the vault
- If you changed the vault PIN on-device while in AP mode (via Settings → Change PIN), the cached `_apPin` becomes stale — exit and re-enter AP mode

---

## Open questions / future work

- **WiFi QR code:** SecureGen shows a `WIFI:S:...;T:WPA;P:...;H:false;;` QR on the TFT for instant phone-camera join. Not implemented yet — would need a QR encoder library. The current "type the SSID + password" UX is acceptable for the AP-mode use case.
- **Persistent AP password:** SecureGen stores the AP password AES-256-encrypted in LittleFS and lets you change it via `/api/change_ap_password`. We use SecureKey's per-session random password instead (better security, slightly more friction). If you want both options, the `WebAuthManager` could be extended to support a persistent password mode.
- **CSV import/export:** SecureKey supports bulk CSV import (Chrome/Bitwarden/Google auto-detect). Not ported — the webapp has add/edit/delete, which covers the common case. Easy to add later by extending the webapp + adding `/api/vault/import` and `/api/vault/export` endpoints.
- **mDNS not used:** In ESP-IDF 5.5.4, `mdns` is a managed component (not in core components/), and this project has `IDF_COMPONENT_MANAGER=0` set because PlatformIO's framework-espidf package isn't a git checkout. The DNS hijack (`DNSServer.start(53, "*", softAPIP)`) makes every hostname resolve to 192.168.4.1, which is functionally equivalent for the captive-portal use case. The user can type `192.168.4.1` OR `securevault.local` OR any hostname — they all work. If true mDNS service discovery is needed in the future, the `mdns` component can be vendored under `components/` like `esp_tinyusb` already is.
