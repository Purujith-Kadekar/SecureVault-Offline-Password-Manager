# SecureVault — Architecture & Feature Concepts

A deep dive into how SecureVault works, for contributors and the curious. For the high-level pitch and setup, see the [README](../README.md).

---

## 1. The big picture

SecureVault firmware is a single-threaded Arduino-style loop built around a **screen state machine** (`UiController` with `Screen` enum) and a **non-blocking main loop**. There is no RTOS scheduling in user code — instead `loop()` polls touch at ~60 Hz, runs per-screen animation timers, and services background managers (BLE, WiFi AP, USB-CDC serial, auto-lock). The two HID stacks (USB via TinyUSB, BLE via NimBLE) run their own tasks under the hood, and the secure session (ECDH + AES-GCM) runs in its own ESP-IDF task when Dashboard Mode or AP Mode is active.

```
            ┌────────────────────────── loop() @ ~60 Hz ──────────────────────────┐
            │  pollTouch() ─► tap / drag / swipe / long-press  ─►  handleXxxTouch() │
            │  per-screen animation ticks (lock pulse, PIN shake, list inertia)    │
            │  BLE keyboard manager (advertise state, connect gate)                │
            │  WiFi captive-portal service (AP Mode)                              │
            │  USB-CDC serial secure session (Dashboard Mode)                     │
            │  auto-lock / LED auto-clear / physical button                       │
            │  secure key lifecycle (zero on lock/timeout/exit)                   │
            └──────────────────────────────────────────────────────────────────────┘
```

---

## 2. Screen state machine & navigation (`UiController`)

Every screen is implemented as methods on the `UiController` class:
- `drawXxx()` — render the whole screen into the TFT framebuffer
- `handleXxxTouch(x, y)` — handle a tap at pixel coordinates

`_currentScreen` holds the active `Screen` enum value. A navigation stack (`_navStack[]`, `_navTop`) gives Android-style back behavior. Key lifecycle hooks run on transitions (e.g., AP Mode start/stop, secure session teardown, PIN zeroing).

**Adding a screen = add a `Screen::XXX` enum value, implement `drawXxx()` + `handleXxxTouch()`, register both in the dispatch switches.**

Rendering is direct-draw to the ILI9341 TFT via the display manager — no double-buffering on this hardware, but the drawing routines are optimized for minimal visual artifacts.

---

## 3. Touch: from capacitive data to gesture

The XPT2046 touch controller is read over SPI. `pollTouch()` runs a small state machine:

| Transition | Meaning | Fires |
|---|---|---|
| no-touch → touch | finger down | records start point + time |
| touch → touch (moved > threshold) | it's a drag | scroll/drag callbacks |
| touch held > 500 ms, no move | **long-press** | context actions |
| touch → release, was a drag | swipe/scroll end | `onSwipeEnd()` |
| touch → release, was short & still | **tap** | `handleXxxTouch()` |

This machine powers list scrolling, swipe-back gestures, and the hold-to-lock gesture.

---

## 4. Data model & storage (`VaultManager`)

### Vault entries

Vault entries are stored in an **AES-256-GCM encrypted database** on the SD card (`vault.db`). The database uses a JSON-based format with per-entry encryption. Operations:

| Op | Strategy |
|---|---|
| Add | Append new encrypted entry, re-encrypt file |
| Edit | Decrypt, modify, re-encrypt entire file |
| Delete | Decrypt, remove entry, re-encrypt |
| Toggle favorite | Same as edit |

### Atomic writes

`VaultManager::saveToSD()` uses a 4-step atomic write with integrity verification:
1. **Backup**: `vault.db` → `vault.db.bak`
2. **Write**: encrypted vault → `vault.db.tmp`
3. **Verify**: re-read `.tmp`, decrypt, parse, check entry count matches
4. **Commit**: if verified, `SD.remove(vault.db)` + `SD.rename(tmp, vault.db)`; if not, wipe `.tmp` and keep the original

Boot-time recovery: if `vault.db` fails to decrypt, falls back to `vault.db.bak`.

### LittleFS partition

A LittleFS partition on the 16MB flash stores session-specific data (AP Mode credentials, temporary keys). This partition is wiped clean on mode exit.

---

## 5. 6-Layer Security Stack

Every management session (AP Mode, Dashboard Mode) is protected by six layers:

### Layer 1: ECDH P-256 Key Exchange
- Device and client perform ECDH P-256 key exchange
- Shared secret derived without ever transmitting the private key
- Proof derived from the 6-digit code prevents unauthorized handshakes

### Layer 2: HKDF-SHA256 Key Derivation
- Session key = `HKDF-SHA256(ecdh_shared_secret || SHA-256(code))`
- Domain separation string prevents cross-mode key reuse
- Different keys for AP Mode vs Dashboard Mode even if the code is the same

### Layer 3: AES-256-GCM Encryption
- Every message after handshake is encrypted + authenticated
- 12-byte nonce, 16-byte authentication tag per message
- Tampered or forged messages are rejected before decryption

### Layer 4: Per-Message Nonces
- Sequential nonce counter prevents replay attacks
- Duplicate or out-of-order nonces are rejected
- Counter resets with each new session (fresh ECDH key)

### Layer 5: Method Tunneling
- Request types (GET, ADD, DELETE, etc.) are wrapped in obfuscated envelopes
- Method name is not visible in ciphertext — prevents traffic analysis
- Each method has its own domain-separation prefix

### Layer 6: Traffic Obfuscation
- Padding to fixed block sizes hides exact message lengths
- Chaff traffic (dummy requests) injected during active sessions
- Prevents statistical analysis of request patterns

### Key lifecycle

All private keys, session keys, and PIN buffers are zeroed with `secureZero()`:
- On lock (hold-to-lock, idle auto-lock)
- On mode exit (AP Mode → BLE, Dashboard → BLE)
- On timeout (60s handshake, 5min AP idle)
- On power-off (`enterPowerOff()` explicitly zeros before sleep)

`secureZero()` uses `volatile` pointers to prevent the compiler from optimizing away the memset — this is a well-known security pattern.

---

## 6. HID: the device pretends to be a keyboard

Both USB (TinyUSB) and Bluetooth LE (NimBLE) advertise a standard **HID keyboard** profile. The host OS sees a normal keyboard — no drivers, no software needed.

### Dual-transport dispatch

`typeViaHID()` sends keystrokes to **every ready transport**:
```
if (BLE enabled && connected && user-accepted)  bleKeyboard.print(s);
if (USB HID mounted by host)                    usbKeyboard.print(s);
```

### BLE pairing gate

A BLE device can connect to SecureVault at any time, but **typing is blocked until the user accepts on the device**. The prompt shows the peer's Bluetooth MAC address. Options: Accept, Reject (snooze 20s), Block 5 min (drop radio).

### Dashboard Mode / AP Mode disable BLE

BLE HID typing is intentionally disabled while Dashboard Mode or AP Mode is active. The mode badge shows the current mode. Switch back to BLE Mode to re-enable typing.

---

## 7. AP Mode architecture

See [AP_MODE.md](AP_MODE.md) for the complete AP Mode documentation. Summary:

1. User selects AP Mode → device starts WiFi SoftAP + DNS captive portal + HTTPS web server
2. Phone joins WiFi → captive portal auto-opens → user enters 6-digit code
3. ECDH handshake completes in the browser → AES-256-GCM session established
4. All vault operations (list, get, add, edit, delete) flow as encrypted JSON over HTTPS
5. Every session regenerates: WPA2 password, 6-digit code, ECDH keypair, session keys
6. Exit: WiFi + DNS + mDNS + web server all tear down, BLE restored, all keys zeroed

---

## 8. Dashboard Mode architecture

1. User selects Dashboard Mode → device generates 6-digit code → displays on TFT
2. Electron app connects over USB-CDC serial → sends ECDH pubkey + code proof
3. Device verifies proof → completes ECDH exchange → derives session key
4. All vault operations flow as AES-256-GCM encrypted frames over the serial link
5. Timeout / lock / mode exit: all keys zeroed

No HTTP, no network interface, no web server — the serial protocol (`serial_protocol.h`) handles everything over the same USB-CDC connection used for normal sync.

---

## 9. PIN lockout backoff

Wrong PIN attempts trigger an **escalating, persisted** lockout:
- 3rd wrong: 30s
- 4th wrong: 60s
- 5th wrong: 2m
- 6th+ wrong: 5m

The cumulative fail count is stored in **AT24C32 EEPROM** (I²C), so power-cycling doesn't reset the penalty. A brute-force attacker can't just yank power to retry instantly.

### Duress mode

A secondary "duress PIN" can be configured. Entering the duress PIN unlocks a **decoy vault** with fake entries. The real vault remains hidden. This protects against physical coercion scenarios.

---

## 10. Duress manager

The `DuressManager` handles:
- Setting a separate duress PIN (different from the real vault PIN)
- Maintaining a separate decoy vault on SD card (`vault_duress.db`)
- When duress PIN is entered, the device behaves identically to normal unlock — no visible difference
- The real vault is never accessed or decrypted during duress mode

---

## File map

| File | Responsibility |
|------|----------------|
| `main.cpp` | setup/loop, mode dispatch, auto-lock, BLE gate, background managers |
| `ui_screens.cpp` + `ui_screens.h` | All screen drawing + touch handlers (UiController) |
| `vault_manager.cpp` + `vault_manager.h` | Encrypted vault CRUD, atomic SD writes, backup rotation |
| `web_vault_server.cpp` + `web_vault_server.h` | AP Mode HTTPS server, E2EE webapp, request lifecycle |
| `ap_mode_manager.cpp` + `ap_mode_manager.h` | WiFi AP lifecycle (start/stop/teardown, DNS, mDNS) |
| `secure_session.cpp` + `secure_session.h` | ECDH P-256 + HKDF + AES-256-GCM session management |
| `serial_protocol.cpp` + `serial_protocol.h` | Dashboard Mode USB-CDC serial protocol |
| `secure_layer_manager.cpp` + `secure_layer_manager.h` | Session key lifecycle, secure zeroing |
| `ble_keyboard_manager.cpp` + `ble_keyboard_manager.h` | BLE HID keyboard + pairing gate |
| `crypto_utils.cpp` + `crypto_utils.h` | AES-GCM helpers, HKDF, SHA-256, secureZero() |
| `web_crypto_utils.cpp` + `web_crypto_utils.h` | Web-specific crypto (ECDH in browser context) |
| `web_auth_manager.cpp` + `web_auth_manager.h` | AP Mode authentication, code verification |
| `method_tunneling_manager.cpp` + `method_tunneling_manager.h` | Method obfuscation layer |
| `traffic_obfuscation_manager.cpp` + `traffic_obfuscation_manager.h` | Traffic padding + chaff |
| `header_obfuscation_manager.cpp` + `header_obfuscation_manager.h` | Header obfuscation layer |
| `url_obfuscation_manager.cpp` + `url_obfuscation_manager.h` | URL obfuscation layer |
| `display_manager.cpp` + `display_manager.h` | ILI9341 TFT driver, drawing primitives |
| `diagnostics.cpp` + `diagnostics.h` | System diagnostics, serial logging |
| `rtc_manager.cpp` + `rtc_manager.h` | DS3231 RTC driver |
| `mpu_manager.cpp` + `mpu_manager.h` | MPU6050 IMU driver (motion detection) |
| `eeprom_manager.cpp` + `eeprom_manager.h` | AT24C32 EEPROM driver (lockout counters) |
| `button_manager.cpp` + `button_manager.h` | Physical button handler (hold-to-lock) |
| `audio_manager.cpp` + `audio_manager.h` | Audio feedback (beeps) |
| `sd_manager.cpp` + `sd_manager.h` | SD card mount/unmount |
| `duress_manager.cpp` + `duress_manager.h` | Duress vault management |
| `totp_generator.cpp` + `totp_generator.h` | TOTP code generation (HMAC-SHA1) |
| `qr_display.cpp` + `qr_display.h` | QR code rendering |
| `portal_html.h` | Captive-portal SPA (embedded HTML + JS + CSS) |
| `vault_types.h` | VaultEntry, SessionData, and other shared structs |
| `ui_theme.h` | Colors, layout constants, drawing helpers |
| `board_config.h` | GPIO pin assignments, I²C addresses, hardware constants |

---

## Electron app architecture

The Electron desktop companion (`electron/`) connects to the ESP32 over **USB-CDC serial** (no HTTP, no network):

- `main.js` — Electron main process: serial port management, IPC handlers for all vault operations, `.svlt` file sync, safeStorage-wrapped master password
- `secureChannel.js` — ECDH P-256 + AES-256-GCM over serial frames
- `vaultCrypto.js` — Vault encryption/decryption (PBKDF2 + AES-256-GCM)
- `vaultFileCrypto.js` — `.svlt` v2 file format (PBKDF2-SHA512@600k + AES-256-GCM + HMAC-SHA256) — shared format between Electron and Extension
- `preload.js` — Context bridge: renderer never sees keys, ECDH private keys, or raw serial bytes
- `renderer/` — UI (index.html + renderer.js + style.css)

Security rules enforced in the Electron app:
- `contextIsolation: true`, `nodeIntegration: false`, `sandbox: true`
- All crypto in the main process — renderer never sees keys
- All sensitive Buffers `.fill(0)'d` before going out of scope
- Master password wrapped with Electron's `safeStorage` (DPAPI/Keychain/libsecret)
- Atomic file writes (.tmp → fsync → rename) for both vault.db and vault.svlt

---

## Chrome extension architecture

Manifest V3 extension (`extension/`):

- `background.js` — Service worker: vault state management, `.svlt` file read/write, autofill dispatch, breach check coordination
- `content.js` — Content script: detects login/registration forms on web pages
- `inline-overlay.js` — In-page overlay: captures credentials and offers to save
- `save-prompt.js` — Save prompt: suggests saving new credentials
- `urlMatcher.js` — URL matching engine: matches current page URL to vault entries
- `window.js` + `window.html` + `window.css` — Vault popup UI: list, detail, search, add/edit
- `vaultFileCrypto.js` — Same `.svlt` v2 format as Electron (format compatibility)
- `breachCheck.js` — HaveIBeenPwned k-anonymity API (shared with Electron)

The extension and Electron app share the `.svlt` encrypted vault file for two-way sync:
1. Extension captures credentials on web pages → writes to `.svlt`
2. Electron reads `.svlt` → pushes new entries to the ESP32
3. ESP32 syncs entries back → Electron writes updated `.svlt`
4. Extension reads updated `.svlt` → new entries available for autofill
