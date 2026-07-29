#pragma once
// ═══════════════════════════════════════════════════════════════════════════════
//  ap_mode_manager.h — AP Mode core (SoftAP + DNS hijack + mDNS + captive portal)
// ═══════════════════════════════════════════════════════════════════════════════
//  Combines patterns from both reference projects:
//
//    From SecureKey (study_securekey_dynamic_password.md):
//      - Per-session 8-char WPA2 password from 31-char "no-confusable"
//        alphabet (ABCDEFGHJKLMNPQRSTUVWXYZ23456789) via esp_random().
//      - Per-session 6-digit code (0-9) via esp_random() % 1000000.
//        Both shown on the TFT. Both regenerated on each AP-mode start.
//      - max_clients=1 on softAP (single-client, single-phone assumption).
//      - WiFi.setTxPower(WIFI_POWER_8_5dBm) — phone is inches away,
//        doesn't need the default 19.5 dBm blast, and the cap avoids
//        current-spike resets on battery.
//      - BLE suspended before AP start, restored on stop (shared 2.4GHz
//        radio — leaving BLE on causes coexistence arbitration resets).
//      - 5-min idle auto-off (matches SEC_SESSION_TIMEOUT_MS — consistent
//        across both network modes).
//
//    From SecureGen (study_securegen_ap_mode.md):
//      - SSID scheme: "SecureVault-<last 4 hex of MAC>" — deterministic
//        per device, easy to recognize in the WiFi list.
//      - DNS hijack on port 53 ("*" → softAPIP) for captive portal pop-up.
//      - mDNS responder so the device is reachable as
//        securevault-<last4hex>.local (avoids typing 192.168.4.1).
//      - Captive portal detection routes: /generate_204 (Android),
//        /hotspot-detect.html (Apple), /ncsi.txt (Windows), /fwlink
//        (legacy Microsoft). All redirect to the captive portal page.
//      - 404 handler → 302 redirect to the captive portal page.
//
//  Lifecycle:
//    1. User taps "AP" in the mode menu.
//    2. APModeManager::start() is called:
//       a. BLE suspend.
//       b. Generate WPA2 password + 6-digit code (secureRandom).
//       c. WiFi.mode(WIFI_AP) + WiFi.softAP(ssid, password, 1, 0, 1).
//       d. WiFi.setTxPower(WIFI_POWER_8_5dBm).
//       e. DNS hijack start.
//       f. mDNS begin.
//       g. WebAuthManager::begin() + generateCode().
//       h. SecureLayerManager::begin() (generates device ECDH keypair).
//       i. URLObfuscationManager::begin() (generates session seed).
//       j. MethodTunnelingManager::begin().
//       k. HeaderObfuscationManager::begin().
//       l. TrafficObfuscationManager::begin().
//       m. WebVaultServer::begin() (registers all HTTP routes).
//    3. UI shows the AP info screen (SSID, password, 6-digit code, BACK).
//    4. User joins the AP on their phone, opens the captive portal,
//       enters the 6-digit code, does vault CRUD.
//    5. User taps BACK on the device, OR 5 min of inactivity elapses.
//    6. APModeManager::stop() is called:
//       a. WebVaultServer::end().
//       b. TrafficObfuscationManager::end().
//       c. HeaderObfuscationManager::end().
//       d. MethodTunnelingManager::end().
//       e. URLObfuscationManager::end().
//       f. SecureLayerManager::end() (zeroes device ECDH keypair + sessions).
//       g. WebAuthManager::end() (zeroes 6-digit code + sessions).
//       h. mDNS end.
//       i. DNS hijack stop.
//       j. WiFi.softAPdisconnect(true) + WiFi.mode(WIFI_OFF).
//       k. BLE restore.
// ═══════════════════════════════════════════════════════════════════════════════
#include <Arduino.h>
#include <WiFi.h>
#include <DNSServer.h>
// v5.4: mDNS intentionally NOT used. In ESP-IDF 5.5.4, `mdns` is a
// managed component (not in core components/), and this project has
// IDF_COMPONENT_MANAGER=0 set because PlatformIO's framework-espidf
// package isn't a git checkout. We don't need mDNS anyway — the DNS
// hijack (DNSServer.start(53, "*", softAPIP)) makes every hostname
// resolve to 192.168.4.1, so the user can type "192.168.4.1" OR
// "securevault.local" OR any hostname — they all work.
#include "ble_keyboard_manager.h"  // for BLE suspend/restore
#include "web_auth_manager.h"
#include "secure_layer_manager.h"
#include "url_obfuscation_manager.h"
#include "method_tunneling_manager.h"
#include "traffic_obfuscation_manager.h"
#include "header_obfuscation_manager.h"
#include "session_context.h"  // F6: single authoritative PIN holder
// SoftAP configuration.
#define AP_SSID_PREFIX       "SecureVault-"
#define AP_SSID_SUFFIX_LEN   4     // last 4 hex chars of MAC
#define AP_SSID_BUF_LEN      16    // prefix(11) + 4 + null + slack
#define AP_WPA2_PASSWORD_LEN 8     // 8 chars (matches SecureKey)
#define AP_WPA2_BUF_LEN      16    // 8 + null + slack
#define AP_CODE_LEN          6     // 6-digit code
#define AP_CODE_BUF_LEN      7     // 6 + null
#define AP_MAX_CLIENTS       1     // single-phone assumption
#define AP_TX_POWER_DBM      WIFI_POWER_8_5dBm

// 5-min idle timeout (matches SEC_SESSION_TIMEOUT_MS).
#define AP_IDLE_TIMEOUT_MS 300000UL

// 31-char "no-confusable" alphabet (no O/0/I/1) — matches SecureKey.
extern const char* const AP_WPA2_ALPHABET;
#define AP_WPA2_ALPHABET_LEN 31

class WebVaultServer;  // forward declaration

class APModeManager {
public:
  static APModeManager& getInstance();

  // F8: Explicit initialization — called once in main.cpp setup() before
  // any dependent component uses this singleton. Marks _initialized = true.
  // If getInstance() is called before begin(), it auto-initializes with a
  // warning (safe fallback — the singleton is just an empty shell until
  // start() is called anyway).
  bool begin();

  // True after begin() has been called successfully.
  bool isInitialized() const { return _initialized; }

  // vault + sessionCtx are needed because WebVaultServer needs to call
  // vault.addEntry/updateEntry/deleteEntry on incoming requests. The
  // PIN is read from SessionContext (single authoritative copy — F6 fix)
  // instead of being stored as a local char[] buffer.
  bool start(VaultManager* vault, SessionContext* sessionCtx, BleKeyboardManager* ble);
  void stop();

  // True between start() and stop().
  bool isActive() const { return _active; }

  // ── Per-session credentials (read by ui_screens.cpp) ─────────────
  const char* ssid() const { return _ssid; }
  const char* wpa2Password() const { return _wpa2Password; }
  const char* code() const { return _code; }  // 6-digit code

  // v5.4.3: Regenerate ALL per-session credentials (SSID suffix + WPA2
  // password + 6-digit code) and restart the AP. Called by the "NEW SSID"
  // button on the AP info screen. Any connected client is disconnected.
  // This is the nuclear-option credential rotation — use it if you think
  // someone nearby has seen your SSID/password.
  bool regenerateCredentials();

  // ── Background tick (called from main loop) ──────────────────────
  // Processes DNS requests, runs traffic obfuscation, ticks all the
  // secure-layer TTLs, and checks the idle timeout.
  void tick();

  // ── Idle timeout ─────────────────────────────────────────────────
  // Called by WebVaultServer on every successful authenticated request
  // to refresh the idle timer.
  void noteActivity();

  // ── BLE suspend/restore (called internally by start/stop) ────────
  // Exposed publicly so unit tests can call them in isolation.
  void suspendBLE();
  void restoreBLE();

private:
  APModeManager() = default;
  APModeManager(const APModeManager&) = delete;
  APModeManager& operator=(const APModeManager&) = delete;

  // F8: Initialization tracking — prevents use before explicit begin().
  bool _initialized = false;

  bool _active = false;
  char _ssid[AP_SSID_BUF_LEN] = {0};
  char _wpa2Password[AP_WPA2_BUF_LEN] = {0};
  char _code[AP_CODE_BUF_LEN] = {0};

  DNSServer _dnsServer;
  bool _dnsRunning = false;
  // v5.4.9 FIX: removed dead _mdnsRunning flag — it was always false
  // (mDNS is intentionally not used; DNS hijack covers the same need).
  // The commented-out mDNS init/teardown code in _doStart/_doStop is
  // retained as reference but the flag that tracked it was pure dead weight.
  bool _bleWasSuspended = false;  // for restore-on-stop correctness
  unsigned long _lastActivity = 0;

  VaultManager* _vault = nullptr;
  BleKeyboardManager* _ble = nullptr;
  SessionContext* _sessionCtx = nullptr;  // F6: read PIN from here, never store own copy

  WebVaultServer* _webServer = nullptr;

  // v5.4.8: Synchronous implementations (called directly by start/stop/regenerate).
  bool _doStart();
  void _doStop();
  bool _doRegenerate();

  void _generateSsid();
  void _generateWpa2Password();
  void _generateCode();
  void _buildSsidFromMac();
};

inline APModeManager& apMode() { return APModeManager::getInstance(); }
