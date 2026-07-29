#include "ble_keyboard_manager.h"
#include <esp_random.h>
#include <string.h>
#include <ctype.h>

#define KEYBOARD_REPORT_ID 1
#define MOD_LEFT_SHIFT      0x02

// Domain-sync GATT service — separate from the HID service. The extension's
// Python bridge writes a hostname to SYNC_DOMAIN_UUID; the device looks it
// up in the (already-unlocked) in-memory vault and, on a match, types the
// password via the HID service and notifies SYNC_STATUS_UUID with "FOUND".
// No password ever crosses this characteristic — only FOUND/NOT_FOUND.
// These UUIDs must match SERVICE_UUID/DOMAIN_CHAR_UUID/STATUS_CHAR_UUID in
// bridge/ble_bridge.py exactly.
static const char* SYNC_SERVICE_UUID = "4fafc201-1fb5-459e-8fcc-c5c9c331914b";
static const char* SYNC_DOMAIN_UUID  = "beb5483e-36e1-4688-b7f5-ea07361b26a8";
static const char* SYNC_STATUS_UUID  = "0ce50f6e-0b58-4f4c-a092-8b1c6f6b0e1a";

// Standard USB HID keyboard report descriptor: report ID 1, one modifier
// byte + one reserved byte + six keycode bytes (8-byte input report).
// This is the well-known boilerplate descriptor used by essentially every
// USB/BLE HID keyboard implementation.
static const uint8_t HID_REPORT_DESCRIPTOR[] = {
  0x05, 0x01,                    // USAGE_PAGE (Generic Desktop)
  0x09, 0x06,                    // USAGE (Keyboard)
  0xA1, 0x01,                    // COLLECTION (Application)
  0x85, KEYBOARD_REPORT_ID,      //   REPORT_ID (1)
  0x05, 0x07,                    //   USAGE_PAGE (Keyboard)
  0x19, 0xE0,                    //   USAGE_MINIMUM (Left Control)
  0x29, 0xE7,                    //   USAGE_MAXIMUM (Right GUI)
  0x15, 0x00,                    //   LOGICAL_MINIMUM (0)
  0x25, 0x01,                    //   LOGICAL_MAXIMUM (1)
  0x75, 0x01,                    //   REPORT_SIZE (1)
  0x95, 0x08,                    //   REPORT_COUNT (8)
  0x81, 0x02,                    // INPUT (Data,Var,Abs) — modifier byte
  0x95, 0x01,                    //   REPORT_COUNT (1)
  0x75, 0x08,                    //   REPORT_SIZE (8)
  0x81, 0x03,                    // INPUT (Cnst,Var,Abs) — reserved byte
  0x95, 0x06,                    //   REPORT_COUNT (6)
  0x75, 0x08,                    //   REPORT_SIZE (8)
  0x15, 0x00,                    //   LOGICAL_MINIMUM (0)
  0x25, 0x65,                    //   LOGICAL_MAXIMUM (101)
  0x05, 0x07,                    //   USAGE_PAGE (Keyboard)
  0x19, 0x00,                    //   USAGE_MINIMUM (Reserved)
  0x29, 0x65,                    //   USAGE_MAXIMUM (Keyboard Application)
  0x81, 0x00,                    // INPUT (Data,Ary,Abs) — 6 keycodes
  0xC0                            // END_COLLECTION
};

// Standard US-QWERTY printable ASCII -> USB HID usage code. Written out
// explicitly (rather than trusting an opaque lookup table) so every entry
// is individually checkable against the USB HID usage tables.
static bool asciiToHid(char c, uint8_t& keycode, uint8_t& modifier) {
  modifier = 0;
  if (c >= 'a' && c <= 'z') { keycode = 0x04 + (c - 'a'); return true; }
  if (c >= 'A' && c <= 'Z') { keycode = 0x04 + (c - 'A'); modifier = MOD_LEFT_SHIFT; return true; }
  if (c >= '1' && c <= '9') { keycode = 0x1E + (c - '1'); return true; }
  switch (c) {
    case '0':  keycode = 0x27; return true;
    case ' ':  keycode = 0x2C; return true;
    case '-':  keycode = 0x2D; return true;
    case '_':  keycode = 0x2D; modifier = MOD_LEFT_SHIFT; return true;
    case '=':  keycode = 0x2E; return true;
    case '+':  keycode = 0x2E; modifier = MOD_LEFT_SHIFT; return true;
    case '[':  keycode = 0x2F; return true;
    case '{':  keycode = 0x2F; modifier = MOD_LEFT_SHIFT; return true;
    case ']':  keycode = 0x30; return true;
    case '}':  keycode = 0x30; modifier = MOD_LEFT_SHIFT; return true;
    case '\\': keycode = 0x31; return true;
    case '|':  keycode = 0x31; modifier = MOD_LEFT_SHIFT; return true;
    case ';':  keycode = 0x33; return true;
    case ':':  keycode = 0x33; modifier = MOD_LEFT_SHIFT; return true;
    case '\'': keycode = 0x34; return true;
    case '"':  keycode = 0x34; modifier = MOD_LEFT_SHIFT; return true;
    case '`':  keycode = 0x35; return true;
    case '~':  keycode = 0x35; modifier = MOD_LEFT_SHIFT; return true;
    case ',':  keycode = 0x36; return true;
    case '<':  keycode = 0x36; modifier = MOD_LEFT_SHIFT; return true;
    case '.':  keycode = 0x37; return true;
    case '>':  keycode = 0x37; modifier = MOD_LEFT_SHIFT; return true;
    case '/':  keycode = 0x38; return true;
    case '?':  keycode = 0x38; modifier = MOD_LEFT_SHIFT; return true;
    case '!':  keycode = 0x1E; modifier = MOD_LEFT_SHIFT; return true;
    case '@':  keycode = 0x1F; modifier = MOD_LEFT_SHIFT; return true;
    case '#':  keycode = 0x20; modifier = MOD_LEFT_SHIFT; return true;
    case '$':  keycode = 0x21; modifier = MOD_LEFT_SHIFT; return true;
    case '%':  keycode = 0x22; modifier = MOD_LEFT_SHIFT; return true;
    case '^':  keycode = 0x23; modifier = MOD_LEFT_SHIFT; return true;
    case '&':  keycode = 0x24; modifier = MOD_LEFT_SHIFT; return true;
    case '*':  keycode = 0x25; modifier = MOD_LEFT_SHIFT; return true;
    case '(':  keycode = 0x26; modifier = MOD_LEFT_SHIFT; return true;
    case ')':  keycode = 0x27; modifier = MOD_LEFT_SHIFT; return true;
    default: return false;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  BLE INIT — order matches the working Proper code.txt:
//    1. init()
//    2. setPower()
//    3. createServer() + setCallbacks()
//    4. setSecurityAuth() + setSecurityIOCap()   ← AFTER server creation
//    5. HID device setup + advertising
//
//  The previous order had security config BEFORE createServer(), which
//  prevented BLE from starting on some ESP32-S3 dual-framework builds.
// ═══════════════════════════════════════════════════════════════════════════════
bool BleKeyboardManager::begin(const char* deviceName) {
  // v5.4: Cache the device name so resume() can re-init with the same name
  // after AP-mode teardown. Truncate to fit.
  if (deviceName) {
    strncpy(_deviceName, deviceName, sizeof(_deviceName) - 1);
    _deviceName[sizeof(_deviceName) - 1] = '\0';
  }
  NimBLEDevice::init(deviceName);
  NimBLEDevice::setPower(ESP_PWR_LVL_P9);

  // Create the server and register callbacks BEFORE configuring security.
  // This matches the confirmed-working order in Proper code.txt's initBle().
  _server = NimBLEDevice::createServer();
  _server->setCallbacks(this);

  // Security settings AFTER server creation — this is the fix.
  // DISPLAY_YESNO switches from Passkey Entry to Numeric Comparison: the
  // Security Manager (not our app) picks the 6-digit code, shows it on
  // both sides, and the user just confirms they match. See
  // onConfirmPassKey() below — onPassKeyDisplay() is kept only as a
  // fallback for older devices that don't support Numeric Comparison.
  NimBLEDevice::setSecurityAuth(true, true, true);
  NimBLEDevice::setSecurityIOCap(BLE_HS_IO_DISPLAY_YESNO);

  _hid = new NimBLEHIDDevice(_server);
  _input = _hid->getInputReport(KEYBOARD_REPORT_ID);
  _hid->setManufacturer("Purujith Kadekar");
  _hid->setPnp(0x02, 0x05AC, 0x820A, 0x0110);
  _hid->setHidInfo(0x00, 0x01);
  _hid->setReportMap((uint8_t*)HID_REPORT_DESCRIPTOR, sizeof(HID_REPORT_DESCRIPTOR));
  // NimBLEHIDDevice::startServices() is marked deprecated as of NimBLE-Arduino
  // 2.1 (services now auto-start with the server) but is still present and
  // functional through the 2.x line — kept explicit here since it's the one
  // call that's guaranteed correct across the whole ^2.1.0 range this project
  // targets, rather than relying on undocumented auto-start timing.
  _hid->startServices();

  NimBLEAdvertising* adv = NimBLEDevice::getAdvertising();
  adv->setAppearance(0x03C1); // BLE SIG appearance value: HID Keyboard
  adv->addServiceUUID(_hid->getHidService()->getUUID());
  // NimBLE-Arduino 2.x stopped putting the device name in the adv packet
  // automatically — without these two calls, Android/Windows/iPad all fall
  // back to showing the raw MAC address instead of "SecureVault".
  adv->setName(deviceName);
  adv->enableScanResponse(true);

  // Domain-sync service — created on the same GATT server as HID, but its
  // UUID is deliberately left out of the advertising payload (the legacy
  // 31-byte adv packet is already close to full with the HID service UUID
  // + appearance + name). The Python bridge finds it via service discovery
  // right after connecting, so it doesn't need to be advertised.
  NimBLEService* syncSvc = _server->createService(SYNC_SERVICE_UUID);
  _syncDomainChar = syncSvc->createCharacteristic(SYNC_DOMAIN_UUID, NIMBLE_PROPERTY::WRITE);
  _syncStatusChar = syncSvc->createCharacteristic(SYNC_STATUS_UUID, NIMBLE_PROPERTY::NOTIFY);
  _syncDomainChar->setCallbacks(&_syncCallbacks);
  syncSvc->start();

  adv->start();

  return (_input != nullptr);
}

void BleKeyboardManager::sendReport(uint8_t modifier, uint8_t keycode) {
  if (!_connected || !_input) return;
  uint8_t rpt[8] = { modifier, 0x00, keycode, 0x00, 0x00, 0x00, 0x00, 0x00 };
  _input->setValue(rpt, sizeof(rpt));
  _input->notify();
  delay(8);
  memset(rpt, 0, sizeof(rpt)); // key-up
  _input->setValue(rpt, sizeof(rpt));
  _input->notify();
  delay(8);
}

void BleKeyboardManager::typeString(const char* s) {
  if (!_connected) return;
  for (size_t i = 0; s[i] != '\0'; i++) {
    uint8_t keycode, modifier;
    if (asciiToHid(s[i], keycode, modifier)) sendReport(modifier, keycode);
  }
}

void BleKeyboardManager::sendEnter() {
  sendReport(0x00, 0x28); // Keyboard Return (Enter)
}

void BleKeyboardManager::sendTab() {
  sendReport(0x00, 0x2B); // Keyboard Tab
}

void BleKeyboardManager::onConnect(NimBLEServer*, NimBLEConnInfo&) {
  _connected = true;
}

void BleKeyboardManager::onDisconnect(NimBLEServer*, NimBLEConnInfo&, int) {
  _connected = false;
  _pairingActive = false;
  _pairingDone = true; // make sure the UI doesn't get stuck on the pairing screen
  NimBLEDevice::startAdvertising();
}

uint32_t BleKeyboardManager::onPassKeyDisplay() {
  // Fallback ONLY — called if the connecting device doesn't support
  // Numeric Comparison (rare; only very old BLE stacks). With
  // BLE_HS_IO_DISPLAY_YESNO set, modern phones/laptops go through
  // onConfirmPassKey() below instead, where the Security Manager (not us)
  // picks the code. esp_random() is the ESP32 hardware TRNG — fine for a
  // display passkey, not used as a crypto key.
  uint32_t pin = 100000 + (esp_random() % 900000);
  _passkey = pin;
  _pairingDone = false;
  _pairingActive = true; // main.cpp picks this up and shows the pairing screen
  return pin;
}

void BleKeyboardManager::onConfirmPassKey(NimBLEConnInfo& connInfo, uint32_t pass_key) {
  // Numeric Comparison path (the normal case on modern phones/laptops).
  // pass_key here is the code the Security Manager generated — this is
  // the value that must match what's shown on the peer's screen, so we
  // display exactly this, not a code we generate ourselves.
  _passkey = pass_key;
  _pairingDone = false;
  _pairingActive = true; // main.cpp shows the same pairing screen as before

  // Auto-confirm our side of the comparison. The device has no way to see
  // what the phone is displaying, so it can't meaningfully compare — the
  // real security check is the user visually comparing both screens and
  // tapping "Pair" on the phone side. If that code doesn't match, the
  // phone user simply won't confirm and the phone-side pairing fails.
  NimBLEDevice::injectConfirmPasskey(connInfo, true);
}

void BleKeyboardManager::onAuthenticationComplete(NimBLEConnInfo& info) {
  if (!info.isEncrypted()) {
    NimBLEDevice::getServer()->disconnect(info.getConnHandle());
  }
  _pairingActive = false;
  _pairingDone = true; // success or failure, either way return to the previous screen
}

bool BleKeyboardManager::consumePairingDone() {
  if (!_pairingDone) return false;
  _pairingDone = false;
  return true;
}

void BleKeyboardManager::cancelPairing() {
  if (!_server) return;
  for (auto handle : _server->getPeerDevices()) {
    _server->disconnect(handle);
  }
  _pairingActive = false;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Domain-sync service
// ═══════════════════════════════════════════════════════════════════════════════
// The write callback runs on the NimBLE host task — kept tiny and
// non-blocking (just a bounded copy + a flag) so it can't stall the BLE
// stack. The actual vault lookup + typing happens in update(), which
// main.cpp's loop() polls every tick, same pattern as the pairing screen.
void BleKeyboardManager::SyncDomainCallbacks::onWrite(NimBLECharacteristic* c, NimBLEConnInfo&) {
  _owner->_handleSyncWrite(c->getValue());
}

void BleKeyboardManager::_handleSyncWrite(const std::string& domain) {
  size_t n = domain.size();
  if (n >= sizeof(_syncDomainBuf)) n = sizeof(_syncDomainBuf) - 1;
  memcpy(_syncDomainBuf, domain.data(), n);
  _syncDomainBuf[n] = '\0';
  _syncPending = true;
}

void BleKeyboardManager::_notifySyncStatus(const char* status) {
  if (!_syncStatusChar || !_connected) return;
  _syncStatusChar->setValue((const uint8_t*)status, strlen(status));
  _syncStatusChar->notify();
}

static void toLowerCopy(const char* in, char* out, size_t outSize) {
  size_t i = 0;
  for (; in[i] != '\0' && i + 1 < outSize; i++) out[i] = (char)tolower((unsigned char)in[i]);
  out[i] = '\0';
}

bool BleKeyboardManager::_domainMatches(const char* site, const char* domain) {
  if (!site || !domain || site[0] == '\0' || domain[0] == '\0') return false;
  char siteLower[32];
  char domainLower[64];
  toLowerCopy(site, siteLower, sizeof(siteLower));
  toLowerCopy(domain, domainLower, sizeof(domainLower));

  // v10.9 FIX: Replaced loose bidirectional strstr() matching with proper
  // domain suffix matching. The old code had a credential misuse vulnerability:
  // "github.com" in the vault matched "notgithub.com" in the browser, and
  // vice versa. An attacker registering "mygoogle.com" could trigger
  // auto-typing of the Google password.
  //
  // New logic: the vault entry's site must be an exact match for the domain,
  // OR a proper suffix of it (site is a parent domain of domain), OR the
  // domain must be a proper suffix of the site (domain is a parent domain
  // of site). In all cases, the match must be at a domain boundary (dot
  // separator), not at an arbitrary substring position.
  //
  // Examples:
  //   site="github.com", domain="www.github.com" → MATCH (site is suffix of domain at dot)
  //   site="github.com", domain="notgithub.com"  → NO MATCH (site is suffix but NOT at dot boundary)
  //   site="www.github.com", domain="github.com" → MATCH (domain is suffix of site at dot)
  //   site="example.com", domain="example.com"   → MATCH (exact match)

  // Case 1: Exact match
  if (strcmp(siteLower, domainLower) == 0) return true;

  // Case 2: site is a suffix of domain (vault entry = parent domain, browser = subdomain)
  // e.g. domain="www.github.com", site="github.com" → match at ".github.com"
  size_t siteLen = strlen(siteLower);
  size_t domainLen = strlen(domainLower);
  if (siteLen < domainLen) {
    // The domain must end with "." + site, meaning site is a parent domain
    const char* suffix = domainLower + domainLen - siteLen;
    if (suffix[-1] == '.' && strcmp(suffix, siteLower) == 0) return true;
  }

  // Case 3: domain is a suffix of site (browser = parent domain, vault entry = subdomain)
  // e.g. site="www.github.com", domain="github.com" → match at ".github.com"
  if (domainLen < siteLen) {
    const char* suffix = siteLower + siteLen - domainLen;
    if (suffix[-1] == '.' && strcmp(suffix, domainLower) == 0) return true;
  }

  return false;
}

void BleKeyboardManager::update() {
  if (!_syncPending) return;
  _syncPending = false;

  bool found = false;
  if (_vault) {
    int n = _vault->count();
    for (int i = 0; i < n; i++) {
      VaultEntry e = _vault->entryAt(i);
      if (_domainMatches(e.site, _syncDomainBuf)) {
        found = true;
        _notifySyncStatus("FOUND");
        // Give the bridge/extension a moment to see the status notify and
        // finish focusing the target field before keystrokes start landing —
        // BLE HID types into whatever the OS currently has focused.
        delay(150);
        if (_connected) typeString(e.pass);
        break;
      }
    }
  }
  if (!found) {
    _notifySyncStatus("NOT_FOUND");
  }

  // Best-effort: this buffer briefly held a hostname, not a secret, but
  // clearing it keeps the "nothing lingers longer than it needs to" habit
  // consistent with the rest of this codebase.
  memset(_syncDomainBuf, 0, sizeof(_syncDomainBuf));
}
// ═══════════════════════════════════════════════════════════════════════════════
//  v5.4: end() + resume() — BLE suspend/restore for AP mode coexistence
// ═══════════════════════════════════════════════════════════════════════════════
//  WiFi + BLE share the same 2.4GHz radio on the ESP32-S3. Leaving BLE
//  advertising/connected while bringing up a SoftAP causes coexistence
//  arbitration resets (see study_securekey_dynamic_password.md §1.5 —
//  SecureKey hit this exact issue and fixed it with the same suspend/
//  restore pattern). The AP mode tears BLE down before softAP() and
//  restores it after softAPdisconnect().
//
//  end(): stops advertising, disconnects any connected client, de-inits
//  the NimBLE stack. The HID service + characteristics are freed.
//
//  resume(): re-runs begin() with the cached device name. The user may
//  need to re-pair if the bonding info was lost, but NimBLE-Arduino 2.x
//  persists bonds in NVS by default so usually no re-pair is needed.
// ═══════════════════════════════════════════════════════════════════════════════
void BleKeyboardManager::end() {
  // Stop advertising. We skip explicit per-client disconnects because
  // NimBLE-Arduino 2.x's NimBLEServer API for peer iteration changed
  // across minor versions (getPeerIDs vs getPeerInfo by index), and
  // the deinit() call below tears down the entire stack anyway — any
  // connected client will see a connection drop, which is the desired
  // behavior when entering AP mode.
  if (_server) {
    NimBLEDevice::stopAdvertising();
  }
  // v5.4.7: H7 fix — delete the HID device + characteristics BEFORE
  // deinit(). NimBLEDevice::deinit() frees the internal stack but
  // doesn't delete the objects we allocated with `new`. Without this,
  // every AP-mode cycle leaked the NimBLEHIDDevice + its characteristics.
  if (_hid) {
    delete _hid;
    _hid = nullptr;
  }
  // De-init the NimBLE stack. Frees the heap allocated by init() and
  // disconnects any connected clients as part of teardown.
  NimBLEDevice::deinit();

  // Clear our state — _server pointer is now dangling (NimBLE freed it
  // in deinit()).
  _server = nullptr;
  _input = nullptr;
  _syncDomainChar = nullptr;
  _syncStatusChar = nullptr;
  _connected = false;
  _pairingActive = false;
  _pairingDone = false;
  _syncPending = false;
  // NOTE: _deviceName is intentionally kept — resume() uses it.
}

bool BleKeyboardManager::resume() {
  if (_deviceName[0] == '\0') {
    // BLE was never begun — nothing to resume.
    return false;
  }
  return begin(_deviceName);
}
