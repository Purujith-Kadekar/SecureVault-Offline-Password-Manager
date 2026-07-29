#pragma once
// ═══════════════════════════════════════════════════════════════════════════════
//  ble_keyboard_manager.h — BLE HID keyboard + domain-sync service over NimBLE
// ═══════════════════════════════════════════════════════════════════════════════
// Uses NimBLEHIDDevice with a standard USB HID keyboard report descriptor,
// so it actually enumerates as a keyboard on Windows/macOS/Android/iOS.
//
// Also hosts a second, custom GATT service ("sync service") on the same
// server so the Python bridge / browser extension can ask the device to
// type a password for a given hostname. The extension NEVER receives the
// plaintext password over BLE — it only gets a FOUND/NOT_FOUND status
// notification. The device types the password itself via the HID service,
// straight into whatever field the OS currently has focused. See
// setVault()/update() below.
#include <Arduino.h>
#include <NimBLEDevice.h>
#include <NimBLEHIDDevice.h>
#include <string>
#include "vault_manager.h"

class BleKeyboardManager : public NimBLEServerCallbacks {
public:
  bool begin(const char* deviceName);

  // v5.4: Tear down the BLE stack (for AP mode — WiFi + BLE share the
  // 2.4GHz radio, leaving BLE on during AP causes coexistence arbitration
  // resets, especially on battery). Safe to call even if BLE was never
  // initialized — does nothing in that case.
  void end();

  // v5.4: Re-initialize BLE after end() was called. Uses the same
  // device name as the previous begin() call (cached). Returns false
  // if BLE was never begun (no cached name).
  bool resume();

  bool isConnected() const { return _connected; }
  void typeString(const char* s);
  void sendEnter();
  void sendTab();

  // Pairing UI — main.cpp polls these each loop() tick to drive the
  // BLE pairing screen off the real NimBLE passkey callback.
  bool pairingActive() const { return _pairingActive; }
  bool consumePairingDone();     // returns true once, then clears the flag
  uint32_t pairingPasskey() const { return _passkey; }
  void cancelPairing();          // disconnect any in-progress link

  // Domain-sync — lets a paired PC/extension trigger autofill by hostname
  // without ever seeing the password itself.
  void setVault(VaultManager* vault) { _vault = vault; }
  void update();  // call every loop() tick; services pending sync requests

private:
  // NimBLEServerCallbacks overrides
  void onConnect(NimBLEServer* server, NimBLEConnInfo& info) override;
  void onDisconnect(NimBLEServer* server, NimBLEConnInfo& info, int reason) override;
  uint32_t onPassKeyDisplay() override;             // fallback: old Passkey Entry devices only
  void onConfirmPassKey(NimBLEConnInfo& connInfo, uint32_t pass_key) override; // Numeric Comparison
  void onAuthenticationComplete(NimBLEConnInfo& info) override;

  void sendReport(uint8_t modifier, uint8_t keycode);

  // Write callback for the domain-sync characteristic. Kept as a tiny
  // nested class (rather than a free function) so it can carry an owner
  // pointer back to this manager — NimBLE callback objects don't take
  // user context args.
  class SyncDomainCallbacks : public NimBLECharacteristicCallbacks {
  public:
    explicit SyncDomainCallbacks(BleKeyboardManager* owner) : _owner(owner) {}
    void onWrite(NimBLECharacteristic* c, NimBLEConnInfo& connInfo) override;
  private:
    BleKeyboardManager* _owner;
  };

  void _handleSyncWrite(const std::string& domain);
  void _notifySyncStatus(const char* status);
  static bool _domainMatches(const char* site, const char* domain);

  NimBLEServer* _server = nullptr;
  NimBLEHIDDevice* _hid = nullptr;
  NimBLECharacteristic* _input = nullptr;
  bool _connected = false;

  volatile bool _pairingActive = false;
  volatile bool _pairingDone = false;
  volatile uint32_t _passkey = 0;

  VaultManager* _vault = nullptr;
  NimBLECharacteristic* _syncDomainChar = nullptr;
  NimBLECharacteristic* _syncStatusChar = nullptr;
  SyncDomainCallbacks _syncCallbacks{this};
  volatile bool _syncPending = false;
  char _syncDomainBuf[64] = {0};

  // v5.4: Cached device name for resume() after AP-mode teardown.
  // 32 chars matches NimBLE's max device name length.
  char _deviceName[32] = {0};
};
