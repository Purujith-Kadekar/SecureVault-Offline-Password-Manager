#pragma once
// ═══════════════════════════════════════════════════════════════════════════════
//  settings_manager.h — F11: Unified Settings/Persistence Layer
// ═══════════════════════════════════════════════════════════════════════════════
//  Purpose: A lightweight FACADE over the 4 storage backends (NVS, LittleFS,
//  Flash partition, SD card). Provides a single `get(key, default)` and
//  `set(key, value)` interface for all settings. Each key has an associated
//  storage backend declared in a key→backend mapping table.
//
//  IMPORTANT: This is a FACADE pattern, NOT a replacement. The individual
//  managers (VaultManager for NVS, SdManager for SD, etc.) still exist and
//  still handle their own specialized operations. This layer just provides
//  a unified interface for the common get/set pattern so that:
//    1. Adding a new setting is a one-line mapping entry, not hunting
//       through 4 different manager files to figure out which backend
//       stores it.
//    2. Factory reset can call settingsManager.resetAll() to clear ALL
//       backends without missing any.
//    3. Settings UI code doesn't need to know which backend stores what.
//
//  Storage backends:
//    NVS     — small key-value pairs (PIN, theme ID, auto-lock timeout,
//              PIN fail count, KDF iters, first-boot flag). Fast, survives
//              reboot, limited to ~30KB namespace.
//    LittleFS — files on the "littlefs" flash partition (touch calibration,
//              duress PIN hash, config files). Medium speed, survives reboot.
//    Flash   — raw flash partition (reserved for future OTA/firmware data).
//              Not currently used by settings, but declared for completeness.
//    SD      — files on the microSD card (vault.db, CSV exports). Slowest,
//              may not be present.
//
//  Key format: "namespace.key" (e.g. "securevault.pin", "ui.theme_id").
//  This avoids collisions and makes the backend mapping obvious.
// ═══════════════════════════════════════════════════════════════════════════════
#include <Arduino.h>
#include <Preferences.h>
#include <LittleFS.h>
#include <SD.h>

// ── Storage backend enum ────────────────────────────────────────────────────
enum class SettingsBackend : uint8_t {
  NVS     = 0,
  LITTLEFS = 1,
  FLASH   = 2,   // reserved — not currently used
  SD_CARD = 3,
};

// ── Key→backend mapping entry ──────────────────────────────────────────────
struct SettingsKeyMapping {
  const char* key;            // e.g. "securevault.pin"
  SettingsBackend backend;    // which backend stores this key
  const char* nvsNamespace;   // only meaningful for NVS keys
  const char* nvsKey;         // only meaningful for NVS keys
  const char* filePath;       // only meaningful for LittleFS/SD keys
};

// ── Maximum settings keys ──────────────────────────────────────────────────
#define SM_MAX_KEYS 32

// ── Settings value type ────────────────────────────────────────────────────
// Settings can be strings or integers. We use a tagged union to handle both.
struct SettingsValue {
  enum Type : uint8_t { STRING, INTEGER, BOOL_VAL, NOT_FOUND };
  Type type = NOT_FOUND;
  String strVal;
  int32_t intVal = 0;
  bool boolVal = false;
};

class SettingsManager {
public:
  SettingsManager() = default;

  // ── Initialization ────────────────────────────────────────────────────
  // Must be called AFTER LittleFS and SD are mounted (in main.cpp setup()
  // after those mount steps). Initializes the key mapping table.
  bool begin();

  // ── Key registration ─────────────────────────────────────────────────
  // Add a key→backend mapping. Called during begin() for all known keys,
  // and can be called later for new keys added by future features.
  bool registerKey(const char* key, SettingsBackend backend,
                   const char* nvsNamespace = nullptr,
                   const char* nvsKey = nullptr,
                   const char* filePath = nullptr);

  // ── Unified get/set interface ─────────────────────────────────────────
  // get(): returns the value for the given key. If the key is not found
  //   in any backend, returns a SettingsValue with type = NOT_FOUND.
  //   For string keys, the default is returned if the backend has no entry.
  //   For integer keys, the default is returned if the backend has no entry.
  SettingsValue get(const char* key);

  // Convenience getters that return a default if not found.
  String getString(const char* key, const String& defaultValue = "");
  int32_t getInt(const char* key, int32_t defaultValue = 0);
  bool getBool(const char* key, bool defaultValue = false);

  // set(): writes the value to the appropriate backend for the given key.
  // Returns true on success, false on failure (backend not mounted, etc.).
  bool set(const char* key, const String& value);
  bool setInt(const char* key, int32_t value);
  bool setBool(const char* key, bool value);

  // ── Factory reset ────────────────────────────────────────────────────
  // Clears ALL backends: NVS namespaces, LittleFS files, SD vault data.
  // This is what VaultManager::factoryReset() calls through the facade.
  void resetAll();

  // ── Diagnostics ──────────────────────────────────────────────────────
  // Print the key mapping table and current values to Serial.
  void printKeyMap() const;

  // Returns the backend for a given key, or NVS if the key isn't registered.
  SettingsBackend getBackendForKey(const char* key) const;

  // Returns the number of registered keys.
  int getKeyCount() const { return _keyCount; }

private:
  SettingsKeyMapping _keys[SM_MAX_KEYS];
  int _keyCount = 0;

  // NVS Preferences handle — opened/closed per operation (NVS is not
  // thread-safe with a persistent handle when multiple tasks access it).
  bool _nvsGet(const char* namespace_, const char* key, SettingsValue& out);
  bool _nvsSet(const char* namespace_, const char* key, const String& value);
  bool _nvsSetInt(const char* namespace_, const char* key, int32_t value);
  bool _nvsSetBool(const char* namespace_, const char* key, bool value);
  void _nvsClearNamespace(const char* namespace_);

  bool _littlefsGet(const char* filePath, SettingsValue& out);
  bool _littlefsSet(const char* filePath, const String& value);
  void _littlefsClearAll();

  // SD and Flash backend stubs — currently SD is handled by VaultManager
  // directly (vault.db), and Flash is reserved. These stubs are here for
  // future expansion.
  bool _sdGet(const char* filePath, SettingsValue& out);
  bool _sdSet(const char* filePath, const String& value);
  void _sdClearSettingsFiles();

  // Find a key mapping by key name. Returns nullptr if not found.
  const SettingsKeyMapping* _findKey(const char* key) const;
};

// ── Global settings manager instance ────────────────────────────────────────
extern SettingsManager settingsMgr;
