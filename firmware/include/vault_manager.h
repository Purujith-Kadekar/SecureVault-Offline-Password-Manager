#pragma once
// ═══════════════════════════════════════════════════════════════════════════════
//  vault_manager.h — password vault: demo entries + optional SD load/save
//  + on-device settings (PIN, auto-lock timeout) persisted in NVS
// ═══════════════════════════════════════════════════════════════════════════════
#include <Arduino.h>
#include <Preferences.h>
#include <SD.h>
#include <freertos/semphr.h>
#include "vault_types.h"
#include "crypto_utils.h"  // VAULT_IV_LEN / VAULT_TAG_LEN / VAULT_SALT_LEN / VAULT_KEY_LEN
#include "crypto_buffer.h"  // cryptoAlloc/cryptoFree/largeAlloc/largeFree — unified DMA-safe allocator
#include "error_framework.h" // F15: formal error handling — replaces _lastError[80]

class VaultManager {
public:
  VaultManager() = default;
  ~VaultManager();  // frees PSRAM storage arrays

  void begin();

  // v5.4.7: H4 fix — lock/unlock the vault mutex.
  // AsyncWebServer handlers run on the AsyncTCP task, the UI runs on the
  // loop task, and BLE sync runs on the NimBLE task. Without a mutex,
  // concurrent addEntry/updateEntry/deleteEntry calls could corrupt the
  // in-memory vault arrays or the on-disk vault.db.
  // These are reentrant-safe (same task can lock multiple times).
  void lock();
  void unlock();

  // Initialize storage AND load vault from SD card with the given PIN.
  // This caches the PBKDF2-derived key so subsequent saves are instant
  // (<1s instead of 2-5s). Called by SerialProtocol after ECDH handshake.
  void beginWithPin(const char* pin);

  int count() const { return _count; }
  VaultEntry entryAt(int idx) const;

  // Tries to load /vault.db from SD -- an AES-256-GCM encrypted JSON
  // blob, keyed via PBKDF2(pin, salt). Falls back to empty vault if the
  // card/file isn't present, or if pin doesn't decrypt it (wrong PIN or
  // corrupted file -- GCM's auth tag catches both).
  // IMPORTANT: This also caches the vault key in SRAM so subsequent
  // saveToSD() calls skip PBKDF2 entirely (<1s saves).
  void loadFromSD(const char* pin);

  // Web dashboard API — pin derives the AES-256-GCM key used to encrypt
  // /vault.db. Each of these persists to SD immediately on success
  // (saveToSD is called internally), so dashboard edits survive a reboot.
  bool addEntry(const VaultEntryRW& e, const char* pin);
  bool updateEntry(int idx, const VaultEntryRW& e, const char* pin);
  bool deleteEntry(int idx, const char* pin);

  // Re-encrypts and writes the entire in-memory vault to /vault.db with
  // a freshly-generated salt + IV. Returns true on success.
  bool saveToSD(const char* pin);

  // F15: Replaced _lastError[80] char buffer with the formal error framework.
  // lastSaveError() now reads from the VAULT subsystem's LastError slot.
  // The _setError() helper logs to both the framework and Serial.
  const char* lastSaveError() const;

  // CSV import/export (Bitwarden-compatible)
  String exportCSV() const;
  bool importCSV(const String& csvText, const char* pin);

  // ── On-device settings (persisted in NVS) ──────────────────────────
  // The PIN is stored in NVS and can be changed on-device via the
  // Settings screen. On first boot, no PIN exists — the user MUST
  // choose one via the first-boot PIN setup screen.
  // F12: Removed DEFAULT_VAULT_PIN fallback. If NVS has no PIN set,
  // getPin() returns FIRST_BOOT_PIN_SENTINEL, and verifyPin() always
  // returns false. The device forces mandatory PIN setup on first boot.
  String getPin() const;
  bool setPin(const char* oldPin, const char* newPin);
  bool verifyPin(const char* pin) const;

  // ── First-boot PIN setup (F12) ─────────────────────────────────────
  // isFirstBoot(): returns true if the device has never had a PIN set
  //   (NVS flag not present, or stored PIN equals FIRST_BOOT_PIN_SENTINEL).
  //   Used by UiController to show the mandatory PIN setup screen.
  // completeFirstBoot(newPin): sets the user-chosen PIN in NVS and marks
  //   the first-boot flag as complete, so subsequent boots skip the
  //   setup screen and go directly to the normal lock screen.
  bool isFirstBoot() const;
  void completeFirstBoot(const char* newPin);

  // Auto-lock timeout (milliseconds). 0 = never. Persisted in NVS.
  uint32_t getAutoLockMs() const;
  void setAutoLockMs(uint32_t ms);

  // Theme ID (0=Air-Gapped, 1=Monochrome, 2=Emerald). Persisted in NVS.
  uint8_t getThemeId() const;
  void setThemeId(uint8_t id);

  // ── PIN lockout (NVS-backed, survives reboot) ─────────────────────
  // After 3+ failed attempts, escalating backoff: 30s → 60s → 2m → 5m.
  // Fail count persists across reboots so power-cycling can't bypass it.
  // Resets to 0 on successful unlock.
  uint8_t getPinFailCount() const;
  void incrementPinFailCount();
  void resetPinFailCount();
  uint32_t getPinLockUntil() const;  // epoch ms when lockout expires (0 = no lock)
  void setPinLockUntil(uint32_t ms);
  bool isPinLocked() const;  // true if currently in lockout period

  // Manually reclaim dead space left behind by UPDATE (grown records)
  // and permanent DELETE (purged rows) by rewriting the vault file
  // contiguously. Safe to call any time the vault is unlocked; also
  // called automatically after loadFromSD() when dead space is large
  // (see _maybeAutoCompact). Returns false (and sets lastSaveError())
  // if the rewrite fails — the old vault.db is left untouched on failure.
  bool compactVault(const char* pin) { return _rewriteWholeVault(pin); }

  // Factory reset: wipes NVS settings + SD vault.
  void factoryReset();

  // ── Vault key cache ────────────────────────────────────────────────
  // After the first successful loadFromSD(), the PBKDF2-derived vault
  // key and its associated salt are cached in internal SRAM.  Subsequent
  // saveToSD() calls reuse the cached key instead of re-deriving it
  // (which takes 2-5 seconds of PBKDF2 on every add/edit/delete — the
  // root cause of the "Response timeout" bug).
  //
  // Security model: the cached key lives in ESP32 internal SRAM (not
  // PSRAM — harder to extract physically).  It is zeroed on:
  //   - explicit lock / clearCachedKey() call
  //   - session teardown (serial disconnect)
  //   - factory reset
  //   - destructor
  // The salt is reused across saves (it doesn't need to rotate — the IV
  // provides per-save uniqueness for AES-GCM).  This means the same key
  // is valid for every save during the session, eliminating PBKDF2 from
  // the hot path entirely.
  bool isKeyCached() const { return _keyCached; }
  void clearCachedKey();

  // ── Load error diagnostic (v5.3) ──────────────────────────────────
  // After loadFromSD(), check this to find out WHY the vault is empty.
  // Returns a human-readable string for display on the TFT or serial log.
  const char* lastLoadErrorStr() const;

public:
  // ── MAX_ENTRIES ────────────────────────────────────────────────────
  // Public (not just private) so the on-disk format constants in
  // vault_manager.cpp (row table size, etc.) can reference it directly
  // instead of duplicating the number.
  // 256 entries. The original 4-array schema (site/user/pass/totp) was
  // ~40KB at 256 entries and fit in internal SRAM. The v9.10 per-type
  // expansion added ~629 bytes/entry × 256 = ~157KB of new storage,
  // plus the _applyJSON scratch buffers mirror that (~157KB more).
  // Total ~354KB of BSS overflowed dram0_0_seg (internal SRAM) by
  // ~229KB. Fix: ALL per-entry char[] arrays are now heap-allocated
  // in PSRAM (8MB octal PSRAM, CONFIG_SPIRAM_USE_MALLOC=y). Allocations
  // >16KB automatically go to PSRAM (CONFIG_SPIRAM_MALLOC_ALWAYSINTERNAL=16384).
  static const int MAX_ENTRIES = 256;

  // ── On-disk paths (public so file-scope helpers like _svPreflightSDCheck()
  // in vault_manager.cpp can open the same files without duplicating the
  // string literals). These are constant path strings, not state — no
  // encapsulation reason to hide them.
  static const char* DB_PATH;
  static const char* DB_TMP_PATH;
  static const char* DB_BAK_PATH;

private:
  // ── Per-entry field storage (PSRAM heap, allocated in begin()) ─────
  // These are char (*)[N] pointers — each points to a MAX_ENTRIES × N
  // block allocated via `new char[MAX_ENTRIES * N]` and cast to the
  // 2D array type. Accessed as _site[i] (a char[N] array) just like
  // the old static arrays, so all existing strncpy/memcpy code works
  // unchanged.
  //
  // IMPORTANT: These arrays live in PSRAM (via C++ new, which routes
  // allocations >CONFIG_SPIRAM_MALLOC_ALWAYSINTERNAL to SPIRAM). They
  // NEVER touch the AES-GCM crypto engine — they're just UI/storage
  // field data. If a buffer WILL be passed to aesGcmEncrypt/Decrypt,
  // it must use cryptoAlloc() (see crypto_buffer.h), NOT new/malloc.
  // ORIGINAL (kept: login core fields)
  char (*_site)[32];
  char (*_user)[48];
  char (*_pass)[48];
  char (*_totp)[32];
  uint8_t* _type;     // [MAX_ENTRIES]
  bool* _favorite;    // [MAX_ENTRIES]
  bool* _deleted;     // [MAX_ENTRIES]

  // LOGIN extras
  char (*_url)[64];
  char (*_notes)[160];
  char (*_folder)[24];
  // CARD extras
  char (*_cardholder)[32];
  char (*_cardNumber)[24];
  char (*_exp)[8];
  char (*_cvv)[5];
  // IDENTITY extras
  char (*_firstName)[24];
  char (*_lastName)[24];
  char (*_email)[48];
  char (*_phone)[20];
  char (*_address)[48];
  char (*_city)[24];
  char (*_state)[24];
  char (*_postal)[12];
  char (*_country)[24];
  char (*_ssn)[16];
  char (*_passport)[24];
  char (*_license)[24];

  bool _storageAllocated = false;  // true after _allocStorage() succeeds
  // F15: Removed _lastError[80] — replaced by error_framework.h.
  // _setError() now calls logError() from the formal framework.
  void _setError(const char* msg); // helper: logs via error framework
  void _allocStorage();            // new[] all the above from PSRAM
  void _freeStorage();             // delete[] all the above (destructor / factory reset)

  int _count = 0;

  // ── Record-oriented on-disk storage (v10.0 — replaces monolithic-blob
  // vault.db with per-entry records + a fixed row table). See the format
  // doc block at the top of vault_manager.cpp ("SVR1" format) for the
  // full on-disk layout. This is what makes ADD/UPDATE/DELETE touch only
  // the SD bytes for the one entry involved, instead of re-serializing +
  // re-encrypting the entire vault on every edit.
  //
  // _diskSlot[i]: for the in-memory entry currently at dense index i,
  // which row (0..MAX_ENTRIES-1) in the on-disk row table holds its
  // ciphertext record. Entries are kept dense in memory (same as always
  // — UI code, entryAt(), etc. are completely unchanged) but their
  // physical row on disk does NOT need to match their in-memory index,
  // and does NOT shift when other entries are added/removed. That
  // decoupling is what makes hard-delete an O(1) disk operation instead
  // of an (n - idx)-entry rewrite.
  int _diskSlot[MAX_ENTRIES];

  // RAM mirror of the on-disk row table (kept in sync with the file on
  // every incremental write, so ADD/UPDATE don't need to re-read the
  // whole table from SD just to find a free row). Small (256 * 37B =
  // ~9.3KB) — kept as plain members, no PSRAM needed.
  // VAULT_IV_LEN (12) / VAULT_TAG_LEN (16) come from crypto_utils.h --
  // reused as-is, every record uses the same GCM IV/tag sizes as before.
  uint8_t  _rowStatus[MAX_ENTRIES];      // 0 = free/reusable, 1 = occupied
  uint32_t _rowOffset[MAX_ENTRIES];      // file offset of this row's ciphertext
  uint32_t _rowLen[MAX_ENTRIES];         // ciphertext length
  uint8_t  _rowIv[MAX_ENTRIES][VAULT_IV_LEN];
  uint8_t  _rowTag[MAX_ENTRIES][VAULT_TAG_LEN];
  uint32_t _dataEnd = 0;                 // next-append offset in the data area

  // Serialize/parse ONE entry (not the whole vault) to/from JSON. Same
  // field set as the old _toJSON()/_applyJSON() loop bodies, just for a
  // single index. Used by every incremental disk write/read.
  // Serializes entry `i` as a single JSON object into `out` (caller-owned,
  // must be a stack or DMA-safe buffer -- see crypto_buffer.h's cryptoAlloc()
  // for why this deliberately doesn't return a String).
  // Returns the number of bytes written (excludes the null terminator).
  static const size_t MAX_RECORD_JSON_LEN = 2048; // Identity entries with all fields filled can reach ~1100B
  size_t _entryToJSON(int i, char* out, size_t outCap) const;
  bool _jsonToEntry(const char* json, size_t len, int destIdx);

  // Low-level row-table helpers (all fixed-offset seeks — O(1) I/O).
  size_t _rowFileOffset(int slot) const;
  bool _writeRowToFile(File& f, int slot);
  bool _writeDataEndToFile(File& f);
  bool _readTableFromFile(File& f); // reads header + all rows into the mirror above
  int _findFreeRow() const;         // first row with status == 0, or -1 if table is full

  // Incremental single-record operations — the whole point of this
  // redesign. Each does a handful of small fixed-offset writes instead
  // of re-encrypting the whole vault.
  bool _appendRecordToSD(int memIdx, const char* pin);   // used by addEntry
  bool _updateRecordOnSD(int memIdx, const char* pin);   // used by updateEntry
  bool _purgeRowOnSD(int slot);                          // used by deleteEntry (hard delete)

  // Full rewrite: re-encrypts and writes every live entry contiguously
  // (no dead space). This both (a) creates a brand-new vault.db, and
  // (b) doubles as compaction/garbage-collection for the dead space left
  // behind by UPDATE (grown records) and DELETE (purged rows). Renamed
  // from a one-shot "save the whole thing" into "the compaction path" —
  // still used for: first save after boot, PIN change (needs a new key
  // for everything anyway), CSV import (bulk replace), and periodic GC.
  bool _rewriteWholeVault(const char* pin);

  // Heuristic: called after loadFromSD(). If dead space (bytes in the
  // data area no longer referenced by any occupied row) is large
  // relative to the live data, compacts automatically. Threshold is
  // intentionally simple/conservative — tune freely.
  void _maybeAutoCompact(const char* pin);

  // ── Views (also PSRAM — grew from ~40B to ~96B per entry in v9.10) ──
  mutable const char** _entrySite;
  mutable const char** _entryUser;
  mutable const char** _entryPass;
  mutable const char** _entryTotp;
  mutable VaultEntry* _views;
  mutable bool _viewsBuilt = false;

  void _buildViews() const;
  void _loadDemo();
  // Zero one entry's worth of char[] slots at index `i` across every
  // per-field array. Used by addEntry/updateEntry/deleteEntry so stale
  // data from a previous entry at the same index can never leak in.
  void _zeroEntrySlot(int i);
  static void _appendCsvField(String& out, const char* field, bool last);
  static bool _parseCsvLine(const String& line, String outFields[4]);
  // Reads/decrypts every occupied row from an already-open,
  // header-validated file into the live arrays + _diskSlot[].
  bool _loadRecordsFromOpenFile(File& f, const uint8_t* key);
  // Opens `path`, validates header, derives/reuses key, and loads via
  // _loadRecordsFromOpenFile(). Used for both vault.db and the
  // vault.db.bak fallback in loadFromSD().
  bool _tryLoadFile(const char* path, const char* pin, bool setLoadError);

  // ── Vault key cache (internal SRAM, not PSRAM) ──────────────────
  // Cached after first successful loadFromSD().  Reused by saveToSD()
  // to avoid 2-5s PBKDF2 re-derivation on every add/edit/delete.
  // Zeroed by clearCachedKey() on lock / session end / factory reset.
  uint8_t _cachedKey[32] = {0};       // AES-256 vault key
  uint8_t _cachedSalt[16] = {0};      // PBKDF2 salt from the vault file
  bool _keyCached = false;            // true after first successful decrypt

  // ── Load error tracking (v5.3) ────────────────────────────────────
  // After loadFromSD() returns, call lastLoadError() to find out WHY
  // the vault is empty. UI code uses this to show a diagnostic message
  // on the TFT ("No vault found", "Wrong PIN", "SD card error", etc.)
  // instead of silently showing an empty list.
  enum class LoadError : uint8_t {
    NONE = 0,           // load succeeded (or never attempted)
    NO_STORAGE,         // PSRAM alloc failed — vault disabled
    SD_FAILED,          // SD card not present / mount failed / I/O error
    NO_FILE,            // /vault.db doesn't exist on SD
    BAD_FORMAT,         // header magic/version mismatch (not SVL1 v1)
    DECRYPT_FAILED,     // AES-GCM tag mismatch (wrong PIN or corrupt)
    BAD_JSON,           // decrypt OK but JSON parse failed
  };
  LoadError _lastLoadError = LoadError::NONE;

  // NVS-backed settings
  mutable Preferences _prefs;
  // v5.4.7: H4 fix — mutex for thread-safe vault access.
  SemaphoreHandle_t _mutex = nullptr;
  static const char* PREFS_NAMESPACE;
  static const char* PREFS_KEY_PIN;
  static const char* PREFS_KEY_AUTOLOCK;
  static const char* PREFS_KEY_THEME;
  static const char* PREFS_KEY_PIN_FAILS;
  static const char* PREFS_KEY_PIN_LOCK_UNTIL;
  // v10.7: KDF iter count that last unlocked the vault on this device.
  // Lets subsequent unlocks skip the legacy 20000-iter retry path.
  static const char* PREFS_KEY_KDF_ITERS;
  // F12: NVS key for the first-boot flag. "false" = first boot (no PIN set
  // yet), "true" = PIN has been set at least once. Stored as a bool in the
  // same securevault namespace as all other NVS settings.
  static const char* PREFS_KEY_FIRST_BOOT;
  uint32_t _getCachedKdfIters() const;
  void     _setCachedKdfIters(uint32_t iters);
};