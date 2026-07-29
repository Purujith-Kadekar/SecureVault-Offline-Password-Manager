#pragma once
// ═══════════════════════════════════════════════════════════════════════════════
//  error_framework.h — F15: Formal Error Handling Framework
// ═══════════════════════════════════════════════════════════════════════════════
//  Purpose: Replaces ad-hoc error handling (_lastError[80] char buffer in
//  VaultManager, begin() returns bool but callers don't always check, no
//  severity levels, no error codes) with a structured framework that
//  provides:
//
//    1. Error severity enum: INFO, WARN, ERROR, CRITICAL
//    2. Error code enum for each subsystem
//    3. logError(severity, code, message) function that logs to Serial
//    4. LastError struct that tracks the last error per subsystem
//    5. Optional ring buffer of recent errors for diagnostics
//    6. begin() functions that returned void now return bool
//    7. Return values of begin() calls checked in main.cpp setup()
//
//  Design choices:
//    - Lightweight: no dynamic allocation, fixed-size buffers.
//    - Thread-safe: each subsystem has its own LastError slot (no shared
//      mutex needed for per-subsystem reads).
//    - Log function is a simple Serial.printf wrapper — no complex
//      formatting infrastructure.
//    - Ring buffer is optional and small (16 entries) — enough for
//      diagnostics, not enough to waste memory.
//
//  Usage:
//    logError(ErrSeverity::ERROR, ErrCode::VAULT_SAVE_FAILED, "AES-GCM tag mismatch");
//    LastError err = getLastError(ErrSubsystem::ERR_VAULT);
//    if (err.code != ErrCode::NONE) { ... handle error ... }
// ═══════════════════════════════════════════════════════════════════════════════
#include <Arduino.h>

// ── Error severity ──────────────────────────────────────────────────────────
enum class ErrSeverity : uint8_t {
  INFO     = 0,   // informational, no action needed
  WARN     = 1,   // warning, may need attention
  ERROR    = 2,   // error, operation failed but system can continue
  CRITICAL = 3,   // critical, system cannot continue safely
};

// ── Error subsystems ────────────────────────────────────────────────────────
enum class ErrSubsystem : uint8_t {
  // All prefixed with ERR_ to avoid clashes with Arduino.h macros
  // (e.g. Arduino.h #define DISPLAY 0x1 would break bare DISPLAY)
  ERR_DISPLAY     = 0,
  ERR_RTC         = 1,
  ERR_MPU         = 2,
  ERR_EEPROM      = 3,
  ERR_BUTTONS     = 4,
  ERR_SD          = 5,
  ERR_AUDIO       = 6,
  ERR_BLE         = 7,
  ERR_SERIAL      = 8,
  ERR_VAULT       = 9,
  ERR_SESSION     = 10,
  ERR_CRYPTO      = 11,
  ERR_DURESS      = 12,
  ERR_INA219      = 13,
  ERR_LITTLEFS    = 14,
  ERR_AP_MODE     = 15,
  ERR_WEB_AUTH    = 16,
  ERR_SEC_LAYER   = 17,
  ERR_URL_OBF     = 18,
  ERR_METHOD_TUN  = 19,
  ERR_HEADER_OBF  = 20,
  ERR_TRAFFIC_OBF = 21,
  ERR_SETTINGS    = 22,
  ERR_GENERAL     = 23,
  ERR_MAX_SUBSYSTEM = 24,
};

// ── Error codes (per subsystem, using 16-bit for namespace + code) ────────
// Format: high byte = subsystem, low byte = specific error code.
// This gives 256 error codes per subsystem, which is more than enough.
enum class ErrCode : uint16_t {
  // ── General (0x0000) ──────────────────
  NONE              = 0x0000,
  UNKNOWN           = 0x00FF,

  // ── Display (0x0001) ──────────────────
  DISPLAY_INIT_FAILED     = 0x0001,
  DISPLAY_SPI_FAILED      = 0x0002,

  // ── RTC (0x0100) ──────────────────────
  RTC_INIT_FAILED         = 0x0101,
  RTC_I2C_FAILED          = 0x0102,
  RTC_CLOCK_NOT_SET       = 0x0103,

  // ── MPU (0x0200) ──────────────────────
  MPU_INIT_FAILED         = 0x0201,
  MPU_I2C_FAILED          = 0x0202,

  // ── EEPROM (0x0300) ──────────────────
  EEPROM_INIT_FAILED      = 0x0301,
  EEPROM_I2C_FAILED       = 0x0302,

  // ── SD (0x0500) ──────────────────────
  SD_INIT_FAILED          = 0x0501,
  SD_MOUNT_FAILED         = 0x0502,
  SD_FILE_NOT_FOUND       = 0x0503,
  SD_WRITE_FAILED         = 0x0504,
  SD_READ_FAILED          = 0x0505,

  // ── Audio (0x0600) ──────────────────
  AUDIO_INIT_FAILED       = 0x0601,
  AUDIO_I2S_FAILED        = 0x0602,

  // ── BLE (0x0700) ────────────────────
  BLE_INIT_FAILED         = 0x0701,
  BLE_ADVERTISING_FAILED  = 0x0702,

  // ── Vault (0x0900) ──────────────────
  VAULT_INIT_FAILED       = 0x0901,
  VAULT_ALLOC_FAILED      = 0x0902,
  VAULT_SAVE_FAILED       = 0x0903,
  VAULT_LOAD_FAILED       = 0x0904,
  VAULT_DECRYPT_FAILED    = 0x0905,
  VAULT_ENCRYPT_FAILED    = 0x0906,
  VAULT_BAD_FORMAT        = 0x0907,
  VAULT_NO_FILE           = 0x0908,
  VAULT_PIN_WRONG         = 0x0909,
  VAULT_PIN_LOCKOUT       = 0x090A,
  VAULT_INCREMENTAL_FAIL  = 0x090B,

  // ── Crypto (0x0B00) ─────────────────
  CRYPTO_AES_FAILED       = 0x0B01,
  CRYPTO_PBKDF2_FAILED    = 0x0B02,
  CRYPTO_HASH_FAILED      = 0x0B03,

  // ── INA219 (0x0D00) ─────────────────
  INA219_INIT_FAILED      = 0x0D01,
  INA219_I2C_FAILED       = 0x0D02,

  // ── LittleFS (0x0E00) ───────────────
  LITTLEFS_MOUNT_FAILED   = 0x0E01,
  LITTLEFS_FORMAT_FAILED  = 0x0E02,

  // ── Session (0x0A00) ────────────────
  SESSION_TIMEOUT         = 0x0A01,
  SESSION_HANDSHAKE_FAIL  = 0x0A02,

  // ── AP Mode (0x0F00) ────────────────
  AP_START_FAILED         = 0x0F01,
  AP_WIFI_FAILED          = 0x0F02,
};

// ── LastError struct ────────────────────────────────────────────────────────
// Tracks the last error per subsystem. Each subsystem has one slot.
struct LastError {
  ErrSeverity severity;
  ErrCode code;
  unsigned long timestamp;   // millis() when the error was logged
  char message[64];          // brief human-readable description
};

// ── Ring buffer for recent errors ──────────────────────────────────────────
#define EF_RING_SIZE 16

struct ErrorRingEntry {
  ErrSeverity severity;
  ErrCode code;
  ErrSubsystem subsystem;
  unsigned long timestamp;
  char message[64];
};

// ── Error framework functions ───────────────────────────────────────────────

// Log an error with severity, code, and message. Writes to Serial and
// stores in the per-subsystem LastError slot + the ring buffer.
void logError(ErrSeverity severity, ErrCode code, const char* message);

// Convenience wrapper: log with subsystem context.
void logError(ErrSeverity severity, ErrCode code, ErrSubsystem subsystem, const char* message);

// Get the last error for a subsystem. Returns a LastError with code=NONE
// if no error has been logged for that subsystem.
LastError getLastError(ErrSubsystem subsystem);

// Clear the last error for a subsystem (e.g., after it's been handled).
void clearLastError(ErrSubsystem subsystem);

// Print the error ring buffer to Serial (for diagnostics).
void printErrorRing();

// ── Error severity to string ───────────────────────────────────────────────
const char* errSeverityStr(ErrSeverity s);

// ── Error code to string ───────────────────────────────────────────────────
const char* errCodeStr(ErrCode c);
