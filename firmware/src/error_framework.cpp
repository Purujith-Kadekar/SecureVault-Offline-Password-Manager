// ═══════════════════════════════════════════════════════════════════════════════
//  error_framework.cpp — F15: Formal Error Handling Framework
// ═══════════════════════════════════════════════════════════════════════════════
#include "error_framework.h"
#include <cstring>

// ── Per-subsystem last error slots ──────────────────────────────────────────
static LastError _lastErrors[(int)ErrSubsystem::ERR_MAX_SUBSYSTEM];

// ── Ring buffer ─────────────────────────────────────────────────────────────
static ErrorRingEntry _ring[EF_RING_SIZE];
static int _ringHead = 0;
static int _ringCount = 0;

// ── Log an error ────────────────────────────────────────────────────────────
void logError(ErrSeverity severity, ErrCode code, const char* message) {
  // Determine subsystem from error code.
  ErrSubsystem subsystem;
  uint16_t c = (uint16_t)code;
  uint8_t subIdx = (c >> 8) & 0xFF;
  if (subIdx < (uint8_t)ErrSubsystem::ERR_MAX_SUBSYSTEM) {
    subsystem = (ErrSubsystem)subIdx;
  } else {
    subsystem = ErrSubsystem::ERR_GENERAL;
  }
  logError(severity, code, subsystem, message);
}

void logError(ErrSeverity severity, ErrCode code, ErrSubsystem subsystem, const char* message) {
  // 1. Store in per-subsystem slot.
  int idx = (int)subsystem;
  if (idx >= 0 && idx < (int)ErrSubsystem::ERR_MAX_SUBSYSTEM) {
    _lastErrors[idx].severity = severity;
    _lastErrors[idx].code = code;
    _lastErrors[idx].timestamp = millis();
    if (message) {
      strncpy(_lastErrors[idx].message, message, sizeof(_lastErrors[idx].message) - 1);
      _lastErrors[idx].message[sizeof(_lastErrors[idx].message) - 1] = '\0';
    } else {
      _lastErrors[idx].message[0] = '\0';
    }
  }

  // 2. Add to ring buffer.
  ErrorRingEntry& entry = _ring[_ringHead];
  entry.severity = severity;
  entry.code = code;
  entry.subsystem = subsystem;
  entry.timestamp = millis();
  if (message) {
    strncpy(entry.message, message, sizeof(entry.message) - 1);
    entry.message[sizeof(entry.message) - 1] = '\0';
  } else {
    entry.message[0] = '\0';
  }
  _ringHead = (_ringHead + 1) % EF_RING_SIZE;
  if (_ringCount < EF_RING_SIZE) _ringCount++;

  // 3. Print to Serial.
  Serial.printf("[F15-%s] %s: %s\n",
               errSeverityStr(severity),
               errCodeStr(code),
               message ? message : "");
}

// ── Get last error ──────────────────────────────────────────────────────────
LastError getLastError(ErrSubsystem subsystem) {
  int idx = (int)subsystem;
  if (idx >= 0 && idx < (int)ErrSubsystem::ERR_MAX_SUBSYSTEM) {
    return _lastErrors[idx];
  }
  LastError none;
  none.severity = ErrSeverity::INFO;
  none.code = ErrCode::NONE;
  none.timestamp = 0;
  none.message[0] = '\0';
  return none;
}

// ── Clear last error ────────────────────────────────────────────────────────
void clearLastError(ErrSubsystem subsystem) {
  int idx = (int)subsystem;
  if (idx >= 0 && idx < (int)ErrSubsystem::ERR_MAX_SUBSYSTEM) {
    _lastErrors[idx].code = ErrCode::NONE;
    _lastErrors[idx].message[0] = '\0';
  }
}

// ── Print ring buffer ───────────────────────────────────────────────────────
void printErrorRing() {
  Serial.println("═══════════ F15: Error Ring Buffer ═══════════");
  int start = (_ringHead - _ringCount + EF_RING_SIZE) % EF_RING_SIZE;
  for (int i = 0; i < _ringCount; i++) {
    int idx = (start + i) % EF_RING_SIZE;
    const ErrorRingEntry& e = _ring[idx];
    Serial.printf("  [%lu] %s %s: %s\n",
                 e.timestamp,
                 errSeverityStr(e.severity),
                 errCodeStr(e.code),
                 e.message);
  }
  Serial.println("═══════════════════════════════════════════════════════════");
}

// ── Severity to string ──────────────────────────────────────────────────────
const char* errSeverityStr(ErrSeverity s) {
  switch (s) {
    case ErrSeverity::INFO:     return "INFO";
    case ErrSeverity::WARN:    return "WARN";
    case ErrSeverity::ERROR:   return "ERROR";
    case ErrSeverity::CRITICAL: return "CRITICAL";
    default:                    return "???";
  }
}

// ── Error code to string ────────────────────────────────────────────────────
const char* errCodeStr(ErrCode c) {
  switch (c) {
    case ErrCode::NONE:              return "NONE";
    case ErrCode::UNKNOWN:           return "UNKNOWN";
    case ErrCode::DISPLAY_INIT_FAILED:    return "DISPLAY_INIT_FAILED";
    case ErrCode::DISPLAY_SPI_FAILED:     return "DISPLAY_SPI_FAILED";
    case ErrCode::RTC_INIT_FAILED:        return "RTC_INIT_FAILED";
    case ErrCode::RTC_I2C_FAILED:         return "RTC_I2C_FAILED";
    case ErrCode::RTC_CLOCK_NOT_SET:      return "RTC_CLOCK_NOT_SET";
    case ErrCode::MPU_INIT_FAILED:        return "MPU_INIT_FAILED";
    case ErrCode::MPU_I2C_FAILED:         return "MPU_I2C_FAILED";
    case ErrCode::EEPROM_INIT_FAILED:     return "EEPROM_INIT_FAILED";
    case ErrCode::EEPROM_I2C_FAILED:      return "EEPROM_I2C_FAILED";
    case ErrCode::SD_INIT_FAILED:         return "SD_INIT_FAILED";
    case ErrCode::SD_MOUNT_FAILED:        return "SD_MOUNT_FAILED";
    case ErrCode::SD_FILE_NOT_FOUND:      return "SD_FILE_NOT_FOUND";
    case ErrCode::SD_WRITE_FAILED:        return "SD_WRITE_FAILED";
    case ErrCode::SD_READ_FAILED:         return "SD_READ_FAILED";
    case ErrCode::AUDIO_INIT_FAILED:      return "AUDIO_INIT_FAILED";
    case ErrCode::AUDIO_I2S_FAILED:       return "AUDIO_I2S_FAILED";
    case ErrCode::BLE_INIT_FAILED:        return "BLE_INIT_FAILED";
    case ErrCode::BLE_ADVERTISING_FAILED: return "BLE_ADVERTISING_FAILED";
    case ErrCode::VAULT_INIT_FAILED:      return "VAULT_INIT_FAILED";
    case ErrCode::VAULT_ALLOC_FAILED:     return "VAULT_ALLOC_FAILED";
    case ErrCode::VAULT_SAVE_FAILED:      return "VAULT_SAVE_FAILED";
    case ErrCode::VAULT_LOAD_FAILED:      return "VAULT_LOAD_FAILED";
    case ErrCode::VAULT_DECRYPT_FAILED:   return "VAULT_DECRYPT_FAILED";
    case ErrCode::VAULT_ENCRYPT_FAILED:   return "VAULT_ENCRYPT_FAILED";
    case ErrCode::VAULT_BAD_FORMAT:       return "VAULT_BAD_FORMAT";
    case ErrCode::VAULT_NO_FILE:          return "VAULT_NO_FILE";
    case ErrCode::VAULT_PIN_WRONG:        return "VAULT_PIN_WRONG";
    case ErrCode::VAULT_PIN_LOCKOUT:      return "VAULT_PIN_LOCKOUT";
    case ErrCode::VAULT_INCREMENTAL_FAIL: return "VAULT_INCREMENTAL_FAIL";
    case ErrCode::CRYPTO_AES_FAILED:      return "CRYPTO_AES_FAILED";
    case ErrCode::CRYPTO_PBKDF2_FAILED:   return "CRYPTO_PBKDF2_FAILED";
    case ErrCode::CRYPTO_HASH_FAILED:     return "CRYPTO_HASH_FAILED";
    case ErrCode::INA219_INIT_FAILED:     return "INA219_INIT_FAILED";
    case ErrCode::INA219_I2C_FAILED:      return "INA219_I2C_FAILED";
    case ErrCode::LITTLEFS_MOUNT_FAILED:  return "LITTLEFS_MOUNT_FAILED";
    case ErrCode::LITTLEFS_FORMAT_FAILED: return "LITTLEFS_FORMAT_FAILED";
    case ErrCode::SESSION_TIMEOUT:        return "SESSION_TIMEOUT";
    case ErrCode::SESSION_HANDSHAKE_FAIL: return "SESSION_HANDSHAKE_FAIL";
    case ErrCode::AP_START_FAILED:        return "AP_START_FAILED";
    case ErrCode::AP_WIFI_FAILED:         return "AP_WIFI_FAILED";
    default:                              return "ERR_CODE_xxxx";
  }
}
