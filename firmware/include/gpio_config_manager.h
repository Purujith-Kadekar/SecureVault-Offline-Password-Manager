#pragma once
// ═══════════════════════════════════════════════════════════════════════════════
//  gpio_config_manager.h — Runtime GPIO pin override system
// ═══════════════════════════════════════════════════════════════════════════════
//  Reads a binary config blob from the "gpio_cfg" flash partition at boot.
//  If the partition is missing or invalid, all pins fall back to the compile-
//  time defaults (board_config.h *_DEFAULT macros). This allows the GitHub
//  flasher page to customize GPIO pins per-user without rebuilding firmware.
//
//  Architecture:
//    1. board_config.h defines TFT_CS_DEFAULT, RTC_SDA_DEFAULT, etc.
//    2. This file declares extern runtime variables (PIN_TFT_CS, PIN_RTC_SDA, ...)
//       initialized from the defaults.
//    3. GpioConfigManager::begin() reads the gpio_cfg partition and overrides
//       any pin where the blob value != -1 (0xFF).
//    4. Every manager uses PIN_TFT_CS (runtime) instead of TFT_CS (compile-time).
//       If no config partition exists, PIN_TFT_CS == TFT_CS_DEFAULT == 4.
//
//  This ensures "flash and go" — users who skip the GPIO config page get the
//  exact same behavior as before. Users with different hardware fill in their
//  pins on the flasher page, and the generated binary is flashed alongside
//  the firmware.
// ═══════════════════════════════════════════════════════════════════════════════
#include <Arduino.h>

// ── Pin key identifiers (index into the config blob's pin array) ──────────
// Each key maps to a specific configurable pin. The flasher page uses these
// same numeric IDs to build the binary config blob.
enum PinKey : uint8_t {
  PK_TFT_CS       = 0,
  PK_TFT_RST      = 1,
  PK_TFT_DC       = 2,
  PK_TFT_MOSI     = 3,
  PK_TFT_CLK      = 4,
  PK_TFT_MISO     = 5,
  PK_TOUCH_CS     = 6,
  PK_T_DO         = 7,
  PK_RTC_SDA      = 8,
  PK_RTC_SCL      = 9,
  PK_LADDER_PIN   = 10,
  PK_TOUCH_PIN    = 11,
  PK_BUZZER_PIN   = 12,
  PK_SD_CS        = 13,
  PK_SD_MOSI      = 14,
  PK_SD_SCK       = 15,
  PK_SD_MISO      = 16,
  PK_I2S_MCLK     = 17,
  PK_I2S_SDIN     = 18,
  PK_I2S_LRCLK    = 19,
  PK_I2S_BCLK     = 20,
  PK_RTC_I2C_ADDR = 21,
  PK_MPU_ADDR     = 22,
  PK_EEPROM_ADDR  = 23,
  PK_INA219_ADDR  = 24,
  PK_MAX          = 25
};

// ── Config blob format (256 bytes — fits in a small flash partition) ──────
// The flasher page generates this exact binary structure.
// Pins[i] = -1 (0xFF) means "use default, don't override".
// Pins[i] = GPIO number (0-48) or I2C address (0x00-0x7F) means "override".
struct GpioConfigBlob {
  uint32_t magic;          // Must be 0x47435046 ("GCPF")
  uint16_t version;        // Must be 1
  int8_t   pins[PK_MAX];   // 25 pin override slots
  uint8_t  reserved[225];  // Padding — zeros
  uint32_t checksum;       // CRC32 of bytes [0..251] (everything except checksum)
};
// Static assert: total size must be 256
static_assert(sizeof(GpioConfigBlob) == 256, "GpioConfigBlob must be 256 bytes");

#define GPIO_CFG_MAGIC   0x47435046
#define GPIO_CFG_VERSION 1

// ── Runtime pin variables ────────────────────────────────────────────────
// Initialized from board_config.h *_DEFAULT macros. GpioConfigManager::begin()
// may override these from the gpio_cfg partition. All managers should use
// these variables instead of the old #define macros.
extern int8_t PIN_TFT_CS;
extern int8_t PIN_TFT_RST;
extern int8_t PIN_TFT_DC;
extern int8_t PIN_TFT_MOSI;
extern int8_t PIN_TFT_CLK;
extern int8_t PIN_TFT_MISO;
extern int8_t PIN_TOUCH_CS;
extern int8_t PIN_T_DO;
extern int8_t PIN_RTC_SDA;
extern int8_t PIN_RTC_SCL;
extern int8_t PIN_LADDER_PIN;
extern int8_t PIN_TOUCH_PIN;
extern int8_t PIN_BUZZER_PIN;
extern int8_t PIN_SD_CS;
extern int8_t PIN_SD_MOSI;
extern int8_t PIN_SD_SCK;
extern int8_t PIN_SD_MISO;
extern int8_t PIN_I2S_MCLK;
extern int8_t PIN_I2S_SDIN;
extern int8_t PIN_I2S_LRCLK;
extern int8_t PIN_I2S_BCLK;
extern int8_t PIN_RTC_I2C_ADDR;
extern int8_t PIN_MPU_ADDR;
extern int8_t PIN_EEPROM_ADDR;
extern int8_t PIN_INA219_ADDR;

class GpioConfigManager {
public:
  GpioConfigManager();

  // Read gpio_cfg partition and apply overrides to runtime pin variables.
  // Must be called BEFORE any other manager's begin() in setup().
  // Returns true if a valid config was found and applied.
  bool begin();

  // Returns true if begin() found and applied a valid config.
  bool hasOverrides() const { return _loaded; }

private:
  bool _loaded = false;

  // CRC32 implementation (same as used by the flasher page)
  static uint32_t crc32(const uint8_t* data, size_t length);
};
