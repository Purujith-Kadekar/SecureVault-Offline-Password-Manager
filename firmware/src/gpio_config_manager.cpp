// ═══════════════════════════════════════════════════════════════════════════════
//  gpio_config_manager.cpp — Runtime GPIO pin override system
// ═══════════════════════════════════════════════════════════════════════════════
#include "gpio_config_manager.h"
#include "board_config.h"
#include <esp_partition.h>

// ── Runtime pin variables — initialized from board_config.h defaults ─────
// These start with the EdgeHax S3-PRO pin mapping (compile-time defaults).
// If a valid gpio_cfg partition exists, begin() overrides the ones the user
// changed. This guarantees "flash and go" — no config partition = same
// behavior as before.
int8_t PIN_TFT_CS       = TFT_CS_DEFAULT;
int8_t PIN_TFT_RST      = TFT_RST_DEFAULT;
int8_t PIN_TFT_DC       = TFT_DC_DEFAULT;
int8_t PIN_TFT_MOSI     = TFT_MOSI_DEFAULT;
int8_t PIN_TFT_CLK      = TFT_CLK_DEFAULT;
int8_t PIN_TFT_MISO     = TFT_MISO_DEFAULT;
int8_t PIN_TOUCH_CS     = TOUCH_CS_DEFAULT;
int8_t PIN_T_DO         = T_DO_DEFAULT;
int8_t PIN_RTC_SDA      = RTC_SDA_DEFAULT;
int8_t PIN_RTC_SCL      = RTC_SCL_DEFAULT;
int8_t PIN_LADDER_PIN   = LADDER_PIN_DEFAULT;
int8_t PIN_TOUCH_PIN    = TOUCH_PIN_DEFAULT;
int8_t PIN_BUZZER_PIN   = BUZZER_PIN_DEFAULT;
int8_t PIN_SD_CS        = SD_CS_DEFAULT;
int8_t PIN_SD_MOSI      = SD_MOSI_DEFAULT;
int8_t PIN_SD_SCK       = SD_SCK_DEFAULT;
int8_t PIN_SD_MISO      = SD_MISO_DEFAULT;
int8_t PIN_I2S_MCLK     = I2S_MCLK_DEFAULT;
int8_t PIN_I2S_SDIN     = I2S_SDIN_DEFAULT;
int8_t PIN_I2S_LRCLK    = I2S_LRCLK_DEFAULT;
int8_t PIN_I2S_BCLK     = I2S_BCLK_DEFAULT;
int8_t PIN_RTC_I2C_ADDR = RTC_I2C_ADDR_DEFAULT;
int8_t PIN_MPU_ADDR     = MPU_ADDR_DEFAULT;
int8_t PIN_EEPROM_ADDR  = EEPROM_I2C_ADDR_DEFAULT;
int8_t PIN_INA219_ADDR  = INA219_I2C_ADDR_DEFAULT;

GpioConfigManager::GpioConfigManager() {}

bool GpioConfigManager::begin() {
  // Find the gpio_cfg partition (type=data, subtype=0x40, label="gpio_cfg")
  const esp_partition_t* part = esp_partition_find_first(
      ESP_PARTITION_TYPE_DATA,
      (esp_partition_subtype_t)0x40,
      "gpio_cfg");

  if (!part) {
    Serial.println("[GpioCfg] No gpio_cfg partition — using EdgeHax S3-PRO defaults.");
    return false;
  }

  Serial.printf("[GpioCfg] Found partition at 0x%X, size %d bytes.\n",
                part->address, part->size);

  // Read the blob
  GpioConfigBlob blob;
  memset(&blob, 0, sizeof(blob));
  esp_err_t err = esp_partition_read(part, 0, &blob, sizeof(blob));
  if (err != ESP_OK) {
    Serial.printf("[GpioCfg] Partition read failed: %s\n", esp_err_to_name(err));
    return false;
  }

  // ── Validate magic ────────────────────────────────────────────────────
  if (blob.magic != GPIO_CFG_MAGIC) {
    Serial.println("[GpioCfg] Invalid magic — partition empty or corrupt, using defaults.");
    return false;
  }

  // ── Validate version ──────────────────────────────────────────────────
  if (blob.version != GPIO_CFG_VERSION) {
    Serial.printf("[GpioCfg] Unknown version %u (expected %u) — using defaults.\n",
                  blob.version, GPIO_CFG_VERSION);
    return false;
  }

  // ── Validate CRC32 ────────────────────────────────────────────────────
  uint32_t computed = crc32((const uint8_t*)&blob, sizeof(blob) - 4);
  if (computed != blob.checksum) {
    Serial.printf("[GpioCfg] CRC mismatch (computed 0x%08X, stored 0x%08X) — using defaults.\n",
                  computed, blob.checksum);
    return false;
  }

  // ── Apply overrides ────────────────────────────────────────────────────
  // pins[i] = -1 (0xFF) means "keep default", anything else overrides.
  int overridesApplied = 0;
  for (int i = 0; i < PK_MAX; i++) {
    if (blob.pins[i] == -1) continue;  // no override for this pin
    overridesApplied++;
    switch (i) {
      case PK_TFT_CS:       PIN_TFT_CS       = blob.pins[i]; break;
      case PK_TFT_RST:      PIN_TFT_RST      = blob.pins[i]; break;
      case PK_TFT_DC:       PIN_TFT_DC       = blob.pins[i]; break;
      case PK_TFT_MOSI:     PIN_TFT_MOSI     = blob.pins[i]; break;
      case PK_TFT_CLK:      PIN_TFT_CLK      = blob.pins[i]; break;
      case PK_TFT_MISO:     PIN_TFT_MISO     = blob.pins[i]; break;
      case PK_TOUCH_CS:     PIN_TOUCH_CS     = blob.pins[i]; break;
      case PK_T_DO:         PIN_T_DO         = blob.pins[i]; break;
      case PK_RTC_SDA:      PIN_RTC_SDA      = blob.pins[i]; break;
      case PK_RTC_SCL:      PIN_RTC_SCL      = blob.pins[i]; break;
      case PK_LADDER_PIN:   PIN_LADDER_PIN   = blob.pins[i]; break;
      case PK_TOUCH_PIN:    PIN_TOUCH_PIN    = blob.pins[i]; break;
      case PK_BUZZER_PIN:   PIN_BUZZER_PIN   = blob.pins[i]; break;
      case PK_SD_CS:        PIN_SD_CS        = blob.pins[i]; break;
      case PK_SD_MOSI:      PIN_SD_MOSI      = blob.pins[i]; break;
      case PK_SD_SCK:       PIN_SD_SCK       = blob.pins[i]; break;
      case PK_SD_MISO:      PIN_SD_MISO      = blob.pins[i]; break;
      case PK_I2S_MCLK:     PIN_I2S_MCLK     = blob.pins[i]; break;
      case PK_I2S_SDIN:     PIN_I2S_SDIN     = blob.pins[i]; break;
      case PK_I2S_LRCLK:    PIN_I2S_LRCLK    = blob.pins[i]; break;
      case PK_I2S_BCLK:     PIN_I2S_BCLK     = blob.pins[i]; break;
      case PK_RTC_I2C_ADDR: PIN_RTC_I2C_ADDR = blob.pins[i]; break;
      case PK_MPU_ADDR:     PIN_MPU_ADDR     = blob.pins[i]; break;
      case PK_EEPROM_ADDR:  PIN_EEPROM_ADDR  = blob.pins[i]; break;
      case PK_INA219_ADDR:  PIN_INA219_ADDR  = blob.pins[i]; break;
    }
  }

  _loaded = true;
  Serial.printf("[GpioCfg] Applied %d GPIO overrides from partition.\n", overridesApplied);
  return true;
}

// ── CRC32 (standard Ethernet/PNG polynomial 0xEDB88320) ─────────────────
// Same algorithm used by the flasher page's JavaScript CRC32 implementation.
// Both must produce identical results for the same input bytes.
uint32_t GpioConfigManager::crc32(const uint8_t* data, size_t length) {
  uint32_t crc = 0xFFFFFFFF;
  for (size_t i = 0; i < length; i++) {
    crc ^= data[i];
    for (int j = 0; j < 8; j++) {
      crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
    }
  }
  return ~crc;
}
