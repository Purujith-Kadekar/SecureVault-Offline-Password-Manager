#pragma once
// ═══════════════════════════════════════════════════════════════════════════════
//  board_config.h — EdgeHax ESP32-S3 S3-PRO (N16R8) pin map & UI constants
//  Developed by Purujith Kadekar
// ═══════════════════════════════════════════════════════════════════════════════
#include <Arduino.h>

// ---- Display (ILI9341, hardware SPI — FSPI bus, shared with touch) ----
#define TFT_CS      4
#define TFT_RST     5
#define TFT_DC      7
#define TFT_MOSI    15
#define TFT_CLK     16
#define TFT_MISO    39
#define TFT_SPI_HZ  40000000UL

// ---- Touch (XPT2046, same physical SPI bus as the display, own CS) ----
#define TOUCH_CS    14
#define T_DO        41

// ---- RTC (DS3231) + MPU6050 + EEPROM — shared I2C bus ----
// The DS3231 breakout also carries an AT24C32 EEPROM (32Kbit / 4096 bytes,
// 32-byte page size) on the same board, at its own I2C address -- this is
// NOT a separate peripheral wired up independently, it's on the RTC module
// itself. See eeprom_manager.h/cpp.
#define RTC_SDA     1
#define RTC_SCL     2
#define RTC_I2C_ADDR 0x68
#define MPU_ADDR    0x69
#define EEPROM_I2C_ADDR 0x57
#define INA219_I2C_ADDR 0x40
#define PIN_INA219_ADDR INA219_I2C_ADDR   // alias for ina219_manager.h

// ---- Input ----
#define LADDER_PIN  6    // 5-switch resistor ladder (analog)
#define TOUCH_PIN   40   // TTP223 capacitive wake sensor
#define BUZZER_PIN  38   // Passive buzzer (LEDC PWM) -- sole audio output; I2S/DAC path was removed entirely, this isn't a fallback

// Resistor ladder thresholds — from Buttons.txt's final calibration pass
// (3V3 -> 10K pull-up -> GPIO6). Do not tweak without re-running that
// calibration; these are tuned to the specific insulated-spring build.
#define TH_SPRING_MAX  250
#define TH_RIGHT_MAX   600
#define TH_UP_MAX      1050
#define TH_DOWN_MAX    1680
#define TH_LEFT_MAX    2900

// ---- microSD (dedicated SPI bus — HSPI, separate from the display bus) ----
#define SD_CS       10
#define SD_MOSI     11
#define SD_SCK      12
#define SD_MISO     13

// ---- I2S audio out (CS4344 DAC — UI feedback tones only, no mic capture) ----
#define I2S_MCLK    9
#define I2S_SDIN    38
#define I2S_LRCLK   21
#define I2S_BCLK    42

// ═══════════════════════════════════════════════════════════════════════════════
//  UI LAYOUT
// ═══════════════════════════════════════════════════════════════════════════════
#define SCREEN_W     320
#define SCREEN_H     240
#define SBAR_H       20

#define NUM_COLS     3
#define NUM_ROWS     4
#define NUM_BW       96
#define NUM_BH       38
#define NUM_GAP      3
#define NUM_X0       4
#define NUM_Y0       66

#define LIST_ITEM_H    38
#define LIST_Y0        44
#define LIST_VISIBLE   5

#define MODE_BADGE_X  (SCREEN_W - 80)   // Mode badge moved left for battery space
#define MODE_BADGE_Y  0
#define MODE_BADGE_W  28
#define MODE_BADGE_H  20

// Battery percentage display — horizontal smartphone-style icon sized for 2.4" (320×240).
// Modern phone battery icons are WIDE (width > height) with a small nib on the RIGHT.
// Fill grows from LEFT to RIGHT — charge proportional to fill width.
// Body: 16×9px, Nib: 2×4px on the right edge, icon+text with clear gap.
// Layout: badge(28px) → gap(2px) → icon(18px) → gap(1px) → text("100%"=24px) = fits in 320px
#define BATT_ICON_X  270
#define BATT_ICON_Y  5
#define BATT_ICON_W  16
#define BATT_ICON_H  9
#define BATT_NIB_W   2
#define BATT_NIB_H   4
#define BATT_TEXT_X  290
#define BATT_TEXT_Y  6

#define MENU_OPT_H   26
#define MENU_GAP     4

// ═══════════════════════════════════════════════════════════════════════════════
//  TIMING
// ═══════════════════════════════════════════════════════════════════════════════
#define AUTO_LOCK_MS      60000UL
#define MAX_PIN_LEN       8
#define TOUCH_DEBOUNCE_MS 120
#define SANE_EPOCH        1704067200UL   // 2024-01-01 — reject anything older

// Button poll interval. Lowered from 120ms to 50ms so the TTP223 touch pad
// feels instant. The ladder's 64-sample ADC averaging (3.2ms) is unaffected.
#define BTN_POLL_MS       50

// ─── Pattern unlock (hardcoded) ────────────────────────────────────────────
// The TTP223 capacitive pad doubles as a pattern-entry device: each touch is
// classified as Short (100-500ms) or Long (500ms+). A gap of >2s submits the
// pattern. The pattern is stored as a bitmask (0=Short, 1=Long), MSB first.
//
// Default pattern: L-L-S-S-S-L (6 elements) = 0b110001
// To change: edit UNLOCK_PATTERN_MASK below and reflash. No in-app setting.
//
// The pattern unlock runs in PARALLEL with the PIN unlock on the lock screen.
// Either one matching unlocks the vault.
#define UNLOCK_PATTERN_MASK  0b110001   // L-L-S-S-S-L
#define UNLOCK_PATTERN_LEN   6
#define MAX_PATTERN_LEN      12

// Pattern timing thresholds (milliseconds)
#define PATTERN_SHORT_MIN     100   // below this = noise, ignore
#define PATTERN_SHORT_MAX     500   // 100-500ms = Short (dot)
#define PATTERN_LONG_MIN      500   // 500ms+ = Long (dash)
#define PATTERN_GAP_SUBMIT   2000   // gap > 2s = submit pattern
#define PATTERN_GAP_MAX      5000   // gap > 5s = abandon + clear

// ═══════════════════════════════════════════════════════════════════════════════
//  PALETTE (RGB565)
// ═══════════════════════════════════════════════════════════════════════════════
// F16 FIX: Removed all #define color macros (C_BG, C_PANEL, etc.).
// These were previously #defined here, then #undef'd in ui_theme.h and
// replaced with extern uint16_t variables. If any file forgot to include
// ui_theme.h after this header, it silently used compile-time defaults
// instead of runtime theme variables.
//
// Color values are now defined in ui_theme.h:
//   - ThemeDefaults struct provides compile-time defaults (for files that
//     just need a reference value, not runtime theme support)
//   - extern uint16_t C_* variables provide runtime theme support (for
//     files that need colors to change with the active theme)
//
// If a file uses C_BG (or any C_* name) without including ui_theme.h,
// the compiler will now produce an error — this is a BREAKING CHANGE
// but it is the CORRECT behavior. No silent wrong defaults.
// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
//  VAULT
// ═══════════════════════════════════════════════════════════════════════════════
#define MAX_SD_VAULT 256
// F12: Removed DEFAULT_VAULT_PIN "1234" — hard-coded default PIN is a security
// vulnerability. The device now forces the user to choose their own PIN on
// first boot. FIRST_BOOT_PIN_SENTINEL marks "no PIN has been set yet".
#define FIRST_BOOT_PIN_SENTINEL "UNSET"
// NVS key name for the first-boot flag stored in the securevault namespace.
#define FIRST_BOOT_FLAG_KEY "first_boot"