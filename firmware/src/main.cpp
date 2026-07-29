// ═══════════════════════════════════════════════════════════════════════════════
//  main.cpp — SecureVault v9.20-v5.3.1 (PlatformIO)
//  EdgeHax ESP32-S3 S3-PRO (N16R8) hardware password manager
//  Developed by Purujith Kadekar
// ═══════════════════════════════════════════════════════════════════════════════
// Every feature is a standalone manager class in include/ + src/ — this file
// only wires them together and runs the loop. See README.md for the full
// module list and wiring notes.
//
// F8/F10/F11/F14/F15/F16: Architectural fixes integrated into the boot
// sequence. See individual headers for details.
#include <Arduino.h>
#include <LittleFS.h>
#include <esp_sleep.h>
#include <esp_heap_caps.h>
#include "board_config.h"
// F16: board_config.h no longer defines C_* macros. Files that use color
// variables must include ui_theme.h (which declares the extern uint16_t C_*).
#include "ui_theme.h"       // F16: color variables (extern uint16_t C_*)
#include "display_manager.h"
#include "rtc_manager.h"
#include "mpu_manager.h"
#include "eeprom_manager.h"
#include "button_manager.h"
#include "sd_manager.h"
#include "vault_manager.h"
#include "audio_manager.h"
#include "ble_keyboard_manager.h"
#include "ui_screens.h"
#include "diagnostics.h"
#include "duress_manager.h"
#include "ina219_manager.h"
#include "session_context.h"  // F6: single authoritative PIN holder
// F8: Singleton initialization declarations
#include "ap_mode_manager.h"
#include "web_auth_manager.h"
#include "secure_layer_manager.h"
#include "url_obfuscation_manager.h"
#include "method_tunneling_manager.h"
#include "header_obfuscation_manager.h"
#include "traffic_obfuscation_manager.h"
// F10: State machine coordination
#include "state_coordinator.h"
// F11: Unified settings/persistence
#include "settings_manager.h"
// F14: Initialization orchestrator
#include "init_orchestrator.h"
// F15: Error framework
#include "error_framework.h"

DisplayManager     disp;
RtcManager         rtc;
MpuManager         mpu;
EepromManager      eeprom;
ButtonManager      btn;
SdManager          sd;
VaultManager       vault;
AudioManager       audio;
BleKeyboardManager ble;
SerialProtocol     serialProto;
DuressManager      duress;
Ina219Manager       ina219;

// F6: SessionContext — single authoritative holder of the vault PIN.
// Eliminates 5+ separate char[] PIN copies across components.
// Created here as a global, passed by reference/pointer to all components.
SessionContext sessionCtx;

UiController ui(disp, vault, rtc, mpu, btn, ble, audio, serialProto, duress, ina219, sessionCtx);

// ═══════════════════════════════════════════════════════════════════════════════
//  F14: Init function wrappers for the orchestrator
//  Each component's begin() is wrapped in a static function so the
//  orchestrator can call it via a function pointer.
// ═══════════════════════════════════════════════════════════════════════════════
static bool initSerial()      { Serial.setRxBufferSize(8192); Serial.begin(115200); delay(200); return true; }
static bool initDisplay()     { return disp.begin(); }
static bool initRTC()         { return rtc.begin(); }
static bool initMPU()         { bool ok = mpu.begin(); if (!ok) logError(ErrSeverity::ERROR, ErrCode::MPU_INIT_FAILED, ErrSubsystem::ERR_MPU, "MPU6050 begin() failed"); return ok; }
static bool initEEPROM()      { return eeprom.begin(); }
static bool initButtons()     { btn.begin(); return true; }
static bool initSD()          { return sd.begin(); }
static bool initAudio()       { return audio.begin(); }
static bool initBLE()         { bool ok = ble.begin("SecureVault"); ble.setVault(&vault); return ok; }
static bool initVault()       { vault.begin(); return true; }
static bool initINA219()      { return ina219.begin(); }
static bool initSettingsMgr() { return settingsMgr.begin(); }

// F8: Singleton init wrappers — called in explicit dependency order.
// These call getInstance().begin() on each singleton BEFORE any other
// component uses them. If getInstance() is called before begin(), the
// singleton auto-initializes with a warning (safe fallback).
static bool initAPMode()            { return APModeManager::getInstance().begin(); }
static bool initWebAuth()           { return WebAuthManager::getInstance().begin(); }
static bool initSecureLayer()       { return SecureLayerManager::getInstance().begin(); }
static bool initURLObfuscation()    { return URLObfuscationManager::getInstance().begin(); }
static bool initMethodTunneling()   { return MethodTunnelingManager::getInstance().begin(); }
static bool initHeaderObfuscation() { return HeaderObfuscationManager::getInstance().begin(); }
static bool initTrafficObfuscation() { return TrafficObfuscationManager::getInstance().begin(); }

void setup() {
  // ═══════════════════════════════════════════════════════════════════════════════
  //  Phase 0: Serial + diagnostics (before anything else)
  // ═══════════════════════════════════════════════════════════════════════════════
  // v10.3 FIX: Increase USB CDC RX buffer from default 256 bytes to 8KB.
  Serial.setRxBufferSize(8192);
  Serial.begin(115200);
  delay(200);

  // Check if waking from deep sleep
  esp_sleep_wakeup_cause_t wakeup_reason = esp_sleep_get_wakeup_cause();
  bool fromDeepSleep = (wakeup_reason != ESP_SLEEP_WAKEUP_UNDEFINED);
  if (fromDeepSleep) {
    Serial.println("[BOOT] Waking from deep sleep.");
  }

  pinMode(TOUCH_PIN, INPUT);
  if (digitalRead(TOUCH_PIN) == HIGH && !fromDeepSleep) {
    Serial.println("\n[BOOT] Wake sensor held at power-on — entering diagnostics mode.");
    Diagnostics::runAll();
    Serial.println("[BOOT] Diagnostics complete. Reset the device to boot normally.");
    while (true) delay(1000);
  }

  // ═══════════════════════════════════════════════════════════════════════════════
  //  Phase 1: LittleFS mount (must succeed before settings_manager)
  // ═══════════════════════════════════════════════════════════════════════════════
  bool fsOK = false;
  static const char* LFS_BASE_PATH = "/littlefs";
  static const char* LFS_PARTITION_LABEL = "littlefs";

  fsOK = LittleFS.begin(false, LFS_BASE_PATH, 10, LFS_PARTITION_LABEL);
  if (fsOK) {
    Serial.println("[LittleFS] Mounted on first attempt.");
  } else {
    Serial.println("[LittleFS] Plain mount failed, attempting format...");
    LittleFS.format();
    fsOK = LittleFS.begin(false, LFS_BASE_PATH, 10, LFS_PARTITION_LABEL);
    if (fsOK) {
      Serial.println("[LittleFS] Formatted and mounted successfully.");
    } else {
      Serial.println("[LittleFS] Format+mount failed, trying format-on-fail...");
      fsOK = LittleFS.begin(true, LFS_BASE_PATH, 10, LFS_PARTITION_LABEL);
      if (fsOK) {
        Serial.println("[LittleFS] Mounted via format-on-fail.");
      } else {
        Serial.println("[LittleFS] ERROR: All mount attempts failed!");
        logError(ErrSeverity::CRITICAL, ErrCode::LITTLEFS_MOUNT_FAILED, ErrSubsystem::ERR_LITTLEFS,
                 "All 3 LittleFS mount attempts failed");
      }
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════════
  //  Phase 2: F14 — Initialization Orchestrator (dependency-aware boot)
  // ═══════════════════════════════════════════════════════════════════════════════
  // Register all components with their dependencies. The orchestrator will
  // run them in topological order, skipping those whose hard deps failed.
  InitOrchestrator initOrch;

  // No-dependency components (can init anytime after Serial/LittleFS)
  initOrch.addComponent("Serial",         nullptr,          true, nullptr);
  initOrch.addComponent("LittleFS",       nullptr,          false, nullptr);  // soft — already mounted above
  initOrch.addComponent("Display",        initDisplay,      true, nullptr);
  initOrch.addComponent("RTC",            initRTC,          true, nullptr);
  initOrch.addComponent("Buttons",        initButtons,      true, nullptr);

  // I2C bus components (depend on RTC bringing up I2C)
  initOrch.addComponent("MPU",            initMPU,          false, "RTC");    // soft — screen rotation is optional
  initOrch.addComponent("EEPROM",         initEEPROM,       false, "RTC");    // soft — same I2C bus
  initOrch.addComponent("INA219",         initINA219,       false, "RTC");    // soft — battery % is optional

  // Other peripherals
  initOrch.addComponent("SD",             initSD,           false, nullptr);  // soft — demo vault works without SD
  initOrch.addComponent("Audio",          initAudio,        false, nullptr);  // soft — audio cues are optional

  // BLE (no hard deps, but needs display for pairing screen)
  initOrch.addComponent("BLE",            initBLE,          false, "Display"); // soft — BLE typing is optional

  // Vault (depends on SD for loading vault.db, but demo vault works without)
  initOrch.addComponent("Vault",          initVault,        true, "SD");  // hard — core functionality; only SD needed for vault.db

  // F8: Singleton initializations (no runtime deps at boot — they're
  // just empty shells until AP mode's start() actually brings up WiFi).
  // But we init them here so the _initialized flag is set and any
  // premature getInstance() call logs a warning instead of crashing.
  initOrch.addComponent("APModeManager",       initAPMode,            false, nullptr);
  initOrch.addComponent("WebAuthManager",      initWebAuth,           false, "APModeManager");
  initOrch.addComponent("SecureLayerManager",  initSecureLayer,       false, "WebAuthManager");
  initOrch.addComponent("URLObfuscationManager",    initURLObfuscation,    false, "SecureLayerManager");
  initOrch.addComponent("MethodTunnelingManager",   initMethodTunneling,   false, "URLObfuscationManager");
  initOrch.addComponent("HeaderObfuscationManager", initHeaderObfuscation, false, "MethodTunnelingManager");
  initOrch.addComponent("TrafficObfuscationManager", initTrafficObfuscation, false, "HeaderObfuscationManager");

  // Settings manager (depends on LittleFS and SD/NVS being ready)
  initOrch.addComponent("SettingsManager", initSettingsMgr, false, "LittleFS,SD");

  // Run the orchestrated init sequence.
  initOrch.run();

  // ═══════════════════════════════════════════════════════════════════════════════
  //  Phase 3: Post-init — deep sleep resume / boot splash
  // ═══════════════════════════════════════════════════════════════════════════════
  if (fromDeepSleep) {
    Serial.println("[BOOT] Showing resume screen...");
    disp.tft().fillScreen(0x0000);
    disp.tft().sendCommand(ILI9341_SLPOUT); delay(150);
    disp.tft().sendCommand(ILI9341_DISPON); delay(150);
    // Audio needs its own init before we can play the UNLOCK tone.
    audio.begin();
  } else {
    disp.showBootSplash();
  }

  // ═══════════════════════════════════════════════════════════════════════════════
  //  Phase 4: Theme + UI
  // ═══════════════════════════════════════════════════════════════════════════════
  // v10.4: Load the saved theme from NVS BEFORE showResumeScreen() so the
  // resume animation uses the correct background color.
  ui.loadTheme();

  if (fromDeepSleep) {
    ui.showResumeScreen();
  }

  ui.begin();

  // ═══════════════════════════════════════════════════════════════════════════════
  //  Phase 5: Boot summary
  // ═══════════════════════════════════════════════════════════════════════════════
  bool rtcOK   = initOrch.isAvailable("RTC");
  bool eepromOK = initOrch.isAvailable("EEPROM");
  bool sdOK    = initOrch.isAvailable("SD");
  bool audioOK = initOrch.isAvailable("Audio");
  bool bleOK   = initOrch.isAvailable("BLE");
  bool ina219OK = initOrch.isAvailable("INA219");

  // F15: Log any init failures to the error framework for diagnostics.
  if (!rtcOK)   logError(ErrSeverity::WARN, ErrCode::RTC_INIT_FAILED, ErrSubsystem::ERR_RTC, "RTC not available — time may be wrong");
  if (!sdOK)    logError(ErrSeverity::WARN, ErrCode::SD_INIT_FAILED, ErrSubsystem::ERR_SD, "SD not available — using demo vault");
  if (!bleOK)   logError(ErrSeverity::WARN, ErrCode::BLE_INIT_FAILED, ErrSubsystem::ERR_BLE, "BLE not available — no typing mode");
  if (!fsOK)    logError(ErrSeverity::WARN, ErrCode::LITTLEFS_MOUNT_FAILED, ErrSubsystem::ERR_LITTLEFS, "LittleFS not available — settings may not persist");
  if (!audioOK) logError(ErrSeverity::INFO, ErrCode::AUDIO_INIT_FAILED, ErrSubsystem::ERR_AUDIO, "Audio not available — no sound feedback");

  Serial.println("═══════════════════════════════════════════");
  Serial.println("  SecureVault v9.20-v5.3.1 — ready");
  Serial.printf("  RTC:   %s\n", rtcOK   ? "OK" : "NOT FOUND");
  Serial.printf("  EEPROM:%s\n", eepromOK ? " OK" : " NOT FOUND");
  Serial.printf("  SD:    %s\n", sdOK    ? "OK" : "NOT PRESENT (using demo vault)");
  Serial.printf("  Audio: %s\n", audioOK ? "OK" : "NOT FOUND");
  Serial.printf("  BLE:   %s\n", bleOK   ? "OK" : "FAILED TO START");
  Serial.printf("  INA219:  %s\n", ina219OK ? "OK" : "NOT FOUND (battery % hidden)");
  Serial.printf("  LittleFS: %s\n", fsOK ? "OK" : "MOUNT FAILED");
  Serial.println("═══════════════════════════════════════════");

  // F15: Print the error ring buffer if any errors were logged during boot.
  printErrorRing();
}

void loop() {
  // Serial time-set: send  T<unix_timestamp>  e.g. T1735689600
  // ONLY when NOT in Dashboard Mode — in Dashboard Mode, the serial port
  // is used for the binary secure protocol (serial_protocol.cpp) and
  // text reads would corrupt the frame stream.
  if (Serial.available() && !serialProto.sessionEstablished()) {
    // Peek first — only treat as time-set if it starts with 'T'
    // and we're not in Dashboard Mode at all
    if (ui.isInDashboardMode() == false) {
      String line = Serial.readStringUntil('\n');
      line.trim();
      if (line.length() > 1 && line[0] == 'T') {
        uint32_t epoch = strtoul(line.c_str() + 1, NULL, 10);
        if (epoch >= SANE_EPOCH) {
          rtc.writeRTCFromEpoch(epoch);
          Serial.printf("[RTC] Set to epoch %lu\n", (unsigned long)epoch);
        } else {
          Serial.println("[RTC] Rejected — timestamp before 2024-01-01");
        }
      }
    }
  }

  ui.tick();
  ble.update(); // services any pending BLE domain-sync (autofill) request

  // Throttled heap breakdown — internal vs PSRAM vs largest contiguous
  // block. Diagnostic only, does not touch any other subsystem.
  static uint32_t lastHeapLog = 0;
  if (millis() - lastHeapLog > 30000) {
    lastHeapLog = millis();
    Serial.printf(
      "[HeapMon] total_free=%lu internal_free=%lu psram_free=%lu largest_block=%lu\n",
      (unsigned long)ESP.getFreeHeap(),
      (unsigned long)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
      (unsigned long)heap_caps_get_free_size(MALLOC_CAP_SPIRAM),
      (unsigned long)heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT));
  }

  delay(8);
}
