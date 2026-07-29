#pragma once
// ═══════════════════════════════════════════════════════════════════════════════
//  ina219_manager.h — INA219 battery fuel gauge driver
//  Reads bus voltage (mV), shunt voltage (mV), and current (mA) over I²C,
//  then computes battery percentage using a calibrated Li-Po discharge curve.
// ═══════════════════════════════════════════════════════════════════════════════
#include <Arduino.h>
#include <Wire.h>
#include "board_config.h"   // PIN_INA219_ADDR used as fallback in begin() when addr==0xFF

// INA219 shares the same I2C bus as RTC (SDA=GPIO1, SCL=GPIO2).
// Wire.begin() is called by RtcManager::begin() — Ina219Manager
// does NOT re-initialize the bus, it just starts talking to the sensor.

class Ina219Manager {
public:
  Ina219Manager();

  // Initialize the INA219 at the given I2C address on the shared Wire bus.
  // Returns true if the sensor responded.
  bool begin(uint8_t addr = 0xFF);  // 0xFF means "use PIN_INA219_ADDR"

  // Read the current battery percentage (0-100).
  // Uses a piecewise-linear Li-Po discharge curve mapping bus voltage
  // to percentage. Call this periodically (e.g. every 5 seconds) —
  // the INA219 conversion takes ~1ms per sample.
  uint8_t getBatteryPercent();

  // Read the raw bus voltage in millivolts.
  uint16_t getBusVoltageMv();

  // Read the raw current in milliamps (signed).
  int16_t getCurrentMa();

  // Returns true if begin() succeeded (sensor is present on the bus).
  bool isOK() const { return _ok; }

private:
  bool _ok = false;
  uint8_t _addr;

  // INA219 register addresses
  static const uint8_t REG_CONFIG     = 0x00;
  static const uint8_t REG_SHUNT_VOL  = 0x01;
  static const uint8_t REG_BUS_VOL    = 0x02;
  static const uint8_t REG_POWER      = 0x03;
  static const uint8_t REG_CURRENT    = 0x04;
  static const uint8_t REG_CALIB      = 0x05;

  // Configuration: ±320mV shunt range, 16V bus range, 12-bit, 1 sample,
  // power-down between samples. This gives ~1ms conversion time.
  static const uint16_t CONFIG_VAL = 0x399F;

  // Calibration value for 0.1 ohm shunt, 3.2A max, ~4mA LSB.
  // Formula: cal = trunc(0.04096 / (current_LSB * shunt_ohms))
  // With current_LSB = 4mA, shunt = 0.1 ohm: cal = trunc(0.04096 / 0.0004) = 102
  // Adjusted for actual shunt resistor on the INA219 breakout board.
  static const uint16_t CALIB_VAL = 4096;

  // ── Li-Po discharge curve (piecewise-linear) ─────────────────────────
  // Maps resting bus voltage (mV) → battery percentage.
  // Key reference points for a typical 3.7V nominal Li-Po cell:
  //   4200 mV → 100%  (fully charged, just off charger)
  //   4000 mV → ~80%  (linear region)
  //   3700 mV → ~50%  (nominal voltage, still mostly linear)
  //   3500 mV → ~20%  (approaching knee)
  //   3300 mV → ~5%   (steep knee, cutoff approaching)
  //   3000 mV → 0%    (absolute cutoff)
  //
  // Under load, voltage drops by ~100-200mV depending on current draw.
  // The curve below uses slightly lowered thresholds to account for
  // typical ESP32-S3 load (~150mA avg during normal operation).
  static const int NUM_CURVE_POINTS = 6;
  struct CurvePoint { uint16_t mv; uint8_t pct; };
  static const CurvePoint _dischargeCurve[NUM_CURVE_POINTS];

  // I2C helpers
  uint16_t readReg16(uint8_t reg);
  void writeReg16(uint8_t reg, uint16_t val);
};
