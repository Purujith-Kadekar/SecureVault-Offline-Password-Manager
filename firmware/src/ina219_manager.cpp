// ═══════════════════════════════════════════════════════════════════════════════
//  ina219_manager.cpp — INA219 battery fuel gauge driver
// ═══════════════════════════════════════════════════════════════════════════════
#include "ina219_manager.h"   // includes board_config.h (PIN_INA219_ADDR)
#include <Wire.h>

// ── Li-Po discharge curve (piecewise-linear) ─────────────────────────
// Adjusted for under-load conditions (ESP32-S3 draws ~150mA average).
// The "resting" voltages are lowered by ~100-150mV to prevent the
// percentage from jumping up when the device momentarily enters a
// low-power state (e.g. between screen refreshes).
const Ina219Manager::CurvePoint Ina219Manager::_dischargeCurve[NUM_CURVE_POINTS] = {
  { 3000,  0  },   // absolute cutoff — battery is dead
  { 3300,  5  },   // steep knee — critical low
  { 3500, 20  },   // approaching useful range
  { 3700, 50  },   // nominal voltage — about half
  { 4000, 80  },   // linear region — good
  { 4200, 100 },   // fully charged
};

Ina219Manager::Ina219Manager() : _addr(PIN_INA219_ADDR), _ok(false) {}

bool Ina219Manager::begin(uint8_t addr) {
  _addr = (addr == 0xFF) ? PIN_INA219_ADDR : addr;
  // Wire is already initialized by RtcManager::begin() on the same bus.
  // Don't call Wire.begin() again — that resets the bus and can disrupt
  // the RTC/MPU/EEPROM that are already running on it.

  // Check if the sensor is present by reading the manufacturer ID
  // or by simply writing the config register and verifying.
  writeReg16(REG_CONFIG, CONFIG_VAL);
  delay(1);

  // Verify the config was accepted
  uint16_t cfg = readReg16(REG_CONFIG);
  if (cfg != CONFIG_VAL) {
    Serial.printf("[INA219] Config verification failed (read 0x%04X, expected 0x%04X)\n", cfg, CONFIG_VAL);
    // Try once more — sometimes the first I2C transaction after Wire.begin
    // gets a stale NACK on this shared bus.
    writeReg16(REG_CONFIG, CONFIG_VAL);
    delay(2);
    cfg = readReg16(REG_CONFIG);
    if (cfg != CONFIG_VAL) {
      Serial.println("[INA219] Sensor not found or not responding.");
      _ok = false;
      return false;
    }
  }

  // Write calibration register for current measurement
  writeReg16(REG_CALIB, CALIB_VAL);
  delay(1);

  _ok = true;
  Serial.printf("[INA219] Initialized at addr 0x%02X — config OK, calibration set.\n", _addr);
  return true;
}

uint8_t Ina219Manager::getBatteryPercent() {
  if (!_ok) return 0;
  uint16_t mv = getBusVoltageMv();
  // Clamp to curve bounds
  if (mv <= _dischargeCurve[0].mv) return 0;
  if (mv >= _dischargeCurve[NUM_CURVE_POINTS - 1].mv) return 100;

  // Find the two curve points that bracket the current voltage
  for (int i = 0; i < NUM_CURVE_POINTS - 1; i++) {
    if (mv >= _dischargeCurve[i].mv && mv < _dischargeCurve[i + 1].mv) {
      // Linear interpolation between curve[i] and curve[i+1]
      uint16_t mvLow  = _dischargeCurve[i].mv;
      uint16_t mvHigh = _dischargeCurve[i + 1].mv;
      uint8_t pctLow  = _dischargeCurve[i].pct;
      uint8_t pctHigh = _dischargeCurve[i + 1].pct;
      float fraction = (float)(mv - mvLow) / (float)(mvHigh - mvLow);
      return (uint8_t)(pctLow + fraction * (pctHigh - pctLow));
    }
  }
  return 0;  // shouldn't reach here
}

uint16_t Ina219Manager::getBusVoltageMv() {
  if (!_ok) return 0;
  uint16_t raw = readReg16(REG_BUS_VOL);
  // INA219 bus voltage register: bits [15:3] = voltage in 4mV LSB
  // Bit [1] = CNVR (conversion ready), Bit [0] = OVF (math overflow)
  // Mask off the status bits and shift right by 3.
  uint16_t mv = (raw >> 3) * 4;  // 4mV per LSB
  return mv;
}

int16_t Ina219Manager::getCurrentMa() {
  if (!_ok) return 0;
  int16_t raw = (int16_t)readReg16(REG_CURRENT);
  // Current LSB depends on calibration. With CALIB_VAL = 4096,
  // the LSB is approximately 0.1mA per bit.
  // Actual LSB = 0.04096 / (CALIB_VAL * shunt_ohms)
  // With shunt = 0.1 ohm: LSB = 0.04096 / (4096 * 0.1) = 0.0001A = 0.1mA
  // So raw * 0.1 gives milliamps. For simplicity, just return raw
  // (each unit ≈ 0.1mA) and let the caller interpret.
  return raw;  // each unit ≈ 0.1mA
}

uint16_t Ina219Manager::readReg16(uint8_t reg) {
  // v10.9 FIX: Changed from repeated-START (endTransmission(false)) to
  // STOP-then-fresh-START (endTransmission()). This board's I2C bus has
  // been proven to silently fail with repeated-START on all other drivers
  // (RTC, MPU, EEPROM) — the same bug was present here. With
  // endTransmission(false), Wire.requestFrom() silently returns 0 bytes,
  // making ALL INA219 reads return 0 and battery percentage always show
  // 0%. Now matches the proven pattern from rtc_manager/mpu_manager.
  Wire.beginTransmission(_addr);
  Wire.write(reg);
  if (Wire.endTransmission() != 0) return 0;  // NACK — use STOP, not repeated-START
  if (Wire.requestFrom(_addr, (uint8_t)2) != 2) return 0;
  uint16_t val = (Wire.read() << 8) | Wire.read();
  return val;
}

void Ina219Manager::writeReg16(uint8_t reg, uint16_t val) {
  Wire.beginTransmission(_addr);
  Wire.write(reg);
  Wire.write((uint8_t)(val >> 8));
  Wire.write((uint8_t)(val & 0xFF));
  Wire.endTransmission();
}
