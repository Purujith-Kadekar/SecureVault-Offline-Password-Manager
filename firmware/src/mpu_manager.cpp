#include "mpu_manager.h"
#include "board_config.h"
#include "error_framework.h"  // F15: formal error logging
#include <Wire.h>

bool MpuManager::begin() {
  Wire.beginTransmission(MPU_ADDR);
  Wire.write(0x6B); Wire.write(0x00); // wake from sleep
  uint8_t err = Wire.endTransmission(true);
  if (err != 0) {
    logError(ErrSeverity::ERROR, ErrCode::MPU_INIT_FAILED, ErrSubsystem::ERR_MPU,
             "MPU6050 I2C beginTransmission failed");
    Serial.printf("[MPU] Init failed — I2C error %u\n", err);
    return false;
  }
  Serial.println("[MPU] Init OK");
  return true;
}

void MpuManager::poll() {
  Wire.beginTransmission(MPU_ADDR);
  Wire.write(0x3B);
  // NOTE: this used to be Wire.endTransmission(false) -- a repeated-START.
  // rtc_manager.cpp's readFull() already diagnosed that this exact pattern
  // silently fails on this board/arduino-esp32-core combo (Wire.available()
  // stays 0, every field stuck at its default) and switched to a plain
  // STOP-then-fresh-START. That fix was never carried over here even
  // though this function shares the same I2C bus and the same failure
  // mode -- switched to match, so accelerometer reads stop silently
  // failing the same way the RTC reads used to.
  Wire.endTransmission();
  Wire.requestFrom(MPU_ADDR, (uint8_t)6);
  if (Wire.available() == 6) {
    _ax = (Wire.read() << 8) | Wire.read();
    _ay = (Wire.read() << 8) | Wire.read();
    _az = (Wire.read() << 8) | Wire.read();
  }
}

byte MpuManager::detectRotation() const {
  int16_t ax = abs(_ax), ay = abs(_ay);
  // Original polarity — DO NOT swap. The default rotation was changed from
  // 3 to 1 in display_manager, but the MPU sensor mapping stays as it was.
  // Swapping the polarity here inverts the auto-rotation: when the user
  // rotates the device down, the screen flips to top (wrong). Keeping the
  // original mapping means the MPU correctly detects which landscape
  // orientation the device is in, and the screen follows correctly.
  if (ax > ay && ax > 8000) return _ax > 0 ? 1 : 3;
  return 255;
}
