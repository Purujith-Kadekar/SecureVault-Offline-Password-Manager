#pragma once
// ═══════════════════════════════════════════════════════════════════════════════
//  mpu_manager.h — MPU6050 accelerometer, used only for auto screen rotation
// ═══════════════════════════════════════════════════════════════════════════════
#include <Arduino.h>

class MpuManager {
public:
  // F15: begin() now returns bool (was void). Returns false if I2C
  // communication with the MPU6050 fails (device not on bus, bus error).
  // The I2C bus is shared with RTC — call after RtcManager::begin().
  bool begin();

  void poll(); // refresh the latest accelerometer sample

  // Returns 1 or 3 (landscape orientations, matching tft.setRotation()) if
  // a confident reading is available, or 255 if the device is roughly flat
  // / ambiguous (caller should keep the previous rotation in that case).
  byte detectRotation() const;

private:
  int16_t _ax = 0, _ay = 0, _az = 0;
};
