#pragma once
// ═══════════════════════════════════════════════════════════════════════════════
//  rtc_manager.h — DS3231 real-time clock over the shared I2C bus
// ═══════════════════════════════════════════════════════════════════════════════
#include <Arduino.h>

class RtcManager {
public:
  bool begin();
  bool isOK() const { return _ok; }

  // Primary names — what ui_screens.cpp calls
  uint32_t unixEpoch();
  void writeFromEpoch(uint32_t epoch);

  // Aliases — in case other files use these names
  uint32_t rtcUnixEpoch() { return unixEpoch(); }
  void writeRTCFromEpoch(uint32_t epoch) { writeFromEpoch(epoch); }

  // Prints the raw register values + derived epoch to Serial, regardless
  // of isOK()/sane-time state. Added because isOK() previously only
  // proved the chip ACKed a bare address ping -- it said nothing about
  // whether a real 7-byte register read actually succeeds afterward.
  // Call this right after begin() every boot so a bad read vs. a
  // genuinely-unset clock is visible in the Serial log instead of being
  // indistinguishable behind the same "goes to SET TIME" symptom.
  void debugPrint(Stream& out);

private:
  bool _ok = false;
  void readFull(byte& h, byte& m, byte& s, byte& dow, byte& day, byte& mon, int& year);
  bool readOSF();      // true if the oscillator-stop flag is set (register 0x0F bit7) --
                        // this is the DS3231's own "backup power failed, my time is not
                        // trustworthy" flag, independent of what the date registers say
  void clearOSF();      // ack the flag once the user confirms a fresh time via writeFromEpoch
};