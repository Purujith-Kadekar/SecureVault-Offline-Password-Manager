#pragma once
// ═══════════════════════════════════════════════════════════════════════════════
//  eeprom_manager.h — AT24C32 EEPROM (on the DS3231 RTC breakout), shared I2C bus
// ═══════════════════════════════════════════════════════════════════════════════
// This is NOT a separately-wired peripheral -- the AT24C32 lives on the same
// small board as the DS3231 RTC and rides the same two I2C wires (RTC_SDA /
// RTC_SCL), just at its own bus address (EEPROM_I2C_ADDR, board_config.h).
// Call begin() after RtcManager::begin() has already brought the bus up,
// same convention MpuManager follows.
//
// Capacity: 4096 bytes (32Kbit), organized as 128 pages of 32 bytes each.
// This class is a general-purpose byte/block driver only -- it does not
// assign any particular use to the EEPROM (settings/logging/etc. all
// currently live in NVS/LittleFS instead). Wiring a specific feature to it
// is a separate, later decision.
//
// Two I2C quirks this class exists to get right:
//
// 1. Repeated-START (Wire.endTransmission(false)) silently fails on this
//    board + arduino-esp32 core combination -- already diagnosed once in
//    rtc_manager.cpp and again in mpu_manager.cpp (both switched to a plain
//    STOP-then-fresh-START). This driver never issues a repeated-START.
//
// 2. AT24Cxx page-write wraparound: if a single write transaction crosses a
//    32-byte page boundary, the chip's internal address counter wraps back
//    to the START of the same page instead of continuing into the next one
//    -- silently overwriting the first bytes of that page instead of
//    extending the write. writeBytes() splits every multi-byte write at
//    page boundaries so this can never happen by accident.
#include <Arduino.h>

class EepromManager {
public:
  static const size_t CAPACITY  = 4096; // bytes
  static const size_t PAGE_SIZE = 32;   // bytes per page (AT24C32)

  // Confirms the chip ACKs on the bus AND that a real read of address 0
  // succeeds -- same "ping alone isn't enough" reasoning as RtcManager::
  // begin(), since a bare address ACK can succeed even when the chip is
  // mid-write-cycle from something else and won't answer a real transfer.
  bool begin();
  bool isOK() const { return _ok; }

  // Sequential read, chunked internally at PAGE_SIZE boundaries (a read
  // isn't affected by the page-wrap issue, but chunking keeps every
  // transaction well under the Wire library's internal buffer size
  // regardless of len). Returns false (and leaves buf untouched from the
  // failing chunk onward) on any I2C error or an out-of-range request.
  bool readBytes(uint16_t addr, uint8_t* buf, size_t len);
  bool readByte(uint16_t addr, uint8_t& out);

  // Split at page boundaries per the wraparound note above, and waits out
  // each page's internal write cycle (ack-polls, ~5ms typical) before
  // starting the next page or returning. Returns false on any I2C error,
  // an out-of-range request, or if the write-cycle wait times out.
  bool writeBytes(uint16_t addr, const uint8_t* buf, size_t len);
  bool writeByte(uint16_t addr, uint8_t val);

private:
  bool _ok = false;

  // Address a page-bounded chunk (no repeated-START -- see class comment)
  // and write up to PAGE_SIZE bytes starting at addr, never crossing into
  // the next page. Blocks until the write cycle completes or times out.
  bool _writeChunk(uint16_t addr, const uint8_t* buf, size_t len);

  // Blocks (ack-polling, bounded by a timeout) until the chip responds to
  // its own address again, i.e. the internal write cycle has finished.
  bool _waitForWriteComplete();
};
