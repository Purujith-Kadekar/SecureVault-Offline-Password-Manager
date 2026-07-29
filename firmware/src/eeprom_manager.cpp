#include "eeprom_manager.h"
#include "board_config.h"
#include <Wire.h>

// AT24Cxx write-cycle time is ~5ms typical, ~10ms worst-case per the
// datasheet. Ack-polling (retry the address until it ACKs again) is both
// faster in the common case and safer than a fixed delay if a particular
// chip runs slower than typical.
static const unsigned long WRITE_CYCLE_TIMEOUT_MS = 20;

static inline bool addrInRange(uint16_t addr, size_t len) {
  return len > 0 && addr < EepromManager::CAPACITY &&
         len <= (EepromManager::CAPACITY - addr);
}

bool EepromManager::begin() {
  Wire.beginTransmission(EEPROM_I2C_ADDR);
  bool ping = (Wire.endTransmission() == 0);

  uint8_t probe = 0;
  bool readOk = ping && readByte(0, probe);

  _ok = ping && readOk;
  return _ok;
}

bool EepromManager::_waitForWriteComplete() {
  unsigned long start = millis();
  while (millis() - start < WRITE_CYCLE_TIMEOUT_MS) {
    Wire.beginTransmission(EEPROM_I2C_ADDR);
    if (Wire.endTransmission() == 0) return true; // chip ACKed -- write done
    delay(1);
  }
  return false;
}

bool EepromManager::_writeChunk(uint16_t addr, const uint8_t* buf, size_t len) {
  Wire.beginTransmission(EEPROM_I2C_ADDR);
  Wire.write((uint8_t)(addr >> 8));   // AT24C32 uses a 2-byte address, MSB first
  Wire.write((uint8_t)(addr & 0xFF));
  Wire.write(buf, len);
  if (Wire.endTransmission() != 0) return false; // plain STOP -- no repeated-START, see header note
  return _waitForWriteComplete();
}

bool EepromManager::writeBytes(uint16_t addr, const uint8_t* buf, size_t len) {
  if (!addrInRange(addr, len)) return false;

  size_t written = 0;
  while (written < len) {
    uint16_t curAddr = addr + written;
    size_t pageOffset = curAddr % PAGE_SIZE;
    size_t roomInPage = PAGE_SIZE - pageOffset;
    size_t chunkLen = min(roomInPage, len - written);

    if (!_writeChunk(curAddr, buf + written, chunkLen)) return false;
    written += chunkLen;
  }
  return true;
}

bool EepromManager::writeByte(uint16_t addr, uint8_t val) {
  return writeBytes(addr, &val, 1);
}

bool EepromManager::readBytes(uint16_t addr, uint8_t* buf, size_t len) {
  if (!addrInRange(addr, len)) return false;

  size_t got = 0;
  while (got < len) {
    uint16_t curAddr = addr + got;
    size_t chunkLen = min((size_t)PAGE_SIZE, len - got);

    Wire.beginTransmission(EEPROM_I2C_ADDR);
    Wire.write((uint8_t)(curAddr >> 8));
    Wire.write((uint8_t)(curAddr & 0xFF));
    // Plain STOP, then a fresh START for the read -- same reasoning as
    // rtc_manager.cpp's readFull(): a repeated-START here has already been
    // shown to silently fail on this board/core combination.
    if (Wire.endTransmission() != 0) return false;

    Wire.requestFrom(EEPROM_I2C_ADDR, (uint8_t)chunkLen);
    if ((size_t)Wire.available() < chunkLen) return false;
    for (size_t i = 0; i < chunkLen; i++) buf[got + i] = (uint8_t)Wire.read();

    got += chunkLen;
  }
  return true;
}

bool EepromManager::readByte(uint16_t addr, uint8_t& out) {
  return readBytes(addr, &out, 1);
}
