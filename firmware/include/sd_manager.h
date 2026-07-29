#pragma once
// ═══════════════════════════════════════════════════════════════════════════════
//  sd_manager.h — on-board microSD, its own dedicated SPI bus
// ═══════════════════════════════════════════════════════════════════════════════
// The microSD slot has four pins entirely separate from the display/touch
// bus (GPIO 10-13), so card I/O never contends with screen redraws.
#include <Arduino.h>
#include <SPI.h>

class SdManager {
public:
  bool begin();
  bool isOK() const { return _ok; }

private:
  SPIClass _spi{HSPI};
  bool _ok = false;
};
