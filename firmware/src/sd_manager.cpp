#include "sd_manager.h"
#include "board_config.h"
#include <SD.h>

bool SdManager::begin() {
  // Safe to call again after a prior success (e.g. a save-time remount
  // attempt) — end() the old mount first so SD.begin() doesn't just
  // return the stale cached state.
  if (_ok) {
    SD.end();
    _ok = false;
  }
  _spi.begin(SD_SCK, SD_MISO, SD_MOSI, SD_CS);

  // v9.20 fix: SD.begin() with no frequency arg defaults to 4MHz, which
  // made saves slow enough to blow past the Electron app's 30s request
  // timeout. 20MHz is within spec for most microSD cards over a short
  // SPI trace, but not all — fall back automatically instead of leaving
  // the card unusable at 20MHz.
  //
  // NOTE: an earlier version of this function also did a real
  // write+read-back+compare at each candidate speed to catch marginal
  // signal integrity. That was reverted — on this hardware it left the
  // SD filesystem unmounted (see the "File system is not mounted"
  // errors it produced), which is a worse failure than just picking a
  // conservative speed. SD.begin()'s own handshake success is the
  // signal we trust here.
  static const uint32_t speeds[] = {20000000, 16000000, 10000000, 4000000};
  for (uint32_t hz : speeds) {
    _ok = SD.begin(SD_CS, _spi, hz);
    Serial.printf("[SdManager] begin at %u Hz: %s\n", (unsigned)hz,
                  _ok ? "OK" : "failed");
    if (_ok) return true;
    SD.end();
  }
  return false;
}
