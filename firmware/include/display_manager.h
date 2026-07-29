#pragma once
// ═══════════════════════════════════════════════════════════════════════════════
//  display_manager.h — ILI9341 (hardware SPI) + XPT2046 touch + UI primitives
// ═══════════════════════════════════════════════════════════════════════════════
// Owns the physical display/touch hardware. Screen-specific drawing (lock,
// vault list, detail, TOTP, ...) lives in ui_screens.*, which calls back
// into DisplayManager::tft() for raw Adafruit_GFX primitives and uses the
// helpers here (drawBtn, the flash-tap feedback system, the wipe transition)
// so every screen looks and behaves consistently.
#include <Arduino.h>
#include <SPI.h>
#include <Adafruit_GFX.h>
#include <Adafruit_ILI9341.h>
#include "board_config.h"
#include "ui_theme.h"       // F16: C_WHITE and other color variables (no longer #defined in board_config.h)

inline bool hitTest(int tx, int ty, int x, int y, int w, int h) {
  return tx >= x && tx < x + w && ty >= y && ty < y + h;
}

class DisplayManager {
public:
  // Brings up the hardware SPI bus, resets + initializes the ILI9341, and
  // sets the initial rotation. This is the fix for the multi-second screen
  // lag on the original firmware, which bit-banged every SPI bit with
  // digitalWrite() instead of using a real SPI peripheral.
  bool begin();

  Adafruit_ILI9341& tft() { return _tft; }

  void setRotation(byte r);
  byte rotation() const { return _rot; }

  // "AIR-GAPPED / System Hardening..." boot animation.
  void showBootSplash();

  // Rounded button with centered label — the one shape every screen reuses.
  void drawBtn(int x, int y, int w, int h, const char* label, uint16_t col,
               int textSize = 1, uint16_t textCol = C_WHITE);

  // Tap feedback: flashes a button white for one frame, then the caller's
  // next loop() tick calls restoreFlashedButton() to redraw it normally.
  // transitionTo() MUST cancel a pending flash before switching screens —
  // otherwise the *previous* screen's button gets painted onto the new one.
  void triggerFlash(int x, int y, int w, int h, uint16_t col, const char* label, int textSize);
  void restoreFlashedButton();
  void cancelFlash() { _flash.active = false; }

  // Fast accent-colored curtain sweep, ~8 full-width band fills. On real
  // hardware SPI this completes in well under 100ms, reading as a quick,
  // deliberate wipe rather than the multi-second stall software SPI had.
  void wipeTransition();

  // XPT2046 touch read — deliberately bit-banged, NOT routed through the
  // hardware SPI peripheral used for the display. This is the exact
  // timing from the last confirmed-working version: the touch chip's
  // DOUT is wired to T_DO (GPIO41), a separate pin from the display's
  // MISO, so it can't be read via _spi.transfer(). MOSI/CLK are shared
  // with the display and driven with plain digitalWrite() here to match
  // that timing exactly, since XPT2046 read reliability is sensitive to
  // the precise clock/data relationship.
  bool getTouchPoint(int& px, int& py);

private:
  SPIClass _spi{FSPI};
  Adafruit_ILI9341 _tft{&_spi, TFT_DC, TFT_CS, TFT_RST};
  // Default orientation = landscape rotation 1 (180° from the original
  // rotation 3). Boot splash draws at this rotation so the screen no longer
  // appears upside-down before the MPU auto-rotation kicks in.
  byte _rot = 1;

  struct FlashBtn {
    bool active = false;
    int x = 0, y = 0, w = 0, h = 0;
    uint16_t col = 0;
    const char* label = "";
    int textSize = 1;
  } _flash;

  void _touchSpiRelease();
  void _touchSpiAcquire();
  uint16_t readTouchRaw(uint8_t cmd);
  uint16_t lerp565_helper(uint16_t c1, uint16_t c2, float t);  // boot splash halo
};
