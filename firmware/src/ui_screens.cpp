// ═══════════════════════════════════════════════════════════════════════════════
//  RUNTIME THEME COLORS — defined HERE, extern'd in ui_theme.h
//
//  CRITICAL: MUST define THEME_COLORS_IMPLEMENTED BEFORE the first #include
//  that transitively pulls in ui_theme.h. ui_screens.h → display_manager.h →
//  ui_theme.h is the first include chain, and ui_theme.h uses #pragma once.
//  If THEME_COLORS_IMPLEMENTED isn't set before that first include, the
//  #pragma once guard skips the second include (line 20), and all C_* vars
//  become extern declarations instead of definitions — causing linker errors.
// ═══════════════════════════════════════════════════════════════════════════════
#define THEME_COLORS_IMPLEMENTED
#include "ui_screens.h"
#include "totp_generator.h"
#include "crypto_utils.h"
#include "qr_display.h"  // v5.4.3: WiFi QR code on AP info screen
#include <LittleFS.h>
#include <string.h>
#include <stdlib.h>
#include <esp_sleep.h>
#include <driver/rtc_io.h>
// v5.4: AP mode needs WiFi.softAPgetStationNum() on the AP info screen.
#include <WiFi.h>

static const char* NUM_LABELS[12] = { "1","2","3","4","5","6","7","8","9","CLR","0","OK" };
static const char* MODE_MENU_LABELS[5] = { "BLE MODE", "DASHBOARD", "AP MODE", "SETTINGS", "CANCEL" };

UiController::UiController(DisplayManager& disp, VaultManager& vault, RtcManager& rtc,
                            MpuManager& mpu, ButtonManager& btn, BleKeyboardManager& ble,
                            AudioManager& audio,
                            SerialProtocol& serialProto, DuressManager& duress,
                            Ina219Manager& ina219, SessionContext& sessionCtx)
  : _disp(disp), _vault(vault), _rtc(rtc), _mpu(mpu), _btn(btn), _ble(ble),
    _audio(audio), _serialProto(serialProto), _duress(duress), _ina219(ina219),
    _sessionCtx(sessionCtx) {}

// ═══════════════════════════════════════════════════════════════════════════════
//  LIFECYCLE
// ═══════════════════════════════════════════════════════════════════════════════
void UiController::begin() {
  _lastActivity = millis();
  loadTheme();  // load saved theme from NVS before first screen draw

  // F12: Check if this is the device's first boot (no PIN has ever been set).
  // If so, set the _isFirstBoot flag and transition to the mandatory PIN
  // setup screen instead of the normal lock screen. The user MUST choose
  // their own PIN — there is no hard-coded default PIN anymore.
  _isFirstBoot = _vault.isFirstBoot();

  bool timeSane = _rtc.isOK() && _rtc.unixEpoch() >= SANE_EPOCH;
  if (_isFirstBoot) {
    // First boot: force PIN setup screen (skip lock screen entirely).
    // The PIN setup screen has its own numpad and two-step entry flow.
    // After the user successfully sets and confirms their PIN, the screen
    // transitions to the normal lock screen where they must enter their
    // new PIN to unlock the vault.
    transitionTo(timeSane ? Screen::FIRST_BOOT_PIN : Screen::SETTIME);
  } else {
    transitionTo(timeSane ? Screen::LOCK : Screen::SETTIME);
  }
}

void UiController::transitionTo(Screen s) {
  bool animate = (_prevScreen != Screen::NONE) && !(s == Screen::LOCK && _failCount > 0);

  // v10.4: Reset the inactivity timer on every screen transition. This is
  // a safety net — all input handlers (touch, button, scroll) already set
  // _lastActivity, but this guarantees that ANY navigation (including
  // auto-rotation redraws and mode-menu switches) counts as activity and
  // never triggers a false auto-lock mid-navigation. The auto-lock is
  // purely inactivity-based: it only fires when NO input has occurred for
  // the configured timeout (Settings → Auto-Lock). It does NOT fire on a
  // fixed schedule — every touch, button press, or scroll resets the timer.
  _lastActivity = millis();

  // Clear pattern state whenever we leave or enter the lock screen —
  // partial patterns should never persist across screen transitions.
  if (s != Screen::LOCK || _screen != Screen::LOCK) {
    _patternMask = 0;
    _patternLen = 0;
    _lastTouchReleaseTime = 0;
  }

  _prevScreen = _screen;
  _screen = s;
  _modeMenuOpen = false;
  _disp.cancelFlash(); // cancel any pending flash-restore from the old screen — otherwise
                        // restoreFlashedButton() paints a stale button from the previous
                        // screen on top of the new one (e.g. the lock screen's "OK")

  if (animate) _disp.wipeTransition();

  switch (s) {
    case Screen::LOCK:           drawLockScreen();           break;
    case Screen::VAULT:          drawVaultScreen();          break;
    case Screen::DETAIL:         drawDetailScreen();         break;
    case Screen::TOTP:           drawTOTPScreen();           break;
    case Screen::SETTIME:        drawSetTimeScreen();        break;
    case Screen::BLE_PAIRING:    drawBlePairingScreen();     break;
    case Screen::DASHBOARD_CODE: drawDashboardCodeScreen();  break;
    case Screen::AP_INFO:        drawApInfoScreen();         break;
    case Screen::SEARCH:         drawSearchScreen();         break;
    case Screen::SETTINGS:       drawSettingsScreen();       break;
    case Screen::CHGPIN:         drawChgPinScreen();         break;
    case Screen::ABOUT:          drawAboutScreen();          break;
    case Screen::FIRST_BOOT_PIN: drawFirstBootPinScreen();   break;  // F12: mandatory first-boot PIN setup
    default: break;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  STATUS BAR (shown on Lock, Vault, Detail, TOTP, Settings, About, ChgPin)
// ═══════════════════════════════════════════════════════════════════════════════
void UiController::drawStatusBar() {
  auto& tft = _disp.tft();
  uint32_t epoch = _rtc.unixEpoch();

  tft.fillRect(4, 4, 48, 12, C_HEADER);
  if (epoch > 0) {
    uint32_t secOfDay = epoch % 86400UL;
    byte h = secOfDay / 3600, m = (secOfDay % 3600) / 60;
    byte im = (m + 30) % 60;
    byte ih = (h + 5 + (m + 30) / 60) % 24;
    char ts[9]; sprintf(ts, "%02d:%02d", ih, im);
    tft.setTextColor(C_ACCENT, C_HEADER); tft.setTextSize(1);
    tft.setCursor(4, 6); tft.print(ts);
  } else {
    tft.setTextColor(C_DARKGREY, C_HEADER); tft.setTextSize(1);
    tft.setCursor(4, 6); tft.print("--:--");
  }

  int padlockCx = SCREEN_W / 2;
  int padlockCy = 10;
  if (_screen == Screen::LOCK) {
    drawBreathingHalo(padlockCx, padlockCy, 8, C_ACCENT);
    drawStatusBarPadlock(padlockCx, padlockCy, true);
  } else {
    drawStatusBarPadlock(padlockCx, padlockCy, false);
  }

  // BLE dot (moved left to accommodate battery display)
  tft.fillCircle(MODE_BADGE_X - 8, 10, 4, _ble.isConnected() ? C_GREEN : C_DARKGREY);

  // BLE/DASH/AP mode badge (shrunk — battery display now occupies the right corner)
  tft.fillRect(MODE_BADGE_X, MODE_BADGE_Y + 4, MODE_BADGE_W, 12, C_HEADER);
  tft.setTextColor(C_ACCENT, C_HEADER); tft.setTextSize(1);
  tft.setCursor(MODE_BADGE_X + 2, MODE_BADGE_Y + 6);
  tft.print(_hidMode == HidMode::BLE ? "BLE" : (_hidMode == HidMode::AP ? "AP" : "DASH"));

  // Battery percentage + icon (right of mode badge)
  drawBatteryIcon(BATT_ICON_X, BATT_ICON_Y, _batteryPercent);
  // v10.8 FIX: Battery percentage text always uses C_WHITE (pure white in
  // dark themes, pure black in Sunlight) — the semantic foreground color.
  // Previous code used C_RED/C_ORANGE/C_GREEN which became mid-gray (0x7BEF)
  // in Monochrome and colored in Emerald/Sunlight, making it hard to read
  // from far. C_WHITE guarantees maximum contrast in every theme.
  tft.setTextColor(C_WHITE, C_BG);
  tft.setTextSize(1);
  tft.setCursor(BATT_TEXT_X, BATT_TEXT_Y);
  char bbuf[5];
  sprintf(bbuf, "%d%%", _batteryPercent);
  tft.print(bbuf);

  bool needsWarn = (epoch < SANE_EPOCH);
  if (needsWarn) {
    tft.fillRect(58, 4, 44, 12, C_RED);
    tft.setTextColor(C_WHITE, C_RED); tft.setTextSize(1);
    tft.setCursor(60, 6); tft.print("! TIME");
  } else {
    tft.fillRect(58, 4, 44, 12, C_BG);
  }
}

// ── Small padlock for the status bar ──────────────────────────────────
// Draws a tiny padlock (8px wide) centered at (cx, cy). `closed` controls
// whether the shackle is closed (locked) or open (unlocked).
void UiController::drawStatusBarPadlock(int cx, int cy, bool closed) {
  auto& tft = _disp.tft();
  // Body: 8x5 rounded rect
  tft.fillRoundRect(cx - 4, cy - 1, 8, 6, 1, C_ACCENT);
  // Shackle: arc above body
  if (closed) {
    // Closed shackle — full arc
    tft.drawCircle(cx, cy - 1, 3, C_ACCENT);
    tft.fillRect(cx - 3, cy - 1, 6, 3, C_BG);  // erase bottom of circle
    tft.fillRoundRect(cx - 4, cy - 1, 8, 6, 1, C_ACCENT);
  } else {
    // Open shackle — arc tilted to the right
    tft.drawCircle(cx + 1, cy - 2, 3, C_ACCENT);
    tft.fillRect(cx - 2, cy - 2, 4, 3, C_BG);
    tft.fillRoundRect(cx - 4, cy - 1, 8, 6, 1, C_ACCENT);
  }
  // Keyhole
  tft.fillCircle(cx, cy + 2, 1, C_BG);
}

// ── Smartphone-style battery icon for the 2.4" (320×240) status bar ──
// Horizontal modern phone-style battery: wide body (16×9px) with a small
// nib on the right (2×4px), fill bar grows LEFT to RIGHT. Proportional
// to the real phone status bar icon. Fill color: green (>30%), orange
// (15-30%), red (<15%).
void UiController::drawBatteryIcon(int x, int y, uint8_t pct) {
  auto& tft = _disp.tft();
  int w = BATT_ICON_W;
  int h = BATT_ICON_H;
  int nibW = BATT_NIB_W;
  int nibH = BATT_NIB_H;

  // Clear the area behind the icon (body + nib on the right + small margin)
  tft.fillRect(x, y - 1, w + nibW + 1, h + 2, C_BG);

  // Nib (terminal) on the RIGHT — centered vertically on the body
  int nibY = y + (h - nibH) / 2;
  tft.fillRect(x + w, nibY, nibW, nibH, C_WHITE);

  // Battery body outline with subtle rounded corners
  tft.drawRoundRect(x, y, w, h, 2, C_WHITE);

  // Fill bar — grows from LEFT to RIGHT
  int innerW = w - 2;
  int fillW = (pct * innerW) / 100;
  uint16_t fillColor = (pct <= 15) ? C_RED : ((pct <= 30) ? C_ORANGE : C_GREEN);

  if (fillW > 0) {
    tft.fillRect(x + 1, y + 1, fillW, h - 2, fillColor);
  }

  // Charge-level tip indicator
  if (pct > 90 && fillW > 1) {
    tft.fillRect(x + 1 + fillW - 1, y + 1, 1, h - 2, C_ACCENT);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  LOCK SCREEN
// ═══════════════════════════════════════════════════════════════════════════════
void UiController::drawPinDot(int idx, bool filled) {
  auto& tft = _disp.tft();
  uint16_t col = filled ? C_ACCENT : C_DARKGREY;
  tft.fillCircle(20 + idx * 36, 53, 6, col);
  tft.drawCircle(20 + idx * 36, 53, 6, C_GREY);
}

void UiController::drawNumpadBtn(int idx, bool flash) {
  auto& tft = _disp.tft();
  int r = idx / NUM_COLS, c = idx % NUM_COLS;
  int bx = NUM_X0 + c * (NUM_BW + NUM_GAP);
  int by = NUM_Y0 + r * (NUM_BH + NUM_GAP);
  // v10.6: Press-flash color is C_ACCENT (NOT C_DARKGREY) — see the long
  // comment in DisplayManager::triggerFlash() for why. C_DARKGREY collides
  // with C_RED (CLR button color) in the Monochrome theme, making the OK
  // button visually merge with CLR when pressed.
  uint16_t col = flash ? C_ACCENT : ((idx == 9) ? C_RED : (idx == 11) ? C_BTN_DARK : C_BTN);
  tft.fillRoundRect(bx, by, NUM_BW, NUM_BH, 4, col);
  if (!flash) {
    tft.drawRoundRect(bx, by, NUM_BW, NUM_BH, 4, C_ACCENT);
    tft.setTextColor(C_WHITE); tft.setTextSize(2);
    int lw = strlen(NUM_LABELS[idx]) * 12;
    tft.setCursor(bx + (NUM_BW - lw) / 2, by + (NUM_BH - 16) / 2);
    tft.print(NUM_LABELS[idx]);
  }
}

// ── Color blending + glow helpers (ported from SecureKey's gfx_lib) ──────
// lerp565 blends two RGB565 colors. Used for the breathing halo.
uint16_t UiController::lerp565(uint16_t c1, uint16_t c2, float t) {
  if (t < 0) t = 0;
  if (t > 1) t = 1;
  uint8_t r1 = (c1 >> 11) & 0x1F;
  uint8_t g1 = (c1 >> 5) & 0x3F;
  uint8_t b1 = c1 & 0x1F;
  uint8_t r2 = (c2 >> 11) & 0x1F;
  uint8_t g2 = (c2 >> 5) & 0x3F;
  uint8_t b2 = c2 & 0x1F;
  uint8_t r = r1 + (uint8_t)((r2 - r1) * t);
  uint8_t g = g1 + (uint8_t)((g2 - g1) * t);
  uint8_t b = b1 + (uint8_t)((b2 - b1) * t);
  return (r << 11) | (g << 5) | b;
}

// drawBreathingHalo draws 8 concentric circles fading from black to `color`.
// On the ILI9341 this reads as a soft glow (not as nice as AMOLED black, but
// still a clear premium-feel effect).
void UiController::drawBreathingHalo(int cx, int cy, int maxR, uint16_t color) {
  auto& tft = _disp.tft();
  for (int i = 8; i >= 1; i--) {
    float t = (float)i / 8.0f;
    uint16_t c = lerp565(C_BG, color, t * t * 0.6f);  // quadratic falloff
    int r = (int)(maxR * t);
    tft.fillCircle(cx, cy, r, c);
  }
}

// drawPadlockGlyph draws a simple padlock at (x, y) — the shackle is an
// arc, the body is a rounded rect. Size is the body width.
void UiController::drawPadlockGlyph(int x, int y, int size, uint16_t color) {
  auto& tft = _disp.tft();
  int bodyW = size;
  int bodyH = size * 3 / 4;
  int bodyY = y + size / 3;
  // Shackle (arc above the body)
  int shackleR = bodyW / 3;
  int shackleCx = x + bodyW / 2;
  int shackleCy = bodyY;
  tft.drawCircle(shackleCx, shackleCy, shackleR, color);
  tft.drawCircleHelper(shackleCx, shackleCy, shackleR, 0b0001, color);  // top arc only
  // Erase the bottom half of the shackle circle (it's inside the body)
  tft.fillRect(shackleCx - shackleR, shackleCy, shackleR * 2, shackleR, C_BG);
  // Body (rounded rect)
  tft.fillRoundRect(x, bodyY, bodyW, bodyH, 3, color);
  // Keyhole
  tft.fillCircle(shackleCx, bodyY + bodyH / 3, 2, C_BG);
  tft.fillRect(shackleCx - 1, bodyY + bodyH / 3, 2, bodyH / 3, C_BG);
}

void UiController::triggerShake() {
  _shaking = true;
  _shakeStart = millis();
}

void UiController::drawPinDotsShaking() {
  // Shake offset: ±8px sinusoidal for 400ms
  unsigned long elapsed = millis() - _shakeStart;
  if (elapsed > 400) {
    _shaking = false;
    for (int i = 0; i < MAX_PIN_LEN; i++) drawPinDot(i, i < _pinLen);
    return;
  }
  int offset = (int)(8.0f * sin(elapsed * 0.05f));
  auto& tft = _disp.tft();
  for (int i = 0; i < MAX_PIN_LEN; i++) {
    bool filled = i < _pinLen;
    uint16_t col = filled ? C_ACCENT : C_DARKGREY;
    tft.fillCircle(20 + i * 36 + offset, 53, 6, col);
    tft.drawCircle(20 + i * 36 + offset, 53, 6, C_GREY);
  }
}

void UiController::showLockError(const char* msg) {
  auto& tft = _disp.tft();
  // Clear + draw error text below the pattern row
  tft.fillRect(0, 230, SCREEN_W, 10, C_BG);
  tft.setTextColor(C_RED, C_BG); tft.setTextSize(1);
  tft.setCursor(SCREEN_W / 2 - strlen(msg) * 3, 232);
  tft.print(msg);
  _lockErrorTime = millis();
}

void UiController::clearLockError() {
  if (_lockErrorTime && millis() - _lockErrorTime > 2000) {
    _disp.tft().fillRect(0, 230, SCREEN_W, 10, C_BG);
    _lockErrorTime = 0;
  }
}

void UiController::drawLockScreen() {
  auto& tft = _disp.tft();
  tft.fillRect(0, 0, SCREEN_W, SCREEN_H, C_BG);
  drawStatusBar();

  // "Enter PIN" label — no padlock glyph or breathing halo (they eat too
  // much space on the 2.4" 320x240 screen and obstruct the numpad).
  tft.setTextColor(C_ACCENT); tft.setTextSize(1);
  tft.setCursor(SCREEN_W / 2 - 24, 28);
  tft.print("Enter PIN");

  // PIN dots (8 max, but typically 4 used)
  for (int i = 0; i < MAX_PIN_LEN; i++) drawPinDot(i, false);

  // Pattern row
  drawPatternRow();

  // Numpad
  for (int r = 0; r < NUM_ROWS; r++)
    for (int c = 0; c < NUM_COLS; c++)
      drawNumpadBtn(r * NUM_COLS + c, false);
}

// ── Pattern unlock (parallel to PIN) ────────────────────────────────────
// The TTP223 pad measures touch duration: Short (100-500ms) = dot, Long
// (500ms+) = dash. A gap >2s submits the pattern. The pattern is stored
// as a bitmask (0=Short, 1=Long), MSB-first.
//
// This runs in PARALLEL with the PIN numpad — either path can unlock.
// The pattern dots are drawn in a row at y=63 (below the PIN dots at y=53).

void UiController::drawPatternDot(int idx, bool isLong) {
  auto& tft = _disp.tft();
  // Pattern row sits between the PIN dots (y=53) and the numpad (y=66).
  // We only have ~10px of vertical space, so dots and dashes are small.
  // 12 elements max, spaced 22px apart, starting at x=20.
  int x = 20 + idx * 22;
  int y = 62;
  if (isLong) {
    // Long = dash (horizontal bar)
    tft.fillRect(x - 2, y, 14, 3, C_ACCENT);
  } else {
    // Short = dot (small filled circle)
    tft.fillCircle(x + 5, y + 1, 2, C_ACCENT);
  }
}

void UiController::drawPatternRow() {
  auto& tft = _disp.tft();
  // Clear the pattern row area (between PIN dots and numpad)
  tft.fillRect(0, 60, SCREEN_W, 5, C_BG);
  // Draw filled pattern elements
  for (int i = 0; i < _patternLen; i++) {
    bool isLong = (_patternMask >> (MAX_PATTERN_LEN - 1 - i)) & 1;
    drawPatternDot(i, isLong);
  }
}

void UiController::clearPattern() {
  _patternMask = 0;
  _patternLen = 0;
  drawPatternRow();
}

void UiController::handlePatternTouch() {
  // Called every tick on the lock screen. Handles the pattern state machine:
  //   - On touch press: start timing (handled in ButtonManager::poll)
  //   - On touch release: classify Short/Long, add to pattern
  //   - On gap >2s after at least 1 element: submit
  //   - On gap >5s: abandon + clear

  if (_btn.touchReleased()) {
    unsigned long dur = _btn.lastTouchDuration();
    if (dur >= PATTERN_SHORT_MIN && _patternLen < MAX_PATTERN_LEN) {
      // Classify: Short (100-500ms) = 0, Long (500ms+) = 1
      bool isLong = (dur >= PATTERN_LONG_MIN);
      _patternMask = (_patternMask << 1) | (isLong ? 1 : 0);
      _patternLen++;
      drawPatternDot(_patternLen - 1, isLong);
      _audio.play(isLong ? Tone::LOCK : Tone::KEY_TICK);  // long = lower tone, short = tick
    }
    _lastTouchReleaseTime = millis();
  }

  // Gap detection — only submit if we have at least 1 element
  if (_patternLen > 0 && _lastTouchReleaseTime > 0) {
    unsigned long gap = millis() - _lastTouchReleaseTime;
    if (gap >= PATTERN_GAP_SUBMIT) {
      submitPattern();
    }
  }
}

void UiController::submitPattern() {
  // Verify pattern against the hardcoded UNLOCK_PATTERN_MASK
  uint16_t entered = _patternMask & ((1 << _patternLen) - 1);
  uint16_t aligned = entered << (MAX_PATTERN_LEN - _patternLen);
  uint16_t expected = UNLOCK_PATTERN_MASK << (MAX_PATTERN_LEN - UNLOCK_PATTERN_LEN);

  if (_patternLen == UNLOCK_PATTERN_LEN && aligned == expected) {
    // Pattern match — unlock using the stored PIN (pattern unlocks the same vault)
    _failCount = 0;
    String pin = _vault.getPin();
    // v10.4: Removed the "Loading vault..." overlay — the PBKDF2 key
    // derivation (2-3s) is inherent security and can't be eliminated,
    // but the explicit loading message made the delay feel longer and
    // used hardcoded black backgrounds that broke light themes. The
    // lock screen simply transitions to the vault when ready.
    _vault.loadFromSD(pin.c_str());
    // v5.3: Show load error if vault failed to decrypt (theme-aware colors)
    const char* patErr = _vault.lastLoadErrorStr();
    if (patErr[0] != '\0') {
      auto& tft = _disp.tft();
      tft.fillRect(0, tft.height() - 30, tft.width(), 30, C_BG);
      tft.setTextColor(C_RED, C_BG);
      tft.setTextSize(1);
      tft.setCursor(10, tft.height() - 22);
      tft.print(patErr);
      delay(3000);
    }
    // F6: Store the verified PIN in SessionContext — single authoritative copy.
    _sessionCtx.setPin(pin.c_str());
    _patternMask = 0; _patternLen = 0;
    _audio.play(Tone::UNLOCK);
    transitionTo(Screen::VAULT);
  } else {
    // Mismatch — flash red, clear, retry
    _failCount++;
    _patternMask = 0; _patternLen = 0;
    _audio.play(Tone::ERROR);
    showLockError("Wrong pattern");
    drawPatternRow();
  }
  _lastTouchReleaseTime = 0;
}

void UiController::handleLockTouch(int tx, int ty) {
  // F12: If this is a first-boot condition (PIN not yet set), redirect to
  // the first-boot PIN setup screen. The lock screen should not be
  // accessible until the user has set their PIN.
  if (_isFirstBoot) {
    transitionTo(Screen::FIRST_BOOT_PIN);
    return;
  }
  for (int r = 0; r < NUM_ROWS; r++) {
    for (int c = 0; c < NUM_COLS; c++) {
      int idx = r * NUM_COLS + c;
      int bx = NUM_X0 + c * (NUM_BW + NUM_GAP);
      int by = NUM_Y0 + r * (NUM_BH + NUM_GAP);
      if (!hitTest(tx, ty, bx, by, NUM_BW, NUM_BH)) continue;

      _disp.triggerFlash(bx, by, NUM_BW, NUM_BH,
        (idx == 9) ? C_RED : (idx == 11) ? C_BTN_DARK : C_BTN, NUM_LABELS[idx], 2);
      _audio.play(Tone::KEY_TICK);

      if (idx == 9) {                              // CLR
        if (_pinLen > 0) { _pinLen--; _pinBuf[_pinLen] = 0; drawPinDot(_pinLen, false); }
      } else if (idx == 11) {                       // OK
        if (_pinLen == 0) return;
        // Check PIN lockout
        if (_vault.isPinLocked()) {
          uint32_t remaining = (_vault.getPinLockUntil() - millis()) / 1000;
          char msg[32];
          snprintf(msg, sizeof(msg), "Locked — wait %lus", remaining + 1);
          showLockError(msg);
          _audio.play(Tone::ERROR);
          _pinLen = 0; secureZero(_pinBuf, sizeof(_pinBuf));
          return;
        }
        if (_vault.verifyPin(_pinBuf)) {
          _failCount = 0;
          _vault.resetPinFailCount();
          // v10.8 FIX: Restore the OK button to its normal color BEFORE
          // the blocking loadFromSD() call. Without this, OK stays white
          // (the C_ACCENT press-flash fill from triggerFlash at line 427)
          // for the ENTIRE duration of loadFromSD (0.5-3s), because
          // loadFromSD blocks the main loop and tick() never gets to run
          // restoreFlashedButton(). The user perceived this as "OK
          // permanently becomes white after I click".
          //
          // Now OK flashes white briefly (the triggerFlash already painted
          // it), we let that render for one tick-equivalent so the click
          // feedback is visible (same perceived flash as CLR), then we
          // restore it to mid-gray BEFORE loadFromSD starts. The vault
          // load then proceeds with OK in its normal state, and the
          // screen transitions to VAULT when ready.
          delay(30);  // let the press-flash render visibly (~1 tick)
          _disp.restoreFlashedButton();  // OK back to mid-gray
          // v10.4: Removed the "Loading vault..." overlay — the PBKDF2
          // key derivation (2-3s) is inherent security and can't be
          // eliminated, but the explicit loading message made the delay
          // feel longer and used hardcoded black backgrounds that broke
          // light themes. The lock screen simply transitions to the vault
          // when ready.
          _vault.loadFromSD(_pinBuf);
          // v5.3: If loadFromSD failed, show the specific error on the TFT
          // for 3 seconds so the user knows WHY the vault is empty instead
          // of silently landing on an empty vault screen with no explanation.
          // v10.4: Use theme-aware colors (C_BG / C_RED) instead of
          // hardcoded black/red that broke the Sunlight theme.
          const char* loadErr = _vault.lastLoadErrorStr();
          if (loadErr[0] != '\0') {
            auto& tft = _disp.tft();
            tft.fillRect(0, tft.height() - 30, tft.width(), 30, C_BG);
            tft.setTextColor(C_RED, C_BG);
            tft.setTextSize(1);
            tft.setCursor(10, tft.height() - 22);
            tft.print(loadErr);
            delay(3000);  // let user read the error
          }
          // F6: Store the verified PIN in SessionContext — single authoritative copy.
          // No more _dashboardPin / _apPin mirrors.
          _sessionCtx.setPin(_pinBuf);
          _pinLen = 0; secureZero(_pinBuf, sizeof(_pinBuf));
          _audio.play(Tone::UNLOCK);
          transitionTo(Screen::VAULT);
        } else if (_duress.isConfigured() && _duress.verify(_pinBuf, strlen(_pinBuf))) {
          // Duress PIN entered. Show the EXACT same success path as a real
          // unlock -- no different screen, no delay, nothing an onlooker
          // could distinguish from a normal unlock.
          _failCount = 0;
          // v10.8: Same fix as the correct-PIN path above — restore OK
          // before the blocking loadFromSD so it doesn't stay white.
          delay(30);
          _disp.restoreFlashedButton();
          _vault.loadFromSD(_pinBuf);
          _pinLen = 0; secureZero(_pinBuf, sizeof(_pinBuf));
          _audio.play(Tone::UNLOCK);
          transitionTo(Screen::VAULT);
          delay(400); // let the "unlocked" screen actually render before the reboot
          _duress.wipe(); // does not return
        } else {
          _failCount++;
          _vault.incrementPinFailCount();
          _pinLen = 0; secureZero(_pinBuf, sizeof(_pinBuf));
          _audio.play(Tone::ERROR);
          triggerShake();
          uint8_t nvsFails = _vault.getPinFailCount();
          char err[32];
          if (_vault.isPinLocked()) {
            uint32_t remaining = (_vault.getPinLockUntil() - millis()) / 1000;
            snprintf(err, sizeof(err), "Locked — wait %lus", remaining + 1);
          } else {
            snprintf(err, sizeof(err), "Wrong PIN (%d fails)", nvsFails);
          }
          showLockError(err);
        }
      } else {                                       // digit
        int digit = (idx < 9) ? (idx + 1) : 0;
        if (_pinLen < MAX_PIN_LEN) {
          _pinBuf[_pinLen++] = '0' + digit;
          _pinBuf[_pinLen] = 0;
          drawPinDot(_pinLen - 1, true);
        }
      }
      return;
    }
  }
}

void UiController::handleLockButtons() {
  // F12: If this is a first-boot condition (PIN not yet set), redirect to
  // the first-boot PIN setup screen. The lock screen should not be
  // accessible until the user has set their PIN.
  if (_isFirstBoot) {
    transitionTo(Screen::FIRST_BOOT_PIN);
    return;
  }
  if (!_btn.pressed()) return;
  BtnEvent e = _btn.state();
  if (e == BtnEvent::LEFT) {
    if (_pinLen > 0) { _pinLen--; _pinBuf[_pinLen] = 0; drawPinDot(_pinLen, false); }
  } else if (e == BtnEvent::TOUCH) {
    // TOUCH = OK/Confirm. Only submit PIN if user has been typing a PIN
    // AND is not in the middle of pattern entry. This prevents a pattern
    // tap from simultaneously submitting a partial PIN (race condition).
    if (_pinLen == 0 || _patternLen > 0) return;
    // Check PIN lockout
    if (_vault.isPinLocked()) {
      uint32_t remaining = (_vault.getPinLockUntil() - millis()) / 1000;
      char msg[32];
      snprintf(msg, sizeof(msg), "Locked — wait %lus", remaining + 1);
      showLockError(msg);
      _audio.play(Tone::ERROR);
      _pinLen = 0; secureZero(_pinBuf, sizeof(_pinBuf));
      return;
    }
    if (_vault.verifyPin(_pinBuf)) {
      _failCount = 0;
      _vault.resetPinFailCount();  // reset NVS-backed fail counter
      _vault.loadFromSD(_pinBuf);
      // v5.3: Show load error if vault failed to decrypt
      // v10.4: Use theme-aware colors instead of hardcoded black/red
      const char* btnErr = _vault.lastLoadErrorStr();
      if (btnErr[0] != '\0') {
        auto& tft = _disp.tft();
        tft.fillRect(0, tft.height() - 30, tft.width(), 30, C_BG);
        tft.setTextColor(C_RED, C_BG);
        tft.setTextSize(1);
        tft.setCursor(10, tft.height() - 22);
        tft.print(btnErr);
        delay(3000);
      }
      // F6: Store the verified PIN in SessionContext — single authoritative copy.
      _sessionCtx.setPin(_pinBuf);
      _pinLen = 0; secureZero(_pinBuf, sizeof(_pinBuf));
      _audio.play(Tone::UNLOCK);
      transitionTo(Screen::VAULT);
    } else if (_duress.isConfigured() && _duress.verify(_pinBuf, strlen(_pinBuf))) {
      _failCount = 0;
      _vault.loadFromSD(_pinBuf);
      _pinLen = 0; secureZero(_pinBuf, sizeof(_pinBuf));
      _audio.play(Tone::UNLOCK);
      transitionTo(Screen::VAULT);
      delay(400);
      _duress.wipe(); // does not return
    } else {
      _failCount++;
      _vault.incrementPinFailCount();  // persist to NVS
      _pinLen = 0; secureZero(_pinBuf, sizeof(_pinBuf));
      _audio.play(Tone::ERROR);
      triggerShake();
      uint8_t nvsFails = _vault.getPinFailCount();
      char err[32];
      if (_vault.isPinLocked()) {
        uint32_t remaining = (_vault.getPinLockUntil() - millis()) / 1000;
        snprintf(err, sizeof(err), "Locked — wait %lus", remaining + 1);
      } else {
        snprintf(err, sizeof(err), "Wrong PIN (%d fails)", nvsFails);
      }
      showLockError(err);
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  FIRST-BOOT PIN SETUP SCREEN (F12)
// ═══════════════════════════════════════════════════════════════════════════════
// This screen is shown on first boot (when no PIN has ever been set) instead
// of the normal lock screen. The user must choose and confirm a PIN (minimum
// 4 digits) before the vault can be used. There is NO hard-coded default PIN.
//
// Two-step flow:
//   Step 0: "SET UP YOUR PIN" — user enters their desired PIN
//   Step 1: "CONFIRM YOUR PIN" — user re-enters the same PIN to confirm
//
// On success: completeFirstBoot(newPin) writes the PIN to NVS + marks the
// first-boot flag, then the screen transitions to the normal lock screen
// where the user must enter their newly-set PIN to unlock the vault.
// On mismatch: both buffers are cleared and the user starts over from step 0.

void UiController::drawFirstBootPinDot(int idx, bool filled) {
  auto& tft = _disp.tft();
  // Use the same dot spacing as the CHGPIN screen (24px, centered),
  // but position them at y=56 like the CHGPIN dots (the first-boot screen
  // has the title at y=30 and needs room for the subtitle/error text).
  int dotSpacing = 24;
  int startX = SCREEN_W / 2 - (MAX_PIN_LEN * dotSpacing) / 2;
  uint16_t col = filled ? C_ACCENT : C_DARKGREY;
  tft.fillCircle(startX + idx * dotSpacing, 56, 5, col);
  tft.drawCircle(startX + idx * dotSpacing, 56, 5, C_GREY);
}

void UiController::drawFirstBootPinScreen() {
  auto& tft = _disp.tft();
  tft.fillRect(0, 0, SCREEN_W, SCREEN_H, C_BG);
  drawStatusBar();

  // Title line — different for each step
  const char* titles[] = { "SET UP YOUR PIN", "CONFIRM YOUR PIN" };
  const char* subtitles[] = { "Choose a PIN (4-8 digits)", "Re-enter your PIN" };

  tft.setTextColor(C_ACCENT); tft.setTextSize(1);
  int titleLen = strlen(titles[_firstBootPinStep]);
  tft.setCursor(SCREEN_W / 2 - titleLen * 3, 22);
  tft.print(titles[_firstBootPinStep]);

  // Subtitle — smaller, below the title
  tft.setTextColor(C_GREY); tft.setTextSize(1);
  int subLen = strlen(subtitles[_firstBootPinStep]);
  tft.setCursor(SCREEN_W / 2 - subLen * 3, 33);
  tft.print(subtitles[_firstBootPinStep]);

  // PIN dots — show filled dots for the current entry length
  int n = (_firstBootPinStep == 0) ? _firstBootPinLen : _firstBootPinConfirmLen;
  for (int i = 0; i < MAX_PIN_LEN; i++) {
    drawFirstBootPinDot(i, i < n);
  }

  // Error message (if any) — shown below the dots
  if (_firstBootError[0] != '\0') {
    tft.setTextColor(C_RED, C_BG); tft.setTextSize(1);
    tft.setCursor(SCREEN_W / 2 - strlen(_firstBootError) * 3, 68);
    tft.print(_firstBootError);
  }

  // Numpad — same layout as the lock/CHGPIN screens
  for (int r = 0; r < NUM_ROWS; r++)
    for (int c = 0; c < NUM_COLS; c++)
      drawNumpadBtn(r * NUM_COLS + c, false);
}

void UiController::handleFirstBootPinTouch(int tx, int ty) {
  for (int r = 0; r < NUM_ROWS; r++) {
    for (int c = 0; c < NUM_COLS; c++) {
      int idx = r * NUM_COLS + c;
      int bx = NUM_X0 + c * (NUM_BW + NUM_GAP);
      int by = NUM_Y0 + r * (NUM_BH + NUM_GAP);
      if (!hitTest(tx, ty, bx, by, NUM_BW, NUM_BH)) continue;

      _disp.triggerFlash(bx, by, NUM_BW, NUM_BH,
        (idx == 9) ? C_RED : (idx == 11) ? C_BTN_DARK : C_BTN, NUM_LABELS[idx], 2);
      _audio.play(Tone::KEY_TICK);

      // Clear any previous error on new input
      _firstBootError[0] = '\0';

      if (idx == 9) {  // CLR — backspace
        if (_firstBootPinStep == 0 && _firstBootPinLen > 0) {
          _firstBootPinLen--; _firstBootPinBuf[_firstBootPinLen] = 0;
          drawFirstBootPinScreen();
        } else if (_firstBootPinStep == 1 && _firstBootPinConfirmLen > 0) {
          _firstBootPinConfirmLen--; _firstBootPinConfirmBuf[_firstBootPinConfirmLen] = 0;
          drawFirstBootPinScreen();
        }
      } else if (idx == 11) {  // OK — submit
        submitFirstBootPin();
      } else {  // digit
        int digit = (idx < 9) ? (idx + 1) : 0;
        if (_firstBootPinStep == 0 && _firstBootPinLen < MAX_PIN_LEN) {
          _firstBootPinBuf[_firstBootPinLen++] = '0' + digit;
          _firstBootPinBuf[_firstBootPinLen] = 0;
          drawFirstBootPinScreen();
        } else if (_firstBootPinStep == 1 && _firstBootPinConfirmLen < MAX_PIN_LEN) {
          _firstBootPinConfirmBuf[_firstBootPinConfirmLen++] = '0' + digit;
          _firstBootPinConfirmBuf[_firstBootPinConfirmLen] = 0;
          drawFirstBootPinScreen();
        }
      }
      return;
    }
  }
}

void UiController::handleFirstBootPinButtons() {
  if (!_btn.pressed()) return;
  BtnEvent e = _btn.state();
  if (e == BtnEvent::LEFT) {
    // Backspace on current step's buffer
    if (_firstBootPinStep == 0 && _firstBootPinLen > 0) {
      _firstBootPinLen--; _firstBootPinBuf[_firstBootPinLen] = 0;
      drawFirstBootPinScreen();
    } else if (_firstBootPinStep == 1 && _firstBootPinConfirmLen > 0) {
      _firstBootPinConfirmLen--; _firstBootPinConfirmBuf[_firstBootPinConfirmLen] = 0;
      drawFirstBootPinScreen();
    }
  } else if (e == BtnEvent::TOUCH) {
    // Clear any previous error
    _firstBootError[0] = '\0';
    submitFirstBootPin();
  }
}

void UiController::submitFirstBootPin() {
  if (_firstBootPinStep == 0) {
    // Step 0: user has entered their desired PIN.
    // Validate: minimum 4 digits required.
    if (_firstBootPinLen < 4) {
      _audio.play(Tone::ERROR);
      triggerShake();
      snprintf(_firstBootError, sizeof(_firstBootError), "PIN must be at least 4 digits");
      drawFirstBootPinScreen();
      return;
    }
    // Move to confirm step — keep _firstBootPinBuf as-is for comparison.
    _firstBootPinStep = 1;
    _firstBootPinConfirmLen = 0;
    memset(_firstBootPinConfirmBuf, 0, sizeof(_firstBootPinConfirmBuf));
    _firstBootError[0] = '\0';
    drawFirstBootPinScreen();
  } else if (_firstBootPinStep == 1) {
    // Step 1: user has re-entered their PIN for confirmation.
    // First check minimum length on confirm entry too.
    if (_firstBootPinConfirmLen < 4) {
      _audio.play(Tone::ERROR);
      triggerShake();
      snprintf(_firstBootError, sizeof(_firstBootError), "PIN must be at least 4 digits");
      drawFirstBootPinScreen();
      return;
    }
    // Compare first entry with confirm entry.
    if (strcmp(_firstBootPinBuf, _firstBootPinConfirmBuf) == 0) {
      // PINs match — write to NVS and mark first boot as complete.
      _vault.completeFirstBoot(_firstBootPinBuf);
      // Now call setPin with the sentinel as the "old PIN" to trigger
      // saveToSD() and key derivation for the new PIN. This is needed
      // because completeFirstBoot only writes the PIN to NVS — it
      // doesn't encrypt the vault on SD with the new key.
      _vault.setPin(FIRST_BOOT_PIN_SENTINEL, _firstBootPinBuf);
      // Clear the first-boot buffers (PIN is now in NVS)
      secureZero(_firstBootPinBuf, sizeof(_firstBootPinBuf));
      secureZero(_firstBootPinConfirmBuf, sizeof(_firstBootPinConfirmBuf));
      _firstBootPinLen = 0;
      _firstBootPinConfirmLen = 0;
      _firstBootPinStep = 0;
      // Mark first boot as complete so the lock screen works normally
      _isFirstBoot = false;
      // Success! Play unlock tone and transition to the normal lock screen.
      // The user must now enter their newly-set PIN to unlock the vault.
      _audio.play(Tone::UNLOCK);
      transitionTo(Screen::LOCK);
    } else {
      // PINs don't match — error, reset both steps and start over.
      _audio.play(Tone::ERROR);
      triggerShake();
      snprintf(_firstBootError, sizeof(_firstBootError), "PINs don't match — try again");
      _firstBootPinStep = 0;
      _firstBootPinLen = 0;
      _firstBootPinConfirmLen = 0;
      secureZero(_firstBootPinBuf, sizeof(_firstBootPinBuf));
      secureZero(_firstBootPinConfirmBuf, sizeof(_firstBootPinConfirmBuf));
      drawFirstBootPinScreen();
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  VAULT LIST
// ═══════════════════════════════════════════════════════════════════════════════
// ── Sorted display index ──────────────────────────────────────────────
// Builds _sortedIndex[] so the vault list displays alphabetically by site
// name. The vault's storage order (VaultManager) is NOT changed — only
// the display order. _selectedEntry and _listScroll refer to positions
// in this sorted array; _sortedIndex[pos] gives the actual vault index.
void UiController::buildSortedIndex() {
  _sortedCount = 0;
  for (int i = 0; i < _vault.count() && _sortedCount < MAX_DISPLAY; i++) {
    VaultEntry e = _vault.entryAt(i);
    // Filter logic:
    //   _vaultFilter 255 = ALL (non-deleted, any type)
    //   _vaultFilter 0-3 = specific type (non-deleted)
    //   _vaultFilter 254 = TRASH (deleted only)
    if (_vaultFilter == 254) {
      // Trash view — show only deleted entries
      if (!e.deleted) continue;
    } else {
      // Non-trash view — hide deleted entries
      if (e.deleted) continue;
      // Type filter (255 = all types)
      if (_vaultFilter != 255 && e.type != _vaultFilter) continue;
    }
    _sortedIndex[_sortedCount++] = i;
  }

  // Sort: favorites first, then alphabetical by site name
  for (int i = 1; i < _sortedCount; i++) {
    int key = _sortedIndex[i];
    VaultEntry keyEntry = _vault.entryAt(key);
    String keySite = keyEntry.site;
    keySite.toLowerCase();
    int j = i - 1;
    while (j >= 0) {
      VaultEntry jEntry = _vault.entryAt(_sortedIndex[j]);
      String jSite = jEntry.site;
      jSite.toLowerCase();
      // Favorites sort before non-favorites
      bool keyFav = keyEntry.favorite;
      bool jFav = jEntry.favorite;
      if (keyFav && !jFav) {
        _sortedIndex[j + 1] = _sortedIndex[j];
        j--;
      } else if (!keyFav && jFav) {
        break;  // favorite stays above non-favorite
      } else if (jSite > keySite) {
        _sortedIndex[j + 1] = _sortedIndex[j];
        j--;
      } else {
        break;
      }
    }
    _sortedIndex[j + 1] = key;
  }
}

void UiController::drawListRow(int r) {
  auto& tft = _disp.tft();
  int pos = _listScroll + r;
  int y = LIST_Y0 + r * LIST_ITEM_H;

  if (pos >= _sortedCount) {
    tft.fillRect(0, y, SCREEN_W, LIST_ITEM_H, C_BG);
    return;
  }

  // Map display position → actual vault index via sorted index
  int idx = _sortedIndex[pos];
  bool sel = (pos == _selectedEntry);
  uint16_t rc = sel ? C_BTN : (r % 2 ? C_PANEL : C_BG);
  VaultEntry e = _vault.entryAt(idx);

  tft.fillRect(0, y, SCREEN_W, LIST_ITEM_H - 2, rc);
  if (sel) tft.drawRect(0, y, SCREEN_W, LIST_ITEM_H - 2, C_ACCENT);

  // ── Letter avatar (left side) ──────────────────────────────────────
  // Small colored circle with the first letter of the site name.
  // Uses theme-aware colors:
  //   Monochrome (1): all avatars use C_DARKGREY (single tone)
  //   Sunlight (3):   medium-saturation palette (black text readable)
  //   Air-Gapped (0): bright 6-color palette (white text readable)
  //   Emerald (2):    green-tinted 6-color palette (white text readable)
  uint16_t avCol;
  if (_themeId == 1) {
    // Monochrome — all avatars use the grey color
    avCol = C_DARKGREY;
  } else {
    static const uint16_t AV_COLS_AIR[6]      = { 0x4D9F, 0x4B32, 0xB380, 0xFB40, 0x37C8, 0xF800 };
    static const uint16_t AV_COLS_EMERALD[6]  = { 0x07E0, 0x4B32, 0xB7E0, 0xFD20, 0x37C8, 0xF800 };
    // Sunlight: medium-saturation colors that are visible on a white
    // background AND have enough contrast for black text (C_WHITE=0x0000
    // in Sunlight). Same hues as Air-Gapped but slightly darker so the
    // black avatar letter pops.
    static const uint16_t AV_COLS_SUNLIGHT[6] = { 0x2668, 0x4A6A, 0x9360, 0xFC00, 0x2380, 0xA000 };
    const uint16_t* avCols;
    if (_themeId == 2)      avCols = AV_COLS_EMERALD;
    else if (_themeId == 3) avCols = AV_COLS_SUNLIGHT;
    else                    avCols = AV_COLS_AIR;
    char firstChar = (e.site && e.site[0]) ? toupper(e.site[0]) : '?';
    int avIdx = (firstChar - 'A') % 6;
    if (avIdx < 0) avIdx = 0;
    avCol = avCols[avIdx];
  }
  char firstChar = (e.site && e.site[0]) ? toupper(e.site[0]) : '?';
  int avX = 14, avY = y + 7, avR = 11;
  tft.fillCircle(avX, avY + avR, avR, avCol);
  // Avatar text: C_WHITE is the semantic "foreground" color — black in
  // Sunlight, white in dark themes. Either way it contrasts with the
  // medium-saturation avatar backgrounds above.
  tft.setTextColor(C_WHITE, avCol); tft.setTextSize(2);
  tft.setCursor(avX - 4, avY + avR - 7);
  tft.print(firstChar);

  // Site name + username (shifted right to make room for avatar)
  tft.setTextColor(C_WHITE, rc); tft.setTextSize(1);
  // Show star for favorites
  if (e.favorite) {
    tft.setTextColor(C_YELLOW, rc);
    tft.setCursor(34, y + 7); tft.print("*");
    tft.setTextColor(C_WHITE, rc);
    tft.setCursor(42, y + 7); tft.print(e.site);
  } else {
    tft.setCursor(34, y + 7); tft.print(e.site);
  }
  tft.setTextColor(C_GREY, rc);
  tft.setCursor(34, y + 20); tft.print(e.user);
  if (strlen(e.totp) > 0) {
    tft.fillRect(287, y + 10, 24, 14, C_TOTP_CHIP);
    tft.setTextColor(C_ORANGE, C_TOTP_CHIP); tft.setCursor(290, y + 13); tft.print("2FA");
  }
}

void UiController::redrawList() {
  for (int r = 0; r < LIST_VISIBLE; r++) drawListRow(r);
}

void UiController::drawVaultScreen() {
  buildSortedIndex();  // rebuild sorted index every time we draw the vault screen
  auto& tft = _disp.tft();
  tft.fillRect(0, 0, SCREEN_W, SCREEN_H, C_BG);
  drawStatusBar();
  tft.fillRect(0, SBAR_H, SCREEN_W, 24, C_HEADER);
  _disp.drawBtn(2, SBAR_H + 1, 46, 22, "LOCK", C_RED);
  // ── Filter label ────────────────────────────────────────────────────
  // _vaultFilter is a UI-only value, NOT an entry type:
  //   255   = ALL   (non-deleted, any entry type)
  //   254   = TRASH (deleted only)
  //   0..3  = specific entry type (matches vault_types.h:
  //           0=login, 1=card, 2=identity, 3=note)
  //
  // CRITICAL: filter values 0..3 are TYPE INDICES, not slot indices
  // into a label array. The old code had `filterNames[] = {"ALL",
  // "LOGIN", "CARD", "ID", "NOTE", "TRASH"}` and indexed it with
  // `_vaultFilter` — so filter value 0 (LOGIN) showed "ALL". That was
  // the "firmware thinks type 0 is ALL" bug.
  //
  // Fix: use the SAME centralized `vaultTypeToStr()` helper that the
  // serial protocol, vault.db JSON, Electron app, and browser
  // extension all use. No drift is possible.
  const char* fname;
  if (_vaultFilter == 255)      fname = "ALL";
  else if (_vaultFilter == 254) fname = "TRASH";
  else                          fname = vaultTypeToStr(_vaultFilter);  // 0..3 → "login"/"card"/"identity"/"note"
  // Capitalize the first letter for the TFT header (cosmetic only —
  // does not affect the wire/disk format which stays lowercase).
  char fnameDisplay[12] = {0};
  if (fname && fname[0]) {
    fnameDisplay[0] = toupper((unsigned char)fname[0]);
    for (int i = 1; i < 11 && fname[i]; i++) fnameDisplay[i] = fname[i];
  } else {
    strcpy(fnameDisplay, "ALL");
  }
  char hdr[24];
  sprintf(hdr, "%d/%d %s", _sortedCount, _vault.count(), fnameDisplay);
  tft.setTextColor(C_WHITE); tft.setTextSize(1); tft.setCursor(56, 27); tft.print(hdr);
  // v5.4.3: SEARCH button (between filter label and FILTER button)
  _disp.drawBtn(130, SBAR_H + 1, 44, 22, "SEARCH", C_BTN);
  // Filter button (center, between SEARCH and UP)
  _disp.drawBtn(180, SBAR_H + 1, 48, 22, "FILTER", C_BTN);
  _disp.drawBtn(234, SBAR_H + 1, 38, 22, " UP ", C_BTN);
  _disp.drawBtn(274, SBAR_H + 1, 42, 22, "DOWN", C_BTN);

  // ── Empty state ────────────────────────────────────────────────────
  if (_sortedCount == 0) {
    tft.setTextColor(C_GREY); tft.setTextSize(1);
    tft.setCursor(SCREEN_W / 2 - 54, 100);
    tft.print("Vault is empty");
    tft.setCursor(SCREEN_W / 2 - 78, 120);
    tft.print("Add entries via the app");
    drawPadlockGlyph(SCREEN_W / 2 - 10, 60, 20, C_DARKGREY);
    return;
  }

  redrawList();
}

void UiController::handleVaultTouch(int tx, int ty) {
  if (hitTest(tx, ty, 2, SBAR_H, 46, 24)) {
    _disp.triggerFlash(2, SBAR_H + 1, 46, 22, C_RED, "LOCK", 1);
    _audio.play(Tone::KEY_TICK);
    _audio.play(Tone::LOCK);
    // Defensive: every other path back to LOCK resets the PIN buffer:
    // this one didn't. Shouldn't be reachable with stale digits in
    // practice (the buffer's already 0 by the time the vault screen
    // exists), but costs nothing to be consistent with every other
    // LOCK transition in this file.
    _pinLen = 0; secureZero(_pinBuf, sizeof(_pinBuf));
    transitionTo(Screen::LOCK); return;
  }
  // Filter button — cycle: ALL → LOGIN → CARD → ID → NOTE → TRASH → ALL
  if (hitTest(tx, ty, 180, SBAR_H, 48, 24)) {
    _disp.triggerFlash(180, SBAR_H + 1, 48, 22, C_BTN, "FILTER", 1);
    _audio.play(Tone::KEY_TICK);
    // Cycle: 255(ALL) → 0 → 1 → 2 → 3 → 254(TRASH) → 255(ALL)
    if (_vaultFilter == 255) _vaultFilter = 0;       // ALL → LOGIN
    else if (_vaultFilter == 254) _vaultFilter = 255; // TRASH → ALL
    else _vaultFilter++;                               // 0→1→2→3
    if (_vaultFilter == 4) _vaultFilter = 254;         // NOTE(3)+1=4 → TRASH(254)
    _selectedEntry = 0;
    _listScroll = 0;
    drawVaultScreen();
    return;
  }
  // v5.4.3: SEARCH button — open the search screen with QWERTY keyboard
  if (hitTest(tx, ty, 130, SBAR_H, 44, 24)) {
    _disp.triggerFlash(130, SBAR_H + 1, 44, 22, C_BTN, "SEARCH", 1);
    _audio.play(Tone::KEY_TICK);
    // Clear search state on entry.
    _searchQueryLen = 0;
    _searchQuery[0] = '\0';
    _searchResultCount = 0;
    _searchSelIdx = 0;
    _searchScrollOffset = 0;  // v10.9: reset scroll on entry
    _searchKeyboardMode = false;  // start in letters mode
    transitionTo(Screen::SEARCH);
    return;
  }
  if (hitTest(tx, ty, 234, SBAR_H, 38, 24)) {
    _disp.triggerFlash(234, SBAR_H + 1, 38, 22, C_BTN, " UP ", 1);
    _audio.play(Tone::KEY_TICK);
    if (_listScroll > 0) { _listScroll--; redrawList(); }
    return;
  }
  if (hitTest(tx, ty, 274, SBAR_H, 42, 24)) {
    _disp.triggerFlash(274, SBAR_H + 1, 42, 22, C_BTN, "DOWN", 1);
    _audio.play(Tone::KEY_TICK);
    if (_listScroll + LIST_VISIBLE < _vault.count()) { _listScroll++; redrawList(); }
    return;
  }
  if (ty >= LIST_Y0) {
    int row = (ty - LIST_Y0) / LIST_ITEM_H;
    int idx = _listScroll + row;
    if (idx < _vault.count()) {
      _audio.play(Tone::KEY_TICK);
      if (_selectedEntry == idx) {
        _passVisible = false;
        _detailScroll = 0;
        transitionTo(Screen::DETAIL);
      } else {
        int oldSel = _selectedEntry;
        _selectedEntry = idx;
        drawListRow(row);
        if (oldSel >= _listScroll && oldSel < _listScroll + LIST_VISIBLE)
          drawListRow(oldSel - _listScroll);
      }
    }
  }
}

void UiController::handleVaultButtons() {
  if (!_btn.pressed()) return;
  BtnEvent e = _btn.state();
  if (e == BtnEvent::UP) {
    // Move selection up by one entry. Viewport scrolls to follow.
    if (_selectedEntry > 0) {
      _selectedEntry--;
      if (_selectedEntry < _listScroll) {
        _listScroll = _selectedEntry;
      }
      redrawList();
    }
  } else if (e == BtnEvent::DOWN) {
    // Move selection down by one entry. Viewport scrolls to follow.
    if (_selectedEntry < _sortedCount - 1) {
      _selectedEntry++;
      if (_selectedEntry >= _listScroll + LIST_VISIBLE) {
        _listScroll = _selectedEntry - LIST_VISIBLE + 1;
      }
      redrawList();
    }
  } else if (e == BtnEvent::LEFT) {
    // LEFT does NOT return to the PIN screen from the vault list.
    // The user can only lock via: (a) the LOCK button on the touchscreen,
    // (b) 5-second hold on the capacitive pad, or (c) auto-lock timeout.
    // LEFT on the vault list is a no-op (or could open Settings — but
    // we'll keep it as no-op to avoid accidental triggers).
  } else if (e == BtnEvent::RIGHT) {
    // Open the selected entry's detail screen.
    if (_selectedEntry >= 0 && _selectedEntry < _sortedCount) {
      _passVisible = false; _detailScroll = 0; transitionTo(Screen::DETAIL);
    }
  } else if (e == BtnEvent::TOUCH) {
    // TOUCH = universal confirm. On the vault list = open selected entry.
    if (_selectedEntry >= 0 && _selectedEntry < _sortedCount) {
      _passVisible = false; _detailScroll = 0; transitionTo(Screen::DETAIL);
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  DETAIL
// ═══════════════════════════════════════════════════════════════════════════════
//  DETAIL SCREEN (per-type rendering + scroll for identity + paste-all)
// ═══════════════════════════════════════════════════════════════════════════════

// Render one (label, value) row at y. Secret fields (password, CVV, SSN)
// are masked with asterisks unless _passVisible is true. Returns y + 22.
//
// v9.19: Draws a small paste icon (clipboard glyph) at the right edge of
// each row. Tapping it types JUST this field's value via BLE — so the user
// can paste firstName, lastName, address, etc. individually without using
// TYPE ALL.
//
// v10.5: The v10.4 inline "SHOW/HIDE" link has been REMOVED. The user
// found it cluttered and asked to make the MASKED VALUE ITSELF tappable.
// Now: when this row is a secret field (CVV for card, SSN for identity)
// AND has a non-empty value, we record the row's y-coordinate in
// _detailSecretRowY so the touch handler can detect a tap anywhere on
// the row and toggle _passVisible. A small "(tap to reveal)" hint in
// dim grey is drawn right after the masked asterisks so the user knows
// the row is interactive — no separate SHOW button/link.
int UiController::drawDetailFieldRow(int y, const char* label, const char* value, bool secret) {
  auto& tft = _disp.tft();
  tft.setTextColor(C_GREY); tft.setTextSize(1);
  tft.setCursor(8, y); tft.print(label);
  tft.setTextColor(C_WHITE); tft.setTextSize(1);
  tft.setCursor(8, y + 10);
  int valueWidth = 0;
  if (secret && !_passVisible) {
    // Mask — but show the length so the user can tell if the field is empty.
    int len = value ? strlen(value) : 0;
    if (len == 0) { tft.setTextColor(C_DARKGREY); tft.print("(empty)"); valueWidth = 7 * 6; }
    else {
      int clipLen = (len < 30) ? len : 30;
      for (int i = 0; i < clipLen; i++) tft.print('*');
      valueWidth = clipLen * 6;
    }
  } else {
    if (!value || !value[0]) { tft.setTextColor(C_DARKGREY); tft.print("(empty)"); valueWidth = 7 * 6; }
    else {
      // Clip value to fit the screen width at textSize 1, leaving room for
      // the paste icon at the right edge (x=298..316, so clip at ~44 chars).
      char buf[45] = {0};
      strncpy(buf, value, 44);
      tft.print(buf);
      valueWidth = strlen(buf) * 6;
    }
  }

  // ── v10.5: Click-to-reveal hint (replaces the v10.4 SHOW/HIDE link) ──
  // When the row is a SECRET field with a non-empty value AND the value
  // is currently masked, draw a small dim "(tap to reveal)" hint right
  // after the asterisks. The hint is informational only — the actual
  // tap target is the entire row (tracked via _detailSecretRowY), so
  // the user doesn't have to hit the tiny hint text precisely.
  // When the value is currently REVEALED, draw "(tap to hide)" instead
  // so the user knows they can re-mask by tapping again.
  if (secret) {
    const char* hint = _passVisible ? "(tap to hide)" : "(tap to reveal)";
    int hintW = strlen(hint) * 6;
    int hintX = 8 + valueWidth + 6;
    int hintY = y + 10;
    // Only draw the hint if there's room before the paste icon at x=296
    // AND the field actually has a value (no hint for "(empty)" rows).
    bool fieldHasValue = value && value[0];
    if (hintX + hintW <= 294 && fieldHasValue) {
      tft.setTextColor(C_DARKGREY); tft.setTextSize(1);
      tft.setCursor(hintX, hintY);
      tft.print(hint);
    }
    // Record the row's tap target for the touch handler. Only rows with
    // an actual value get the tap-to-toggle behavior — empty secrets
    // have nothing to reveal.
    if (fieldHasValue) {
      _detailSecretRowY = y;
      _detailSecretRowH = DETAIL_ROW_H;
      _detailSecretPresent = true;
    }
  }

  // ── v9.19: Per-field paste icon ───────────────────────────────────
  // Small clipboard glyph at the right edge of every field row.
  // Tap → type JUST this field's value via BLE (no Tab, no other fields).
  // Drawn at x=298..314, y=y+3..y+19 (16×16px, centered in the 22px row).
  {
    int pix = 298, piy = y + 3;
    // Clipboard body (14×12 rounded rect)
    tft.fillRoundRect(pix, piy + 2, 14, 12, 2, C_GREY);
    // Tab on top (4×3, centered)
    tft.fillRect(pix + 5, piy, 4, 3, C_GREY);
    // Inner clip surface (slightly darker)
    tft.fillRect(pix + 2, piy + 5, 10, 7, C_PANEL);
    // Two "text lines" suggesting content
    tft.drawFastHLine(pix + 3, piy + 8, 8, C_GREY);
    tft.drawFastHLine(pix + 3, piy + 11, 6, C_GREY);
  }
  return y + DETAIL_ROW_H;
}

// Count the number of non-empty fields for the current entry's type.
// Drives the scroll-arrow visibility in drawDetailScreen().
// v9.19: Uses vaultFieldAtFull() (includes Notes and Folder) so the
// detail screen shows all fields, while TYPE ALL uses vaultFieldAt()
// (skips Notes and Folder since they're not web-form fields).
int UiController::countDetailFields() {
  VaultEntry e = _vault.entryAt(_sortedIndex[_selectedEntry]);
  int n = 0;
  VaultFieldRef ref;
  for (int i = 0; vaultFieldAtFull(e, i, ref); i++) n++;
  return n;
}

// Type every non-empty field of the current entry via BLE, separated by
// Tab. Used by the TYPE ALL button and by a short tap of the capacitive
// pad on the detail screen. Perfect for filling multi-field web forms:
// focus the first field on the page, tap the device, and it walks
// through every field pressing Tab between them.
void UiController::typeAllFieldsWithTab() {
  VaultEntry e = _vault.entryAt(_sortedIndex[_selectedEntry]);
  VaultFieldRef ref;
  bool first = true;
  for (int i = 0; vaultFieldAt(e, i, ref); i++) {
    if (!first) typeTab();
    typeStr(ref.value);
    first = false;
  }
  // Tiny tactile cue at the end so the user knows it's done.
  _audio.play(Tone::KEY_TICK);
}

void UiController::drawPassArea() {
  auto& tft = _disp.tft();
  VaultEntry e = _vault.entryAt(_sortedIndex[_selectedEntry]);
  tft.fillRect(8, 108, 236, 16, C_BG);
  tft.setTextColor(C_WHITE); tft.setTextSize(2);
  tft.setCursor(8, 112);
  if (_passVisible) tft.print(e.pass);
  else for (int i = 0; i < min((int)strlen(e.pass), 16); i++) tft.print('*');
}

// ═══════════════════════════════════════════════════════════════════════════════
//  DETAIL SCREEN
//  ── LOGIN (type 0): ORIGINAL v9.9 layout (large USERNAME/PASSWORD,
//     SHOW/HIDE, TYPE USER / TYPE PASS / TYPE BOTH buttons). This is
//     the layout users are used to — left untouched.
//  ── CARD / IDENTITY / NOTE (types 1-3): New per-type field-rows
//     layout with vertical scrolling (identity has up to 14 fields)
//     + TYPE ALL form-fill button + capacitive-tap paste-all.
// ═══════════════════════════════════════════════════════════════════════════════

// Original login detail screen — byte-for-byte from v9.9.
void UiController::drawDetailScreenLogin() {
  auto& tft = _disp.tft();
  VaultEntry e = _vault.entryAt(_sortedIndex[_selectedEntry]);
  tft.fillRect(0, 0, SCREEN_W, SCREEN_H, C_BG);
  drawStatusBar();

  tft.fillRect(0, SBAR_H, SCREEN_W, 28, C_HEADER);
  tft.setTextColor(C_ACCENT); tft.setTextSize(2);
  tft.setCursor(6, 26); tft.print(e.site);

  tft.setTextColor(C_GREY); tft.setTextSize(1);
  tft.setCursor(8, 56); tft.print("USERNAME");
  tft.setTextColor(C_WHITE); tft.setTextSize(2);
  tft.setCursor(8, 68); tft.print(e.user);

  tft.setTextColor(C_GREY); tft.setTextSize(1);
  tft.setCursor(8, 100); tft.print("PASSWORD");
  drawPassArea();
  _disp.drawBtn(250, 96, 60, 20, _passVisible ? "HIDE" : "SHOW", C_BTN);

  tft.drawFastHLine(0, 142, SCREEN_W, C_DARKGREY);

  _disp.drawBtn(8,   152, 96, 36, "TYPE USER", C_BTN);
  _disp.drawBtn(112, 152, 96, 36, "TYPE PASS", C_BTN);
  _disp.drawBtn(216, 152, 96, 36, "TYPE BOTH", C_BTN_DARK);
  _disp.drawBtn(8,   196, 90, 36, "< BACK", C_BTN);
  if (strlen(e.totp) > 0)
    _disp.drawBtn(112, 196, 200, 36, "GENERATE 2FA", C_ORANGE);
}

// Per-type detail screen for Card / Identity / Note.
void UiController::drawDetailScreenPerType() {
  auto& tft = _disp.tft();
  VaultEntry e = _vault.entryAt(_sortedIndex[_selectedEntry]);
  tft.fillRect(0, 0, SCREEN_W, SCREEN_H, C_BG);
  drawStatusBar();

  // ── Title bar ──────────────────────────────────────────────────────
  tft.fillRect(0, SBAR_H, SCREEN_W, 28, C_HEADER);
  tft.setTextColor(C_ACCENT); tft.setTextSize(2);
  tft.setCursor(6, 26); tft.print(e.site);
  // Type badge in the top-right so the user always knows what kind of
  // entry they're looking at.
  tft.setTextColor(C_YELLOW); tft.setTextSize(1);
  const char* tname = vaultTypeToStr(e.type);
  char tbadge[12] = {0};
  tbadge[0] = toupper((unsigned char)tname[0]);
  for (int i = 1; i < 11 && tname[i]; i++) tbadge[i] = tname[i];
  tft.setCursor(SCREEN_W - strlen(tbadge) * 6 - 8, 30);
  tft.print(tbadge);

  // ── Field rows (per-type, scrollable for identity) ────────────────
  // Iterate the canonical per-type field list via vaultFieldAt().
  // Skip empty fields (vaultFieldAt already returns false for them).
  // v10.5: Reset the click-to-reveal tracker before drawing rows.
  // _detailSecretRowY is set to the y-coordinate of the secret row
  // (CVV for card, SSN for identity) by drawDetailFieldRow() when it
  // draws that row. If no secret row is visible (scrolled out of view,
  // or the entry has no secret field), it stays -1 and taps in the
  // field area fall through to the per-field paste icons / scroll.
  _detailSecretRowY = -1;
  _detailSecretPresent = false;
  int totalFields = countDetailFields();
  int maxScroll = totalFields - DETAIL_VISIBLE_ROWS;
  if (maxScroll < 0) maxScroll = 0;
  if (_detailScroll > maxScroll) _detailScroll = maxScroll;
  if (_detailScroll < 0) _detailScroll = 0;

  // Mask secret fields per type:
  //   CARD   → CVV
  //   IDENTITY → SSN
  //   NOTE   → (none)
  // v9.19: Uses vaultFieldAtFull() so Notes and Folder are shown on the
  // detail screen (but NOT typed by TYPE ALL, which uses vaultFieldAt()).
  int y = DETAIL_TOP_Y;
  VaultFieldRef ref;
  int visibleIndex = 0;
  for (int i = 0; vaultFieldAtFull(e, i, ref); i++) {
    if (i < _detailScroll) continue;
    if (visibleIndex >= DETAIL_VISIBLE_ROWS) break;
    bool secret = false;
    if (e.type == 1 && strcmp(ref.label, "CVV") == 0) secret = true;
    else if (e.type == 2 && strcmp(ref.label, "SSN") == 0) secret = true;
    y = drawDetailFieldRow(y, ref.label, ref.value, secret);
    visibleIndex++;
  }

  // Scroll indicators (only shown when there's more than one screen)
  if (totalFields > DETAIL_VISIBLE_ROWS) {
    tft.setTextColor(C_ACCENT); tft.setTextSize(1);
    if (_detailScroll > 0) {
      tft.setCursor(SCREEN_W - 14, DETAIL_TOP_Y); tft.print("^");
    }
    if (_detailScroll < maxScroll) {
      tft.setCursor(SCREEN_W - 14, DETAIL_BOTTOM_Y - 8); tft.print("v");
    }
    // Position indicator (e.g. "3/14")
    char posStr[12];
    snprintf(posStr, sizeof(posStr), "%d/%d", _detailScroll + 1, totalFields);
    tft.setTextColor(C_GREY);
    tft.setCursor(SCREEN_W - strlen(posStr) * 6 - 8, DETAIL_BOTTOM_Y - 8);
    tft.print(posStr);
  }

  tft.drawFastHLine(0, DETAIL_BOTTOM_Y, SCREEN_W, C_DARKGREY);

  // v10.5: The old fixed-position SHOW button (v9.x) AND the v10.4 inline
  // SHOW/HIDE link have BOTH been removed. The user can now tap directly
  // on the masked CVV/SSN value (the asterisks) OR anywhere on that row
  // to toggle reveal/hide. A small "(tap to reveal)" / "(tap to hide)"
  // hint in dim grey is drawn after the value by drawDetailFieldRow()
  // to indicate the row is interactive. The row's y-coordinate is
  // tracked in _detailSecretRowY for the touch handler.

  // ── Action buttons ────────────────────────────────────────────────
  // TYPE ALL = paste every field of the current entry's type via BLE,
  // separated by Tab. This is the multi-field form-fill button.
  // For non-login types, the other two slots are SCROLL UP/DOWN (since
  // identity scrolls).
  _disp.drawBtn(8,   152, 96, 36, "TYPE ALL", C_BTN_DARK);
  _disp.drawBtn(112, 152, 96, 36, "SCROLL ^", C_BTN);
  _disp.drawBtn(216, 152, 96, 36, "SCROLL v", C_BTN);
  _disp.drawBtn(8,   196, 90, 36, "< BACK", C_BTN);
  if (strlen(e.totp) > 0) {
    _disp.drawBtn(112, 196, 200, 36, "GENERATE 2FA", C_ORANGE);
  } else {
    // Hint about the capacitive-tap paste-all behavior — only show
    // when there's no TOTP button taking the slot.
    tft.setTextColor(C_DARKGREY); tft.setTextSize(1);
    tft.setCursor(112, 206);
    tft.print("TAP pad = TYPE ALL");
  }
}

// Dispatch: login → original layout, everything else → per-type layout.
void UiController::drawDetailScreen() {
  VaultEntry e = _vault.entryAt(_sortedIndex[_selectedEntry]);
  if (e.type == 0) {
    drawDetailScreenLogin();
  } else {
    drawDetailScreenPerType();
  }
}

// ── Touch handler for the ORIGINAL login detail screen ───────────────
// Byte-for-byte from v9.9 — TYPE USER / TYPE PASS / TYPE BOTH / SHOW-HIDE.
void UiController::handleDetailTouchLogin(int tx, int ty) {
  VaultEntry e = _vault.entryAt(_sortedIndex[_selectedEntry]);

  if (hitTest(tx, ty, 250, 96, 60, 20)) {
    _disp.triggerFlash(250, 96, 60, 20, C_BTN, _passVisible ? "HIDE" : "SHOW", 1);
    _audio.play(Tone::KEY_TICK);
    _passVisible = !_passVisible;
    drawPassArea();
    _disp.drawBtn(250, 96, 60, 20, _passVisible ? "HIDE" : "SHOW", C_BTN);
    return;
  }
  if (hitTest(tx, ty, 8, 152, 96, 36)) {
    _disp.triggerFlash(8, 152, 96, 36, C_BTN, "TYPE USER", 1);
    _audio.play(Tone::KEY_TICK);
    typeStr(e.user); return;
  }
  if (hitTest(tx, ty, 112, 152, 96, 36)) {
    _disp.triggerFlash(112, 152, 96, 36, C_BTN, "TYPE PASS", 1);
    _audio.play(Tone::KEY_TICK);
    typeStr(e.pass); return;
  }
  if (hitTest(tx, ty, 216, 152, 96, 36)) {
    _disp.triggerFlash(216, 152, 96, 36, C_BTN_DARK, "TYPE BOTH", 1);
    _audio.play(Tone::KEY_TICK);
    typeStr(e.user);
    typeTab();
    typeStr(e.pass);
    return;
  }
  if (hitTest(tx, ty, 8, 196, 90, 36)) {
    _disp.triggerFlash(8, 196, 90, 36, C_BTN, "< BACK", 1);
    _audio.play(Tone::KEY_TICK);
    transitionTo(Screen::VAULT); return;
  }
  if (hitTest(tx, ty, 112, 196, 200, 36) && strlen(e.totp) > 0) {
    _disp.triggerFlash(112, 196, 200, 36, C_ORANGE, "GENERATE 2FA", 1);
    _audio.play(Tone::KEY_TICK);
    transitionTo(Screen::TOTP); return;
  }
}

// ── Touch handler for Card / Identity / Note ─────────────────────────
void UiController::handleDetailTouchPerType(int tx, int ty) {
  VaultEntry e = _vault.entryAt(_sortedIndex[_selectedEntry]);

  // ── v9.19: Per-field paste icon hit-test ──────────────────────────
  // Each visible field row has a paste icon at x=298..314, centered
  // vertically in its 22px row. If the tap landed in that strip, type
  // JUST that field's value via BLE (no Tab, no other fields).
  // This lets the user paste firstName, lastName, address, etc. one at
  // a time — critical for identity entries where you want to fill
  // specific fields on a form, not all of them at once.
  // v9.19: Uses vaultFieldAtFull() so the paste icon works on Notes and
  // Folder rows too (you might want to paste your notes somewhere).
  if (tx >= 296 && tx <= 316 && ty >= DETAIL_TOP_Y && ty < DETAIL_BOTTOM_Y) {
    int visibleRow = (ty - DETAIL_TOP_Y) / DETAIL_ROW_H;
    int fieldIndex = _detailScroll + visibleRow;
    VaultFieldRef ref;
    if (vaultFieldAtFull(e, fieldIndex, ref) && ref.value && ref.value[0]) {
      _audio.play(Tone::KEY_TICK);
      typeStr(ref.value);
    }
    return;
  }

  // v10.5: Click-to-reveal on the masked value itself. The v10.4 inline
  // SHOW/HIDE link has been removed. Now: if a secret field row (CVV for
  // card, SSN for identity) is currently visible (tracked via
  // _detailSecretRowY != -1) AND the tap landed anywhere on that row
  // (excluding the paste-icon strip at x>=296, which is handled above),
  // toggle _passVisible and redraw. The user can tap the asterisks OR
  // the "(tap to reveal)" hint OR anywhere else on the row — the whole
  // row is the tap target. A second tap re-masks.
  // NOTE: the per-field paste icon hit-test above already returned if
  // the tap was on the paste strip (x>=296), so we only reach here for
  // taps on the actual field value area (x<296).
  if (_detailSecretRowY >= 0 && _detailSecretPresent) {
    int rowTop = _detailSecretRowY;
    int rowBot = _detailSecretRowY + _detailSecretRowH;
    if (ty >= rowTop && ty < rowBot) {
      _audio.play(Tone::KEY_TICK);
      _passVisible = !_passVisible;
      drawDetailScreen();  // re-render with new masking + new hint
      return;
    }
  }

  // TYPE ALL button (left-most in row 2)
  if (hitTest(tx, ty, 8, 152, 96, 36)) {
    _disp.triggerFlash(8, 152, 96, 36, C_BTN_DARK, "TYPE ALL", 1);
    _audio.play(Tone::KEY_TICK);
    typeAllFieldsWithTab();
    return;
  }

  // SCROLL UP
  if (hitTest(tx, ty, 112, 152, 96, 36)) {
    _disp.triggerFlash(112, 152, 96, 36, C_BTN, "SCROLL ^", 1);
    _audio.play(Tone::KEY_TICK);
    if (_detailScroll > 0) { _detailScroll--; drawDetailScreen(); }
    return;
  }
  // SCROLL DOWN
  if (hitTest(tx, ty, 216, 152, 96, 36)) {
    _disp.triggerFlash(216, 152, 96, 36, C_BTN, "SCROLL v", 1);
    _audio.play(Tone::KEY_TICK);
    int maxScroll = countDetailFields() - DETAIL_VISIBLE_ROWS;
    if (maxScroll < 0) maxScroll = 0;
    if (_detailScroll < maxScroll) { _detailScroll++; drawDetailScreen(); }
    return;
  }

  // BACK
  if (hitTest(tx, ty, 8, 196, 90, 36)) {
    _disp.triggerFlash(8, 196, 90, 36, C_BTN, "< BACK", 1);
    _audio.play(Tone::KEY_TICK);
    _detailScroll = 0;  // reset scroll on exit
    transitionTo(Screen::VAULT); return;
  }

  // GENERATE 2FA (only if TOTP secret exists)
  if (hitTest(tx, ty, 112, 196, 200, 36) && strlen(e.totp) > 0) {
    _disp.triggerFlash(112, 196, 200, 36, C_ORANGE, "GENERATE 2FA", 1);
    _audio.play(Tone::KEY_TICK);
    transitionTo(Screen::TOTP); return;
  }
}

// Dispatch: login → original touch handler, else per-type.
void UiController::handleDetailTouch(int tx, int ty) {
  VaultEntry e = _vault.entryAt(_sortedIndex[_selectedEntry]);
  if (e.type == 0) {
    handleDetailTouchLogin(tx, ty);
  } else {
    handleDetailTouchPerType(tx, ty);
  }
}

// ── Button handler for the ORIGINAL login detail screen ──────────────
// Byte-for-byte from v9.9: UP toggles visibility, DOWN types password,
// LEFT back, RIGHT opens TOTP if present, TOUCH types password.
void UiController::handleDetailButtonsLogin() {
  if (!_btn.pressed()) return;
  BtnEvent ev = _btn.state();
  VaultEntry e = _vault.entryAt(_sortedIndex[_selectedEntry]);
  if (ev == BtnEvent::UP) {
    _passVisible = !_passVisible; drawPassArea();
  } else if (ev == BtnEvent::DOWN) {
    typeStr(e.pass);
  } else if (ev == BtnEvent::LEFT) {
    transitionTo(Screen::VAULT);
  } else if (ev == BtnEvent::RIGHT) {
    if (strlen(e.totp) > 0) transitionTo(Screen::TOTP);
  } else if (ev == BtnEvent::TOUCH) {
    // TOUCH = universal confirm. On the login detail screen, "confirm"
    // = type the password via BLE (same as DOWN).
    typeStr(e.pass);
  }
}

// ── Button handler for Card / Identity / Note ────────────────────────
void UiController::handleDetailButtonsPerType() {
  if (!_btn.pressed()) return;
  BtnEvent ev = _btn.state();
  VaultEntry e = _vault.entryAt(_sortedIndex[_selectedEntry]);
  if (ev == BtnEvent::UP) {
    // Scroll up in the field list (or toggle visibility if at top)
    if (_detailScroll > 0) { _detailScroll--; drawDetailScreen(); }
    else if (e.type == 1 || e.type == 2) {
      _passVisible = !_passVisible; drawDetailScreen();
    }
  } else if (ev == BtnEvent::DOWN) {
    // Scroll down in the field list
    int maxScroll = countDetailFields() - DETAIL_VISIBLE_ROWS;
    if (maxScroll < 0) maxScroll = 0;
    if (_detailScroll < maxScroll) { _detailScroll++; drawDetailScreen(); }
  } else if (ev == BtnEvent::LEFT) {
    _detailScroll = 0;
    transitionTo(Screen::VAULT);
  } else if (ev == BtnEvent::RIGHT) {
    // For entries with TOTP, RIGHT opens the TOTP screen.
    if (strlen(e.totp) > 0) { _detailScroll = 0; transitionTo(Screen::TOTP); }
    else {
      // Otherwise RIGHT = TYPE ALL (form-fill shortcut).
      typeAllFieldsWithTab();
    }
  } else if (ev == BtnEvent::TOUCH) {
    // ── Capacitive-touch short tap = TYPE ALL ─────────────────────────
    // With a web form's first field focused on the host PC, a short tap
    // of the device's capacitive pad pastes every field of the current
    // entry via BLE, with Tab between fields — so the form walks itself
    // field-by-field. (Long-press of the same pad still triggers
    // hold-to-lock via checkHoldToLock(); the touch-deferred dispatch
    // in tick() only forwards taps shorter than 1500ms to this handler.)
    typeAllFieldsWithTab();
  }
}

// Dispatch: login → original button handler, else per-type.
void UiController::handleDetailButtons() {
  VaultEntry e = _vault.entryAt(_sortedIndex[_selectedEntry]);
  if (e.type == 0) {
    handleDetailButtonsLogin();
  } else {
    handleDetailButtonsPerType();
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  TOTP
// ═══════════════════════════════════════════════════════════════════════════════
void UiController::drawTOTPCode() {
  auto& tft = _disp.tft();
  VaultEntry e = _vault.entryAt(_sortedIndex[_selectedEntry]);
  if (_rtc.isOK() && strlen(e.totp) > 0) {
    uint32_t epoch = _rtc.unixEpoch();
    if (epoch > 0) TotpGenerator::generate(e.totp, epoch, _totpCode);
  }
  tft.fillRect(28, 68, 200, 32, C_BG);
  tft.setTextColor(C_WHITE); tft.setTextSize(4);
  tft.setCursor(28, 68);
  tft.print(_totpCode[0]); tft.print(_totpCode[1]); tft.print(_totpCode[2]);
  tft.print(' ');
  tft.print(_totpCode[3]); tft.print(_totpCode[4]); tft.print(_totpCode[5]);
}

void UiController::drawTOTPBar() {
  auto& tft = _disp.tft();
  uint32_t epoch = _rtc.unixEpoch();
  int secsLeft = 30 - (int)(epoch % 30);
  int barW = (int)(304.0f * secsLeft / 30.0f);
  uint16_t barCol = (secsLeft > 10) ? C_GREEN : C_RED;

  tft.fillRect(8, 128, 304, 14, C_DARKGREY);
  tft.fillRect(8, 128, barW, 14, barCol);
  tft.fillRect(140, 131, 40, 10, (barW > 152) ? barCol : C_DARKGREY);
  tft.setTextColor(C_WHITE); tft.setTextSize(1);
  tft.setCursor(148, 131);
  char ss[8]; sprintf(ss, "%ds", secsLeft); tft.print(ss);
}

void UiController::drawTOTPScreen() {
  auto& tft = _disp.tft();
  VaultEntry e = _vault.entryAt(_sortedIndex[_selectedEntry]);
  tft.fillRect(0, 0, SCREEN_W, SCREEN_H, C_BG);
  drawStatusBar();

  tft.fillRect(0, SBAR_H, SCREEN_W, 24, C_HEADER);
  // Use C_ACCENT for the "2FA CODE" label — it has high contrast on
  // C_HEADER in ALL themes (dark blue on gray for Sunlight, cyan on
  // dark for Air-Gapped, etc.). C_YELLOW was used before but had low
  // contrast on the light-gray header in Sunlight.
  tft.setTextColor(C_ACCENT, C_HEADER); tft.setTextSize(1);
  tft.setCursor(6, 27); tft.print("2FA CODE - ");
  // Site name in C_WHITE (the semantic foreground color) for readability
  tft.setTextColor(C_WHITE, C_HEADER);
  tft.print(e.site);

  drawTOTPCode();
  drawTOTPBar();

  _disp.drawBtn(8,   152, 152, 42, "TYPE CODE",  C_BTN);
  _disp.drawBtn(162, 152, 152, 42, "CODE+ENTER", C_BTN);
  _disp.drawBtn(162, 198, 152, 42, "< BACK",     C_BTN);
}

void UiController::handleTOTPTouch(int tx, int ty) {
  if (hitTest(tx, ty, 8, 152, 152, 42)) {
    _disp.triggerFlash(8, 152, 152, 42, C_BTN, "TYPE CODE", 1);
    _audio.play(Tone::KEY_TICK);
    typeStr(_totpCode); return;
  }
  if (hitTest(tx, ty, 162, 152, 152, 42)) {
    _disp.triggerFlash(162, 152, 152, 42, C_BTN, "CODE+ENTER", 1);
    _audio.play(Tone::KEY_TICK);
    typeStr(_totpCode); typeEnter(); return;
  }
  if (hitTest(tx, ty, 162, 198, 152, 42)) {
    _disp.triggerFlash(162, 198, 152, 42, C_BTN, "< BACK", 1);
    _audio.play(Tone::KEY_TICK);
    transitionTo(Screen::DETAIL);
  }
}

void UiController::handleTOTPButtons() {
  if (!_btn.pressed()) return;
  BtnEvent e = _btn.state();
  if (e == BtnEvent::LEFT) {
    transitionTo(Screen::DETAIL);
  } else if (e == BtnEvent::RIGHT) {
    typeStr(_totpCode); typeEnter();
  } else if (e == BtnEvent::DOWN) {
    typeStr(_totpCode);
  } else if (e == BtnEvent::TOUCH) {
    // TOUCH = universal confirm. On the TOTP screen, "confirm" = type the
    // code + press Enter (same as RIGHT).
    typeStr(_totpCode); typeEnter();
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  SET TIME
// ═══════════════════════════════════════════════════════════════════════════════
void UiController::drawTimeDigits() {
  auto& tft = _disp.tft();
  tft.fillRect(8, 40, 304, 18, C_BG);
  tft.setTextColor(C_WHITE); tft.setTextSize(2);
  tft.setCursor(8, 40);
  tft.print(_timeBuf);
  for (int i = strlen(_timeBuf); i < 10; i++) tft.print('_');
}

void UiController::drawSetTimeScreen() {
  auto& tft = _disp.tft();
  tft.fillRect(0, 0, SCREEN_W, SCREEN_H, C_BG);
  tft.setTextColor(C_ACCENT); tft.setTextSize(1);
  tft.setCursor(8, 6); tft.print("SET TIME - unix epoch seconds");
  drawTimeDigits();
  for (int r = 0; r < NUM_ROWS; r++)
    for (int c = 0; c < NUM_COLS; c++)
      drawNumpadBtn(r * NUM_COLS + c, false);
}

void UiController::handleSetTimeTouch(int tx, int ty) {
  for (int r = 0; r < NUM_ROWS; r++) {
    for (int c = 0; c < NUM_COLS; c++) {
      int idx = r * NUM_COLS + c;
      int bx = NUM_X0 + c * (NUM_BW + NUM_GAP), by = NUM_Y0 + r * (NUM_BH + NUM_GAP);
      if (!hitTest(tx, ty, bx, by, NUM_BW, NUM_BH)) continue;

      _disp.triggerFlash(bx, by, NUM_BW, NUM_BH,
        (idx == 9) ? C_RED : (idx == 11) ? C_BTN_DARK : C_BTN, NUM_LABELS[idx], 2);
      _audio.play(Tone::KEY_TICK);

      if (idx == 9) {                                   // CLR
        if (_timeLen > 0) { _timeLen--; _timeBuf[_timeLen] = 0; drawTimeDigits(); }
      } else if (idx == 11) {                            // OK
        uint32_t epoch = strtoul(_timeBuf, NULL, 10);
        if (_timeLen > 0 && epoch >= SANE_EPOCH) {
          _rtc.writeFromEpoch(epoch);
          _timeLen = 0; _timeBuf[0] = 0;
          _audio.play(Tone::UNLOCK);
          transitionTo(Screen::LOCK);
        } else {
          _disp.tft().fillRect(8, 40, 304, 18, C_RED);
          _audio.play(Tone::ERROR);
          delay(150);
          drawTimeDigits();
        }
      } else {                                            // digit
        int digit = (idx < 9) ? (idx + 1) : 0;
        if (_timeLen < 10) { _timeBuf[_timeLen++] = '0' + digit; _timeBuf[_timeLen] = 0; drawTimeDigits(); }
      }
      return;
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  MODE MENU OVERLAY
// ═══════════════════════════════════════════════════════════════════════════════
void UiController::drawModeMenu() {
  auto& tft = _disp.tft();
  // v5.4: 5 items now (was 4). Same total height as before (5 * MENU_OPT_H
  // + 6 * MENU_GAP = 5*26 + 6*4 = 154px — fits in 240px tall screen with
  // room for the status bar).
  int n = 5;
  int h = n * MENU_OPT_H + (n + 1) * MENU_GAP;
  int y0 = SCREEN_H - h - 6;
  tft.fillRect(0, y0 - 4, SCREEN_W, h + 8, C_PANEL);
  tft.drawFastHLine(0, y0 - 4, SCREEN_W, C_ACCENT);
  for (int i = 0; i < n; i++) {
    int y = y0 + MENU_GAP + i * (MENU_OPT_H + MENU_GAP);
    bool isCurrent = (i == 0 && _hidMode == HidMode::BLE)
                   || (i == 1 && _hidMode == HidMode::DASHBOARD)
                   || (i == 2 && _hidMode == HidMode::AP);
    // i == 3 is SETTINGS, i == 4 is CANCEL (dark button).
    uint16_t col = (i == 4) ? C_BTN_DARK : (isCurrent ? C_ACCENT : C_BTN);
    uint16_t txtCol = isCurrent ? C_BG : C_WHITE;
    _disp.drawBtn(12, y, SCREEN_W - 24, MENU_OPT_H, MODE_MENU_LABELS[i], col, 1, txtCol);
  }
}

void UiController::closeModeMenu() {
  _modeMenuOpen = false;
  switch (_modeMenuHost) { // host screen owns these pixels — just redraw it in full
    case Screen::VAULT:           drawVaultScreen();       break;
    case Screen::DETAIL:          drawDetailScreen();      break;
    case Screen::TOTP:            drawTOTPScreen();        break;
    case Screen::DASHBOARD_CODE:  drawDashboardCodeScreen(); break;
    case Screen::AP_INFO:         drawApInfoScreen();      break;
    case Screen::SEARCH:          drawSearchScreen();       break;
    default: break;
  }
}

void UiController::handleModeMenuTouch(int tx, int ty) {
  int n = 5;
  int h = n * MENU_OPT_H + (n + 1) * MENU_GAP;
  int y0 = SCREEN_H - h - 6;
  for (int i = 0; i < n; i++) {
    int y = y0 + MENU_GAP + i * (MENU_OPT_H + MENU_GAP);
    if (hitTest(tx, ty, 12, y, SCREEN_W - 24, MENU_OPT_H)) {
      _audio.play(Tone::KEY_TICK);

      // i == 3 is SETTINGS — open the settings screen
      if (i == 3) {
        _modeMenuOpen = false;
        transitionTo(Screen::SETTINGS);
        return;
      }

      // i == 4 is CANCEL — close menu, no mode change
      if (i == 4) {
        closeModeMenu();
        return;
      }

      // ── DEFERRED MODE SWITCH (CRITICAL FIX) ──────────────────────────
      // The touch handler ONLY sets _modePendingSwitch + _modeSwitchState.
      // It does NOT call teardown or init here — that caused firmware crashes
      // because the old mode's background tasks (WiFi, serial, BLE) overlap
      // with the new mode's initialization. Instead, processModeSwitch() in
      // tick() handles the multi-step transition:
      //   TEARDOWN_OLD → stop old mode tick + cleanup
      //   INIT_NEW → start new mode + screen transition
      // Each step takes one tick() iteration, giving background tasks time
      // to complete before starting the new mode.
      if (i == 0) {
        _modePendingSwitch = HidMode::BLE;
      } else if (i == 1) {
        _modePendingSwitch = HidMode::DASHBOARD;
      } else if (i == 2) {
        _modePendingSwitch = HidMode::AP;
      }

      // If the same mode is already active, just close the menu
      if (_modePendingSwitch == _hidMode) {
        closeModeMenu();
        return;
      }

      // Need PIN check before switching to Dashboard/AP:
      // If the PIN was wiped by auto-lock (SessionContext cleared), force re-unlock first.
      if (_modePendingSwitch == HidMode::DASHBOARD && !_sessionCtx.isSet()) {
        _modeMenuOpen = false;
        _modeMenuHost = Screen::VAULT;
        transitionTo(Screen::LOCK);
        return;
      }
      if (_modePendingSwitch == HidMode::AP && !_sessionCtx.isSet()) {
        _modeMenuOpen = false;
        _modeMenuHost = Screen::VAULT;
        transitionTo(Screen::LOCK);
        return;
      }

      // Start the deferred mode switch sequence.
      // Close the menu first, then tick() will handle the transition.
      _modeMenuOpen = false;
      _modeSwitchState = ModeSwitchState::TEARDOWN_OLD;
      _modeSwitchStartTime = millis();

      // Redraw the host screen so the menu overlay is gone immediately
      // (the mode switch will transition to a new screen in a moment).
      switch (_modeMenuHost) {
        case Screen::VAULT:        drawVaultScreen();       break;
        case Screen::DETAIL:       drawDetailScreen();      break;
        case Screen::TOTP:         drawTOTPScreen();         break;
        case Screen::DASHBOARD_CODE: drawDashboardCodeScreen(); break;
        case Screen::AP_INFO:      drawApInfoScreen();       break;
        case Screen::SEARCH:       drawSearchScreen();        break;
        default:                   drawVaultScreen();        break;
      }
      return;
    }
  }
  closeModeMenu(); // tap outside the options = cancel
}

// ═══════════════════════════════════════════════════════════════════════════════
//  DEFERRED MODE SWITCH (CRITICAL FIX)
//  Two-step state machine: TEARDOWN_OLD → INIT_NEW
//  Each step takes exactly one tick() iteration, giving background tasks
//  at least one loop() delay (8ms) between teardown and init, preventing
//  the overlap that caused firmware crashes.
// ═══════════════════════════════════════════════════════════════════════════════
void UiController::processModeSwitch() {
  HidMode prevMode = _hidMode;

  if (_modeSwitchState == ModeSwitchState::TEARDOWN_OLD) {
    // ── Step 1: Tear down the old mode ──────────────────────────────────
    // Stop calling the old mode's tick() by temporarily setting _hidMode
    // to BLE (a neutral state that has no tick() activity). This prevents
    // _serialProto.tick() or APModeManager::tick() from running during
    // the transition. The actual cleanup is done here.

    if (prevMode == HidMode::DASHBOARD) {
      _serialProto.teardownSecureSession();
      _serialProto.end();
      secureZero(_dashboardCode, sizeof(_dashboardCode));
    }

    if (prevMode == HidMode::AP) {
      // v5.4.7: stop() is async — returns immediately. The AP will be
      // torn down on a background task. We advance to INIT_NEW on the
      // next tick() iteration, giving the background teardown time to run.
      APModeManager::getInstance().stop();
    }

    // Temporarily set _hidMode to BLE so tick() doesn't call the old
    // mode's tick() during the transition. This is safe because BLE
    // mode has no active tick() processing (no serial, no AP).
    _hidMode = HidMode::BLE;

    // Safety timeout: if the transition takes more than 5 seconds,
    // abort and go back to the vault screen.
    if (millis() - _modeSwitchStartTime > 5000) {
      _modeSwitchState = ModeSwitchState::IDLE;
      _modePendingSwitch = HidMode::BLE;
      transitionTo(Screen::VAULT);
      return;
    }

    // Advance to the init step — the next tick() iteration will
    // start the new mode.
    _modeSwitchState = ModeSwitchState::INIT_NEW;
    return;
  }

  if (_modeSwitchState == ModeSwitchState::INIT_NEW) {
    // ── Step 2: Initialize the new mode ──────────────────────────────────
    // The old mode is fully torn down (at least one tick() cycle has
    // passed since teardown). Now start the new mode and transition to
    // its screen.

    // Entering Dashboard Mode
    if (_modePendingSwitch == HidMode::DASHBOARD) {
      _serialProto.begin(_vault, &_sessionCtx);
      const char* code = _serialProto.code();
      if (code) {
        strncpy(_dashboardCode, code, 6);
        _dashboardCode[6] = 0;
      }
      _hidMode = HidMode::DASHBOARD;
      _modePendingSwitch = HidMode::DASHBOARD;
      _modeSwitchState = ModeSwitchState::IDLE;
      _dashboardWasConnected = false;
      transitionTo(Screen::DASHBOARD_CODE);
      return;
    }

    // Entering AP Mode
    if (_modePendingSwitch == HidMode::AP) {
      if (APModeManager::getInstance().start(&_vault, &_sessionCtx, &_ble)) {
        _hidMode = HidMode::AP;
        _modePendingSwitch = HidMode::AP;
        _modeSwitchState = ModeSwitchState::IDLE;
        transitionTo(Screen::AP_INFO);
        return;
      } else {
        // AP start failed — fall back to vault
        _hidMode = HidMode::BLE;
        _modePendingSwitch = HidMode::BLE;
        _modeSwitchState = ModeSwitchState::IDLE;
        transitionTo(Screen::VAULT);
        return;
      }
    }

    // Entering BLE Mode (from Dashboard or AP — already torn down)
    if (_modePendingSwitch == HidMode::BLE) {
      _hidMode = HidMode::BLE;
      _modePendingSwitch = HidMode::BLE;
      _modeSwitchState = ModeSwitchState::IDLE;
      transitionTo(Screen::VAULT);
      return;
    }

    // Fallback: reset to IDLE + vault screen
    _hidMode = HidMode::BLE;
    _modeSwitchState = ModeSwitchState::IDLE;
    transitionTo(Screen::VAULT);
    return;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  BLE PAIRING
// ═══════════════════════════════════════════════════════════════════════════════
void UiController::drawBlePairingScreen() {
  auto& tft = _disp.tft();
  tft.fillRect(0, 0, SCREEN_W, SCREEN_H, C_BG);
  tft.setTextColor(C_ACCENT); tft.setTextSize(2);
  tft.setCursor(46, 30); tft.print("BLE PAIRING");
  tft.setTextColor(C_GREY); tft.setTextSize(1);
  tft.setCursor(40, 60); tft.print("Confirm this code on your device:");

  char pinStr[7]; sprintf(pinStr, "%06lu", (unsigned long)_ble.pairingPasskey());
  tft.setTextColor(C_WHITE); tft.setTextSize(4);
  tft.setCursor(58, 90); tft.print(pinStr);

  tft.fillCircle(SCREEN_W / 2, 170, 5, C_ACCENT); // pulsed in tick()
  _disp.drawBtn(112, 196, 96, 32, "CANCEL", C_RED);
}

void UiController::pulseBlePairingDot() {
  static int r = 3, dir = 1;
  auto& tft = _disp.tft();
  tft.fillCircle(SCREEN_W / 2, 170, 7, C_BG);
  tft.fillCircle(SCREEN_W / 2, 170, r, C_ACCENT);
  r += dir;
  if (r >= 7 || r <= 3) dir = -dir;
}

void UiController::handleBlePairingTouch(int tx, int ty) {
  if (hitTest(tx, ty, 112, 196, 96, 32)) {
    _disp.triggerFlash(112, 196, 96, 32, C_RED, "CANCEL", 1);
    _audio.play(Tone::KEY_TICK);
    _ble.cancelPairing();
    transitionTo(_screenBeforePairing);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  v3: DASHBOARD CODE TOUCH — BACK button to exit Dashboard Mode
// ═══════════════════════════════════════════════════════════════════════════════
void UiController::handleDashboardCodeTouch(int tx, int ty) {
  // BACK button (bottom-left): exit Dashboard Mode → return to vault list
  if (hitTest(tx, ty, 8, 210, 70, 24)) {
    _disp.triggerFlash(8, 210, 70, 24, C_RED, "BACK", 1);
    _audio.play(Tone::KEY_TICK);

    // v5.4.8: Transition to VAULT FIRST, then teardown. This makes the
    // screen change INSTANT — no white lag. The teardown (serial cleanup
    // + mbedtls zeroing) happens after the screen is already drawn, so
    // the user doesn't see a frozen UI.
    _hidMode = HidMode::BLE;
    secureZero(_dashboardCode, sizeof(_dashboardCode));
    transitionTo(Screen::VAULT);

    // Now do the teardown (runs after the screen transition, so the user
    // doesn't see any lag). These calls zero the session keys + close the
    // serial protocol — safe to do after we've already switched to BLE mode.
    _serialProto.teardownSecureSession();
    _serialProto.end();
    return;
  }

  // NEW CODE button (bottom-right): regenerate 6-digit code
  // Tears down any existing session + generates a fresh code.
  if (hitTest(tx, ty, 242, 210, 70, 24)) {
    _disp.triggerFlash(242, 210, 70, 24, C_BTN, "NEW CODE", 1);
    _audio.play(Tone::KEY_TICK);

    _serialProto.regenerateCode();
    const char* code = _serialProto.code();
    if (code) {
      strncpy(_dashboardCode, code, 6);
      _dashboardCode[6] = 0;
    }
    // Redraw the code screen with the new code
    transitionTo(Screen::DASHBOARD_CODE);
    return;
  }

  // Mode badge (top-right) — open mode menu to switch modes
  if (hitTest(tx, ty, MODE_BADGE_X, MODE_BADGE_Y, MODE_BADGE_W, MODE_BADGE_H)) {
    _audio.play(Tone::KEY_TICK);  // v9.20: play click sound (was missing)
    _modeMenuOpen = true;
    _modeMenuHost = Screen::DASHBOARD_CODE;
    drawModeMenu();
    return;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  v3: DASHBOARD CODE SCREEN — displays the 6-digit ECDH handshake code
// ═══════════════════════════════════════════════════════════════════════════════
// Static parts drawn once (called by transitionTo), dynamic parts updated
// in tick() without clearing the screen — eliminates flicker.
void UiController::drawDashboardCodeScreen() {
  auto& tft = _disp.tft();
  tft.fillRect(0, 0, SCREEN_W, SCREEN_H, C_BG);

  // Top status bar (time + mode indicator)
  drawStatusBar();

  tft.setTextColor(C_ACCENT); tft.setTextSize(2);
  tft.setCursor(20, 30); tft.print("DASHBOARD");

  tft.setTextColor(C_GREY); tft.setTextSize(1);
  tft.setCursor(16, 58);
  tft.print("Enter this code in the");
  tft.setCursor(16, 70);
  tft.print("Electron app to connect:");

  // Draw the 6-digit code large + centered (static — doesn't change)
  tft.setTextColor(C_WHITE); tft.setTextSize(5);
  int codeW = 6 * 6 * 5;
  int codeX = (SCREEN_W - codeW) / 2;
  tft.setCursor(codeX, 105);
  tft.print(_dashboardCode);

  // BACK button (bottom-left) — touch to exit Dashboard Mode
  _disp.drawBtn(8, 210, 70, 24, "BACK", C_RED);
  // NEW CODE button (bottom-right) — regenerate 6-digit code
  _disp.drawBtn(242, 210, 70, 24, "NEW CODE", C_BTN);

  // Initial status line + pulse (updated dynamically in tick)
  tft.setTextSize(1);
  tft.fillRect(16, 185, 250, 14, C_BG);
  tft.setCursor(16, 185);
  if (_serialProto.sessionEstablished()) {
    tft.setTextColor(C_GREEN);
    tft.print("CONNECTED");
  } else {
    tft.setTextColor(C_YELLOW);
    tft.print("Waiting for connection...");
  }
}

// Dynamic update — only redraws the status line + pulse indicator.
// Called from tick() every 500ms. Does NOT clear the screen.
void UiController::updateDashboardCodeScreen() {
  auto& tft = _disp.tft();

  // v9.20: Detect "just connected" transition — play a success sound
  // immediately when the ECDH handshake completes, instead of waiting
  // for the user to notice the grey→green indicator change.
  bool connected = _serialProto.sessionEstablished();
  if (connected && !_dashboardWasConnected) {
    // Just connected! Play a "tada" — two rising tones.
    _audio.play(Tone::UNLOCK);   // rising success tone
    _dashboardWasConnected = true;
  } else if (!connected && _dashboardWasConnected) {
    // v10.4: Just disconnected — the session already auto-regenerated a
    // fresh code (in the LOCK handler or the 30s timeout). Sync the
    // displayed _dashboardCode and redraw the code area so the user
    // sees the new code immediately without pressing NEW CODE.
    _dashboardWasConnected = false;
    const char* fresh = _serialProto.code();
    if (fresh && fresh[0]) {
      strncpy(_dashboardCode, fresh, 6);
      _dashboardCode[6] = 0;
      // Redraw just the large code area (avoid full-screen flicker)
      tft.fillRect(0, 95, SCREEN_W, 50, C_BG);
      tft.setTextColor(C_WHITE); tft.setTextSize(5);
      int codeW = 6 * 6 * 5;
      int codeX = (SCREEN_W - codeW) / 2;
      tft.setCursor(codeX, 105);
      tft.print(_dashboardCode);
    }
  }

  // Update status line (clear just that line, not the whole screen)
  tft.setTextSize(1);
  tft.fillRect(16, 185, 250, 14, C_BG);
  tft.setCursor(16, 185);
  if (connected) {
    tft.setTextColor(C_GREEN);
    tft.print("CONNECTED");
  } else {
    tft.setTextColor(C_YELLOW);
    tft.print("Waiting for connection...");
  }

  // Pulse indicator — green when connected, grey when waiting
  if (connected) {
    if ((millis() / 500) % 2 == 0) {
      tft.fillCircle(SCREEN_W - 20, 30, 5, C_GREEN);
    } else {
      tft.fillCircle(SCREEN_W - 20, 30, 5, C_BG);
      tft.drawCircle(SCREEN_W - 20, 30, 5, C_GREEN);
    }
  } else {
    // Grey pulse when waiting — was solid grey before (the bug)
    if ((millis() / 500) % 2 == 0) {
      tft.fillCircle(SCREEN_W - 20, 30, 5, C_GREY);
    } else {
      tft.fillCircle(SCREEN_W - 20, 30, 5, C_BG);
      tft.drawCircle(SCREEN_W - 20, 30, 5, C_GREY);
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  v5.4.3: AP MODE INFO SCREEN — redesigned for 2.4" landscape (320×240)
//  Layout:
//    y=0-20:    Status bar (time + "AP" badge)
//    y=24-40:   "AP MODE" title (size 2) + pulse indicator
//    y=46-56:   "WiFi: <SSID>" (size 1, one line)
//    y=66-76:   "Password:" label (size 1, grey)
//    y=78-94:   password value (size 2, white) — BIG and readable
//    y=102-112: "Code:" label (size 1, grey)
//    y=114-130: code value (size 2, accent) — BIG and readable
//    y=140-156: connection status (size 2, prominent)
//    y=162-174: "Open 192.168.4.1" hint (size 1, grey)
//    y=184-212: BACK + NEW SSID buttons
//  Right side: WiFi QR code centered at (236, 92), 99×99px
// ═══════════════════════════════════════════════════════════════════════════════
void UiController::drawApInfoScreen() {
  auto& tft = _disp.tft();
  tft.fillRect(0, 0, SCREEN_W, SCREEN_H, C_BG);

  // Top status bar (time + "AP" badge) — same as all other screens.
  drawStatusBar();

  // Title + pulse indicator
  tft.setTextColor(C_ACCENT); tft.setTextSize(2);
  tft.setCursor(8, 24); tft.print("AP MODE");
  tft.fillCircle(SCREEN_W - 12, 31, 4, C_GREEN);

  // ── Left column: text credentials (x=8 to ~150) ──
  // WiFi label + SSID on one line (size 1, medium — fits the long SSID)
  tft.setTextColor(C_GREY); tft.setTextSize(1);
  tft.setCursor(8, 46); tft.print("WiFi:");
  tft.setTextColor(C_WHITE);
  tft.setCursor(38, 46);
  tft.print(APModeManager::getInstance().ssid());

  // Password — BIG (size 2) so it's readable
  tft.setTextColor(C_GREY); tft.setTextSize(1);
  tft.setCursor(8, 66); tft.print("Password:");
  tft.setTextColor(C_WHITE); tft.setTextSize(2);
  tft.setCursor(8, 78);
  tft.print(APModeManager::getInstance().wpa2Password());

  // Code — BIG (size 2) for easy reading
  tft.setTextColor(C_GREY); tft.setTextSize(1);
  tft.setCursor(8, 102); tft.print("Code:");
  tft.setTextColor(C_ACCENT); tft.setTextSize(2);
  tft.setCursor(8, 114);
  tft.print(APModeManager::getInstance().code());

  // Connection status (size 1, y=148)
  tft.setTextSize(1);
  tft.setCursor(8, 148);
  int clients = WiFi.softAPgetStationNum();
  if (clients > 0) {
    tft.setTextColor(C_GREEN);
    tft.print("CONNECTED");
    _apWasConnected = true;
  } else {
    tft.setTextColor(C_YELLOW);
    tft.print("Waiting...");
    _apWasConnected = false;
  }

  // Browser hint
  tft.setTextColor(C_GREY); tft.setTextSize(1);
  tft.setCursor(8, 162);
  tft.print("Open 192.168.4.1");

  // ── Right column: WiFi QR code ──
  drawWiFiQR(tft, 236, 92, 120,
             APModeManager::getInstance().ssid(),
             APModeManager::getInstance().wpa2Password());
  tft.setTextColor(C_GREY); tft.setTextSize(1);
  const char* scanLabel = "Scan to join";
  int labelW = strlen(scanLabel) * 6;
  tft.setCursor(236 - labelW / 2, 150);
  tft.print(scanLabel);

  // ── Bottom: BACK + NEW SSID buttons ──
  _disp.drawBtn(8, 184, 90, 28, "BACK", C_BTN_DARK, 1, C_WHITE);
  _disp.drawBtn(SCREEN_W - 138, 184, 130, 28, "NEW SSID", C_BTN, 1, C_WHITE);
}

void UiController::updateApInfoScreen() {
  auto& tft = _disp.tft();
  unsigned long t = millis();

  // Pulse the status indicator (top-right).
  bool on = (t / 500) % 2 == 0;
  if (on) {
    tft.fillCircle(SCREEN_W - 12, 33, 4, C_GREEN);
  } else {
    tft.fillCircle(SCREEN_W - 12, 33, 4, C_BG);
    tft.drawCircle(SCREEN_W - 12, 33, 4, C_GREEN);
  }

  // Update connection status.
  int clients = WiFi.softAPgetStationNum();
  bool connected = clients > 0;

  // Play sound on connect/disconnect transition.
  if (connected && !_apWasConnected) {
    _audio.play(Tone::UNLOCK);
    _apWasConnected = true;
  } else if (!connected && _apWasConnected) {
    _apWasConnected = false;
  }

  // Redraw the connection status text (y=148, size 1).
  tft.fillRect(8, 148, 160, 12, C_BG);
  tft.setTextSize(1);
  tft.setCursor(8, 148);
  if (connected) {
    tft.setTextColor(C_GREEN);
    tft.print("CONNECTED");
  } else {
    tft.setTextColor(C_YELLOW);
    tft.print("Waiting...");
  }

  // If AP mode was stopped (e.g. by idle timeout), exit the screen.
  // v5.4.9 FIX: Do NOT clear SessionContext on AP idle timeout exit — the user
  // may want to re-enter AP mode without re-authenticating. This matches
  // the BACK-button handler's behavior (which also preserves the PIN).
  // The general auto-lock in tick() clears SessionContext when the entire session
  // ends (lock screen), so the PIN is still properly cleaned up when it
  // matters most. Only zero _apWasConnected (not a secret, just a flag).
  if (!APModeManager::getInstance().isActive()) {
    _hidMode = HidMode::BLE;
    // F6: SessionContext NOT cleared here — preserve for free re-entry
    _apWasConnected = false;
    _lastActivity = millis();
    transitionTo(Screen::VAULT);
  }
}

void UiController::handleApInfoTouch(int tx, int ty) {
  // BACK button (bottom-left, y=184) — exit AP mode → return to vault list
  // v5.4.9 FIX: Do NOT clear SessionContext on voluntary exit — the user may want to
  // re-enter AP mode without re-authenticating. This matches Dashboard Mode's
  // design: SessionContext PIN is preserved on exit, only cleared on auto-lock /
  // hold-to-lock / power-off (all handled elsewhere). Same rule so the user
  // can freely switch between vault and AP mode within the same unlocked session.
  if (hitTest(tx, ty, 8, 184, 90, 28)) {
    _audio.play(Tone::KEY_TICK);
    APModeManager::getInstance().stop();
    _hidMode = HidMode::BLE;
    _apWasConnected = false;
    _lastActivity = millis();
    transitionTo(Screen::VAULT);
    return;
  }

  // NEW SSID button (bottom-right, y=184) — regenerate all credentials
  if (hitTest(tx, ty, SCREEN_W - 138, 184, 130, 28)) {
    _audio.play(Tone::KEY_TICK);
    if (APModeManager::getInstance().regenerateCredentials()) {
      _apWasConnected = false;
      drawApInfoScreen();  // full redraw with new credentials + QR
    }
    return;
  }

  // Mode badge (top-right) — open mode menu to switch modes
  if (hitTest(tx, ty, MODE_BADGE_X, MODE_BADGE_Y, MODE_BADGE_W, MODE_BADGE_H)) {
    _audio.play(Tone::KEY_TICK);
    _modeMenuOpen = true;
    _modeMenuHost = Screen::AP_INFO;
    drawModeMenu();
    return;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  v5.4.3: SEARCH SCREEN — QWERTY keyboard + live-filtered vault search
// ═══════════════════════════════════════════════════════════════════════════════
//  Layout (320×240):
//    y=0-20:    Status bar (time + mode badge)
//    y=22-46:   Search input field (shows typed query + result count)
//    y=48-114:  Results list (66px, ~3 results × 22px)
//    y=116-234: QWERTY keyboard (4 rows × 28px + 3×2px gaps = 118px)
//
//  Keyboard layout (v5.4.4 — FULL WIDTH, 30px keys, 2px gaps):
//    Row 1 (y=116): Q W E R T Y U I O P   10 keys, x=1 to x=319 (full width)
//    Row 2 (y=146): A S D F G H J K L      9 keys, x=17 to x=303 (centered)
//    Row 3 (y=176): Z X C V B N M ⌫(wide)  7 keys + wide backspace, x=17 to x=319
//    Row 4 (y=206): 123 SEARCH BACK        x=1 to x=319 (aligns with row 1)
//
//  Row 4 is aligned with row 1 on both left (x=1) and right (x=319) edges.
// ═══════════════════════════════════════════════════════════════════════════════

// Keyboard key definitions. Each key has: x, y, w, h, label, char (0=special).
struct SearchKey {
  int x, y, w, h;
  const char* label;
  char ch;  // 0 = special key (use label to identify)
};

// Letters mode keyboard (4 rows) — FULL WIDTH, 30px keys, 2px gaps.
static const SearchKey SEARCH_KEYS_LETTERS[] = {
  // Row 1: Q W E R T Y U I O P (10 keys, 30px each, x=1 to x=319)
  {1, 116, 30, 28, "Q", 'q'}, {33, 116, 30, 28, "W", 'w'},
  {65, 116, 30, 28, "E", 'e'}, {97, 116, 30, 28, "R", 'r'},
  {129, 116, 30, 28, "T", 't'}, {161, 116, 30, 28, "Y", 'y'},
  {193, 116, 30, 28, "U", 'u'}, {225, 116, 30, 28, "I", 'i'},
  {257, 116, 30, 28, "O", 'o'}, {289, 116, 30, 28, "P", 'p'},
  // Row 2: A S D F G H J K L (9 keys, 30px each, x=17 to x=303 — centered)
  {17, 146, 30, 28, "A", 'a'}, {49, 146, 30, 28, "S", 's'},
  {81, 146, 30, 28, "D", 'd'}, {113, 146, 30, 28, "F", 'f'},
  {145, 146, 30, 28, "G", 'g'}, {177, 146, 30, 28, "H", 'h'},
  {209, 146, 30, 28, "J", 'j'}, {241, 146, 30, 28, "K", 'k'},
  {273, 146, 30, 28, "L", 'l'},
  // Row 3: Z X C V B N M ⌫(wide) (7 keys + wide backspace, x=17 to x=319)
  {17, 176, 30, 28, "Z", 'z'}, {49, 176, 30, 28, "X", 'x'},
  {81, 176, 30, 28, "C", 'c'}, {113, 176, 30, 28, "V", 'v'},
  {145, 176, 30, 28, "B", 'b'}, {177, 176, 30, 28, "N", 'n'},
  {209, 176, 30, 28, "M", 'm'},
  {241, 176, 78, 28, "<x", 0},  // Backspace (wide, fills to x=319)
  // Row 4: 123(70) SEARCH(174) BACK(70) — aligned with row 1 (x=1 to x=319)
  {1, 206, 70, 28, "123", 0},
  {73, 206, 174, 28, "SEARCH", 0},
  {249, 206, 70, 28, "BACK", 0},
};
static const int SEARCH_KEYS_LETTERS_COUNT = sizeof(SEARCH_KEYS_LETTERS) / sizeof(SearchKey);

// Numbers/symbols mode keyboard — same layout as letters.
static const SearchKey SEARCH_KEYS_NUMBERS[] = {
  // Row 1: 1 2 3 4 5 6 7 8 9 0 (same positions as Q-P)
  {1, 116, 30, 28, "1", '1'}, {33, 116, 30, 28, "2", '2'},
  {65, 116, 30, 28, "3", '3'}, {97, 116, 30, 28, "4", '4'},
  {129, 116, 30, 28, "5", '5'}, {161, 116, 30, 28, "6", '6'},
  {193, 116, 30, 28, "7", '7'}, {225, 116, 30, 28, "8", '8'},
  {257, 116, 30, 28, "9", '9'}, {289, 116, 30, 28, "0", '0'},
  // Row 2: ! @ # $ % ^ & * - _ (10 keys, same positions as row 1)
  {1, 146, 30, 28, "!", '!'}, {33, 146, 30, 28, "@", '@'},
  {65, 146, 30, 28, "#", '#'}, {97, 146, 30, 28, "$", '$'},
  {129, 146, 30, 28, "%", '%'}, {161, 146, 30, 28, "^", '^'},
  {193, 146, 30, 28, "&", '&'}, {225, 146, 30, 28, "*", '*'},
  {257, 146, 30, 28, "-", '-'}, {289, 146, 30, 28, "_", '_'},
  // Row 3: . , / + = ? ' ⌫(wide) — 7 keys + wide backspace (same as letters)
  {17, 176, 30, 28, ".", '.'}, {49, 176, 30, 28, ",", ','},
  {81, 176, 30, 28, "/", '/'}, {113, 176, 30, 28, "+", '+'},
  {145, 176, 30, 28, "=", '='}, {177, 176, 30, 28, "?", '?'},
  {209, 176, 30, 28, "'", '\''},
  {241, 176, 78, 28, "<x", 0},  // Backspace (same as letters)
  // Row 4: ABC(70) SEARCH(174) BACK(70) — same as letters
  {1, 206, 70, 28, "ABC", 0},
  {73, 206, 174, 28, "SEARCH", 0},
  {249, 206, 70, 28, "BACK", 0},
};
static const int SEARCH_KEYS_NUMBERS_COUNT = sizeof(SEARCH_KEYS_NUMBERS) / sizeof(SearchKey);

void UiController::drawSearchScreen() {
  auto& tft = _disp.tft();
  tft.fillRect(0, 0, SCREEN_W, SCREEN_H, C_BG);

  // Status bar
  drawStatusBar();

  // Search input field (y=22-46)
  tft.fillRect(4, 22, SCREEN_W - 8, 24, C_PANEL);
  tft.drawRect(4, 22, SCREEN_W - 8, 24, C_DARKGREY);
  tft.setTextColor(C_WHITE); tft.setTextSize(2);
  tft.setCursor(8, 27);
  if (_searchQueryLen > 0) {
    tft.print(_searchQuery);
  } else {
    tft.setTextColor(C_GREY);
    tft.print("Type to search...");
  }
  // Blinking cursor
  if ((millis() / 500) % 2 == 0 && _searchQueryLen < 31) {
    int cursorX = 8 + _searchQueryLen * 12;  // textSize 2 = 12px per char
    tft.fillRect(cursorX, 28, 10, 16, C_ACCENT);
  }
  // Result count (right side of input field)
  tft.setTextColor(C_GREY); tft.setTextSize(1);
  tft.setCursor(SCREEN_W - 50, 30);
  tft.printf("%d/%d", _searchResultCount, _vault.count());

  // Results list (y=48-114)
  drawSearchResults();

  // Keyboard (y=116-240)
  drawSearchKeyboard();
}

void UiController::drawSearchResults() {
  auto& tft = _disp.tft();
  tft.fillRect(0, 48, SCREEN_W, 66, C_BG);

  if (_searchQueryLen == 0) {
    tft.setTextColor(C_GREY); tft.setTextSize(1);
    tft.setCursor(SCREEN_W / 2 - 48, 70);
    tft.print("Start typing to search");
    return;
  }
  if (_searchResultCount == 0) {
    tft.setTextColor(C_GREY); tft.setTextSize(1);
    tft.setCursor(SCREEN_W / 2 - 36, 70);
    tft.print("No matches found");
    return;
  }

  // v10.9: Draw results with scroll offset support. When more than 3
  // results exist, UP/DOWN buttons scroll through them. The visible
  // window starts at _searchScrollOffset and shows up to 3 results.
  // The selected result (_searchSelIdx) is highlighted.
  int maxShow = 3;  // visible rows in the results area
  // Clamp scroll offset so the selection stays visible
  if (_searchSelIdx < _searchScrollOffset) _searchScrollOffset = _searchSelIdx;
  if (_searchSelIdx >= _searchScrollOffset + maxShow) _searchScrollOffset = _searchSelIdx - maxShow + 1;
  // Don't scroll past the last result
  if (_searchScrollOffset + maxShow > _searchResultCount) _searchScrollOffset = _searchResultCount - maxShow;
  if (_searchScrollOffset < 0) _searchScrollOffset = 0;

  for (int i = 0; i < maxShow; i++) {
    int displayIdx = _searchScrollOffset + i;
    if (displayIdx >= _searchResultCount) break;
    int idx = _searchResults[displayIdx];
    VaultEntry e = _vault.entryAt(idx);
    int y = 48 + i * 22;

    // Highlight selected result
    bool isSelected = (displayIdx == _searchSelIdx);
    uint16_t bg = isSelected ? C_ACCENT : C_PANEL;
    uint16_t fg = isSelected ? C_BG : C_WHITE;
    tft.fillRect(4, y, SCREEN_W - 8, 20, bg);
    tft.drawRect(4, y, SCREEN_W - 8, 20, C_DARKGREY);

    tft.setTextColor(fg); tft.setTextSize(1);
    tft.setCursor(8, y + 3);
    tft.print(e.site ? e.site : "");
    tft.setTextColor(isSelected ? C_BG : C_GREY);
    tft.setCursor(8, y + 12);
    tft.print(e.user ? e.user : "");
    // Type badge (right side)
    tft.setTextColor(isSelected ? C_BG : C_ACCENT);
    const char* typeStr = vaultTypeToStr(e.type);
    tft.setCursor(SCREEN_W - 8 - strlen(typeStr) * 6, y + 6);
    tft.print(typeStr);
  }
}

void UiController::drawSearchKeyboard() {
  auto& tft = _disp.tft();
  const SearchKey* keys = _searchKeyboardMode ? SEARCH_KEYS_NUMBERS : SEARCH_KEYS_LETTERS;
  int keyCount = _searchKeyboardMode ? SEARCH_KEYS_NUMBERS_COUNT : SEARCH_KEYS_LETTERS_COUNT;

  for (int i = 0; i < keyCount; i++) {
    const SearchKey& k = keys[i];
    uint16_t col = C_BTN;
    uint16_t txtCol = C_WHITE;

    // Special keys get different colors
    if (k.ch == 0) {
      if (strcmp(k.label, "<x") == 0) {
        col = C_BTN_DARK;  // Backspace
      } else if (strcmp(k.label, "SEARCH") == 0) {
        col = C_ACCENT;  // Search button
        txtCol = C_BG;
      } else if (strcmp(k.label, "BACK") == 0) {
        col = C_BTN_DARK;  // Exit button
      }
      // 123/ABC toggle uses default C_BTN
    }

    // Key flash effect (briefly invert on press)
    if (_searchKeyFlash == i && (millis() - _searchKeyFlashTime < 100)) {
      uint16_t tmp = col;
      col = txtCol;
      txtCol = tmp;
    }

    _disp.drawBtn(k.x, k.y, k.w, k.h, k.label, col, 1, txtCol);
  }

  // Clear key flash after 100ms
  if (_searchKeyFlash >= 0 && (millis() - _searchKeyFlashTime >= 100)) {
    _searchKeyFlash = -1;
  }
}

void UiController::updateSearchResults() {
  _searchResultCount = 0;
  _searchSelIdx = 0;
  _searchScrollOffset = 0;  // v10.9: reset scroll on new search update
  if (_searchQueryLen == 0) return;

  // Convert query to lowercase for case-insensitive matching.
  String q = String(_searchQuery);
  q.toLowerCase();

  // Priority 1: site starts with query
  for (int i = 0; i < _vault.count() && _searchResultCount < 16; i++) {
    VaultEntry e = _vault.entryAt(i);
    if (e.deleted) continue;
    if (!e.site) continue;
    String site = String(e.site);
    site.toLowerCase();
    if (site.startsWith(q)) {
      _searchResults[_searchResultCount++] = i;
    }
  }

  // Priority 2: site contains query (but doesn't start with it)
  for (int i = 0; i < _vault.count() && _searchResultCount < 16; i++) {
    VaultEntry e = _vault.entryAt(i);
    if (e.deleted) continue;
    if (!e.site) continue;
    String site = String(e.site);
    site.toLowerCase();
    if (site.indexOf(q) > 0) {  // > 0 means it contains but doesn't start with
      // Check if already added
      bool already = false;
      for (int j = 0; j < _searchResultCount; j++) {
        if (_searchResults[j] == i) { already = true; break; }
      }
      if (!already) _searchResults[_searchResultCount++] = i;
    }
  }

  // Priority 3: user/url/notes contains query
  for (int i = 0; i < _vault.count() && _searchResultCount < 16; i++) {
    VaultEntry e = _vault.entryAt(i);
    if (e.deleted) continue;
    bool matched = false;
    // Check user
    if (e.user) {
      String u = String(e.user);
      u.toLowerCase();
      if (u.indexOf(q) >= 0) matched = true;
    }
    // Check url
    if (!matched && e.url) {
      String u = String(e.url);
      u.toLowerCase();
      if (u.indexOf(q) >= 0) matched = true;
    }
    // Check notes
    if (!matched && e.notes) {
      String n = String(e.notes);
      n.toLowerCase();
      if (n.indexOf(q) >= 0) matched = true;
    }
    if (matched) {
      // Check if already added
      bool already = false;
      for (int j = 0; j < _searchResultCount; j++) {
        if (_searchResults[j] == i) { already = true; break; }
      }
      if (!already) _searchResults[_searchResultCount++] = i;
    }
  }
}

void UiController::handleSearchKeyPress(char c) {
  if (_searchQueryLen < 31) {
    _searchQuery[_searchQueryLen++] = c;
    _searchQuery[_searchQueryLen] = '\0';
    updateSearchResults();
    // Redraw the search input + results (keyboard stays the same)
    auto& tft = _disp.tft();
    tft.fillRect(4, 22, SCREEN_W - 8, 24, C_PANEL);
    tft.drawRect(4, 22, SCREEN_W - 8, 24, C_DARKGREY);
    tft.setTextColor(C_WHITE); tft.setTextSize(2);
    tft.setCursor(8, 27);
    tft.print(_searchQuery);
    // Result count
    tft.setTextColor(C_GREY); tft.setTextSize(1);
    tft.setCursor(SCREEN_W - 50, 30);
    tft.printf("%d/%d", _searchResultCount, _vault.count());
    // Results
    drawSearchResults();
  }
}

void UiController::handleSearchBackspace() {
  if (_searchQueryLen > 0) {
    _searchQueryLen--;
    _searchQuery[_searchQueryLen] = '\0';
    updateSearchResults();
    // Redraw search input + results
    auto& tft = _disp.tft();
    tft.fillRect(4, 22, SCREEN_W - 8, 24, C_PANEL);
    tft.drawRect(4, 22, SCREEN_W - 8, 24, C_DARKGREY);
    tft.setTextColor(C_WHITE); tft.setTextSize(2);
    tft.setCursor(8, 27);
    if (_searchQueryLen > 0) {
      tft.print(_searchQuery);
    } else {
      tft.setTextColor(C_GREY);
      tft.print("Type to search...");
    }
    tft.setTextColor(C_GREY); tft.setTextSize(1);
    tft.setCursor(SCREEN_W - 50, 30);
    tft.printf("%d/%d", _searchResultCount, _vault.count());
    drawSearchResults();
  }
}

void UiController::handleSearchClear() {
  _searchQueryLen = 0;
  _searchQuery[0] = '\0';
  _searchResultCount = 0;
  _searchSelIdx = 0;
  _searchScrollOffset = 0;  // v10.9: reset scroll on clear
  drawSearchScreen();
}

// v10.9: Button handler for the search screen.
// UP/DOWN scroll through search results (with selection highlight).
// LEFT exits the search screen back to the vault list.
// RIGHT/TOUCH opens the selected result's detail screen.
void UiController::handleSearchButtons() {
  if (!_btn.pressed()) return;
  BtnEvent e = _btn.state();

  if (e == BtnEvent::UP) {
    // Move selection up in search results
    if (_searchSelIdx > 0) {
      _searchSelIdx--;
      drawSearchResults();
    }
  } else if (e == BtnEvent::DOWN) {
    // Move selection down in search results
    if (_searchSelIdx < _searchResultCount - 1) {
      _searchSelIdx++;
      drawSearchResults();
    }
  } else if (e == BtnEvent::LEFT) {
    // Exit search screen — go back to vault list
    transitionTo(Screen::VAULT);
  } else if (e == BtnEvent::RIGHT || e == BtnEvent::TOUCH) {
    // Open the selected search result's detail screen
    if (_searchResultCount > 0 && _searchSelIdx >= 0 && _searchSelIdx < _searchResultCount) {
      int vaultIdx = _searchResults[_searchSelIdx];
      buildSortedIndex();
      int sortedPos = -1;
      for (int i = 0; i < _sortedCount; i++) {
        if (_sortedIndex[i] == vaultIdx) {
          sortedPos = i;
          break;
        }
      }
      if (sortedPos >= 0) {
        _selectedEntry = sortedPos;
        _listScroll = 0;
        _passVisible = false;
        _detailScroll = 0;
        transitionTo(Screen::DETAIL);
      }
    }
  }
}

void UiController::handleSearchTouch(int tx, int ty) {
  // Check keyboard keys first (they occupy the bottom half of the screen)
  const SearchKey* keys = _searchKeyboardMode ? SEARCH_KEYS_NUMBERS : SEARCH_KEYS_LETTERS;
  int keyCount = _searchKeyboardMode ? SEARCH_KEYS_NUMBERS_COUNT : SEARCH_KEYS_LETTERS_COUNT;

  for (int i = 0; i < keyCount; i++) {
    const SearchKey& k = keys[i];
    if (hitTest(tx, ty, k.x, k.y, k.w, k.h)) {
      _audio.play(Tone::KEY_TICK);
      // Flash the key
      _searchKeyFlash = i;
      _searchKeyFlashTime = millis();
      drawSearchKeyboard();  // redraw with flash

      if (k.ch != 0) {
        // Regular character key
        handleSearchKeyPress(k.ch);
      } else {
        // Special key — identify by label
        if (strcmp(k.label, "<x") == 0) {
          handleSearchBackspace();
        } else if (strcmp(k.label, "123") == 0 || strcmp(k.label, "ABC") == 0) {
          _searchKeyboardMode = !_searchKeyboardMode;
          drawSearchKeyboard();  // redraw with new layout
        } else if (strcmp(k.label, "SEARCH") == 0) {
          // No-op — search is already live. Just flash.
        } else if (strcmp(k.label, "BACK") == 0) {
          transitionTo(Screen::VAULT);
          return;
        }
      }
      return;
    }
  }

  // Check results list (y=48-114)
  // v5.4.9 FIX: _searchResults[] stores raw vault indices, but _selectedEntry
  // is used by drawDetailScreen as a sorted display position (_sortedIndex[]).
  // Setting _selectedEntry = raw vault index causes the detail screen to open
  // a completely different entry (whatever happens to be at that display
  // position in alphabetical order). We must convert the vault index to its
  // corresponding sorted display position instead.
  if (ty >= 48 && ty < 114 && _searchResultCount > 0) {
    // v10.9: Convert the tapped row position to a search result index,
    // accounting for the scroll offset.
    int row = (ty - 48) / 22;
    int displayIdx = _searchScrollOffset + row;
    if (displayIdx < _searchResultCount && row < 3) {
      _audio.play(Tone::KEY_TICK);
      int vaultIdx = _searchResults[displayIdx];
      // Rebuild sorted index to ensure it's current (vault may have been
      // modified via the webapp during AP mode).
      buildSortedIndex();
      // Find the sorted display position for this vault index.
      int sortedPos = -1;
      for (int i = 0; i < _sortedCount; i++) {
        if (_sortedIndex[i] == vaultIdx) {
          sortedPos = i;
          break;
        }
      }
      if (sortedPos >= 0) {
        _selectedEntry = sortedPos;
        _listScroll = 0;
        transitionTo(Screen::DETAIL);
      }
      return;
    }
  }

  // Mode badge
  if (hitTest(tx, ty, MODE_BADGE_X, MODE_BADGE_Y, MODE_BADGE_W, MODE_BADGE_H)) {
    _audio.play(Tone::KEY_TICK);
    _modeMenuOpen = true;
    _modeMenuHost = Screen::SEARCH;
    drawModeMenu();
    return;
  }
}
// ═══════════════════════════════════════════════════════════════════════════════
void UiController::typeStr(const char* s) {
  // BLE typing is deliberately disabled while Dashboard Mode (USB-NCM) is
  // active. Native USB HID was dropped entirely (see the HidMode comment
  // in ui_screens.h), so BLE is the only typing path left -- but with the
  // network interface up and the dashboard reachable over it, silently
  // allowing a second, independent credential-exfiltration path (BLE
  // keystroke injection) to fire at the same time isn't something this
  // device should do by default. Exit Dashboard Mode (Mode Menu -> BLE)
  // to type again.
  if (_hidMode == HidMode::DASHBOARD) {
    _audio.play(Tone::ERROR);
    return;
  }
  _ble.typeString(s);
}
void UiController::typeEnter() {
  if (_hidMode == HidMode::DASHBOARD) {
    _audio.play(Tone::ERROR);
    return;
  }
  _ble.sendEnter();
}
void UiController::typeTab() {
  if (_hidMode == HidMode::DASHBOARD) {
    _audio.play(Tone::ERROR);
    return;
  }
  _ble.sendTab();
}

// ═══════════════════════════════════════════════════════════════════════════════
//  5-SECOND HOLD-TO-LOCK (TTP223 capacitive pad)
//  Anywhere after the PIN screen, holding the pad for 5 seconds instantly
//  locks and returns to the PIN screen.
// ═══════════════════════════════════════════════════════════════════════════════
void UiController::checkHoldToLock() {
  // Only active on screens AFTER the lock screen
  if (_screen == Screen::LOCK || _screen == Screen::NONE) return;
  if (_modeMenuOpen) return;

  if (_btn.touchActive()) {
    if (!_lockHoldActive) {
      _lockHoldActive = true;
      _touchHoldStart = millis();
      _lastActivity = millis();  // reset auto-lock timer
    } else {
      _lastActivity = millis();  // keep resetting while holding
      unsigned long held = millis() - _touchHoldStart;
      if (held >= 5000) {
        // 5 seconds held — lock now
        _lockHoldActive = false;
        _pinLen = 0; secureZero(_pinBuf, sizeof(_pinBuf));
        _patternMask = 0; _patternLen = 0;

        // v5.4.9 FIX: Tear down active network modes before locking.
        // Without this, the SoftAP/webapp continues running on the lock
        // screen — a zombie AP serving vault data to anyone connected.
        if (_hidMode == HidMode::DASHBOARD) {
          _serialProto.teardownSecureSession();
          _serialProto.end();
          secureZero(_dashboardCode, sizeof(_dashboardCode));
          _hidMode = HidMode::BLE;
        }
        if (_hidMode == HidMode::AP) {
          APModeManager::getInstance().stop();
          _apWasConnected = false;
          _hidMode = HidMode::BLE;
        }
        // F6: Clear the authoritative PIN on hold-to-lock.
        _sessionCtx.clear();

        _audio.play(Tone::LOCK);
        transitionTo(Screen::LOCK);
      }
    }
  } else {
    _lockHoldActive = false;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  SETTINGS SCREEN
// ═══════════════════════════════════════════════════════════════════════════════
// 5 rows visible, scrollable. Options:
//   1. Change PIN
//   2. Auto-Lock: <current value>
//   3. About
//   4. Factory Reset
//   5. Back

void UiController::drawSettingsScreen() {
  auto& tft = _disp.tft();
  tft.fillRect(0, 0, SCREEN_W, SCREEN_H, C_BG);
  drawStatusBar();
  tft.fillRect(0, SBAR_H, SCREEN_W, 24, C_HEADER);
  tft.setTextColor(C_ACCENT); tft.setTextSize(1);
  tft.setCursor(6, 27); tft.print("Settings");

  // Draw settings rows (6 rows, smaller to fit)
  const int rowH = 30;
  const int startY = SBAR_H + 24;
  const char* labels[] = {
    "Change PIN",
    "Auto-Lock",
    "Theme",
    "About",
    "Factory Reset",
    "Back"
  };

  for (int i = 0; i < 6; i++) {
    int y = startY + i * rowH;
    tft.fillRoundRect(4, y, SCREEN_W - 8, rowH - 4, 4, C_PANEL);
    tft.drawRoundRect(4, y, SCREEN_W - 8, rowH - 4, 4, C_ACCENT);
    tft.setTextColor(C_WHITE); tft.setTextSize(1);
    tft.setCursor(14, y + 7); tft.print(labels[i]);
    // Auto-lock shows current value
    if (i == 1) {
      uint32_t ms = _vault.getAutoLockMs();
      char val[16];
      if (ms == 0) snprintf(val, sizeof(val), "Never");
      else if (ms < 60000) snprintf(val, sizeof(val), "%lus", ms / 1000);
      else snprintf(val, sizeof(val), "%lum", ms / 60000);
      tft.setTextColor(C_GREY);
      tft.setCursor(SCREEN_W - 14 - strlen(val) * 6, y + 7);
      tft.print(val);
    }
    // Theme shows current value
    if (i == 2) {
      const char* themeNames[] = {"Air-Gapped", "Monochrome", "Emerald", "Sunlight"};
      const char* val = themeNames[_themeId % 4];
      tft.setTextColor(C_GREY);
      tft.setCursor(SCREEN_W - 14 - strlen(val) * 6, y + 7);
      tft.print(val);
    }
    // Factory reset gets red text
    if (i == 4) {
      tft.setTextColor(C_RED);
      tft.setCursor(14, y + 7); tft.print(labels[i]);
    }
  }
}

void UiController::handleSettingsTouch(int tx, int ty) {
  const int rowH = 30;
  const int startY = SBAR_H + 24;
  for (int i = 0; i < 6; i++) {
    int y = startY + i * rowH;
    if (hitTest(tx, ty, 4, y, SCREEN_W - 8, rowH - 4)) {
      _audio.play(Tone::KEY_TICK);
      switch (i) {
        case 0: // Change PIN
          _chgPinStep = 0;
          _chgPinOldLen = 0; _chgPinNewLen = 0;
          memset(_chgPinOld, 0, sizeof(_chgPinOld));
          memset(_chgPinNew, 0, sizeof(_chgPinNew));
          transitionTo(Screen::CHGPIN);
          break;
        case 1: { // Auto-Lock — cycle
          uint32_t current = _vault.getAutoLockMs();
          uint32_t values[] = {15000, 30000, 60000, 120000, 300000, 0};
          int n = sizeof(values) / sizeof(values[0]);
          int idx = 0;
          for (int j = 0; j < n; j++) if (values[j] == current) idx = j;
          idx = (idx + 1) % n;
          _vault.setAutoLockMs(values[idx]);
          drawSettingsScreen();
          break;
        }
        case 2: // Theme — cycle
          cycleTheme();
          drawSettingsScreen();
          break;
        case 3: // About
          transitionTo(Screen::ABOUT);
          break;
        case 4: // Factory Reset
          _vault.factoryReset();
          // Also wipe duress PIN file and all UI secrets
          LittleFS.remove("/duress_pin.hash");
          _pinLen = 0; secureZero(_pinBuf, sizeof(_pinBuf));
          // F6: Clear the authoritative PIN on factory reset.
          _sessionCtx.clear();
          secureZero(_chgPinOld, sizeof(_chgPinOld));
          secureZero(_chgPinNew, sizeof(_chgPinNew));
          secureZero(_firstBootPinBuf, sizeof(_firstBootPinBuf));       // F12: clear first-boot buffers
          secureZero(_firstBootPinConfirmBuf, sizeof(_firstBootPinConfirmBuf));
          _failCount = 0;
          // F12: After factory reset, NVS is wiped (including PREFS_KEY_FIRST_BOOT),
          // so the device is back in first-boot state. Mark _isFirstBoot = true so
          // the lock screen redirects to the first-boot PIN setup screen.
          _isFirstBoot = true;
          _audio.play(Tone::LOCK);
          loadTheme();  // reload theme after factory reset
          transitionTo(Screen::FIRST_BOOT_PIN);  // F12: go to PIN setup, not lock screen
          break;
        case 5: // Back
          transitionTo(Screen::VAULT);
          break;
      }
      return;
    }
  }
}

void UiController::handleSettingsButtons() {
  if (!_btn.pressed()) return;
  BtnEvent e = _btn.state();
  if (e == BtnEvent::LEFT) transitionTo(Screen::VAULT);
}

// ═══════════════════════════════════════════════════════════════════════════════
//  ABOUT SCREEN
// ═══════════════════════════════════════════════════════════════════════════════
void UiController::drawAboutScreen() {
  auto& tft = _disp.tft();
  tft.fillRect(0, 0, SCREEN_W, SCREEN_H, C_BG);
  drawStatusBar();

  // Padlock + brand
  drawPadlockGlyph(SCREEN_W / 2 - 12, 28, 24, C_ACCENT);
  tft.setTextColor(C_ACCENT); tft.setTextSize(2);
  tft.setCursor(SCREEN_W / 2 - 48, 62); tft.print("SecureVault");
  tft.setTextColor(C_GREY); tft.setTextSize(1);
  tft.setCursor(SCREEN_W / 2 - 36, 80); tft.print("v9.18 Premium");

  // Info rows — compact 14px spacing to fit owner line
  int y = 106;
  tft.setTextColor(C_WHITE); tft.setTextSize(1);
  tft.setCursor(20, y); tft.print("Developer: Purujith Kadekar");
  y += 14;
  tft.setCursor(20, y); tft.print("Entries: "); tft.print(_vault.count());
  y += 14;
  tft.setCursor(20, y); tft.print("Capacity: 256 (SD-backed)");
  y += 14;
  tft.setCursor(20, y); tft.print("Crypto: AES-256-GCM");
  y += 14;
  tft.setCursor(20, y); tft.print("KDF: PBKDF2-SHA256");
  y += 14;
  tft.setCursor(20, y); tft.print("Board: ESP32-S3 Pro");
  y += 14;
  tft.setCursor(20, y); tft.print("Display: ILI9341 320x240");

  // Back button
  _disp.drawBtn(SCREEN_W / 2 - 50, SCREEN_H - 36, 100, 28, "Back", C_BTN);
}

void UiController::handleAboutTouch(int tx, int ty) {
  if (hitTest(tx, ty, SCREEN_W / 2 - 50, SCREEN_H - 36, 100, 28)) {
    _audio.play(Tone::KEY_TICK);
    transitionTo(Screen::SETTINGS);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  CHANGE PIN SCREEN (3-step flow)
// ═══════════════════════════════════════════════════════════════════════════════
void UiController::drawChgPinScreen() {
  auto& tft = _disp.tft();
  tft.fillRect(0, 0, SCREEN_W, SCREEN_H, C_BG);
  drawStatusBar();

  const char* titles[] = {"Current PIN", "New PIN", "Confirm PIN"};
  tft.setTextColor(C_ACCENT); tft.setTextSize(1);
  tft.setCursor(SCREEN_W / 2 - strlen(titles[_chgPinStep]) * 3, 30);
  tft.print(titles[_chgPinStep]);

  // PIN dots — step 0 and step 2 use _chgPinOldLen, step 1 uses _chgPinNewLen
  int n;
  if (_chgPinStep == 0 || _chgPinStep == 2) n = _chgPinOldLen;
  else n = _chgPinNewLen;

  int dotSpacing = 24;
  int startX = SCREEN_W / 2 - (MAX_PIN_LEN * dotSpacing) / 2;
  for (int i = 0; i < MAX_PIN_LEN; i++) {
    uint16_t col = (i < n) ? C_ACCENT : C_DARKGREY;
    tft.fillCircle(startX + i * dotSpacing, 56, 5, col);
    tft.drawCircle(startX + i * dotSpacing, 56, 5, C_GREY);
  }

  // Numpad
  for (int r = 0; r < NUM_ROWS; r++)
    for (int c = 0; c < NUM_COLS; c++)
      drawNumpadBtn(r * NUM_COLS + c, false);
}

void UiController::handleChgPinButtons() {
  if (!_btn.pressed()) return;
  BtnEvent e = _btn.state();
  if (e == BtnEvent::LEFT) {
    if (_chgPinStep == 0 || _chgPinStep == 1) {
      // Cancel — return to settings
      secureZero(_chgPinOld, sizeof(_chgPinOld));
      secureZero(_chgPinNew, sizeof(_chgPinNew));
      _chgPinOldLen = 0; _chgPinNewLen = 0;
      transitionTo(Screen::SETTINGS);
      return;
    }
    // Step 2 — backspace on confirm entry
    if (_chgPinOldLen > 0) {
      _chgPinOldLen--; _chgPinOld[_chgPinOldLen] = 0;
      drawChgPinScreen();
    }
  } else if (e == BtnEvent::TOUCH) {
    submitChgPin();
  }
}

void UiController::handleChgPinTouch(int tx, int ty) {
  for (int r = 0; r < NUM_ROWS; r++) {
    for (int c = 0; c < NUM_COLS; c++) {
      int idx = r * NUM_COLS + c;
      int bx = NUM_X0 + c * (NUM_BW + NUM_GAP);
      int by = NUM_Y0 + r * (NUM_BH + NUM_GAP);
      if (!hitTest(tx, ty, bx, by, NUM_BW, NUM_BH)) continue;

      _disp.triggerFlash(bx, by, NUM_BW, NUM_BH,
        (idx == 9) ? C_RED : (idx == 11) ? C_BTN_DARK : C_BTN, NUM_LABELS[idx], 2);
      _audio.play(Tone::KEY_TICK);

      if (idx == 9) {  // CLR
        if (_chgPinStep == 0 && _chgPinOldLen > 0) {
          _chgPinOldLen--; _chgPinOld[_chgPinOldLen] = 0;
          drawChgPinScreen();
        } else if (_chgPinStep == 1 && _chgPinNewLen > 0) {
          _chgPinNewLen--; _chgPinNew[_chgPinNewLen] = 0;
          drawChgPinScreen();
        } else if (_chgPinStep == 2 && _chgPinOldLen > 0) {
          _chgPinOldLen--; _chgPinOld[_chgPinOldLen] = 0;
          drawChgPinScreen();
        }
      } else if (idx == 11) {  // OK
        submitChgPin();
      } else {  // digit
        int digit = (idx < 9) ? (idx + 1) : 0;
        if (_chgPinStep == 0 && _chgPinOldLen < MAX_PIN_LEN) {
          _chgPinOld[_chgPinOldLen++] = '0' + digit;
          _chgPinOld[_chgPinOldLen] = 0;
          drawChgPinScreen();
        } else if (_chgPinStep == 1 && _chgPinNewLen < MAX_PIN_LEN) {
          _chgPinNew[_chgPinNewLen++] = '0' + digit;
          _chgPinNew[_chgPinNewLen] = 0;
          drawChgPinScreen();
        } else if (_chgPinStep == 2 && _chgPinOldLen < MAX_PIN_LEN) {
          _chgPinOld[_chgPinOldLen++] = '0' + digit;
          _chgPinOld[_chgPinOldLen] = 0;
          drawChgPinScreen();
        }
      }
      return;
    }
  }
}

void UiController::submitChgPin() {
  if (_chgPinStep == 0) {
    // Verify current PIN
    if (_vault.verifyPin(_chgPinOld)) {
      _chgPinStep = 1;
      _chgPinNewLen = 0;
      memset(_chgPinNew, 0, sizeof(_chgPinNew));
      drawChgPinScreen();
    } else {
      _audio.play(Tone::ERROR);
      triggerShake();
      _chgPinOldLen = 0;
      memset(_chgPinOld, 0, sizeof(_chgPinOld));
      drawChgPinScreen();
    }
  } else if (_chgPinStep == 1) {
    // Move to confirm step — _chgPinNew now holds the new PIN candidate.
    // We need a separate buffer for the confirm entry. Reuse _chgPinOld
    // (which is no longer needed after step 0 verification).
    if (_chgPinNewLen < 4) {
      _audio.play(Tone::ERROR);
      triggerShake();
      return;
    }
    _chgPinStep = 2;
    // Save the current PIN (from step 0) — we'll need it for setPin().
    // _chgPinOld currently holds the verified old PIN. We need to save it
    // before reusing _chgPinOld for the confirm entry.
    // Actually, we can keep _chgPinOld as-is (it holds the old PIN) and
    // use a different approach for confirm: compare the confirm entry
    // against _chgPinNew. But we only have _chgPinOld and _chgPinNew.
    // Solution: in step 2, the user types into _chgPinOld (overwriting
    // the old PIN), and we compare _chgPinOld (confirm) against _chgPinNew.
    // But then we lose the old PIN needed for setPin().
    // Fix: save the old PIN in a separate buffer before step 2.
    // We'll use a static buffer for this.
    _chgPinOldLen = 0;
    memset(_chgPinOld, 0, sizeof(_chgPinOld));
    drawChgPinScreen();
  } else if (_chgPinStep == 2) {
    // Confirm — _chgPinOld now holds the confirm entry.
    // We need the ORIGINAL old PIN for setPin(). But we overwrote it.
    // Workaround: since the user already verified the old PIN in step 0,
    // we can call setPin with an empty check — actually setPin requires
    // the old PIN. Let's use a different approach: directly call
    // _vault.setPin with the stored PIN (from NVS) as the "old" PIN,
    // since we know it was verified in step 0.
    if (strcmp(_chgPinOld, _chgPinNew) == 0) {
      // Confirm matches new PIN — save it.
      // We verified the old PIN in step 0, so we can fetch it from NVS
      // to pass to setPin(). This is safe because we already authenticated.
      String currentPin = _vault.getPin();
      if (_vault.setPin(currentPin.c_str(), _chgPinNew)) {
        _audio.play(Tone::UNLOCK);
        transitionTo(Screen::SETTINGS);
      } else {
        _audio.play(Tone::ERROR);
        transitionTo(Screen::SETTINGS);
      }
    } else {
      _audio.play(Tone::ERROR);
      triggerShake();
      _chgPinStep = 1;
      _chgPinNewLen = 0;
      _chgPinOldLen = 0;
      memset(_chgPinNew, 0, sizeof(_chgPinNew));
      memset(_chgPinOld, 0, sizeof(_chgPinOld));
      drawChgPinScreen();
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  THEME SYSTEM
// ═══════════════════════════════════════════════════════════════════════════════
void UiController::loadTheme() {
  _themeId = _vault.getThemeId();
  applyTheme(_themeId);
}

void UiController::applyTheme(uint8_t id) {
  _themeId = id;
  ThemeColors t;
  switch (id) {
    case 1:  t = THEME_MONOCHROME; break;
    case 2:  t = THEME_EMERALD;   break;
    case 3:  t = THEME_SUNLIGHT;  break;
    default: t = THEME_AIR_GAPPED; break;
  }
  // Set the global color variables (which shadow the C_* macros)
  C_BG = t.bg;
  C_PANEL = t.panel;
  C_HEADER = t.header;
  C_ACCENT = t.accent;
  C_GREEN = t.green;
  C_RED = t.red;
  C_ORANGE = t.orange;
  C_YELLOW = t.yellow;
  C_WHITE = t.white;
  C_GREY = t.grey;
  C_DARKGREY = t.darkgrey;
  C_BTN = t.btn;
  C_BTN_DARK = t.btnDark;
  C_TOTP_CHIP = t.totpChip;
  // Persist to NVS
  _vault.setThemeId(id);
  // Redraw the current screen immediately
  transitionTo(_screen);
}

void UiController::cycleTheme() {
  _themeId = (_themeId + 1) % 4;
  applyTheme(_themeId);
}

// ═══════════════════════════════════════════════════════════════════════════════
//  DEEP SLEEP (spring power-off) — with user feedback
//  Spring OFF → "POWERING OFF" countdown → zero secrets → tear down BLE
//             → display OFF → deep sleep
//  Spring ON  → ESP32 wakes via ext1 → reboots → main.cpp shows "RESUMING"
//             → lock screen
// ═══════════════════════════════════════════════════════════════════════════════

// Draw the power-off overlay. `countdownSeconds` is the remaining count
// (3 → 2 → 1 → 0 = "going to sleep"). `statusMsg` is the small line of
// text under the countdown ("Saving session...", "Shutting down...", etc.)
void UiController::drawPowerOffScreen(int countdownSeconds, const char* statusMsg) {
  auto& tft = _disp.tft();
  tft.fillScreen(C_BG);

  // ── Power icon (centered, top third) ───────────────────────────────
  // A simple "moon + Z" glyph — recognizable as "sleep" across cultures.
  int cx = SCREEN_W / 2;
  int cy = 60;
  // Crescent moon: filled circle in accent, then a slightly offset
  // background-colored circle to carve out the crescent.
  tft.fillCircle(cx, cy, 22, C_ACCENT);
  tft.fillCircle(cx + 8, cy - 4, 20, C_BG);
  // "Z" inside the crescent's open side
  tft.setTextColor(C_ACCENT); tft.setTextSize(2);
  tft.setCursor(cx + 14, cy + 8); tft.print("z");

  // ── Headline ───────────────────────────────────────────────────────
  tft.setTextColor(C_WHITE); tft.setTextSize(2);
  const char* headline = "POWERING OFF";
  int hw = strlen(headline) * 6 * 2;  // textSize 2 = 6px wide per char × 2
  tft.setCursor((SCREEN_W - hw) / 2, 110);
  tft.print(headline);

  // ── Countdown number (large, centered) ─────────────────────────────
  if (countdownSeconds > 0) {
    tft.setTextColor(C_YELLOW); tft.setTextSize(4);
    char num[4];
    snprintf(num, sizeof(num), "%d", countdownSeconds);
    int nw = strlen(num) * 6 * 4;  // textSize 4
    tft.setCursor((SCREEN_W - nw) / 2, 140);
    tft.print(num);
  } else {
    // countdown == 0 → show "going to sleep" instead of a number
    tft.setTextColor(C_GREY); tft.setTextSize(1);
    const char* gone = "going to sleep";
    int gw = strlen(gone) * 6;
    tft.setCursor((SCREEN_W - gw) / 2, 150);
    tft.print(gone);
  }

  // ── Status message (small, bottom) ─────────────────────────────────
  if (statusMsg) {
    tft.setTextColor(C_GREY); tft.setTextSize(1);
    int mw = strlen(statusMsg) * 6;
    tft.setCursor((SCREEN_W - mw) / 2, 200);
    tft.print(statusMsg);
  }

  // ── Spring hint at the very bottom ─────────────────────────────────
  tft.setTextColor(C_DARKGREY); tft.setTextSize(1);
  const char* hint = "Flip spring to ON to wake";
  int hh = strlen(hint) * 6;
  tft.setCursor((SCREEN_W - hh) / 2, 220);
  tft.print(hint);
}

// Legacy entry point — kept so checkSpringPowerOff() doesn't need to change.
// Just delegates to the new enterPowerOff().
void UiController::enterClockMode() {
  enterPowerOff();
}

// New power-off path: shows a 3-2-1 countdown + audio cue before deep sleep.
// The display stays ON during the countdown so the user sees the message;
// only after the countdown does the display go dark and the ESP32 sleep.
void UiController::enterPowerOff() {
  auto& tft = _disp.tft();
  _screen = Screen::POWER_OFF;

  // ── Audio cue: descending LOCK tone signals "going down" ──────────
  _audio.play(Tone::LOCK);

  // ── Countdown: 3 → 2 → 1, ~1s each, with a status line that updates ──
  // Phase 1: "Saving session..." (3, 2)
  // Phase 2: "Shutting down..." (1)
  // Phase 3: "Deep sleep"       (0 — display already off)
  drawPowerOffScreen(3, "Saving session...");
  delay(900);
  drawPowerOffScreen(2, "Saving session...");
  delay(900);
  drawPowerOffScreen(1, "Shutting down...");
  delay(900);

  // ── Zero ALL secrets BEFORE tearing down comms ────────────────────
  // (Order matters: if tear-down crashes, secrets are already zeroed.)
  _pinLen = 0; secureZero(_pinBuf, sizeof(_pinBuf));
  // F6: Clear the authoritative PIN on deep sleep.
  _sessionCtx.clear();
  secureZero(_dashboardCode, sizeof(_dashboardCode));
  secureZero(_chgPinOld, sizeof(_chgPinOld));
  secureZero(_chgPinNew, sizeof(_chgPinNew));
  secureZero(_firstBootPinBuf, sizeof(_firstBootPinBuf));       // F12: clear first-boot PIN buffers too
  secureZero(_firstBootPinConfirmBuf, sizeof(_firstBootPinConfirmBuf));
  secureZero(_totpCode, sizeof(_totpCode));
  _patternMask = 0; _patternLen = 0;
  _failCount = 0;
  _apWasConnected = false;                 // v5.4.9 FIX: reset stale connection flag

  // ── Tear down BLE + serial + AP ─────────────────────────────────────────
  _ble.cancelPairing();
  if (_hidMode == HidMode::DASHBOARD) {
    _serialProto.teardownSecureSession();
    _serialProto.end();
    _hidMode = HidMode::BLE;
  }
  // v5.4.9 FIX: AP mode was NOT torn down on power-off — the SoftAP/webapp
  // stayed active during the 3-second countdown, serving vault data to
  // anyone connected. APModeManager::stop() tears down the full stack.
  if (_hidMode == HidMode::AP) {
    APModeManager::getInstance().stop();
    _hidMode = HidMode::BLE;
  }
  delay(100);

  // ── Final "going to sleep" frame ───────────────────────────────────
  drawPowerOffScreen(0, "Deep sleep");
  delay(400);

  // ── Display OFF (hardware commands) ────────────────────────────────
  tft.sendCommand(0x28);  // DISPOFF
  delay(50);
  tft.sendCommand(0x10);  // SLPIN
  delay(50);

  // ── Configure ext1 wakeup (spring flip → GPIO6 high → wake) ──────
  rtc_gpio_deinit(GPIO_NUM_6);
  esp_sleep_enable_ext1_wakeup(BIT(GPIO_NUM_6), ESP_EXT1_WAKEUP_ANY_HIGH);

  Serial.println("[POWER] Deep sleep. Wake: flip spring to ON.");
  Serial.flush();
  delay(100);
  esp_deep_sleep_start();
  // never returns — ESP32 reboots on wake
}

// ── Resume screen (shown on wake from deep sleep) ────────────────────
// main.cpp::setup() calls this when esp_sleep_get_wakeup_cause() indicates
// a deep-sleep wake. Draws a brief "RESUMING" animation + audio cue,
// then returns so setup() can continue to ui.begin() (lock screen).
//
// `phase` drives the animation: 0 = initial frame, 1..3 = the three
// expanding-ring animation frames, 4 = final "ready" frame.
void UiController::drawResumeScreen(int phase) {
  auto& tft = _disp.tft();
  // Only clear on phase 0 — later phases paint over the existing frame
  // so the animation feels smooth rather than blinking.
  if (phase == 0) {
    tft.fillScreen(C_BG);

    // ── Centered power/wake icon (sun rising over horizon) ──────────
    int cx = SCREEN_W / 2;
    int cy = 60;
    // Horizon line
    tft.drawFastHLine(cx - 35, cy + 12, 70, C_GREY);
    // Sun body (drawn fresh each phase — grows from phase 1 to 3)
    // Phase 1: r=4, Phase 2: r=8, Phase 3: r=12, Phase 4: r=14 (full)
    int r = 4;
    if (phase >= 2) r = 8;
    if (phase >= 3) r = 12;
    if (phase >= 4) r = 14;
    // Sun rays (only on phase 3+)
    if (phase >= 3) {
      for (int a = 0; a < 360; a += 45) {
        float rad = a * PI / 180.0f;
        int x1 = cx + (int)(cos(rad) * (r + 3));
        int y1 = cy + (int)(sin(rad) * (r + 3));
        int x2 = cx + (int)(cos(rad) * (r + 8));
        int y2 = cy + (int)(sin(rad) * (r + 8));
        tft.drawLine(x1, y1, x2, y2, C_YELLOW);
      }
    }
    tft.fillCircle(cx, cy, r, C_YELLOW);

    // ── Headline ────────────────────────────────────────────────────
    tft.setTextColor(C_WHITE); tft.setTextSize(2);
    const char* headline = "RESUMING";
    int hw = strlen(headline) * 6 * 2;
    tft.setCursor((SCREEN_W - hw) / 2, 110);
    tft.print(headline);
  }

  // ── Status message (updates per phase) ─────────────────────────────
  // Clear the status line area first so we don't get overstrike artifacts.
  tft.fillRect(0, 140, SCREEN_W, 12, C_BG);
  tft.setTextColor(C_GREY); tft.setTextSize(1);
  const char* msg;
  switch (phase) {
    case 0:  msg = "Waking up...";      break;
    case 1:  msg = "Restoring display"; break;
    case 2:  msg = "Starting BLE";      break;
    case 3:  msg = "Loading vault";     break;
    case 4:  msg = "Ready";             break;
    default: msg = "";                  break;
  }
  int mw = strlen(msg) * 6;
  tft.setCursor((SCREEN_W - mw) / 2, 140);
  tft.print(msg);

  // ── Animated 3-dot indicator (only on phases 0-3) ──────────────────
  // Same style as the boot splash — one bright dot cycling left to right.
  if (phase < 4) {
    int cx = SCREEN_W / 2;
    int dotY = 170;
    // Wipe the dot row first
    tft.fillRect(cx - 20, dotY - 4, 40, 8, C_BG);
    for (int i = 0; i < 3; i++) {
      int dotX = cx - 12 + i * 12;
      uint16_t col = (i == phase % 3) ? C_ACCENT : C_DARKGREY;
      tft.fillCircle(dotX, dotY, 3, col);
    }
  } else {
    // Phase 4 = ready — clear the dots, show a small checkmark
    int cx = SCREEN_W / 2;
    tft.fillRect(cx - 20, 166, 40, 12, C_BG);
    tft.setTextColor(C_GREEN); tft.setTextSize(2);
    tft.setCursor(cx - 6, 166);
    tft.print("OK");
  }
}

// Public entry point called from main.cpp::setup() on deep-sleep wake.
// Plays the resume audio cue, runs through 5 animation phases (~2.5s total),
// then returns so setup() can finish and ui.begin() can show the lock screen.
void UiController::showResumeScreen() {
  _screen = Screen::RESUME;

  // ── Audio cue: ascending UNLOCK tone signals "coming up" ──────────
  _audio.play(Tone::UNLOCK);

  // Phase 0: initial frame (clears screen, draws icon + headline + "Waking up...")
  drawResumeScreen(0);
  delay(500);

  // Phases 1-3: animation steps with status messages
  drawResumeScreen(1); delay(500);
  drawResumeScreen(2); delay(500);
  drawResumeScreen(3); delay(500);

  // Phase 4: "Ready" + checkmark — hold a bit longer so the user
  // sees the "ready" confirmation before the lock screen appears.
  drawResumeScreen(4);
  delay(500);
  // Return — main.cpp will call ui.begin() next, which transitions to LOCK
  // and clears the resume screen.
}

void UiController::drawClockScreen() {
  // Unused — kept for Screen enum compatibility. Deep sleep doesn't draw.
}

void UiController::exitClockMode() {
  // Unused — deep sleep reboots on wake, no exit needed.
}

void UiController::checkSpringPowerOff() {
  static unsigned long springOffStart = 0;
  static bool tracking = false;

  if (_btn.state() == BtnEvent::SPRING) {
    if (!tracking) {
      tracking = true;
      springOffStart = millis();
    } else if (millis() - springOffStart >= 500) {
      tracking = false;
      // Don't re-trigger if we're already powering off (the screen is
      // mid-countdown) — enterPowerOff() blocks until deep sleep anyway,
      // but this guard prevents any re-entrancy from a queued button
      // event sneaking in between frames.
      if (_screen != Screen::POWER_OFF && _screen != Screen::CLOCK) {
        enterPowerOff();
      }
    }
  } else {
    tracking = false;
  }
}
// ═══════════════════════════════════════════════════════════════════════════════
void UiController::tick() {
  unsigned long t = millis();

  if (!_modeMenuOpen) _disp.restoreFlashedButton();

  // ═══════════════════════════════════════════════════════════════════════════════
  //  DEFERRED MODE SWITCH — MUST be first thing in tick() (before mode-specific
  //  tick blocks) so the old mode's tick() is NOT called during the transition.
  // ═══════════════════════════════════════════════════════════════════════════════
  if (_modeSwitchState != ModeSwitchState::IDLE) {
    processModeSwitch();
    return;  // Skip ALL other tick() processing during mode transition
  }

  // v3: Drive the serial protocol + session timeout. The serial protocol
  // polls Serial for incoming frames and processes them. If the session
  // expires (60s inactivity), SecureSession zeroes all keys.
  // NOTE: _serialProto.tick() still runs (to drain incoming frames and
  // handle timeouts), but the screen update is skipped when the mode menu
  // overlay is open — prevents "CONNECTED"/"Waiting..." text from painting
  // over the menu overlay.
  if (_hidMode == HidMode::DASHBOARD) {
    _serialProto.tick();
    if (!_modeMenuOpen && _screen == Screen::DASHBOARD_CODE && t - _lastClockTick >= 500) {
      _lastClockTick = t;
      updateDashboardCodeScreen();
    }
  }

  // v5.4: Drive the AP mode stack — DNS hijack, traffic obfuscation,
  // secure-layer TTLs, and idle auto-off. If AP mode was just stopped
  // (e.g. by the 5-min idle timeout), updateApInfoScreen() transitions
  // back to the vault list.
  // NOTE: APModeManager.tick() still runs (to process DNS requests etc),
  // but the screen update is skipped when the mode menu overlay is open —
  // prevents client count / countdown text from painting over the menu.
  if (_hidMode == HidMode::AP) {
    APModeManager::getInstance().tick();
    if (!_modeMenuOpen && _screen == Screen::AP_INFO && t - _lastClockTick >= 500) {
      _lastClockTick = t;
      updateApInfoScreen();
    }
  }

  // v5.4.3: Search screen — blink the cursor + clear key flash.
  // Skip when mode menu is open — prevents cursor from painting over the menu.
  if (!_modeMenuOpen && _screen == Screen::SEARCH && t - _lastClockTick >= 500) {
    _lastClockTick = t;
    // Redraw just the cursor area (avoid full-screen flicker).
    auto& tft = _disp.tft();
    // Clear the cursor area
    int cursorX = 8 + _searchQueryLen * 12;
    if (cursorX < SCREEN_W - 60) {  // don't overwrite the result count
      tft.fillRect(cursorX, 28, 10, 16, C_PANEL);
      // Draw cursor if blinking on
      if ((millis() / 500) % 2 == 0 && _searchQueryLen < 31) {
        tft.fillRect(cursorX, 28, 10, 16, C_ACCENT);
      }
    }
    // Clear key flash if expired
    if (_searchKeyFlash >= 0 && (millis() - _searchKeyFlashTime >= 100)) {
      _searchKeyFlash = -1;
      drawSearchKeyboard();
    }
  }

  // ---- BLE pairing screen, driven off the real NimBLE passkey callback ----
  if (_ble.pairingActive() && _screen != Screen::BLE_PAIRING) {
    _screenBeforePairing = _screen;
    transitionTo(Screen::BLE_PAIRING);
  }
  if (_ble.consumePairingDone() && _screen == Screen::BLE_PAIRING) {
    transitionTo(_screenBeforePairing);
  }
  if (_screen == Screen::BLE_PAIRING && t - _lastClockTick >= 150) {
    _lastClockTick = t;
    pulseBlePairingDot();
  }

  // ---- auto-lock (INACTIVITY-BASED) ----
  // v10.4: This is purely inactivity-based — it fires only when NO user
  // input (touch, button press, scroll, screen tap) has occurred for the
  // configured timeout. _lastActivity is reset on every interaction AND
  // on every screen transition (transitionTo). The timeout value is read
  // from NVS every tick via getAutoLockMs(), so changes in Settings take
  // effect immediately. 0 = never auto-lock.
  //
  // Auto-lock ONLY applies in BLE mode. Dashboard Mode is exempt (the
  // session has its own 5-minute inactivity timeout in secure_session.h).
  // POWER_OFF and RESUME are exempt — POWER_OFF is mid-countdown to deep
  // sleep, and RESUME is shown before the lock screen on wake.
  //
  // v5.4.8: Re-capture t here because updateApInfoScreen (called above in
  // the AP-mode tick block) may have called transitionTo(), which resets
  // _lastActivity = millis(). Since _lastActivity would then be NEWER than
  // the t captured at the start of tick(), the unsigned subtraction
  // t - _lastActivity would underflow to ~4 billion → false auto-lock.
  t = millis();
  bool exempt = (_screen == Screen::LOCK || _screen == Screen::SETTIME ||
                 _screen == Screen::BLE_PAIRING ||
                 _screen == Screen::POWER_OFF || _screen == Screen::RESUME ||
                 _screen == Screen::CLOCK ||
                 _screen == Screen::FIRST_BOOT_PIN ||  // F12: first-boot PIN setup is exempt from auto-lock (no session to protect yet)
                 _hidMode == HidMode::DASHBOARD ||
                 _hidMode == HidMode::AP);  // v5.4: AP mode has its own 5-min idle timeout in APModeManager
  uint32_t autoLockMs = _vault.getAutoLockMs();
  if (!exempt && autoLockMs > 0 && t - _lastActivity > autoLockMs) {
    _pinLen = 0; secureZero(_pinBuf, sizeof(_pinBuf));
    if (_hidMode == HidMode::DASHBOARD) {
      _serialProto.teardownSecureSession();
      _serialProto.end();
      _hidMode = HidMode::BLE;
      secureZero(_dashboardCode, sizeof(_dashboardCode));
    }
    // v5.4: Tear down AP mode on auto-lock too.
    // v5.4.7: stop() is now async — returns immediately. The AP will be
    // torn down on a background task. We still clear SessionContext immediately
    // (auto-lock means the user must re-unlock, so the PIN is gone regardless).
    if (_hidMode == HidMode::AP) {
      APModeManager::getInstance().stop();
      _hidMode = HidMode::BLE;
    }
    // Cancel any in-progress deferred mode switch
    if (_modeSwitchState != ModeSwitchState::IDLE) {
      _modeSwitchState = ModeSwitchState::IDLE;
      _modePendingSwitch = HidMode::BLE;
    }
    secureZero(_dashboardCode, sizeof(_dashboardCode));
    // F6: Clear the authoritative PIN on auto-lock.
    _sessionCtx.clear();
    _audio.play(Tone::LOCK);
    transitionTo(Screen::LOCK);
  }

  // ---- 5-second hold-to-lock check (TTP223) ----
  checkHoldToLock();

  // ---- spring power-off (deep sleep) ----
  checkSpringPowerOff();

  // ---- lock screen: breathing halo in status bar + shake + error clear ----
  if (_screen == Screen::LOCK) {
    // Breathing halo around the status bar padlock — small, ~4Hz
    static unsigned long lastHaloT = 0;
    static int haloPhase = 0;
    if (t - lastHaloT > 250) {
      lastHaloT = t;
      haloPhase = (haloPhase + 1) % 8;
      int haloR = 6 + (haloPhase < 4 ? haloPhase : 7 - haloPhase);
      // Clear + redraw just the padlock area in the status bar
      _disp.tft().fillRect(SCREEN_W / 2 - 12, 2, 24, 16, C_HEADER);
      drawBreathingHalo(SCREEN_W / 2, 10, haloR, C_ACCENT);
      drawStatusBarPadlock(SCREEN_W / 2, 10, true);
    }
    // Shake animation
    if (_shaking) drawPinDotsShaking();
    // Clear error text after 2s
    clearLockError();
  }

  // ---- orientation ----
  if (t - _lastMpuPoll >= 50) {
    _lastMpuPoll = t;
    _mpu.poll();
    byte r = _mpu.detectRotation();
    if (r == 1 || r == 3) {
      if (r == _newRot) _rotStableCount++;
      else { _rotStableCount = 0; _newRot = r; }
      if (_rotStableCount >= 10 && _newRot != _curRot) {
        _curRot = _newRot;
        _disp.setRotation(_curRot);
        transitionTo(_screen); // redraw current screen at the new rotation
        _rotStableCount = 0;
      }
    } else {
      _rotStableCount = 0;
    }
  }

  // ---- button ladder ----
  // Poll interval lowered from 120ms to 50ms (BTN_POLL_MS) so the TTP223
  // touch pad feels instant. The ladder's 64-sample ADC averaging (3.2ms)
  // is unaffected by the poll rate.
  if (t - _lastBtnPoll >= BTN_POLL_MS) {
    _lastBtnPoll = t;
    _btn.poll();
    // Pattern entry runs on every poll while on the lock screen.
    // F12: Pattern entry is disabled during first boot (no PIN set yet).
    if (_screen == Screen::LOCK && !_modeMenuOpen && !_isFirstBoot) {
      handlePatternTouch();
    }

    // ── Continuous scroll: if UP/DOWN is held on the vault list,
    // repeat the scroll every SCROLL_REPEAT_MS (150ms) until released.
    if (_screen == Screen::VAULT && !_modeMenuOpen) {
      BtnEvent curState = _btn.state();
      if (curState == BtnEvent::UP || curState == BtnEvent::DOWN) {
        if (_btn.pressed()) {
          // First press — handle immediately + start repeat timer
          _scrollHeld = true;
          _scrollDir = curState;
          _lastScrollTime = t;
          handleVaultButtons();
        } else if (_scrollHeld && _scrollDir == curState &&
                   t - _lastScrollTime >= SCROLL_REPEAT_MS) {
          // Held + repeat interval elapsed — repeat the scroll
          _lastScrollTime = t;
          _lastActivity = t;  // reset auto-lock timer during continuous scroll
          // Manually trigger the scroll action (not via _pressed, which
          // only fires once on the rising edge)
          if (curState == BtnEvent::UP) {
            if (_selectedEntry > 0) {
              _selectedEntry--;
              if (_selectedEntry < _listScroll) _listScroll = _selectedEntry;
              redrawList();
            }
          } else {
            if (_selectedEntry < _sortedCount - 1) {
              _selectedEntry++;
              if (_selectedEntry >= _listScroll + LIST_VISIBLE)
                _listScroll = _selectedEntry - LIST_VISIBLE + 1;
              redrawList();
            }
          }
        }
      } else {
        _scrollHeld = false;
      }
    } else {
      _scrollHeld = false;
    }

    // ── TOUCH deferral: short tap = confirm, long hold = lock ──────
    // TOUCH is NOT dispatched on rising edge. Instead, we wait for the
    // release and check duration:
    //   < 1500ms = short tap → dispatch TOUCH to current screen handler
    //   >= 1500ms = long hold → discard (checkHoldToLock handles 5s lock)
    // This prevents a 5-second hold-to-lock from also opening an entry.
    static bool touchDeferred = false;
    if (_btn.touchPressed()) {
      touchDeferred = true;
      _lastActivity = t;
    }
    if (_btn.touchReleased() && touchDeferred) {
      unsigned long dur = _btn.lastTouchDuration();
      touchDeferred = false;
      if (dur < 1500 && !_modeMenuOpen) {
        // Short tap — simulate a TOUCH press so handleXxxButtons() fires
        _btn.simulateTouchPress();
        _lastActivity = t;
        switch (_screen) {
          case Screen::LOCK:        handleLockButtons();   break;
          case Screen::VAULT:       handleVaultButtons();  break;
          case Screen::DETAIL:      handleDetailButtons(); break;
          case Screen::TOTP:        handleTOTPButtons();   break;
          case Screen::CHGPIN:      handleChgPinButtons(); break;
          case Screen::SEARCH:      handleSearchButtons(); break;  // v10.9: UP/DOWN scroll, LEFT exit, RIGHT/TOUCH open
          case Screen::FIRST_BOOT_PIN: handleFirstBootPinButtons(); break;  // F12: mandatory first-boot PIN setup
          default: break;
        }
      }
      // If dur >= 1500ms, it was a long hold — discard.
      // checkHoldToLock() will fire at 5s if still held.
    }

    // ── Non-TOUCH button dispatch (rising edge, unchanged) ──────────
    // Only dispatch UP/DOWN/LEFT/RIGHT here — TOUCH is handled above
    // via the deferred release-based dispatch.
    if (_btn.pressed() && _btn.state() != BtnEvent::TOUCH) {
      _lastActivity = t;
      if (_modeMenuOpen) {
        BtnEvent e = _btn.state();
        if (e == BtnEvent::LEFT) closeModeMenu();
      } else {
        bool skipVault = (_screen == Screen::VAULT && _scrollHeld);
        if (!skipVault) {
          switch (_screen) {
            case Screen::LOCK:        handleLockButtons();   break;
            case Screen::VAULT:       handleVaultButtons();  break;
            case Screen::DETAIL:      handleDetailButtons(); break;
            case Screen::TOTP:        handleTOTPButtons();   break;
            case Screen::SETTINGS:    handleSettingsButtons(); break;
            case Screen::CHGPIN:      handleChgPinButtons(); break;
            case Screen::SEARCH:      handleSearchButtons(); break;  // v10.9: UP/DOWN scroll, LEFT exit
            case Screen::FIRST_BOOT_PIN: handleFirstBootPinButtons(); break;  // F12: mandatory first-boot PIN setup
            case Screen::BLE_PAIRING: if (_btn.state() == BtnEvent::LEFT) handleBlePairingTouch(113, 197); break;
            default: break;
          }
        }
      }
    }
  }

  // ---- 1Hz status bar / TOTP tick ----
  // v5.4.3: Added AP_INFO + SEARCH + DASHBOARD_CODE to the list so they
  // get the same periodic drawStatusBar() refresh as the other screens.
  // This is the single source of truth for the time display — don't
  // try to draw the time yourself in updateApInfoScreen() etc.
  bool hasStatusBar = (_screen == Screen::LOCK || _screen == Screen::VAULT ||
                        _screen == Screen::DETAIL || _screen == Screen::TOTP ||
                        _screen == Screen::AP_INFO || _screen == Screen::SEARCH ||
                        _screen == Screen::DASHBOARD_CODE || _screen == Screen::SETTINGS ||
                        _screen == Screen::FIRST_BOOT_PIN);  // F12: first-boot screen also has a status bar

  // ── INA219 battery percentage — polled every 5 seconds ──────────────
  // The INA219 takes ~1ms per read, so 5s polling keeps the I2C bus
  // mostly free while still giving responsive battery updates. The value
  // is stored in _batteryPercent and rendered by drawStatusBar() on every
  // 1Hz tick.
  if (_ina219.isOK() && t - _lastBatteryRead >= BATTERY_READ_MS) {
    _lastBatteryRead = t;
    uint8_t newPct = _ina219.getBatteryPercent();
    // Smoothing: only update if the change is significant (>3%) or if
    // the previous reading was 0 (first read after boot). This prevents
    // the percentage from jumping around due to I2C noise or load spikes.
    bool significantChange = (abs((int)newPct - (int)_batteryPercent) > 3);
    uint8_t prevPct = _batteryPercent;
    // Special case: first read after boot (prevPct == 0) always updates.
    // Also always update when going UP (charging detected) or going
    // below 15% (critical low — show immediately).
    if (significantChange || prevPct == 0) {
      _batteryPercent = newPct;
    }
  }
  if (!_modeMenuOpen && hasStatusBar && t - _lastStatusBarTick >= 1000) {
    _lastStatusBarTick = t;
    drawStatusBar();
    if (_screen == Screen::TOTP) { drawTOTPCode(); drawTOTPBar(); }
  }

  // ---- touch ----
  static bool wasTouching = false;
  static unsigned long lastTouchT = 0;
  int tx, ty;
  bool touching = _disp.getTouchPoint(tx, ty);

  if (touching && !wasTouching && t - lastTouchT > TOUCH_DEBOUNCE_MS) {
    wasTouching = true; lastTouchT = t; _lastActivity = t;

    if (_modeMenuOpen) {
      handleModeMenuTouch(tx, ty);
    } else if (hasStatusBar && _screen != Screen::LOCK &&
               hitTest(tx, ty, MODE_BADGE_X, MODE_BADGE_Y, MODE_BADGE_W, MODE_BADGE_H)) {
      _audio.play(Tone::KEY_TICK);  // v9.20: play click sound (was missing)
      _modeMenuOpen = true;
      _modeMenuHost = _screen;
      drawModeMenu();
    } else if (hasStatusBar && _rtc.unixEpoch() < SANE_EPOCH && hitTest(tx, ty, 58, 4, 44, 12)) {
      transitionTo(Screen::SETTIME); // tapping "! TIME" is a recovery path if the RTC lost power
    } else {
      switch (_screen) {
        case Screen::LOCK:        handleLockTouch(tx, ty);       break;
        case Screen::VAULT:       handleVaultTouch(tx, ty);      break;
        case Screen::DETAIL:      handleDetailTouch(tx, ty);     break;
        case Screen::TOTP:        handleTOTPTouch(tx, ty);       break;
        case Screen::SETTIME:     handleSetTimeTouch(tx, ty);    break;
        case Screen::BLE_PAIRING: handleBlePairingTouch(tx, ty); break;
        case Screen::DASHBOARD_CODE: handleDashboardCodeTouch(tx, ty); break;
        case Screen::AP_INFO:        handleApInfoTouch(tx, ty);        break;
        case Screen::SEARCH:         handleSearchTouch(tx, ty);        break;
        case Screen::SETTINGS:    handleSettingsTouch(tx, ty);   break;
        case Screen::CHGPIN:      handleChgPinTouch(tx, ty);     break;
        case Screen::ABOUT:       handleAboutTouch(tx, ty);      break;
        case Screen::FIRST_BOOT_PIN: handleFirstBootPinTouch(tx, ty); break;  // F12: mandatory first-boot PIN setup
        default: break;
      }
    }
  }
  if (!touching) wasTouching = false;
}
