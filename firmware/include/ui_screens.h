#pragma once
// ═══════════════════════════════════════════════════════════════════════════════
//  ui_screens.h — screen state machine: Lock, Vault, Detail, TOTP,
//  Set Time, BLE Pairing, and the Mode Menu overlay
// ═══════════════════════════════════════════════════════════════════════════════
#include <Arduino.h>
#include "board_config.h"
#include "display_manager.h"
#include "vault_manager.h"
#include "rtc_manager.h"
#include "mpu_manager.h"
#include "button_manager.h"
#include "ble_keyboard_manager.h"
#include "audio_manager.h"
#include "serial_protocol.h"
#include "duress_manager.h"
// v5.4: AP mode — needed for APModeManager + the AP info screen state.
#include "ap_mode_manager.h"
#include "ina219_manager.h"
#include "session_context.h"  // F6: single authoritative PIN holder

enum class Screen { LOCK, VAULT, DETAIL, TOTP, SETTIME, BLE_PAIRING, DASHBOARD_CODE, AP_INFO, SEARCH, SETTINGS, CHGPIN, ABOUT, CLOCK, POWER_OFF, RESUME, FIRST_BOOT_PIN, NONE };
// USB HID mode removed: Arduino's native USBHIDKeyboard and our vendored
// esp_tinyusb (needed for Network Mode's USB-NCM) both need to own the
// same underlying TinyUSB tusb_config.h, and can't coexist -- see
// components/README.md. BLE typing covers the "type credentials" use
// case unconditionally, so this was dropped rather than Network Mode.
//
// v5.4: AP added — when the user selects AP, the device brings up a
// SoftAP + captive portal + 6-layer-protected vault CRUD webapp.
// See ap_mode_manager.h + web_vault_server.h for the implementation.
enum class HidMode { BLE, DASHBOARD, AP };

class UiController {
public:
  UiController(DisplayManager& disp, VaultManager& vault, RtcManager& rtc,
               MpuManager& mpu, ButtonManager& btn, BleKeyboardManager& ble,
               AudioManager& audio,
               SerialProtocol& serialProto, DuressManager& duress,
               Ina219Manager& ina219, SessionContext& sessionCtx);

  // Chooses the initial screen (Lock, or Set Time if the RTC has never
  // been set) and draws it.
  void begin();

  // Call every loop() iteration. Handles: auto-lock timeout, orientation
  // changes, button ladder events, touch events, the 1Hz clock/TOTP tick,
  // and the BLE pairing screen driven off BleKeyboardManager's flags.
  void tick();

  // Returns true if Dashboard Mode (serial protocol) is currently active.
  // Used by main.cpp to avoid text-based Serial reads during binary protocol.
  bool isInDashboardMode() const { return _hidMode == HidMode::DASHBOARD; }

  // ── Public: called from main.cpp on deep-sleep wake ────────────────
  // Shows the "RESUMING" animation + audio cue before the lock screen.
  // Must be public because main.cpp::setup() calls it after ui.begin().
  void showResumeScreen();

  // v10.4: Public so main.cpp can load the saved theme from NVS BEFORE
  // showResumeScreen() runs — otherwise the resume animation always uses
  // the default Air-Gapped (black) background, showing a dark screen on
  // boot/wake for Sunlight theme users.
  void loadTheme();

private:
  DisplayManager& _disp;
  VaultManager& _vault;
  RtcManager& _rtc;
  MpuManager& _mpu;
  ButtonManager& _btn;
  BleKeyboardManager& _ble;
  AudioManager& _audio;
  SerialProtocol& _serialProto;
  DuressManager& _duress;
  Ina219Manager&  _ina219;
  SessionContext& _sessionCtx;  // F6: single authoritative PIN holder

  Screen _screen = Screen::NONE;
  Screen _prevScreen = Screen::NONE;
  HidMode _hidMode = HidMode::BLE;

  // ── First-boot PIN setup (F12) ────────────────────────────────────
  // When the device boots with no PIN set (isFirstBoot() == true), the
  // lock screen is replaced by a mandatory PIN setup screen that forces
  // the user to choose and confirm a PIN before the vault can be used.
  // This eliminates the hard-coded "1234" default PIN vulnerability.
  bool _isFirstBoot = false;
  // Two-step setup: 0 = enter new PIN, 1 = confirm new PIN.
  int _firstBootPinStep = 0;
  char _firstBootPinBuf[MAX_PIN_LEN + 1] = {0};  // first entry
  int _firstBootPinLen = 0;
  char _firstBootPinConfirmBuf[MAX_PIN_LEN + 1] = {0};  // confirm entry
  int _firstBootPinConfirmLen = 0;
  // Error message for the first-boot screen (e.g. "PIN must be at least
  // 4 digits", "PINs don't match")
  char _firstBootError[40] = {0};
  unsigned long _firstBootErrorTime = 0;
  void drawFirstBootPinScreen();
  void handleFirstBootPinTouch(int tx, int ty);
  void handleFirstBootPinButtons();
  void submitFirstBootPin();

  // ---- Deferred mode switching (prevents crash from simultaneous mode teardown+init) ----
  // CRITICAL FIX: Mode switching via the mode menu is now fully deferred to tick().
  // The touch handler ONLY sets _modePendingSwitch + _modeSwitchState.
  // tick() handles the actual teardown of the old mode and init of the new mode
  // in a multi-step sequence, preventing the old mode's background tasks from
  // overlapping with the new mode's initialization (which caused firmware crashes).
  //
  // Sequence: IDLE → TEARDOWN_OLD (stop old mode tick + cleanup) → INIT_NEW
  //   (start new mode) → IDLE. Each step takes exactly one tick() iteration,
  //   giving background tasks time to complete before starting the new mode.
  enum class ModeSwitchState { IDLE, TEARDOWN_OLD, INIT_NEW };
  ModeSwitchState _modeSwitchState = ModeSwitchState::IDLE;
  HidMode _modePendingSwitch = HidMode::BLE;
  uint32_t _modeSwitchStartTime = 0;

  // PIN entry
  char _pinBuf[MAX_PIN_LEN + 1] = {0};
  int _pinLen = 0;
  int _failCount = 0;

  // ── Pattern entry (parallel to PIN on lock screen) ─────────────────
  uint16_t _patternMask = 0;
  int _patternLen = 0;
  unsigned long _lastTouchReleaseTime = 0;
  void handlePatternTouch();
  void submitPattern();
  void clearPattern();
  void drawPatternDot(int idx, bool isLong);
  void drawPatternRow();

  // ── 5-second hold-to-lock (TTP223) ────────────────────────────────
  // Anywhere after the PIN screen, holding the capacitive pad for 5
  // seconds instantly locks and returns to the PIN screen.
  unsigned long _touchHoldStart = 0;
  bool _lockHoldActive = false;
  void checkHoldToLock();

  // ── Lock screen error feedback ────────────────────────────────────
  void showLockError(const char* msg);
  void clearLockError();
  unsigned long _lockErrorTime = 0;

  // ── Change PIN flow (3-step) ──────────────────────────────────────
  // Step 1: enter current PIN
  // Step 2: enter new PIN
  // Step 3: confirm new PIN
  // NOTE: On first boot, the CHGPIN screen is NOT used — instead the
  // FIRST_BOOT_PIN screen handles the mandatory initial PIN setup.
  int _chgPinStep = 0;
  char _chgPinOld[MAX_PIN_LEN + 1] = {0};
  int _chgPinOldLen = 0;
  char _chgPinNew[MAX_PIN_LEN + 1] = {0};
  int _chgPinNewLen = 0;
  void drawChgPinScreen();
  void handleChgPinButtons();
  void handleChgPinTouch(int tx, int ty);
  void submitChgPin();

  // ── Settings screen ───────────────────────────────────────────────
  int _settingsScroll = 0;
  static const int SETTINGS_VISIBLE = 5;
  void drawSettingsScreen();
  void handleSettingsTouch(int tx, int ty);
  void handleSettingsButtons();

  // ── About screen ──────────────────────────────────────────────────
  void drawAboutScreen();
  void handleAboutTouch(int tx, int ty);

  // ── Lock screen polish (glyph + halo + shake) ─────────────────────
  void drawPadlockGlyph(int x, int y, int size, uint16_t color);
  void drawBreathingHalo(int x, int y, int maxR, uint16_t color);
  void drawStatusBarPadlock(int cx, int cy, bool closed);
  uint16_t lerp565(uint16_t c1, uint16_t c2, float t);
  bool _shaking = false;
  unsigned long _shakeStart = 0;
  void triggerShake();
  void drawPinDotsShaking();

  // ── Deep sleep (spring power-off) ─────────────────────────────────
  // When the spring is flipped to OFF, the firmware shows a brief
  // "POWERING OFF" countdown screen + audio cue, then enters deep sleep
  // (display off, BLE off, secrets zeroed). When the spring is flipped
  // back to ON, the ESP32 wakes via ext1 wakeup and reboots; main.cpp
  // detects the wake cause and calls showResumeScreen() (declared
  // public above) to show a "RESUMING" screen before the lock screen.
  void enterClockMode();       // legacy name — now wraps enterPowerOff()
  void enterPowerOff();        // power-off with user feedback
  void drawPowerOffScreen(int countdownSeconds, const char* statusMsg);
  void drawResumeScreen(int phase);
  // v5.4.9 FIX: drawClockScreen() and exitClockMode() are dead code —
  // never called, no Screen::CLOCK transition exists. The CLOCK enum
  // value is kept (removing it would shift all subsequent enum values
  // and break serialized state if any). Marked DEPRECATED; remove the
  // function bodies if flash space becomes critical.
  void drawClockScreen() __attribute__((deprecated("unused dead code")));
  void checkSpringPowerOff();
  void exitClockMode() __attribute__((deprecated("unused dead code")));
  unsigned long _lastScrollTime = 0;
  bool _scrollHeld = false;
  BtnEvent _scrollDir = BtnEvent::IDLE;
  static const unsigned long SCROLL_REPEAT_MS = 150;  // repeat rate when held
  // Active theme colors (runtime — set from ui_theme.h structs).
  // These shadow the C_* macros from board_config.h so all existing
  // draw calls automatically use the active theme without code changes.
  uint8_t _themeId = 0;  // 0=Air-Gapped, 1=Monochrome, 2=Emerald
  void applyTheme(uint8_t id);
  void cycleTheme();

  // F6: REMOVED _dashboardPin — PIN is now held ONLY in SessionContext.
  // Components that need it read from _sessionCtx.pin(), never their own copy.

  // v3: 6-digit out-of-band code shown on the TFT during the ECDH
  // handshake. Generated by SerialProtocol::begin() when the user
  // selects Dashboard Mode. Zeroed on exit/auto-lock.
  char _dashboardCode[7] = {0};

  // v9.20: Track the previous connection state so we can detect the
  // "just connected" transition and play a sound immediately (instead
  // of waiting for the next 500ms poll).
  bool _dashboardWasConnected = false;

  // ── v5.4: AP Mode state ────────────────────────────────────────────
  // The AP-mode info screen shows: SSID, WPA2 password, 6-digit code,
  // BACK button. All four are read from APModeManager (which generates
  // them in start()). The AP_INFO screen is purely a display — the
  // webapp traffic flows through APModeManager + WebVaultServer, not
  // through the UI.
  //
  // F6: REMOVED _apPin — PIN is now held ONLY in SessionContext.
  // Components that need it read from _sessionCtx.pin(), never their own copy.

  // v5.4.3: Track previous connection state for connect/disconnect sound.
  bool _apWasConnected = false;

  void drawApInfoScreen();
  void handleApInfoTouch(int tx, int ty);
  // 1Hz refresh of the AP info screen — updates the "active clients"
  // indicator + the idle-timeout countdown.
  void updateApInfoScreen();

  // ── v5.4.3: Search screen state ────────────────────────────────────
  // QWERTY keyboard with live-filtered vault search.
  // Layout: search input (top) + results list (middle) + keyboard (bottom)
  // Keyboard: 4 rows, 28px keys, 123/ABC toggle for numbers/symbols.
  // Search matches: site (primary), user, url, notes (case-insensitive).
  char _searchQuery[32] = {0};    // current search text
  int _searchQueryLen = 0;        // length of _searchQuery
  int _searchResults[16];         // vault indices matching the query
  int _searchResultCount = 0;     // number of valid results
  int _searchSelIdx = 0;          // selected result (for scrolling)
  int _searchScrollOffset = 0;   // v10.9: scroll offset for results > 3 visible rows
  bool _searchKeyboardMode = false;  // false=letters, true=numbers/symbols
  int _searchKeyFlash = -1;       // index of the key being flashed (-1=none)
  unsigned long _searchKeyFlashTime = 0;

  void drawSearchScreen();
  void drawSearchKeyboard();
  void drawSearchResults();
  void handleSearchTouch(int tx, int ty);
  void handleSearchButtons();     // v10.9: UP/DOWN scroll results, LEFT exits, RIGHT/TOUCH opens entry
  void updateSearchResults();     // re-filter the vault based on _searchQuery
  void handleSearchKeyPress(char c);  // append a character to _searchQuery
  void handleSearchBackspace();
  void handleSearchClear();

  // Vault list / detail
  int _selectedEntry = 0;
  int _listScroll = 0;
  bool _passVisible = false;
  // Detail-screen vertical scroll offset (in field-rows). Identity has
  // up to 14 fields — too many for one screen — so the detail screen
  // scrolls. Login/Card/Note fit on one screen so _detailScroll stays 0.
  int _detailScroll = 0;
  // v10.5: Click-to-reveal target for the per-type detail screen.
  // v10.4 had an inline "SHOW/HIDE" LINK drawn next to the CVV/SSN value
  // — the user found it cluttered and asked to make the MASKED VALUE
  // ITSELF tappable instead. Now: when a secret field (CVV for card,
  // SSN for identity) is drawn, the entire field row's tap rectangle
  // (x=8..294, y=row_top..row_top+DETAIL_ROW_H) is stored here. The
  // touch handler treats a tap anywhere on that row (when the value is
  // masked) as a toggle-reveal. A second tap re-masks.
  // -1 in _detailSecretRowY means "no secret field is currently visible".
  // _detailSecretRowH is initialized in the .cpp via DETAIL_ROW_H
  // (the static const is declared below — can't be used in a member
  // initializer here because of declaration order).
  int _detailSecretRowY = -1;
  int _detailSecretRowH = 22;
  bool _detailSecretPresent = false;  // true if the visible secret field has a non-empty value
  // Number of field rows currently visible without scrolling. Recomputed
  // in drawDetailScreen() per entry type.
  static const int DETAIL_ROW_H = 22;     // label (8px) + value (12px) + 2px gap
  static const int DETAIL_TOP_Y = SBAR_H + 28;  // below the title bar
  static const int DETAIL_BOTTOM_Y = 142;       // above the button row
  static const int DETAIL_VISIBLE_ROWS =
      (DETAIL_BOTTOM_Y - DETAIL_TOP_Y) / DETAIL_ROW_H;  // ≈ 5 rows visible
  // UI filter value (NOT an entry type — has extra meta-values for ALL/TRASH):
  //   255 = ALL    — show all non-deleted entries regardless of type
  //   254 = TRASH  — show only deleted entries
  //   0..3 = specific entry type — matches vault_types.h
  //          (0=login, 1=card, 2=identity, 3=note)
  // When displaying the label for 0..3, ALWAYS use vaultTypeToStr()
  // from vault_types.h — never index a local label array, that's what
  // caused the "type 0 = ALL" bug in v9.9.
  uint8_t _vaultFilter = 255;

  // Sorted display index — maps display position → actual vault index.
  // Built in drawVaultScreen() by sorting entries alphabetically by site.
  // The vault's storage order (VaultManager) is unchanged; only the
  // DISPLAY is sorted. _selectedEntry and _listScroll refer to positions
  // in this sorted array, not raw vault indices.
  static const int MAX_DISPLAY = 256;  // matches VaultManager::MAX_ENTRIES
  int _sortedIndex[MAX_DISPLAY];
  int _sortedCount = 0;
  void buildSortedIndex();

  // Set Time
  char _timeBuf[11] = {0};
  int _timeLen = 0;

  // Mode menu overlay
  bool _modeMenuOpen = false;
  Screen _modeMenuHost = Screen::VAULT;

  // BLE pairing screen
  Screen _screenBeforePairing = Screen::LOCK;

  // Timing
  unsigned long _lastActivity = 0;
  unsigned long _lastClockTick = 0;
  unsigned long _lastStatusBarTick = 0;
  void drawBatteryIcon(int x, int y, uint8_t pct);
  uint8_t _batteryPercent = 0;
  unsigned long _lastBatteryRead = 0;
  static const unsigned long BATTERY_READ_MS = 5000;  // read INA219 every 5 seconds
  unsigned long _lastBtnPoll = 0;
  unsigned long _lastMpuPoll = 0;
  // Default orientation matches DisplayManager (rotation 1, 180° from rot 3).
  byte _curRot = 1, _newRot = 1, _rotStableCount = 0;

  // TOTP
  char _totpCode[7] = "------";

  // ---- transitions ----
  void transitionTo(Screen s);

  // ---- screen draws (each does a full redraw — cheap now on hardware SPI) ----
  void drawLockScreen();
  void drawPinDot(int idx, bool filled);
  void drawNumpadBtn(int idx, bool flash);
  // F12: Draw a PIN dot for the first-boot setup screen (same visual
  // style as the lock/CHGPIN screens, but positioned differently).
  void drawFirstBootPinDot(int idx, bool filled);

  void drawVaultScreen();
  void drawListRow(int row);
  void redrawList();

  void drawDetailScreen();
  // Per-type detail screen dispatch: login (type 0) uses the original
  // v9.9 large-text layout; card/identity/note use the new scrollable
  // field-rows layout. The touch + button handlers are similarly split.
  void drawDetailScreenLogin();
  void drawDetailScreenPerType();
  void handleDetailTouchLogin(int tx, int ty);
  void handleDetailTouchPerType(int tx, int ty);
  void handleDetailButtonsLogin();
  void handleDetailButtonsPerType();
  void drawPassArea();
  // Render a single (label, value) row at the given y-coordinate for
  // the detail screen. `secret` controls masking (e.g. for passwords,
  // CVV, SSN). Returns the next y position (y + DETAIL_ROW_H).
  int  drawDetailFieldRow(int y, const char* label, const char* value, bool secret = false);
  // Type every non-empty field of the current entry, separated by Tab,
  // for form-fill use. Used by the TYPE ALL button and by a short tap
  // of the capacitive pad on the detail screen.
  void typeAllFieldsWithTab();
  // Count the number of non-empty fields for the current entry's type.
  // Used by drawDetailScreen() to decide whether the scroll arrows
  // should be shown.
  int  countDetailFields();

  void drawTOTPScreen();
  void drawTOTPCode();
  void drawTOTPBar();

  void drawSetTimeScreen();
  void drawTimeDigits();

  void drawBlePairingScreen();
  void pulseBlePairingDot();

  // v3: Dashboard Mode 6-digit code display screen
  void drawDashboardCodeScreen();
  void updateDashboardCodeScreen();  // dynamic update only (no flicker)

  void drawModeMenu();
  void closeModeMenu();

  void drawStatusBar();

  // ---- input handling ----
  void handleLockTouch(int tx, int ty);
  void handleLockButtons();

  void handleVaultTouch(int tx, int ty);
  void handleVaultButtons();

  void handleDetailTouch(int tx, int ty);
  void handleDetailButtons();

  void handleTOTPTouch(int tx, int ty);
  void handleTOTPButtons();

  void handleSetTimeTouch(int tx, int ty);

  void handleBlePairingTouch(int tx, int ty);
  void handleDashboardCodeTouch(int tx, int ty);

  void handleModeMenuTouch(int tx, int ty);

  // Deferred mode switch state machine — called at the beginning of tick()
  // when _modeSwitchState != IDLE. Returns early to skip all other tick()
  // processing during the transition, preventing overlap between old/new modes.
  void processModeSwitch();

  // ---- HID dispatch (routes to BLE or USB depending on _hidMode) ----
  void typeStr(const char* s);
  void typeEnter();
  void typeTab();
};
