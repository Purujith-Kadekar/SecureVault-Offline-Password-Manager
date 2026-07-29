#pragma once
// ═══════════════════════════════════════════════════════════════════════════════
//  ui_theme.h — named color palette, kept separate from board_config.h so a
//  future theme swap (or a runtime light/dark toggle) is a one-line change
//  here instead of touching every draw call across ui_screens.cpp.
// ═══════════════════════════════════════════════════════════════════════════════
//  F16 FIX: Removed the #define/#undef macro hack. Previously, board_config.h
//  defined colors as #define macros (C_BG, C_PANEL, etc.), and this file
//  #undef'd all 14 macros and declared extern uint16_t variables with the
//  same names. If any file forgot to include ui_theme.h after board_config.h,
//  it silently used the wrong compile-time defaults.
//
//  New approach:
//    1. board_config.h NO longer defines C_* color macros. The PALETTE
//       section was removed. (A breaking change — any file that used C_*
//       without including ui_theme.h will now get a compiler error, which
//       is the correct behavior.)
//    2. This file declares extern uint16_t C_* variables WITHOUT any #undef.
//    3. A ThemeDefaults struct provides compile-time default values that
//       match the Air-Gapped theme (the original). Files that just need a
//       reference value (not runtime theme support) can use
//       ThemeDefaults::C_BG, etc.
//    4. Files that need runtime theme support use the extern C_* variables
//       directly, which are set by UiController::applyTheme().
//    5. The THEME_COLORS_IMPLEMENTED pattern remains — ui_screens.cpp
//       defines the variables, other files extern them.
// ═══════════════════════════════════════════════════════════════════════════════
#include <Arduino.h>

// ── ThemeDefaults — compile-time defaults (Air-Gapped theme) ────────────────
// These provide the original Air-Gapped color values as struct members.
// Use these when you need a reference/default value but don't need runtime
// theme switching. For runtime theme support, use the extern C_* variables
// below (which are set by applyTheme() at boot).
struct ThemeDefaults {
  static constexpr uint16_t C_BG        = 0x0000;
  static constexpr uint16_t C_PANEL     = 0x1082;
  static constexpr uint16_t C_HEADER    = 0x000B;
  static constexpr uint16_t C_ACCENT    = 0x07FF;
  static constexpr uint16_t C_GREEN     = 0x07E0;
  static constexpr uint16_t C_RED       = 0xF800;
  static constexpr uint16_t C_ORANGE    = 0xFB40;
  static constexpr uint16_t C_YELLOW    = 0xFFE0;
  static constexpr uint16_t C_WHITE     = 0xFFFF;
  static constexpr uint16_t C_GREY      = 0x7BEF;
  static constexpr uint16_t C_DARKGREY  = 0x39E7;
  static constexpr uint16_t C_BTN       = 0x2965;
  static constexpr uint16_t C_BTN_DARK  = 0x0320;
  static constexpr uint16_t C_TOTP_CHIP = 0x1800;
};

struct ThemeColors {
  uint16_t bg, panel, header, accent;
  uint16_t green, red, orange, yellow, white, grey, darkgrey, btn, btnDark, totpChip;
};

// ── Theme 1: Cyan-on-black "Air-Gapped" (the original) ────────────────
static const ThemeColors THEME_AIR_GAPPED = {
  ThemeDefaults::C_BG, ThemeDefaults::C_PANEL, ThemeDefaults::C_HEADER, ThemeDefaults::C_ACCENT,
  ThemeDefaults::C_GREEN, ThemeDefaults::C_RED, ThemeDefaults::C_ORANGE, ThemeDefaults::C_YELLOW,
  ThemeDefaults::C_WHITE, ThemeDefaults::C_GREY, ThemeDefaults::C_DARKGREY,
  ThemeDefaults::C_BTN, ThemeDefaults::C_BTN_DARK, ThemeDefaults::C_TOTP_CHIP
};

// ── Theme 2: Pure Black & White (monochrome) ──────────────────────────
// No color at all — pure black background, white text, white outlines.
// The trick: C_RED and C_ORANGE are used BOTH as button backgrounds
// (where they need to be dark so white text is visible) AND as text/
// indicator colors (where they need to be light so they're visible on
// dark backgrounds). Solution: use mid-gray (0x7BEF) for both — it's
// light enough to be visible as text on black, and dark enough that
// white text is visible on it as a button background.
//
// v10.7 FIX: btnDark = 0x7BEF (same as C_RED), so OK/TYPE BOTH/TYPE ALL
// share the same grey as CLR, as the user requested.
static const ThemeColors THEME_MONOCHROME = {
  0x0000,  // bg       = pure black
  0x2104,  // panel    = very dark gray
  0x1082,  // header   = dark gray
  0xFFFF,  // accent   = pure white
  0xFFFF,  // green    = white (BLE connected dot, TOTP bar)
  0x7BEF,  // red      = mid gray — works as BOTH button bg (white text visible) AND text (visible on black)
  0x7BEF,  // orange   = mid gray — same dual-use as red
  0xFFFF,  // yellow   = white (TOTP header text)
  0xFFFF,  // white    = white
  0xC618,  // grey     = light gray (subtitles, secondary text)
  0x7BEF,  // darkgrey = mid gray (BLE disconnected dot, dim elements)
  0x4208,  // btn      = dark gray (regular buttons — white text visible)
  0x7BEF,  // btnDark  = mid gray — SAME as CLR (C_RED). v10.7: OK / TYPE BOTH / TYPE ALL / settings-OK all match CLR
  0x1082   // totpChip = dark gray (2FA chip bg — white/orange text visible)
};

// ── Theme 3: Emerald (green-on-black, "matrix" style) ─────────────────
static const ThemeColors THEME_EMERALD = {
  0x0000,  // bg       = pure black
  0x0120,  // panel    = very dark green
  0x00C0,  // header   = dark green
  0x07E0,  // accent   = pure green
  0x07E0,  // green    = green
  0xF800,  // red      = red (for errors/danger)
  0xFD20,  // orange   = orange
  0xFFE0,  // yellow   = yellow
  0xFFFF,  // white    = white
  0xB7E0,  // grey     = light green-gray
  0x4B32,  // darkgrey = dark green-gray
  0x0240,  // btn      = dark green
  0x0120,  // btnDark  = very dark green
  0x0240   // totpChip = dark green
};

// ── Theme 4: Sunlight (white background, opposite of Monochrome) ──────
// A clean, bright, "daylight" theme. White background with dark text.
//
// CRITICAL DESIGN NOTE: C_WHITE is used throughout the codebase as the
// PRIMARY TEXT/FOREGROUND color — it's semantic, not literal. In all 3
// dark themes, C_WHITE = 0xFFFF (literal white) which doubles as both
// "foreground text" and "literal white fill". For Sunlight, the primary
// text must be DARK to be visible on a white background, so C_WHITE =
// 0x0000 (black) here. This is the same trick Monochrome plays with
// C_YELLOW (setting it to white). Every draw call that uses C_WHITE as
// text color will automatically get black text — no code changes needed.
static const ThemeColors THEME_SUNLIGHT = {
  0xFFFF,  // bg       = pure white
  0xF7BE,  // panel    = very light gray (alternating list rows)
  0xB5B6,  // header   = medium-light gray (status bar, header bars)
  0x021F,  // accent   = dark blue (outlines, highlights, breathing halo)
  0x0380,  // green    = medium green (BLE connected dot, TOTP bar, success)
  0xD000,  // red      = dark red (CLR/LOCK buttons, danger, errors)
  0xFC00,  // orange   = dark orange (TOTP chip text, warnings)
  0xCC00,  // yellow   = dark goldenrod (favorites star, countdown — readable on white)
  0x0000,  // white    = BLACK (semantic: primary text/foreground color)
  0x630C,  // grey     = medium gray (subtitles, secondary text — readable on white)
  0x9492,  // darkgrey = light-medium gray (dim elements, empty PIN dots — visible on white)
  0xB5B6,  // btn      = medium-light gray (regular buttons — black text visible)
  0x8410,  // btnDark  = darker gray (OK button, TYPE ALL — black text visible)
  0x8410   // totpChip = darker gray (2FA chip bg — orange text visible)
};

// ── Active theme pointer ──────────────────────────────────────────────
// Set by UiController::setTheme(). Defaults to THEME_AIR_GAPPED.
// All draw calls use the C_* runtime variables below, which are set
// from the active ThemeColors struct by applyTheme().
//
// The theme ID is stored in NVS and persists across reboots.
//   0 = Air-Gapped (cyan on black, default)
//   1 = Monochrome (pure black & white)
//   2 = Emerald (green on black)
//   3 = Sunlight (dark text on white background)

// ═══════════════════════════════════════════════════════════════════════════════
//  RUNTIME THEME COLOR VARIABLES (extern)
//
//  F16 FIX: These are now proper extern uint16_t variables WITHOUT any
//  #undef hack. board_config.h no longer defines C_* macros, so there
//  is no macro-variable collision. Every file that draws UI must include
//  this header to get the extern declarations — and if any file forgets
//  to include it, the compiler will error on the undefined C_* symbol
//  (breaking change, but correct — no silent wrong defaults).
//
//  The variables are defined in ui_screens.cpp (with THEME_COLORS_IMPLEMENTED)
//  and set by UiController::applyTheme().
// ═══════════════════════════════════════════════════════════════════════════════

#ifdef THEME_COLORS_IMPLEMENTED
// Variables are being DEFINED here (ui_screens.cpp only)
// Initialized to the Air-Gapped theme values so they're valid before
// applyTheme() is called (showBootSplash runs before begin()).
// F16: Values are now sourced from ThemeDefaults (constexpr struct),
// not from #define macros that needed #undef.
uint16_t C_BG        = ThemeDefaults::C_BG;
uint16_t C_PANEL     = ThemeDefaults::C_PANEL;
uint16_t C_HEADER    = ThemeDefaults::C_HEADER;
uint16_t C_ACCENT    = ThemeDefaults::C_ACCENT;
uint16_t C_GREEN     = ThemeDefaults::C_GREEN;
uint16_t C_RED       = ThemeDefaults::C_RED;
uint16_t C_ORANGE    = ThemeDefaults::C_ORANGE;
uint16_t C_YELLOW    = ThemeDefaults::C_YELLOW;
uint16_t C_WHITE     = ThemeDefaults::C_WHITE;
uint16_t C_GREY      = ThemeDefaults::C_GREY;
uint16_t C_DARKGREY  = ThemeDefaults::C_DARKGREY;
uint16_t C_BTN       = ThemeDefaults::C_BTN;
uint16_t C_BTN_DARK  = ThemeDefaults::C_BTN_DARK;
uint16_t C_TOTP_CHIP = ThemeDefaults::C_TOTP_CHIP;
#else
// Consumer files: extern declarations
extern uint16_t C_BG;
extern uint16_t C_PANEL;
extern uint16_t C_HEADER;
extern uint16_t C_ACCENT;
extern uint16_t C_GREEN;
extern uint16_t C_RED;
extern uint16_t C_ORANGE;
extern uint16_t C_YELLOW;
extern uint16_t C_WHITE;
extern uint16_t C_GREY;
extern uint16_t C_DARKGREY;
extern uint16_t C_BTN;
extern uint16_t C_BTN_DARK;
extern uint16_t C_TOTP_CHIP;
#endif
