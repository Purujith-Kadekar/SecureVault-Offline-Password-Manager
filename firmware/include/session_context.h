#pragma once
// ═══════════════════════════════════════════════════════════════════════════════
//  session_context.h — single authoritative holder of the authenticated vault PIN
//  Developed by Purujith Kadekar
// ═══════════════════════════════════════════════════════════════════════════════
//  F6 fix: eliminates 5+ separate PIN copies across components.
//  The PIN is stored here ONLY after successful verification on the lock screen.
//  All components that need the PIN (SerialProtocol, APModeManager, WebVaultServer)
//  receive a pointer to this single instance, never their own copy.
//  Zeroed on: lock, auto-lock, mode exit, deep sleep, factory reset.
#include "board_config.h"
#include "crypto_utils.h"  // secureZero

class SessionContext {
public:
  SessionContext() = default;

  // Store the verified PIN. Called ONCE after lock-screen PIN verification succeeds.
  // Immediately zeroes any previous PIN.
  void setPin(const char* pin) {
    if (!pin) { clear(); return; }
    secureZero(_pinBuf, sizeof(_pinBuf));
    strncpy(_pinBuf, pin, MAX_PIN_LEN);
    _pinBuf[MAX_PIN_LEN] = '\0';
    _pinSet = true;
  }

  // Read-only access to the PIN. Returns nullptr if no PIN is set (locked state).
  const char* pin() const { return _pinSet ? _pinBuf : nullptr; }

  // True if a PIN is currently set (vault is unlocked).
  bool isSet() const { return _pinSet; }

  // Zero the PIN and mark as unset. Called on lock, auto-lock, mode exit, deep sleep,
  // factory reset. Uses secureZero (volatile pointer memset) to prevent compiler
  // optimizing away the zeroing — same as SecureSession does.
  void clear() {
    secureZero(_pinBuf, sizeof(_pinBuf));
    _pinSet = false;
  }

private:
  char _pinBuf[MAX_PIN_LEN + 1] = {0};
  bool _pinSet = false;
};
