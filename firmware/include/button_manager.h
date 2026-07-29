#pragma once
// ═══════════════════════════════════════════════════════════════════════════════
//  button_manager.h — 5-switch resistor ladder + TTP223 capacitive pad
//
//  The ladder provides RIGHT/UP/DOWN/LEFT (and SPRING, which is now a no-op
//  since the spring is a latching hardware power switch). The TTP223 pad
//  provides TOUCH events + pattern-entry (long/short touch duration).
//
//  Anti-misread: a reading must be STABLE for 2 consecutive polls before
//  it's accepted. This kills the "UP sometimes reads as LEFT" bug caused
//  by ADC noise / battery droop / component tolerance drift.
// ═══════════════════════════════════════════════════════════════════════════════
#include <Arduino.h>

enum class BtnEvent { IDLE, TOUCH, SPRING, RIGHT, UP, DOWN, LEFT };

class ButtonManager {
public:
  void begin();
  void poll(); // averages the ladder ADC and updates state — call periodically

  BtnEvent state() const { return _state; }
  bool pressed() const { return _pressed; } // true only on the rising edge of a new press

  // For deferred TOUCH dispatch: simulates a TOUCH press so that
  // handleXxxButtons() sees _pressed=true and _state=TOUCH.
  // Used when TOUCH is dispatched on release (short tap) instead of
  // on press (rising edge), to distinguish short tap from long hold.
  void simulateTouchPress() { _state = BtnEvent::TOUCH; _pressed = true; }

  // ── Pattern-entry support ──────────────────────────────────────────
  bool touchActive() const { return _touchState == HIGH; }
  unsigned long touchHoldDuration() const {
    if (_touchState != HIGH) return 0;
    return millis() - _touchStartTime;
  }
  unsigned long lastTouchDuration() const { return _lastTouchDuration; }
  bool touchReleased() const { return _touchReleased; }
  bool touchPressed() const { return _touchPressed; }

private:
  BtnEvent _state = BtnEvent::IDLE;
  BtnEvent _prev = BtnEvent::IDLE;
  bool _pressed = false;

  // ── Anti-misread: require 2 consecutive same readings ─────────────
  // The ADC sometimes spikes into the wrong band on a single sample
  // (noise, battery droop, touch-crosstalk). By requiring the SAME
  // classification on 2 consecutive polls, we eliminate phantom "UP
  // reads as LEFT" / "DOWN reads as RIGHT" misfires that were locking
  // the user out.
  BtnEvent _candidate = BtnEvent::IDLE;
  int _candidateCount = 0;

  // TTP223 touch tracking
  int _touchState = LOW;
  int _prevTouchState = LOW;
  unsigned long _touchStartTime = 0;
  unsigned long _lastTouchDuration = 0;
  bool _touchPressed = false;
  bool _touchReleased = false;

  static BtnEvent classify(int raw, int touch);
};
