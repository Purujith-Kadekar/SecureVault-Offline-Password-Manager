#include "button_manager.h"
#include "board_config.h"

void ButtonManager::begin() {
  pinMode(LADDER_PIN, INPUT);
  pinMode(TOUCH_PIN, INPUT);
  analogReadResolution(12);
  analogSetAttenuation(ADC_11db);
}

BtnEvent ButtonManager::classify(int raw, int touch) {
  // Check the physical capacitive line FIRST — this is the crosstalk fix
  // from Buttons.txt: touching the pad injects a ~1225 spike onto the
  // ladder ADC line that would otherwise get misread as a DOWN press.
  if (touch == HIGH) return BtnEvent::TOUCH;

  // SPRING ADC band (≤250) is kept for backwards compatibility, but the
  // spring is a latching hardware power switch. No screen responds to it.
  if (raw <= TH_SPRING_MAX) return BtnEvent::SPRING;
  if (raw <= TH_RIGHT_MAX)  return BtnEvent::RIGHT;
  if (raw <= TH_UP_MAX)     return BtnEvent::UP;
  if (raw <= TH_DOWN_MAX)   return BtnEvent::DOWN;
  if (raw <= TH_LEFT_MAX)   return BtnEvent::LEFT;
  return BtnEvent::IDLE;
}

void ButtonManager::poll() {
  long sum = 0;
  for (int i = 0; i < 64; i++) {
    sum += analogRead(LADDER_PIN);
    delayMicroseconds(50);
  }
  int raw = sum / 64;
  int touch = digitalRead(TOUCH_PIN);

  // ── TTP223 touch tracking (for pattern entry + 5-sec-hold-to-lock) ──
  _touchPressed = false;
  _touchReleased = false;
  if (touch == HIGH && _prevTouchState == LOW) {
    _touchState = HIGH;
    _touchStartTime = millis();
    _touchPressed = true;
  } else if (touch == LOW && _prevTouchState == HIGH) {
    _lastTouchDuration = millis() - _touchStartTime;
    _touchState = LOW;
    _touchReleased = true;
  } else {
    _touchState = touch;
  }
  _prevTouchState = touch;

  // ── Anti-misread: require 2 consecutive same readings ──────────────
  // The ADC sometimes spikes into the wrong band on a single sample.
  // By requiring the SAME classification on 2 consecutive polls, we
  // eliminate phantom "UP reads as LEFT" / "DOWN reads as RIGHT" misfires.
  BtnEvent reading = classify(raw, touch);
  if (reading == _candidate) {
    _candidateCount++;
  } else {
    _candidate = reading;
    _candidateCount = 1;
  }

  // Only accept the reading as the new state if it's been stable for 2 polls.
  // IDLE is accepted immediately (we don't want to delay the "release" edge).
  BtnEvent newState;
  if (reading == BtnEvent::IDLE || _candidateCount >= 2) {
    newState = reading;
  } else {
    // Keep the previous state — the reading is unstable, probably noise.
    newState = _state;
  }

  // "Pressed" is a one-shot rising edge, not "currently active":
  //  - from IDLE, anything real (TOUCH or a ladder direction) is a new press
  //  - from TOUCH, a ladder direction is also a new press
  //  - from any ladder direction, nothing re-fires until back to IDLE
  bool fromIdle  = (_prev == BtnEvent::IDLE)  && (newState != BtnEvent::IDLE);
  bool fromTouch = (_prev == BtnEvent::TOUCH) && (newState != BtnEvent::IDLE) && (newState != BtnEvent::TOUCH);
  _pressed = fromIdle || fromTouch;
  _prev = newState;
  _state = newState;
}
