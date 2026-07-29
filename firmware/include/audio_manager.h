#pragma once
// ═══════════════════════════════════════════════════════════════════════════════
//  audio_manager.h — Passive buzzer via LEDC PWM
// ═══════════════════════════════════════════════════════════════════════════════
// Replaces the I2S DAC output with a simple passive buzzer driven by the
// ESP32-S3's LEDC peripheral.  A passive buzzer produces different pitches
// when driven at different PWM frequencies — tone duration is controlled
// by blocking delay (all tones are short: 8–150 ms).
//
// Buzzer GPIO is set in board_config.h (BUZZER_PIN).  Change it there to
// match your board's physical connection.
#include <Arduino.h>

enum class Tone { KEY_TICK, UNLOCK, ERROR, LOCK };

class AudioManager {
public:
  bool begin();
  bool isOK() const { return _ok; }

  // Blocking — tones are all short (8-150 ms) by design, so the brief stall
  // is intentional/imperceptible UI feedback, not an accidental freeze.
  void play(Tone t);

private:
  bool _ok = false;
  void playTone(float freqHz, uint32_t ms, float volume);
  void silence();
};