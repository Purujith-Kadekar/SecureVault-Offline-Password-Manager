#include "audio_manager.h"
#include "board_config.h"
#include "driver/ledc.h"

// ═══════════════════════════════════════════════════════════════════════════════
//  Passive buzzer — LEDC PWM output
// ═══════════════════════════════════════════════════════════════════════════════
// A passive buzzer has no internal oscillator — the MCU must drive it with
// a square wave at the desired frequency.  We use the ESP32-S3's LEDC
// (LED PWM Controller) in low-speed mode for this.

static const ledc_timer_t   BUZZ_TIMER  = LEDC_TIMER_0;
static const ledc_channel_t BUZZ_CHAN   = LEDC_CHANNEL_0;
static const ledc_mode_t    BUZZ_MODE   = LEDC_LOW_SPEED_MODE;
static const ledc_timer_bit_t BUZZ_RES  = LEDC_TIMER_8_BIT;   // 0-255 duty

bool AudioManager::begin() {
  pinMode(BUZZER_PIN, OUTPUT);
  digitalWrite(BUZZER_PIN, LOW);

  // Timer config — frequency is changed per-tone via ledc_set_freq()
  ledc_timer_config_t timerConf = {
    .speed_mode = BUZZ_MODE,
    .duty_resolution = BUZZ_RES,
    .timer_num = BUZZ_TIMER,
    .freq_hz = 1000,       // placeholder, changed before each tone
    .clk_cfg = LEDC_AUTO_CLK
  };
  if (ledc_timer_config(&timerConf) != ESP_OK) return false;

  // Channel config — routes the timer output to BUZZER_PIN
  ledc_channel_config_t chanConf = {
    .gpio_num   = (gpio_num_t)BUZZER_PIN,
    .speed_mode = BUZZ_MODE,
    .channel    = BUZZ_CHAN,
    .intr_type  = LEDC_INTR_DISABLE,
    .timer_sel  = BUZZ_TIMER,
    .duty       = 0,
    .hpoint     = 0
  };
  if (ledc_channel_config(&chanConf) != ESP_OK) return false;

  _ok = true;
  return true;
}

void AudioManager::silence() {
  ledc_set_duty(BUZZ_MODE, BUZZ_CHAN, 0);
  ledc_update_duty(BUZZ_MODE, BUZZ_CHAN);
}

void AudioManager::playTone(float freqHz, uint32_t ms, float volume) {
  if (!_ok || freqHz <= 0) return;

  // Clamp frequency to what the LEDC timer can actually produce at 8-bit
  // resolution.  With auto-clock (APB = 80 MHz), the minimum period is
  // 2 / (80 MHz / 2^8) = ~6.4 us => ~156 kHz max.  Well above any buzzer.
  uint32_t freq = (uint32_t)freqHz;
  if (freq < 50)  freq = 50;      // inaudible below this anyway
  if (freq > 10000) freq = 10000; // most buzzers top out around 5-8 kHz

  ledc_set_freq(BUZZ_MODE, BUZZ_TIMER, freq);

  // Duty cycle: volume controls the ratio. 50 % is a clean square wave;
  // lower values produce a quieter, thinner sound on most passive buzzers.
  uint32_t duty = (uint32_t)(volume * 255.0f);
  if (duty > 255) duty = 255;
  if (duty < 1)   duty = 1;

  ledc_set_duty(BUZZ_MODE, BUZZ_CHAN, duty);
  ledc_update_duty(BUZZ_MODE, BUZZ_CHAN);

  delay(ms);
  silence();
}

void AudioManager::play(Tone t) {
  switch (t) {
    case Tone::KEY_TICK: playTone(1800.0f, 8,  0.25f); break;
    case Tone::UNLOCK:
      playTone(880.0f,  55, 0.35f);
      playTone(1320.0f, 70, 0.35f);
      break;
    case Tone::ERROR: playTone(440.0f, 150, 0.40f); break;  // was 220Hz (too low for 8-bit LEDC)
    case Tone::LOCK:  playTone(660.0f, 60,  0.30f); break;
  }
}