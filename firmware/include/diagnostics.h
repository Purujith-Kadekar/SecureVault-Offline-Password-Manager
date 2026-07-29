#pragma once
/*
 * SecureVault -- Hardware Diagnostics Module
 * ---------------------------------------------------------------------
 * Standalone hardware self-test. Deliberately does NOT call into
 * rtc_manager / mpu_manager / sd_manager / audio_manager / display_manager
 * internals -- it owns its own bus handles for everything it tests, so it
 * can run independently of boot order and can never corrupt state those
 * managers are relying on.
 *
 * Only dependency: board_config.h, for pin numbers.
 *
 * IMPORTANT CAVEATS (please read before wiring this into main.cpp):
 *
 * 1. I2S tone sweep claims its OWN I2S channel on I2S_NUM_0, using the
 *    same physical pins as audio_manager (MCLK=9, BCLK=42, WS=21,
 *    DOUT=38). It assumes audio_manager has NOT already called
 *    i2s_channel_enable() on those pins when this runs -- ESP-IDF's I2S
 *    driver will fail to claim an already-enabled channel/pin set. Call
 *    runI2SDiagnostic() BEFORE audio_manager initializes, or run
 *    diagnostics in total isolation (e.g. a dedicated test build), not
 *    concurrently with normal app operation.
 *
 * 2. I2S config here (16kHz, 16-bit, mono, Philips standard) is a
 *    reasonable default for the CS4344 but is NOT confirmed against the
 *    actual audio_manager.cpp config, which I don't have visibility
 *    into. If audio_manager uses a different sample rate / bit depth,
 *    that's fine for THIS test in isolation (it's just a tone sweep, not
 *    shared playback), but flag it if you want the two to match exactly.
 *
 * 3. Touch dump reads the XPT2046 directly via its own CS toggle
 *    (T_CS = GPIO14) on the shared SPI bus (MOSI=15, SCK=16, MISO=39).
 *    It does not call anything in display_manager -- it's a fully
 *    independent raw SPI transaction, safe to share the bus with the
 *    display driver as long as they don't run concurrently in different
 *    tasks (standard multi-device-per-bus SPI practice).
 *
 * 4. SD test performs a real write + read-back + delete of a temp file
 *    (`/diag_test.tmp`) on its own SPIClass instance. It does not touch
 *    any files sd_manager/vault_manager may have open elsewhere -- but
 *    if the vault SD card is actively mounted/in-use by sd_manager when
 *    this runs, sharing the physical SD bus with a second independent
 *    SPIClass instance is safe electrically, but the two should still
 *    not be issuing commands at the exact same time. Same rule as #1 --
 *    run this in isolation, not mid-operation.
 */

#include <Arduino.h>

namespace Diagnostics {

// Runs every diagnostic in sequence, printing results to Serial.
// Call this from a dedicated test entry point (not the normal boot
// path) -- see caveats above about I2S/SD bus contention.
void runAll();

// Individual tests, callable standalone if you only want one:
void runI2CScan();          // Scans I2C bus, reports found addresses (expects RTC @0x68, MPU @0x69)
void runSDTest();           // Write/read-back/delete round-trip test on the microSD card
void runSDSeekWriteTest();  // v10.0: verifies seek()+write() can patch bytes MID-FILE without
                            // truncating what follows -- the SVR1 vault format's incremental
                            // ADD/UPDATE/DELETE depend entirely on this working. Run this once
                            // on real hardware before trusting the new vault_manager.cpp.
void runI2SToneSweep();     // Plays a frequency sweep tone through the CS4344 DAC
void runButtonLadderDump(); // Continuously prints raw ADC value from the button resistor ladder (GPIO6)
void runTouchRawDump();     // Continuously prints raw X/Y/Z touch ADC values from the XPT2046

} // namespace Diagnostics
