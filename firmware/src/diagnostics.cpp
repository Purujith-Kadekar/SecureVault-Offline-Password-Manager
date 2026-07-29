#include "diagnostics.h"
#include <Wire.h>
#include <SPI.h>
#include <SD.h>
#include <math.h>
#include "driver/i2s_std.h"

// ---------------------------------------------------------------------
// Pin numbers. I don't have visibility into board_config.h's actual
// macro names, so these are defined locally here, matching the
// confirmed GPIO table from earlier in this project. If board_config.h
// already has named macros for these (e.g. PIN_SDA, PIN_TFT_CS, etc.),
// swap them in here for consistency -- functionally these are
// identical either way since they resolve to the same GPIO numbers.
// ---------------------------------------------------------------------
namespace {

// I2C (RTC + MPU)
constexpr int PIN_SDA = 1;
constexpr int PIN_SCL = 2;

// SD card (dedicated SPI bus)
constexpr int PIN_SD_CS   = 10;
constexpr int PIN_SD_MOSI = 11;
constexpr int PIN_SD_SCK  = 12;
constexpr int PIN_SD_MISO = 13;

// I2S (shared bus, DAC output only -- mic removed from this board revision)
constexpr int PIN_I2S_MCLK = 9;
constexpr int PIN_I2S_WS   = 21;
constexpr int PIN_I2S_BCLK = 42;
constexpr int PIN_I2S_DOUT = 38;

// Button ladder (analog)
constexpr int PIN_BUTTON_LADDER = 6;

// Touch controller (XPT2046), shared SPI bus with display
constexpr int PIN_TOUCH_CS   = 14;
constexpr int PIN_SHARED_MOSI = 15;
constexpr int PIN_SHARED_SCK  = 16;
constexpr int PIN_SHARED_MISO = 39;
// GPIO41 (T_DO) is not used by this diagnostic -- it's a secondary/alt
// data line per the board's original pin table; the standard XPT2046
// read sequence below only needs CS/MOSI/SCK/MISO.

// XPT2046 command bytes for reading X/Y position (12-bit, differential off)
constexpr uint8_t XPT2046_CMD_X = 0xD0;
constexpr uint8_t XPT2046_CMD_Y = 0x90;

} // namespace

namespace Diagnostics {

// =========================================================================
// I2C Bus Scanner
// =========================================================================
void runI2CScan() {
    Serial.println("\n===== I2C BUS SCAN =====");
    Wire.begin(PIN_SDA, PIN_SCL);
    delay(50);

    int found = 0;
    for (uint8_t addr = 1; addr < 127; addr++) {
        Wire.beginTransmission(addr);
        uint8_t err = Wire.endTransmission();
        if (err == 0) {
            found++;
            Serial.printf("  Found device at 0x%02X", addr);
            if (addr == 0x68) Serial.print("  <-- expected DS3231 RTC");
            else if (addr == 0x69) Serial.print("  <-- expected MPU6050");
            else if (addr == 0x57) Serial.print("  <-- expected AT24C32 EEPROM (on the DS3231 breakout)");
            Serial.println();
        }
    }

    if (found == 0) {
        Serial.println("  [FAIL] No I2C devices found. Check SDA/SCL wiring and pull-ups.");
    } else {
        Serial.printf("  Scan complete: %d device(s) found.\n", found);
        Serial.println("  Expecting: 0x68 (DS3231), 0x69 (MPU6050), 0x57 (AT24C32 EEPROM) -- verify all three appeared above.");
    }
    Serial.println("=========================\n");
}

// =========================================================================
// SD Card Round-Trip Test
// =========================================================================
void runSDTest() {
    Serial.println("\n===== SD CARD TEST =====");

    SPIClass sdSPI(HSPI);
    sdSPI.begin(PIN_SD_SCK, PIN_SD_MISO, PIN_SD_MOSI, PIN_SD_CS);

    if (!SD.begin(PIN_SD_CS, sdSPI)) {
        Serial.println("  [FAIL] SD.begin() failed. Check card insertion and wiring.");
        Serial.println("=========================\n");
        return;
    }
    Serial.println("  [OK] SD card mounted.");

    uint64_t cardSize = SD.cardSize() / (1024 * 1024);
    Serial.printf("  Card size: %llu MB\n", cardSize);

    const char* testPath = "/diag_test.tmp";
    const char* testPayload = "SecureVault diagnostics round-trip test";

    File wf = SD.open(testPath, FILE_WRITE);
    if (!wf) {
        Serial.println("  [FAIL] Could not open test file for writing.");
        Serial.println("=========================\n");
        return;
    }
    wf.print(testPayload);
    wf.close();
    Serial.println("  [OK] Test file written.");

    File rf = SD.open(testPath, FILE_READ);
    if (!rf) {
        Serial.println("  [FAIL] Could not open test file for reading.");
        Serial.println("=========================\n");
        return;
    }
    String readback = rf.readString();
    rf.close();

    if (readback == testPayload) {
        Serial.println("  [OK] Read-back matches written data.");
    } else {
        Serial.println("  [FAIL] Read-back mismatch!");
        Serial.printf("    Expected: %s\n", testPayload);
        Serial.printf("    Got:      %s\n", readback.c_str());
    }

    SD.remove(testPath);
    Serial.println("  [OK] Test file cleaned up.");
    Serial.println("=========================\n");
}

// =========================================================================
// SD Seek+Write Test (v10.0 -- validates the SVR1 vault format's core
// assumption: that seek() + write() can patch bytes in the MIDDLE of an
// existing file without truncating/appending past what follows).
//
// The original vault.db format only ever wrote sequentially from byte 0
// of a freshly (re)created file, so this behavior was never exercised.
// The new record-oriented format's whole efficiency gain depends on it:
// ADD/UPDATE/DELETE seek to a specific row/data offset inside an
// ALREADY-POPULATED file and overwrite just those bytes, expecting
// everything after the write to survive untouched.
//
// If your Arduino-ESP32 core version opens FILE_WRITE in a mode where
// writes always land at EOF regardless of a prior seek() (some versions
// of the SD/FS library have exhibited this for "a"/"a+"-style modes),
// this test will FAIL, and vault_manager.cpp's _appendRecordToSD /
// _updateRecordOnSD / _purgeRowOnSD will silently corrupt vault.db the
// first time they patch a row that isn't at the end of the file. Run
// this BEFORE trusting the new vault_manager.cpp on real hardware.
// =========================================================================
void runSDSeekWriteTest() {
    Serial.println("\n===== SD SEEK+WRITE TEST (SVR1 format prerequisite) =====");

    SPIClass sdSPI(HSPI);
    sdSPI.begin(PIN_SD_SCK, PIN_SD_MISO, PIN_SD_MOSI, PIN_SD_CS);
    if (!SD.begin(PIN_SD_CS, sdSPI)) {
        Serial.println("  [FAIL] SD.begin() failed. Check card insertion and wiring.");
        Serial.println("===========================================================\n");
        return;
    }

    const char* testPath = "/diag_seek_test.tmp";
    SD.remove(testPath);

    // Step 1: write "AAAAAAAAAA BBBBBBBBBB CCCCCCCCCC" (32 bytes) from
    // scratch -- this part matches what the OLD format always did, and
    // is expected to work regardless.
    const char* original = "AAAAAAAAAA BBBBBBBBBB CCCCCCCCCC";
    File wf = SD.open(testPath, FILE_WRITE);
    if (!wf) {
        Serial.println("  [FAIL] Could not open test file for initial write.");
        Serial.println("===========================================================\n");
        return;
    }
    wf.print(original);
    wf.close();
    Serial.println("  [OK] Wrote 32-byte baseline file.");

    // Step 2: reopen, seek to offset 11 (start of the "BBBBBBBBBB" block),
    // and overwrite just those 10 bytes with "XXXXXXXXXX" -- WITHOUT
    // rewriting the " CCCCCCCCCC" that follows. This is exactly the
    // pattern _updateRecordOnSD/_writeRowToFile/_writeDataEndToFile rely on.
    File pf = SD.open(testPath, FILE_WRITE);
    if (!pf) {
        Serial.println("  [FAIL] Could not reopen test file for the mid-file patch.");
        Serial.println("===========================================================\n");
        return;
    }
    bool seekOk = pf.seek(11);
    size_t written = seekOk ? pf.write((const uint8_t*)"XXXXXXXXXX", 10) : 0;
    pf.flush();
    pf.close();

    if (!seekOk) {
        Serial.println("  [FAIL] File::seek() returned false -- seeking isn't supported at all.");
        Serial.println("===========================================================\n");
        return;
    }
    if (written != 10) {
        Serial.printf("  [FAIL] write() after seek only wrote %u of 10 bytes.\n", (unsigned)written);
        Serial.println("===========================================================\n");
        return;
    }

    // Step 3: read the whole file back and check BOTH that bytes 11-20
    // became "XXXXXXXXXX" AND that the file is still 32 bytes long with
    // " CCCCCCCCCC" intact at the end -- if the write silently truncated
    // the file to 21 bytes (offset 11 + 10 written), that's the failure
    // mode this test exists to catch.
    File rf = SD.open(testPath, FILE_READ);
    if (!rf) {
        Serial.println("  [FAIL] Could not reopen test file for readback.");
        Serial.println("===========================================================\n");
        return;
    }
    size_t finalSize = rf.size();
    String readback = rf.readString();
    rf.close();
    SD.remove(testPath);

    const char* expected = "AAAAAAAAAA XXXXXXXXXX CCCCCCCCCC";
    Serial.printf("  File size after patch: %u bytes (expected 32)\n", (unsigned)finalSize);
    Serial.printf("  Content after patch:   %s\n", readback.c_str());

    if (finalSize == 32 && readback == expected) {
        Serial.println("  [PASS] seek()+write() patches mid-file bytes correctly.");
        Serial.println("  --> The SVR1 incremental ADD/UPDATE/DELETE path is safe to use.");
    } else if (readback.startsWith("AAAAAAAAAA XXXXXXXXXX") && finalSize < 32) {
        Serial.println("  [FAIL] The write TRUNCATED the file at the patch point --");
        Serial.println("         everything after the seek offset was lost.");
        Serial.println("  --> DO NOT use the incremental SD writes in vault_manager.cpp");
        Serial.println("      as-is. _appendRecordToSD/_updateRecordOnSD/_purgeRowOnSD/");
        Serial.println("      _writeRowToFile/_writeDataEndToFile all assume seek()+write()");
        Serial.println("      preserves trailing bytes. This SD/FS library version doesn't.");
        Serial.println("      Options: try opening with the raw mode string \"r+\" instead of");
        Serial.println("      FILE_WRITE, or fall back to Option B (append-only log) instead.");
    } else {
        Serial.println("  [FAIL] Unexpected content -- investigate before trusting either path.");
    }
    Serial.println("===========================================================\n");
}

// =========================================================================
// I2S Tone Sweep (CS4344 DAC)
// =========================================================================
void runI2SToneSweep() {
    Serial.println("\n===== I2S TONE SWEEP =====");
    Serial.println("  NOTE: assumes audio_manager has NOT already claimed this");
    Serial.println("  I2S channel -- if this fails with ESP_ERR_INVALID_STATE or");
    Serial.println("  similar, audio_manager already owns the bus. Run this test");
    Serial.println("  in isolation, before audio_manager init.");

    constexpr uint32_t SAMPLE_RATE = 16000;

    i2s_chan_handle_t tx_handle = NULL;
    i2s_chan_config_t chan_cfg = I2S_CHANNEL_DEFAULT_CONFIG(I2S_NUM_0, I2S_ROLE_MASTER);
    esp_err_t err = i2s_new_channel(&chan_cfg, &tx_handle, NULL);
    if (err != ESP_OK) {
        Serial.printf("  [FAIL] i2s_new_channel: %s\n", esp_err_to_name(err));
        Serial.println("===========================\n");
        return;
    }

    i2s_std_config_t std_cfg = {
        .clk_cfg = I2S_STD_CLK_DEFAULT_CONFIG(SAMPLE_RATE),
        .slot_cfg = I2S_STD_PHILIPS_SLOT_DEFAULT_CONFIG(I2S_DATA_BIT_WIDTH_16BIT, I2S_SLOT_MODE_MONO),
        .gpio_cfg = {
            .mclk = (gpio_num_t)PIN_I2S_MCLK,
            .bclk = (gpio_num_t)PIN_I2S_BCLK,
            .ws   = (gpio_num_t)PIN_I2S_WS,
            .dout = (gpio_num_t)PIN_I2S_DOUT,
            .din  = I2S_GPIO_UNUSED,
        },
    };

    err = i2s_channel_init_std_mode(tx_handle, &std_cfg);
    if (err != ESP_OK) {
        Serial.printf("  [FAIL] i2s_channel_init_std_mode: %s\n", esp_err_to_name(err));
        i2s_del_channel(tx_handle);
        Serial.println("===========================\n");
        return;
    }

    err = i2s_channel_enable(tx_handle);
    if (err != ESP_OK) {
        Serial.printf("  [FAIL] i2s_channel_enable: %s\n", esp_err_to_name(err));
        i2s_del_channel(tx_handle);
        Serial.println("===========================\n");
        return;
    }
    Serial.println("  [OK] I2S TX channel active. Sweeping 200Hz -> 2000Hz...");

    constexpr int SWEEP_SAMPLES = 256;
    int16_t buf[SWEEP_SAMPLES];

    for (int freq = 200; freq <= 2000; freq += 100) {
        for (int i = 0; i < SWEEP_SAMPLES; i++) {
            float phase = 2.0f * PI * freq * i / SAMPLE_RATE;
            buf[i] = (int16_t)(sinf(phase) * 8000);  // moderate volume, avoid clipping
        }
        size_t written = 0;
        // Write the tone repeatedly for ~80ms per frequency step
        for (int rep = 0; rep < 5; rep++) {
            i2s_channel_write(tx_handle, buf, sizeof(buf), &written, pdMS_TO_TICKS(100));
        }
    }

    Serial.println("  [OK] Sweep complete.");
    i2s_channel_disable(tx_handle);
    i2s_del_channel(tx_handle);
    Serial.println("===========================\n");
}

// =========================================================================
// Button Ladder Raw ADC Dump
// =========================================================================
void runButtonLadderDump() {
    Serial.println("\n===== BUTTON LADDER RAW DUMP =====");
    Serial.println("  Press each button, watch for distinct ADC values.");
    Serial.println("  Ctrl+C / reset to stop (this runs for 15 seconds).");

    uint32_t start = millis();
    while (millis() - start < 15000) {
        int raw = analogRead(PIN_BUTTON_LADDER);
        Serial.printf("  GPIO%d raw ADC: %d\n", PIN_BUTTON_LADDER, raw);
        delay(200);
    }
    Serial.println("===================================\n");
}

// =========================================================================
// Touch Controller Raw ADC Dump (direct XPT2046 SPI read, own CS)
// =========================================================================
namespace {
    uint16_t xpt2046ReadChannel(SPIClass &spi, uint8_t cmd) {
        digitalWrite(PIN_TOUCH_CS, LOW);
        spi.transfer(cmd);
        uint16_t hi = spi.transfer(0x00);
        uint16_t lo = spi.transfer(0x00);
        digitalWrite(PIN_TOUCH_CS, HIGH);
        uint16_t value = ((hi << 8) | lo) >> 3;  // 12-bit result, right-aligned
        return value;
    }
}

void runTouchRawDump() {
    Serial.println("\n===== TOUCH RAW ADC DUMP =====");
    Serial.println("  Touch the screen, watch for changing X/Y values.");
    Serial.println("  This runs for 15 seconds.");
    Serial.println("  NOTE: shares the display's SPI bus via its own CS (GPIO14).");
    Serial.println("  Do not run this concurrently with active display rendering.");

    pinMode(PIN_TOUCH_CS, OUTPUT);
    digitalWrite(PIN_TOUCH_CS, HIGH);

    SPIClass touchSPI(FSPI); // ESP32-S3 only has FSPI/HSPI general-purpose SPI hosts — no VSPI
    touchSPI.begin(PIN_SHARED_SCK, PIN_SHARED_MISO, PIN_SHARED_MOSI, PIN_TOUCH_CS);
    touchSPI.beginTransaction(SPISettings(1000000, MSBFIRST, SPI_MODE0));

    uint32_t start = millis();
    while (millis() - start < 15000) {
        uint16_t x = xpt2046ReadChannel(touchSPI, XPT2046_CMD_X);
        uint16_t y = xpt2046ReadChannel(touchSPI, XPT2046_CMD_Y);
        Serial.printf("  Raw X: %4d  Raw Y: %4d\n", x, y);
        delay(200);
    }

    touchSPI.endTransaction();
    Serial.println("================================\n");
}

// =========================================================================
void runAll() {
    Serial.println("\n\n########## SECUREVAULT HARDWARE DIAGNOSTICS ##########\n");
    runI2CScan();
    runSDTest();
    runSDSeekWriteTest();
    runI2SToneSweep();
    runButtonLadderDump();
    runTouchRawDump();
    Serial.println("########## DIAGNOSTICS COMPLETE ##########\n");
}

} // namespace Diagnostics
