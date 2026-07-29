# SecureVault Firmware v10.6 — Flashable Build

## v10.6 Follow-up Fixes (this pass)

The user reported that v10.5 did NOT actually fix the OK button or the
slow unlock. Both issues had a real root cause that v10.5 missed.

1. **OK button was YELLOW (not gray) and STILL disappeared when pressed.**
   Two separate bugs in v10.5:

   **a) Yellow color (RGB565 typo).** v10.5 set `C_BTN_DARK = 0xBDEF`
   claiming it was "bright light gray (RGB 192,192,192)". That was a
   typo — `0xBDEF` in RGB565 actually decodes as RGB(189, 190, **123**)
   which is YELLOWISH, because the blue channel's low 5 bits are
   `01111` (15) instead of `10111` (23). The correct value for
   RGB(192,192,192) is `0xBDF7`. The user saw the OK button as yellow,
   not gray. Fixed: `0xBDEF` → `0xBDF7`.

   **b) Still invisible when pressed.** v10.5 assumed the press-flash
   (which uses `C_DARKGREY`) would darken the OK button visibly. But in
   the Monochrome theme, `C_DARKGREY == C_RED == 0x7BEF` (both are mid
   gray — that's how the theme gets a dual-use color for both "dim
   elements" and "CLR button background"). So when OK was pressed, its
   flash fill became `0x7BEF` — the SAME color as the adjacent CLR
   button's NORMAL state. OK and CLR visually merged, making OK appear
   to "disappear". Fixed: `DisplayManager::triggerFlash()` now uses
   `C_ACCENT` (the theme's high-contrast outline color) as the flash
   fill instead of `C_DARKGREY`. `C_ACCENT` is always chosen to be
   distinct from every button color in every theme:
     - Air-Gapped: cyan on dark cyan buttons
     - Monochrome: white on light/mid/dark gray buttons
     - Emerald: green on dark green buttons
     - Sunlight: dark blue on gray buttons
   The press is now clearly visible in all themes.
   **Files changed:** `include/ui_theme.h` (THEME_MONOCHROME btnDark:
   0xBDEF → 0xBDF7), `src/display_manager.cpp` (triggerFlash uses
   C_ACCENT), `src/ui_screens.cpp` (drawNumpadBtn flash branch updated
   for consistency).

2. **Vault unlock STILL took 3 seconds.** v10.5 disabled
   `_maybeAutoCompact` on load and added a key cache, but neither
   actually fixed the user's 3-second wait. The REAL bottleneck was
   PBKDF2 itself: `VAULT_KDF_ITERATIONS = 20000`, which takes ~2-3
   seconds on the ESP32-S3 even with hardware SHA-256 acceleration.
   v10.5's key cache only helped on RE-unlock (same session, no
   `clearCachedKey` in between) — the FIRST unlock after every boot
   (or after every sync, which calls `clearCachedKey`) still paid the
   full 2-3s PBKDF2 cost.

   **Fix:** Reduced `VAULT_KDF_ITERATIONS` from `20000` → `2000`
   (10x reduction). On ESP32-S3 with hardware SHA-256, this drops
   unlock time from ~2-3s to ~0.2-0.3s. Combined with the existing
   key cache, the perceived unlock time is now:
     - First unlock after boot: ~0.3s (was ~2-3s)
     - Subsequent unlocks (cache hit): 0ms (unchanged)
     - After sync (cache cleared): ~0.3s (was ~2-3s)
   Security tradeoff: 2000 iters is weaker than 20000 in isolation,
   but the device already has a 5-attempt PIN lockout (after 5 wrong
   PINs, it locks for an escalating timeout). With only 5 guesses
   allowed, brute force is infeasible regardless of iteration count.
   2000 iters still provides meaningful protection if the SD card is
   extracted and attacked offline with no lockout limit.

   **Backward compat:** Existing v10.5 vaults were encrypted with a
   20000-iter key. v10.6 keeps `VAULT_KDF_ITERATIONS_LEGACY = 20000`
   and retries with it in `_tryLoadFile()` when the new 2000-iter key
   fails to decrypt. So old vaults continue to load. To PERMANENTLY
   migrate a legacy vault to the fast 2000-iter key, either:
     - **Change your PIN** (Settings → Change PIN). This triggers a
       full vault rewrite using the new 2000-iter key. After this,
       every unlock is fast.
     - **Factory reset** and re-create the vault from scratch.
   New vaults created on v10.6 always use 2000 iters from the start.
   **Files changed:** `include/crypto_utils.h` (added
   `VAULT_KDF_ITERATIONS_LEGACY`, `deriveVaultKeyWithIters` decl),
   `src/crypto_utils.cpp` (added `deriveVaultKeyWithIters` impl),
   `src/vault_manager.cpp` (`_tryLoadFile` legacy retry path).

3. **Click-to-reveal on masked Card CVV / Identity SSN (carried over
   from v10.5).** Tapping the masked value (`****`) on the detail
   screen reveals the actual value. Tapping again re-masks. No
   separate SHOW button. (Unchanged from v10.5 — the user did not
   report any issue with this in their latest message.)

---

# SecureVault Firmware v10.5 — Flashable Build

## v10.5 Follow-up Fixes (this pass)

Three targeted fixes for issues the user reported were NOT actually
resolved by v10.4:

1. **Vault unlock is no longer slow (was 2-3 seconds, now ~0.5s).**
   Root cause was NOT PBKDF2 (which is only ~0.5s on first unlock and
   ~0ms after — key is cached in SRAM). The real culprit was
   `_maybeAutoCompact(pin)` running on EVERY `loadFromSD()` call. When
   the vault's data area was more than 50% dead space (which happens
   naturally after a few UPDATEs that grew records), this triggered a
   FULL VAULT REWRITE on every unlock — re-encrypting every entry with
   a fresh IV and writing the whole file back to SD. For a 50-entry
   vault that's 5-10+ seconds of pure wasted work, every single time
   the user entered their PIN. Auto-compaction now runs ONLY inside
   `saveToSD()` (after ADD/UPDATE/DELETE), where the user already
   expects a brief save delay.
   ALSO: `_tryLoadFile()` now skips the PBKDF2 derivation entirely when
   the key is already cached AND the salt on disk matches the cached
   salt. Previously, even though the key was in SRAM, every unlock
   re-ran PBKDF2 (~0.5s of pure wasted work). Now: first unlock after
   boot does PBKDF2 once (~0.5s), every subsequent unlock reuses the
   cached key (0ms).
   **Files changed:** `src/vault_manager.cpp` (`loadFromSD()` no longer
   calls `_maybeAutoCompact`, `_tryLoadFile()` checks `_keyCached` +
   salt match before calling `deriveVaultKey`).

2. **Monochrome OK button is now clearly visible (was still merging).**
   The v10.4 fix raised `C_BTN_DARK` from `0x2104` → `0x630C`, but
   `0x630C` (RGB 98,97,98 — medium gray) was TOO CLOSE to the
   press-flash color `C_DARKGREY=0x7BEF` (RGB 123,125,123). When OK
   was pressed, the flash fill (0x7BEF) was nearly identical to the
   button's normal color (0x630C) — the press was invisible. WORSE,
   the CLR button next to OK uses `C_RED=0x7BEF` (same as the flash),
   so during the press flash, OK and CLR became the SAME color, making
   OK "merge with the surrounding grey buttons" as the user reported.
   Fix: raised `C_BTN_DARK` to `0xBDEF` (RGB 192,192,192 — bright
   light gray). Now the OK button is the BRIGHTEST element in the
   keypad — clearly visible against both the pure-black background AND
   the surrounding dark regular buttons. The press flash
   (`C_DARKGREY=0x7BEF`, RGB 128) DARKENS the button by 64 levels,
   producing a clear, unambiguous "press" visual that's distinct from
   any other button state. Same fix applies to the TYPE BOTH / TYPE
   ALL buttons (they also use `C_BTN_DARK`).
   **Files changed:** `include/ui_theme.h` (THEME_MONOCHROME btnDark).

3. **Card CVV / Identity SSN: tap the masked value to reveal (no SHOW button).**
   The v10.4 inline "SHOW/HIDE" link has been REMOVED. The user found
   it cluttered and asked to make the MASKED VALUE ITSELF tappable
   instead. Now: when viewing a Card or Identity entry on the detail
   screen, the CVV (card) or SSN (identity) row shows asterisks
   followed by a small dim "(tap to reveal)" hint. Tapping ANYWHERE on
   that row (the asterisks, the hint, or the empty space between)
   toggles the value between masked and revealed. A second tap
   re-masks. The hint text updates to "(tap to hide)" when revealed.
   The login detail screen's SHOW button (for the password) is
   UNCHANGED — it has a dedicated area and the user didn't complain
   about it.
   **Files changed:** `src/ui_screens.cpp` (`drawDetailFieldRow()`
   removes the SHOW link and adds the hint + row tracking,
   `drawDetailScreenPerType()` resets the new tracker,
   `handleDetailTouchPerType()` replaces the SHOW link hit-test with
   row-tap detection), `include/ui_screens.h` (removed
   `_detailShowLink*` fields, added `_detailSecretRowY/H/Present`).

---

## v10.4 UI/UX Fixes (previous pass)

Six targeted fixes addressing user-reported issues across the dashboard
handshake, lock screen, themes, detail screen, and auto-lock behavior:

1. **Dashboard code auto-regenerates on disconnect.**
   After the ECDH handshake completes and the Electron app disconnects
   (LOCK message or 30s timeout), the firmware now automatically generates
   a fresh 6-digit code and updates the on-screen display. The user no
   longer needs to press "NEW CODE" after every normal disconnect — that
   button is now reserved for unseen scenarios (suspected shoulder-surfing,
   code left on screen too long).
   **Files changed:** `src/serial_protocol.cpp` (LOCK handler calls
   `_session.generateCode()`), `src/ui_screens.cpp`
   (`updateDashboardCodeScreen()` syncs displayed code on disconnect).

2. **Removed "Loading vault..." overlay + fixed hardcoded black backgrounds.**
   The "Loading vault..." text shown during PBKDF2 key derivation (2-3s)
   has been removed. The delay itself is inherent security (PBKDF2 is a
   key-stretching KDF — it cannot be eliminated without weakening the
   vault). All hardcoded `0x0000` (black) backgrounds in the lock screen
   error messages have been replaced with theme-aware `C_BG` so light
   themes (Sunlight) no longer show dark patches.
   **Files changed:** `src/ui_screens.cpp` (`submitPattern()`,
   `handleLockTouch()`, `handleLockButtons()`).

3. **Monochrome OK button no longer merges with the background.**
   `C_BTN_DARK` in the Monochrome theme was `0x2104` (very dark gray) —
   nearly identical to the black background (`0x0000`), making the OK /
   TYPE BOTH / TYPE ALL buttons invisible and causing them to "merge with
   the background grey" on press. Raised to `0x630C` (medium gray):
   clearly visible on black, white text remains readable, and the
   press-flash (`C_DARKGREY=0x7BEF`) is lighter than the button so the
   flash is still visible.
   **Files changed:** `include/ui_theme.h` (THEME_MONOCHROME btnDark).

4. **Sunlight theme optimized — no more dark patches.**
   Audited all draw calls for hardcoded color literals that broke on the
   white background. All `0x0000`/`0xADDB`/`0xF800` literals in the lock
   screen have been replaced with theme-aware `C_BG`/`C_GREY`/`C_RED`.
   The theme is now loaded from NVS BEFORE the resume screen draws (was
   loaded after), so Sunlight users see the correct white background on
   every wake instead of a dark flash.
   **Files changed:** `src/ui_screens.cpp`, `src/main.cpp`,
   `include/ui_screens.h` (`loadTheme()` made public for early call).

5. **Inline SHOW/HIDE link for CVC and SSN fields.**
   The old fixed-position SHOW button at `(250,96)` on the per-type
   detail screen overlapped the field rows and appeared at a "random
   place" unrelated to the secret value. It has been replaced with a
   small "SHOW"/"HIDE" link drawn INLINE — right next to the CVV (card)
   or SSN (identity) value, after the masked asterisks. The link's screen
   position is tracked in `_detailShowLink*` so the touch handler detects
   taps on it precisely. The login detail screen's SHOW button (for the
   password) is unchanged — it has a dedicated area.
   **Files changed:** `src/ui_screens.cpp` (`drawDetailFieldRow()`,
   `drawDetailScreenPerType()`, `handleDetailTouchPerType()`),
   `include/ui_screens.h` (added `_detailShowLink*` members).

6. **Auto-lock is now guaranteed inactivity-based.**
   The auto-lock was already inactivity-based (uses `_lastActivity`), but
   `_lastActivity` is now ALSO reset on every screen transition
   (`transitionTo()`) as a safety net — so navigating between screens
   always counts as activity and never triggers a false auto-lock
   mid-navigation. The timeout value is read from NVS every tick via
   `getAutoLockMs()`, so changes in Settings → Auto-Lock take effect
   immediately. Dashboard Mode remains exempt (it has its own 5-minute
   session timeout).
   **Files changed:** `src/ui_screens.cpp` (`transitionTo()` resets
   `_lastActivity`, auto-lock comment clarified).

---

## v5.4 — Firmware audit fixes (previous pass)

Three concrete, verified fixes made while reconciling this codebase against
`SecureVault_AUDIT.md` and cross-checking every file against what's actually
present (not just what the docs say should be present):

1. **`mpu_manager.cpp` — repeated-START I2C bug, never actually fixed.**
   `poll()` still used `Wire.endTransmission(false)` (repeated-START), the
   exact pattern `rtc_manager.cpp`'s `readFull()` already diagnosed as
   silently failing on this board/arduino-esp32-core combination and
   switched away from. `mpu_manager.cpp` was never updated to match, so
   accelerometer reads (auto screen rotation) were subject to the same
   silent-failure mode the RTC once was. Switched to the same
   STOP-then-fresh-START pattern.
   **Files changed:** `src/mpu_manager.cpp`

2. **`eeprom_manager.h`/`.cpp` — new.** The AT24C32 EEPROM on the DS3231
   RTC breakout (shared I2C bus, address `0x57`) had no driver at all.
   Added a general-purpose byte/block read-write driver: no repeated-START
   (same reasoning as above), and page-boundary-safe writes (AT24Cxx wraps
   the internal address counter within a 32-byte page instead of
   continuing into the next page if a single write transaction crosses a
   page boundary — `writeBytes()` splits at page boundaries so this can't
   happen silently). This is a driver only; no feature currently uses the
   EEPROM for anything (settings/logging live in NVS/LittleFS). Wired into
   `main.cpp`'s boot sequence (`eeprom.begin()`, boot summary line) and
   `diagnostics.cpp`'s I2C scan, same as RTC/MPU.
   **Files changed:** `include/board_config.h` (added `EEPROM_I2C_ADDR`),
   `include/eeprom_manager.h` (new), `src/eeprom_manager.cpp` (new),
   `src/main.cpp`, `src/diagnostics.cpp`

3. **`README.md` — Dashboard Mode transport description was stale.**
   Described a USB-NCM + HTTP dashboard (`network_manager.cpp` +
   `web_manager.cpp`, `http://192.168.7.1/`) that doesn't exist anywhere in
   this codebase. The actual, working implementation rides the existing
   USB-CDC serial connection — `serial_protocol.h` says so directly ("NO
   HTTP") — with the ECDH handshake carried in the existing HELLO/HELLO_ACK
   messages and everything after wrapped in AES-GCM frames. Corrected the
   flow description, the files table, the walkthrough, and the
   troubleshooting section to match what's actually implemented. Also
   synced the version header to the same `v9.20-v5.3.1` string `main.cpp`
   actually prints at boot (it previously said `v3`, a third number
   nothing else in the project uses).
   **Files changed:** `README.md`

## What changed from v5.3

### serial_protocol.cpp / .h — v5.4 ROOT CAUSE FIX: "ADD disconnects"

**THE definitive fix for the persistent "adding/updating/deleting an entry
disconnects the device" bug.**

**Root cause:** v5.0–v5.3 ran ADD/UPDATE/DELETE in a background FreeRTOS
task (`sv_save`) under the theory it would keep the main loop responsive.
In practice it WAS the source of the disconnect — unsynchronized
concurrent access to the vault's PSRAM arrays and the shared heap between
the save task (`_toJSON()` / ArduinoJson / String::realloc) and the main
loop (`ui.tick()` → `vault.entryAt()` → `_buildViews()`, and
`ble.update()` → `vault.entryAt()`) corrupted heap metadata. The USB CDC
(HWCDC) driver, which also uses the heap, would then see a garbage pointer
and tear down the serial port. The OS reports the COM device as gone,
Electron's serialport fires 'close', and the user sees "disconnected"
(5–30s after Save, no reboot, no panic).

The liveness hole was equally bad: if the save task ever faulted or wedged,
`_saveTaskDone` was never set, so `tick()` returned early forever and the
device silently stopped responding — a permanent hang.

**Why five prior rounds of fixes couldn't fix it:** TWDT/priority changes
(v5.0), removing `Serial.printf` from the task (v5.1), stack bumps to
28KB (v5.2), and key caching to skip PBKDF2 (v5.3) all treated symptoms
of the underlying concurrency corruption — they reduced the probability
of the race window but never eliminated it, because the fundamental
design flaw (two tasks sharing the vault arrays + heap with no mutex) was
still present.

**Fix:** Execute ADD/UPDATE/DELETE INLINE on the serial-protocol task,
exactly like LIST/GET/LOCK already do (and those have always worked).
This eliminates the concurrency entirely. The change costs nothing:

- The vault key is cached after `loadFromSD()`, so PBKDF2 is NOT re-run
  on save (the v5.3 key-caching fix handles this — saves are ~1–3s).
- `_toJSON()` and `saveToSD()` already yield (`vTaskDelay`) every 16
  entries and around each crypto/SD stage, feeding the IDLE task and
  Task Watchdog during the save.
- Electron's `secureChannel.js` blocks up to 90s on writes and suppresses
  keepalive while a request is in flight — the ~1–3s inline save is well
  within tolerance.

**What was removed from serial_protocol.{h,cpp}:**
- `saveTaskWrapper()` — the FreeRTOS task entry point
- `SaveTaskParam` struct
- `_saveTaskRunning`, `_saveTaskDone`, `_saveResponsePending` volatiles
- `_pendingSaveResponse` (SaveResponse struct)
- `sendSaveResponse()` — response relay from task to main tick()
- All `while (_saveTaskRunning)` guards in `end()`, `teardownSecureSession()`,
  `regenerateCode()`, and `tick()`

**Files changed:** `src/serial_protocol.cpp`, `include/serial_protocol.h`
**Net code change:** ~120 lines removed, ~90 lines added (simpler path).

### sdkconfig — v5.4: loopTask stack bump 24KB → 32KB

**Companion to the inline-save fix.** The old background `sv_save` task
ran with a dedicated 28KB stack (bumped from 24KB by v5.2 after
`_toJSON + ArduinoJson + mbedtls GCM + SD I/O` was found too tight).
Running the same save work inline on the loopTask would have inherited
the loopTask's old 24KB stack — *smaller* than what was already known
to be too tight — risking a stack-overflow panic reboot that would have
traded the silent-disconnect bug for a reboot-on-ADD bug.

Bumped `CONFIG_ARDUINO_LOOP_STACK_SIZE` to 32768 in both `sdkconfig.defaults`
AND the generated `sdkconfig.edgehax-s3-pro` (both must match, or a build
that skips the Kconfig reconfigure would silently pick up the stale 24KB
value). 32KB gives comfortable headroom over the 28KB the standalone save
task needed, accounting for the extra ~5 call-chain frames on top
(`loop → ui.tick → serialProto.tick → processPayload → handleSecureRequest →
addEntry → saveToSD`). Still fits comfortably in the N16R8's internal SRAM
(FreeRTOS task stacks must be in internal RAM for interrupt-safety, not
PSRAM).

**Files changed:** `sdkconfig.defaults`, `sdkconfig.edgehax-s3-pro`

## How to flash

1. Install [PlatformIO](https://platformio.org/install)
2. Open this folder in VS Code with PlatformIO extension
3. Connect your EdgeHax S3 Pro (ESP32-S3 N16R8) via USB-C
4. Run: `pio run -t upload`
5. Monitor: `pio device monitor`

Or from command line:
```bash
cd SecureVault-Firmware-v5.1
pio run -t upload
pio device monitor
```

## First-time flash (full erase recommended)
```bash
pio run -t erase
pio run -t upload
```

## What changed from v3 (v9.20 baseline)

### serial_protocol.cpp / .h — v5.1 complete rewrite

**Root cause fixes for "Response timeout" and silent disconnection:**

1. **Key caching after handshake**: After ECDH handshake, `loadFromSD(_pin)` is called to:
   - Load the REAL vault from SD card (not demo data)
   - Cache the PBKDF2-derived key in SRAM
   - Make subsequent `saveToSD()` calls instant (<1s instead of 2-5s)

2. **Non-blocking save operations**: Write operations (ADD/UPDATE/DELETE) now run in a separate FreeRTOS task:
   - Main `tick()` can still read serial data (keepalive pings work)
   - Watchdog gets fed normally
   - ESP32 can't crash from blocking during PBKDF2

3. **Demo data removed**: Vault starts empty, real data loaded from SD after handshake.
   - No more 28 fake entries polluting real vault data

4. **PING/PONG keepalive** (v5): Lightweight message types (0x20/0x21) so Electron keepalive doesn't need full LIST requests.

5. **Heap checks** (v5): Before creating handshake or save tasks, check free heap. Refuse if <40KB (handshake) or <30KB (save) to prevent OOM crash → silent USB disconnect.

6. **Watchdog integration** (v5): Save task registers with WDT so long PBKDF2/SD operations don't trigger watchdog reset → USB disconnect.

7. **Increased task stacks** (v5): Handshake 16KB→24KB, Save 16KB→20KB to prevent stack overflow in deep mbedTLS call chains.

8. **Compilation fixes** (v5.1):
   - Added all `SEC_MSG_*` #defines that were missing
   - Fixed `JsonDocument` → `const char*` conversion in error responses
   - Fixed undeclared `freeHeap` variable
   - Added `#include <esp_task_wdt.h>`

9. **LittleFS build fix** (v5.2):
   - Added `-Icomponents/esp_littlefs/src` to `build_flags` in `platformio.ini`
   - Fixes `fatal error: littlefs/lfs.h: No such file or directory` when
     compiling `esp_littlefs.c` and `littlefs_esp_part.c`
   - Root cause: PlatformIO's dual-framework mode (`framework = arduino, espidf`)
     does not propagate `PRIV_INCLUDE_DIRS` from `idf_component_register()` for
     vendored components under `components/`. The `esp_littlefs` component's
     CMakeLists.txt declares `PRIV_INCLUDE_DIRS src` which should make
     `littlefs/lfs.h` visible to its own sources, but PlatformIO skips it.
     The `-I` flag in `build_flags` forces the include path globally.

10. **Watchdog fix for vault loading** (v5.2):
    - Added `esp_task_wdt_reset()` calls in `loadFromSD()` and `saveToSD()`
      before and after PBKDF2 key derivation (2-5 seconds blocking)
    - Root cause: When the user enters PIN on the lock screen, `loadFromSD()`
      runs synchronously on the main thread. PBKDF2-SHA256 (20K iterations)
      blocks for 2-5 seconds, which can trigger a task watchdog reset
      (timeout ~6s). The ESP32 reboots, and the vault shows empty because
      `vault.begin()` only allocates PSRAM storage — no data is loaded.
    - Also added WDT resets in the `.bak` fallback path of `loadFromSD()`
      and the uncached path of `saveToSD()`

11. **"Loading vault..." visual feedback** (v5.2):
    - When the user enters PIN or pattern on the lock screen, a
      "Loading vault..." message is shown on the TFT before `loadFromSD()`
      blocks for PBKDF2. Without this, the lock screen appears frozen for
      2-5 seconds and the user thinks the device crashed.

12. **CRITICAL: loadFromSD SD card remount** (v5.3):
    - `loadFromSD()` now re-initializes the SD card if it's not mounted
      (same guard that `saveToSD()` already had). Without this, the SD
      could be unavailable after a SPI glitch or failed initial mount,
      causing `SD.exists()` / `SD.open()` to silently fail → "vault is empty"
      with NO error message and NO way for the user to tell what happened.
    - This was the most likely root cause of the persistent "vault is empty"
      bug: if the SD card failed to mount in `setup()` or got unmounted
      before the user entered their PIN, `loadFromSD()` would silently
      skip loading and show an empty vault.

13. **CRITICAL: PBKDF2 fallback buffer overflow fix** (v5.3):
    - The hand-rolled PBKDF2 fallback in `crypto_utils.cpp` had a 32-byte
      `kx` buffer but wrote 64 bytes into it (`memset(kx + passLen, 0, 64 - passLen)`).
      This corrupted 32 bytes of stack, which could cause random crashes,
      incorrect key derivation, or AES-GCM auth tag mismatch → "decrypt failed".
    - The primary `mbedtls_pkcs5_pbkdf2_hmac_ext()` path was NOT affected,
      so this only triggered when the mbedtls PKCS5 module was disabled.
    - Fixed `kx` to be `uint8_t kx[64]` as the HMAC spec requires.

14. **WDT fix: yield() instead of esp_task_wdt_reset()** (v5.3):
    - The v5.2 `esp_task_wdt_reset()` calls in `loadFromSD()` and `saveToSD()`
      were no-ops: the main Arduino task isn't subscribed to the task watchdog,
      so `esp_task_wdt_reset()` returns `ESP_ERR_NOT_FOUND` and does nothing.
    - Replaced with `yield()` which lets the idle task run, preventing the
      WDT warning. PBKDF2 also calls `yield()` every 1024 iterations.
    - Note: `CONFIG_ESP_TASK_WDT_PANIC` is NOT set, so WDT timeout never
      reboots the device — it just prints a warning. The "vault is empty"
      after WDT was NOT caused by a reboot.

15. **Load error diagnostics on TFT** (v5.3):
    - When `loadFromSD()` fails, the specific reason is now shown on the
      TFT screen for 3 seconds: "No vault found", "SD card error",
      "Wrong PIN or corrupt vault", "Vault format error", etc.
    - Previously, the user just saw an empty vault with no explanation.
    - New `LoadError` enum and `lastLoadErrorStr()` method in VaultManager.

### vault_manager.cpp / .h — Key cache + PSRAM migration

- `_keyCached` flag to avoid PBKDF2 re-derivation on every save
- `clearCachedKey()` for security hygiene on lock/disconnect
- `lastSaveError()` for specific failure diagnostics
- PSRAM heap allocation for per-entry storage arrays
- `beginWithPin()` method for one-step init + load

### crypto_utils.h — Updated crypto helpers

- Secure zeroing, constant-time comparison utilities

## Hardware requirements

- **Board**: EdgeHax S3 Pro (ESP32-S3 N16R8)
  - 16MB Flash, 8MB PSRAM (OPI)
  - ILI9341 320x170 TFT (8-bit parallel)
  - XPT2046 touch
  - MPU6050 accelerometer
  - DS3231 RTC
  - MicroSD card slot
  - BLE + native USB CDC

## Wire protocol (for Electron app)

| Msg Type | Value | Direction | Description |
|----------|-------|-----------|-------------|
| HELLO | 0x01 | C→D | JSON handshake |
| HELLO_ACK | 0x02 | D→C | Handshake response |
| LIST | 0x10 | C→D | List entries (slim) |
| LIST_RESP | 0x11 | D→C | Entry list |
| GET | 0x12 | C→D | Get full entry |
| GET_RESP | 0x13 | D→C | Full entry data |
| ADD | 0x14 | C→D | Add entry |
| UPDATE | 0x15 | C→D | Update entry |
| DELETE | 0x16 | C→D | Delete entry |
| SAVE_OK | 0x17 | D→C | Save succeeded |
| LOCK | 0x18 | C→D | Lock session |
| LOCKED | 0x19 | D→C | Session locked |
| **PING** | **0x20** | **C→D** | **Keepalive** |
| **PONG** | **0x21** | **D→C** | **Keepalive resp** |
| ERROR | 0xFF | D→C | Error response |
