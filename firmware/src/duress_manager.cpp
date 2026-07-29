#include "duress_manager.h"
#include "crypto_utils.h"
#include <LittleFS.h>
#include <SD.h>
#include <nvs_flash.h>
#include <esp_random.h>
#include <ctype.h>
#include <string.h>

namespace {
  const char* DURESS_FILE = "/duress_pin.hash";
  // v10.9 FIX: Reduced from 25000 to VAULT_KDF_ITERATIONS (2000) to match
  // the real PIN's PBKDF2 iteration count. The previous 25000 iterations
  // created a ~2.5-second response time difference vs. the real PIN's ~0.3s
  // — a timing side-channel that defeats the entire duress feature. An
  // attacker watching the device's response latency can distinguish a
  // duress PIN entry from a real PIN entry. With the same iteration count,
  // both paths take ~0.3s, making them indistinguishable by timing.
  // The header comment explicitly states "Show the SAME success UI" —
  // that includes matching response time. 2000 iterations is already
  // sufficient for PIN verification (4-8 digit numeric PINs have very
  // small keyspaces; the PBKDF2 is primarily a delay + key derivation
  // mechanism, not a brute-force deterrent against offline attacks).
  const uint32_t PBKDF2_ITERATIONS = 2000;

  bool allDigits(const char* pin, int len) {
    for (int i = 0; i < len; i++) if (!isdigit((unsigned char)pin[i])) return false;
    return true;
  }
}

bool DuressManager::saveDuressPin(const char* pin, int expectedLen) {
  int len = strlen(pin);
  if (len != expectedLen) return false;
  if (!allDigits(pin, len)) return false;

  uint8_t salt[16];
  for (int i = 0; i < 16; i++) salt[i] = (uint8_t)esp_random();

  uint8_t hash[32];
  pbkdf2Sha256(pin, len, salt, sizeof(salt), PBKDF2_ITERATIONS, hash, sizeof(hash));

  File f = LittleFS.open(DURESS_FILE, "w");
  if (!f) { secureZero(hash, sizeof(hash)); return false; }

  uint8_t header[2] = { 0x01, 0x01 };
  size_t w1 = f.write(header, 2);
  size_t w2 = f.write(salt, sizeof(salt));
  size_t w3 = f.write(hash, sizeof(hash));
  f.close();
  secureZero(hash, sizeof(hash));

  if (w1 != 2 || w2 != sizeof(salt) || w3 != sizeof(hash)) {
    LittleFS.remove(DURESS_FILE); // don't leave a truncated/corrupt hash file behind
    return false;
  }
  return true;
}

bool DuressManager::verify(const char* pin, int expectedLen) const {
  int len = strlen(pin);
  if (len != expectedLen) return false;
  if (!allDigits(pin, len)) return false;
  if (!LittleFS.exists(DURESS_FILE)) return false;

  File f = LittleFS.open(DURESS_FILE, "r");
  if (!f || f.size() != 50) { if (f) f.close(); return false; }

  uint8_t buf[50];
  f.read(buf, 50);
  f.close();

  if (buf[0] != 0x01 || buf[1] != 0x01) { secureZero(buf, sizeof(buf)); return false; }

  uint8_t computed[32];
  pbkdf2Sha256(pin, len, buf + 2, 16, PBKDF2_ITERATIONS, computed, sizeof(computed));

  // Constant-time compare -- OR-accumulate the diff across every byte
  // instead of an early-exit memcmp, so how many leading bytes matched
  // can't be inferred from timing.
  uint8_t diff = 0;
  for (int i = 0; i < 32; i++) diff |= (buf[18 + i] ^ computed[i]);

  secureZero(buf, sizeof(buf));
  secureZero(computed, sizeof(computed));
  return diff == 0;
}

bool DuressManager::isConfigured() const {
  if (!LittleFS.exists(DURESS_FILE)) return false;
  File f = LittleFS.open(DURESS_FILE, "r");
  bool ok = f && f.size() == 50;
  if (f) f.close();
  return ok;
}

void DuressManager::wipe() {
  // Order matters: vault ciphertext first (the actual secret data),
  // then the duress hash itself (so a partially-completed wipe doesn't
  // leave a device that still thinks it has a configured duress PIN but
  // an already-gone vault), then BLE bonding data, then reboot.
  //
  // This is a straightforward delete-and-reboot, not a secure multi-pass
  // overwrite -- flash wear-leveling on both SD and the internal flash
  // means a "secure erase" at the filesystem layer can't actually
  // guarantee the underlying physical cells are overwritten anyway
  // (the FTL/wear-leveling controller decides that, not this code), so a
  // simple delete is the honest thing to attempt here rather than
  // security theater that doesn't hold up against a determined attacker
  // with direct flash-chip access.
  // NOTE: this used to say "/vault.bin", which is not the filename
  // vault_manager.cpp actually writes (/vault.db) -- that mismatch meant
  // a duress wipe was silently leaving the real encrypted vault on the
  // card untouched. Fixed to match vault_manager's DB_PATH/DB_TMP_PATH.
  SD.remove("/vault.db");
  SD.remove("/vault.db.tmp");
  LittleFS.remove(DURESS_FILE);
  LittleFS.remove("/device_key.bin"); // if/when the PBKDF2 device-key phase lands, this is where its encrypted key file will live

  nvs_flash_erase(); // wipes BLE bonding data and any other NVS-stored state
  nvs_flash_init();

  delay(100);
  esp_restart();
  while (true) {} // unreachable, satisfies [[noreturn]]
}
