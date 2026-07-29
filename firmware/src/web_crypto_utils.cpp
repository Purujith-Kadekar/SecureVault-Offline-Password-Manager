// ═══════════════════════════════════════════════════════════════════════════════
//  web_crypto_utils.cpp — implementation of the AP-mode web crypto helpers
// ═══════════════════════════════════════════════════════════════════════════════
#include "web_crypto_utils.h"
#include <mbedtls/base64.h>
#include <mbedtls/sha256.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <esp_mac.h>
#include <esp_flash.h>
#include <esp_chip_info.h>
#include <cstring>

// ── Base64 ────────────────────────────────────────────────────────────
size_t base64Encode(const uint8_t* in, size_t len, char* out, size_t outCap) {
  if (!in || !out || len == 0) return 0;
  size_t needed = 4 * ((len + 2) / 3) + 1;  // +1 for null
  if (outCap < needed) return 0;
  size_t written = 0;
  if (mbedtls_base64_encode((unsigned char*)out, outCap, &written,
                            in, len) != 0) {
    return 0;
  }
  out[written] = '\0';
  return written;
}

bool base64Decode(const char* in, size_t inLen, uint8_t* out, size_t outCap, size_t* outLen) {
  if (!in || !out || !outLen) return false;
  if (inLen == 0) { *outLen = 0; return true; }
  size_t written = 0;
  if (mbedtls_base64_decode(out, outCap, &written,
                            (const unsigned char*)in, inLen) != 0) {
    return false;
  }
  *outLen = written;
  return true;
}

String base64EncodeStr(const uint8_t* in, size_t len) {
  if (!in || len == 0) return String();
  size_t needed = 4 * ((len + 2) / 3) + 1;
  char* buf = (char*)malloc(needed);
  if (!buf) return String();
  size_t written = base64Encode(in, len, buf, needed);
  String s(buf, written);
  free(buf);
  return s;
}

String base64DecodeStr(const String& in) {
  if (in.length() == 0) return String();
  size_t cap = in.length();  // decoded is always shorter
  uint8_t* buf = (uint8_t*)malloc(cap + 1);
  if (!buf) return String();
  size_t outLen = 0;
  if (!base64Decode(in.c_str(), in.length(), buf, cap, &outLen)) {
    free(buf);
    return String();
  }
  String s((const char*)buf, outLen);
  free(buf);
  return s;
}

// ── SHA-256 ───────────────────────────────────────────────────────────
void sha256(const uint8_t* data, size_t len, uint8_t out32[32]) {
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);  // 0 = SHA-256 (not SHA-224)
  mbedtls_sha256_update(&ctx, data, len);
  mbedtls_sha256_finish(&ctx, out32);
  mbedtls_sha256_free(&ctx);
}

void sha256Hex(const uint8_t* data, size_t len, char out65[65]) {
  uint8_t digest[32];
  sha256(data, len, digest);
  hexEncode(digest, 32, out65);
  out65[64] = '\0';
}

// ── HKDF-SHA256 (RFC 5869) ────────────────────────────────────────────
bool hkdfSha256(const uint8_t* ikm, size_t ikmLen,
                const uint8_t* salt, size_t saltLen,
                const uint8_t* info, size_t infoLen,
                uint8_t* out, size_t outLen) {
  // mbedtls_hkdf expects a non-NULL salt (uses zeros if length is 0).
  uint8_t zeroSalt[32] = {0};
  const uint8_t* saltPtr = salt;
  size_t saltSz = saltLen;
  if (!saltPtr || saltSz == 0) {
    saltPtr = zeroSalt;
    saltSz = 32;  // HKDF recommends salt size = hash output size
  }
  const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (!md) return false;
  int rc = mbedtls_hkdf(md, saltPtr, saltSz, ikm, ikmLen,
                        info, infoLen, out, outLen);
  return rc == 0;
}

// ── HMAC-SHA256 ───────────────────────────────────────────────────────
void hmacSha256(const uint8_t* key, size_t keyLen,
                const uint8_t* msg, size_t msgLen,
                uint8_t out32[32]) {
  const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  mbedtls_md_hmac(md, key, keyLen, msg, msgLen, out32);
}

// ── Device key derivation ────────────────────────────────────────────
// Mirrors SecureGen's DeviceStaticKey — SHA-256 of chip MAC + flash
// identifiers + a static domain-separation string. NOT a secret — see
// the header docstring — but provides defense-in-depth.
bool deriveDeviceStaticKey(uint8_t key32[32]) {
  uint8_t mac[6] = {0};
  esp_read_mac(mac, ESP_MAC_WIFI_SOFTAP);  // softAP MAC is what clients see

  esp_chip_info_t chip;
  esp_chip_info(&chip);

  uint32_t flashSize = 0;
  uint32_t flashSpeed = 0;
  esp_flash_get_size(NULL, &flashSize);
  // esp_flash_get_io_mode could be added; we keep it minimal to match
  // SecureGen's actual surface (which only reads mode/size/speed via
  // ESP.getFlashChipMode() etc. — not all available chip metadata).

  // Domain separation: prevents the same device fingerprint from being
  // reused across projects that use the same derivation scheme.
  static const char DOMAIN[] = "SecureVault-AP-v1-DeviceStaticKey-2026";

  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);
  mbedtls_sha256_update(&ctx, mac, 6);
  mbedtls_sha256_update(&ctx, (const uint8_t*)&chip, sizeof(chip));
  mbedtls_sha256_update(&ctx, (const uint8_t*)&flashSize, sizeof(flashSize));
  mbedtls_sha256_update(&ctx, (const uint8_t*)&flashSpeed, sizeof(flashSpeed));
  mbedtls_sha256_update(&ctx, (const uint8_t*)DOMAIN, sizeof(DOMAIN) - 1);
  mbedtls_sha256_finish(&ctx, key32);
  mbedtls_sha256_free(&ctx);
  return true;
}

// ── Constant-time comparison ─────────────────────────────────────────
bool constantTimeEquals(const uint8_t* a, const uint8_t* b, size_t len) {
  if (!a || !b) return false;
  volatile uint8_t diff = 0;
  for (size_t i = 0; i < len; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

// ── Hex encode/decode ────────────────────────────────────────────────
void hexEncode(const uint8_t* in, size_t len, char* out) {
  // NOTE: Arduino's Print.h #defines HEX as 16, so we use a different
  // local name to avoid the macro collision.
  static const char HEX_CHARS[] = "0123456789abcdef";
  for (size_t i = 0; i < len; i++) {
    out[2 * i]     = HEX_CHARS[(in[i] >> 4) & 0x0F];
    out[2 * i + 1] = HEX_CHARS[in[i] & 0x0F];
  }
  out[2 * len] = '\0';
}

int hexDecode(const char* in, size_t inLen, uint8_t* out, size_t outCap) {
  if (inLen % 2 != 0) return -1;
  size_t n = inLen / 2;
  if (n > outCap) return -1;
  auto hexVal = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  for (size_t i = 0; i < n; i++) {
    int hi = hexVal(in[2 * i]);
    int lo = hexVal(in[2 * i + 1]);
    if (hi < 0 || lo < 0) return -1;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return (int)n;
}

// ── Random hex string ────────────────────────────────────────────────
void randomHex(size_t bytes, char* out) {
  uint8_t* buf = (uint8_t*)malloc(bytes);
  if (!buf) { out[0] = '\0'; return; }
  secureRandom(buf, bytes);
  hexEncode(buf, bytes, out);
  secureZero(buf, bytes);
  free(buf);
}
