#include "totp_generator.h"
#include "crypto_utils.h"
#include <string.h>
#include <mbedtls/md.h>

static size_t base32Decode(const char* enc, uint8_t* out, size_t maxOut) {
  const char* alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  size_t bits = 0, idx = 0;
  uint32_t buf = 0;
  for (size_t i = 0; i < strlen(enc); i++) {
    if (idx >= maxOut) break; // never write past the caller's buffer, no matter
                              // how long a TOTP secret ends up being handed in
    char c = toupper(enc[i]);
    if (c == '=') break;
    const char* p = strchr(alpha, c);
    if (!p) continue;
    buf = (buf << 5) | (p - alpha);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out[idx++] = (buf >> bits) & 0xFF;
    }
  }
  return idx;
}

static void hmacSha1(const uint8_t* key, size_t kl, const uint8_t* data, size_t dl, uint8_t* out) {
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), 1);
  mbedtls_md_hmac_starts(&ctx, key, kl);
  mbedtls_md_hmac_update(&ctx, data, dl);
  mbedtls_md_hmac_finish(&ctx, out);
  mbedtls_md_free(&ctx);
}

static uint32_t truncateTotp(const uint8_t* h) {
  uint32_t off = h[19] & 0x0F;
  return (((h[off] & 0x7F) << 24) | ((h[off + 1] & 0xFF) << 16) |
          ((h[off + 2] & 0xFF) << 8) | (h[off + 3] & 0xFF)) % 1000000;
}

void TotpGenerator::generate(const char* base32Secret, uint32_t epoch, char* out) {
  uint8_t key[32], tb[8], hm[20];
  size_t kl = base32Decode(base32Secret, key, sizeof(key));
  uint32_t ts = epoch / 30;  // RFC 6238 30-second time step
  for (int i = 7; i >= 0; i--) { tb[i] = ts & 0xFF; ts >>= 8; }
  hmacSha1(key, kl, tb, 8, hm);
  sprintf(out, "%06lu", (unsigned long)truncateTotp(hm));
  secureZero(key, 32);
}