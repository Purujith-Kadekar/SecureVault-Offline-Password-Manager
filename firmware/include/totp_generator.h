#pragma once
// ═══════════════════════════════════════════════════════════════════════════════
//  totp_generator.h — RFC 6238 TOTP code generation
// ═══════════════════════════════════════════════════════════════════════════════
#include <Arduino.h>

class TotpGenerator {
public:
  // Generates a 6-digit TOTP code from a base32-encoded secret and a
  // unix-epoch timestamp. Writes 6 digits + NUL into out (min 7 bytes).
  static void generate(const char* base32Secret, uint32_t epoch, char* out);
};