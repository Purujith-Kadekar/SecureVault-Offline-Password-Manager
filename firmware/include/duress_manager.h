#pragma once
// ═══════════════════════════════════════════════════════════════════════════════
//  duress_manager.h — duress PIN detection + silent wipe
// ═══════════════════════════════════════════════════════════════════════════════
// Ported from SecureGen's crypto_manager.cpp (saveDuressPin/verifyDuressPin),
// adapted to this project's LittleFS layout and crypto_utils primitives
// rather than copied wholesale -- SecureGen used mbedtls_pkcs5_pbkdf2_hmac
// directly; this uses the hand-rolled pbkdf2Sha256() in crypto_utils
// instead, for the same MBEDTLS_PKCS5_C-may-not-be-enabled reason
// hkdfSha256() already avoids mbedtls_hkdf().
//
// File format on LittleFS (`/duress_pin.hash`, 50 bytes), same layout as
// the source project:
//   [0x01 version][0x01/0x00 enabled][salt:16][pbkdf2_hash:32]
//
// USAGE: on every lock-screen PIN entry, check verify() BEFORE (or
// alongside) the real vault PIN check. On a match:
//   1. Show the SAME success UI as a real unlock ("PIN OK" / proceed to
//      Vault screen) -- this is the entire point of a duress PIN. Do NOT
//      show any different screen, error, or delay that could tip off
//      someone watching that anything unusual happened.
//   2. Call wipe() -- silently, after the UI has already moved on.
//
// wipe() is destructive and irreversible by design. It is NOT a
// reversible "lock" -- it deletes the vault and reboots to a clean
// state. There is no undo.
#include <Arduino.h>

class DuressManager {
public:
  // Provisions a duress PIN. Requires `pin` to be all-digit and match the
  // same length as the real vault PIN (SecureGen enforces this so the two
  // PINs are indistinguishable by length alone at entry time -- an
  // observer counting keypad taps shouldn't be able to tell which kind
  // of PIN is being entered). Returns false on invalid input or a write
  // failure.
  bool saveDuressPin(const char* pin, int expectedLen);

  // Returns true if `pin` matches the stored duress PIN. Constant-time
  // comparison (branchless OR-accumulate over the full hash) so a
  // timing side-channel can't be used to distinguish "wrong PIN" from
  // "duress PIN entered" or narrow down which bytes matched.
  bool verify(const char* pin, int expectedLen) const;

  bool isConfigured() const;

  // Zeroes the vault (/vault.db on SD), the encrypted settings on
  // LittleFS, and BLE bonding data in NVS, then reboots. Called AFTER
  // the UI has already shown a normal "unlock succeeded" response --
  // see the usage note above. This function does not return.
  [[noreturn]] void wipe();
};
