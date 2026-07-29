#pragma once
// ═══════════════════════════════════════════════════════════════════════════════
//  qr_display.h — WiFi QR code rendering on the ILI9341 (Adafruit_GFX)
// ═══════════════════════════════════════════════════════════════════════════════
//  Uses the ricmoo/QRCode library (pure C encoder, no display deps) and
//  renders the QR matrix as black/white rectangles on the TFT.
//
//  WiFi QR format (per the WiFi Network config spec):
//    WIFI:S:<SSID>;T:<WPA|WEP|nopass>;P:<password>;H:<true|false>;;
//
//  For a SecureVault AP with SSID "SecureVault-XXXX" (16 chars) and an
//  8-char WPA2 password, the QR string is ~50 bytes. QR version 4
//  (33×33 modules) with ECC_MEDIUM holds 64 bytes in byte mode — fits
//  comfortably. At 3px per module, the QR is 99×99px.
// ═══════════════════════════════════════════════════════════════════════════════
#include <Arduino.h>
#include <Adafruit_ILI9341.h>

// Draw a WiFi QR code centered at (cx, cy).
// ssid:     the WiFi network name
// password: the WPA2 password
// maxPx:    maximum width/height in pixels (QR is auto-sized to fit)
//
// Returns the actual QR pixel size (side length), or 0 on failure.
int drawWiFiQR(Adafruit_ILI9341& tft, int cx, int cy, int maxPx,
               const char* ssid, const char* password);
