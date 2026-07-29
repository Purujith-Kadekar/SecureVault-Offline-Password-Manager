// ═══════════════════════════════════════════════════════════════════════════════
//  qr_display.cpp — WiFi QR code rendering on the ILI9341
// ═══════════════════════════════════════════════════════════════════════════════
#include "qr_display.h"
#include <qrcode.h>

int drawWiFiQR(Adafruit_ILI9341& tft, int cx, int cy, int maxPx,
               const char* ssid, const char* password) {
  if (!ssid || !password) return 0;

  // Build the WiFi QR string.
  // Format: WIFI:S:<SSID>;T:WPA;P:<password>;H:false;;
  String qrText = "WIFI:S:";
  qrText += ssid;
  qrText += ";T:WPA;P:";
  qrText += password;
  qrText += ";H:false;;";

  // Generate the QR code.
  // Version 4 (33×33 modules) with ECC_MEDIUM holds 64 bytes in byte
  // mode — enough for our ~50-byte WiFi QR string.
  const uint8_t QR_VERSION = 4;
  QRCode qrcode;
  uint8_t qrcodeData[qrcode_getBufferSize(QR_VERSION)];
  if (qrcode_initText(&qrcode, qrcodeData, QR_VERSION, ECC_MEDIUM,
                      qrText.c_str()) != 0) {
    return 0;  // QR generation failed (text too long for this version+EC)
  }

  // Calculate module size so the QR fits within maxPx.
  int moduleSize = maxPx / qrcode.size;
  if (moduleSize < 2) moduleSize = 2;  // minimum 2px per module for readability
  int qrPx = qrcode.size * moduleSize;

  // Top-left corner of the QR (centered at cx, cy).
  int startX = cx - qrPx / 2;
  int startY = cy - qrPx / 2;

  // Draw a white background with a 4px quiet zone (required by the QR spec
  // for reliable scanning — phones need the white border to detect the QR).
  int quietZone = 4;
  tft.fillRect(startX - quietZone, startY - quietZone,
               qrPx + 2 * quietZone, qrPx + 2 * quietZone, ILI9341_WHITE);

  // Draw the QR modules. Only draw black modules (white is the background).
  // This is ~5x faster than drawing both colors.
  for (int row = 0; row < qrcode.size; row++) {
    for (int col = 0; col < qrcode.size; col++) {
      if (qrcode_getModule(&qrcode, col, row)) {
        tft.fillRect(startX + col * moduleSize,
                     startY + row * moduleSize,
                     moduleSize, moduleSize, ILI9341_BLACK);
      }
    }
  }

  return qrPx;
}
