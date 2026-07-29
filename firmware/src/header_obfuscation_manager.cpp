// ═══════════════════════════════════════════════════════════════════════════════
//  header_obfuscation_manager.cpp — Layer 6: Header Obfuscation
// ═══════════════════════════════════════════════════════════════════════════════
#include "header_obfuscation_manager.h"
#include <ArduinoJson.h>

const char* const HO_FAKE_HEADERS[HO_FAKE_HEADER_COUNT] = {
  "X-Browser-Engine",
  "X-Request-Time",
  "X-Client-Version",
  "X-Feature-Flags",
  "X-Session-State"
};

HeaderObfuscationManager& HeaderObfuscationManager::getInstance() {
  static HeaderObfuscationManager instance;
  // F8: auto-initialize with warning if getInstance() called before begin()
  if (!instance._initialized) {
    Serial.println("[F8-WARN] HeaderObfuscationManager::getInstance() called before begin() — auto-initializing");
    instance.begin();
  }
  return instance;
}

bool HeaderObfuscationManager::begin() {
  if (_initialized) return true;  // idempotent
  // No state to initialize — the mappings are compile-time constants.
  _initialized = true;
  Serial.println("[F8] HeaderObfuscationManager::begin() — initialized");
  return true;
}

void HeaderObfuscationManager::end() {
  // Nothing to clean up.
}

String HeaderObfuscationManager::getClientId(AsyncWebServerRequest* request) const {
  if (!request) return "";
  // Try real first, then obfuscated.
  String v = request->header(HO_REAL_CLIENT_ID_HEADER);
  if (v.length() > 0) return v;
  v = request->header(HO_OBF_CLIENT_ID_HEADER);
  return v;
}

bool HeaderObfuscationManager::isSecureRequest(AsyncWebServerRequest* request) const {
  if (!request) return false;
  if (request->header(HO_REAL_SECURE_REQUEST_HEADER).length() > 0) return true;
  if (request->header(HO_OBF_SECURE_REQUEST_HEADER).length() > 0) return true;
  return false;
}

String HeaderObfuscationManager::getFakeHeadersJSON() const {
  JsonDocument doc;
  JsonArray arr = doc.to<JsonArray>();
  for (int i = 0; i < HO_FAKE_HEADER_COUNT; i++) {
    arr.add(HO_FAKE_HEADERS[i]);
  }
  String out;
  serializeJson(doc, out);
  return out;
}
