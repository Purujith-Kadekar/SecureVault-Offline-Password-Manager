// ═══════════════════════════════════════════════════════════════════════════════
//  traffic_obfuscation_manager.cpp — Layer 5: Traffic Obfuscation
// ═══════════════════════════════════════════════════════════════════════════════
#include "traffic_obfuscation_manager.h"

TrafficObfuscationManager& TrafficObfuscationManager::getInstance() {
  static TrafficObfuscationManager instance;
  // F8: auto-initialize with warning if getInstance() called before begin()
  if (!instance._initialized) {
    Serial.println("[F8-WARN] TrafficObfuscationManager::getInstance() called before begin() — auto-initializing");
    instance.begin();
  }
  return instance;
}

bool TrafficObfuscationManager::begin() {
  if (_initialized) return true;  // idempotent
  _lastDecoyTraffic = millis();
  _decoyInterval = 20000UL + (esp_random() % 40000UL);  // 20-60s
  _totalDecoyRequests = 0;
  _initialized = true;
  Serial.println("[F8] TrafficObfuscationManager::begin() — initialized");
  return true;
}

void TrafficObfuscationManager::end() {
  _lastDecoyTraffic = 0;
  _decoyInterval = 0;
  _totalDecoyRequests = 0;
}

void TrafficObfuscationManager::tick() {
  unsigned long now = millis();
  if (now - _lastDecoyTraffic >= _decoyInterval) {
    generateDecoyTraffic();
    _lastDecoyTraffic = now;
    _decoyInterval = 20000UL + (esp_random() % 40000UL);  // re-randomize
  }
}

void TrafficObfuscationManager::generateDecoyTraffic() {
  // Build a fake HTTP/1.1 GET packet. Mirrors SecureGen's format
  // exactly — same fingerprint to a passive sniffer.
  IPAddress dest = _randomLocalSubnetDest();
  const char* ua = _randomUserAgent();

  // 80% GET, 20% POST (matches SecureGen).
  bool isPost = (esp_random() % 5) == 0;

  // Use a static buffer (no heap fragmentation — see study_securegen_layers.md
  // note about SecureGen's static char packet[256]).
  static char packet[256];
  if (isPost) {
    snprintf(packet, sizeof(packet),
             "POST /api/status HTTP/1.1\r\n"
             "Host: %s\r\n"
             "User-Agent: %s\r\n"
             "Accept: application/json\r\n"
             "Content-Length: 0\r\n"
             "Connection: close\r\n"
             "\r\n",
             dest.toString().c_str(), ua);
  } else {
    snprintf(packet, sizeof(packet),
             "GET /api/status HTTP/1.1\r\n"
             "Host: %s\r\n"
             "User-Agent: %s\r\n"
             "Accept: application/json\r\n"
             "Connection: close\r\n"
             "\r\n",
             dest.toString().c_str(), ua);
  }

  // Send via UDP. Port 80 (HTTP) — same as SecureGen. The packet won't
  // be received by anything (no HTTP server on the random 192.168.4.x
  // address), but it generates wire traffic that a passive sniffer
  // can't distinguish from real HTTP.
  _udp.beginPacket(dest, 80);
  _udp.write((const uint8_t*)packet, strlen(packet));
  _udp.endPacket();

  _totalDecoyRequests++;
}

IPAddress TrafficObfuscationManager::_randomLocalSubnetDest() const {
  // In AP mode the device is 192.168.4.1 and clients are 192.168.4.2+.
  // Pick a random 192.168.4.x (2..254 — avoid .1 (us), .255 (broadcast),
  // and .0 (network)). 10% chance of broadcast for variety.
  uint8_t last = (uint8_t)(esp_random() % 253) + 2;  // 2..254
  if ((esp_random() % 10) == 0) last = 255;          // broadcast
  return IPAddress(192, 168, 4, last);
}

const char* TrafficObfuscationManager::_randomUserAgent() const {
  // Same 5 candidates as SecureGen — same fingerprint.
  static const char* UAS[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X)",
    "ESP32-Status-Checker/1.0"  // SecureGen's signature decoy UA
  };
  return UAS[esp_random() % 5];
}
