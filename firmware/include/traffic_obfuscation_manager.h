#pragma once
// ═══════════════════════════════════════════════════════════════════════════════
//  traffic_obfuscation_manager.h — Layer 5: Traffic Obfuscation (Decoy)
// ═══════════════════════════════════════════════════════════════════════════════
//  Maps to SecureGen's TrafficObfuscationManager (security_model.md L7).
//
//  Purpose: emits fake HTTP-like UDP packets at randomized 15-60s
//  intervals to obscure the real traffic pattern. Defends against
//  timing analysis ("is the user actively editing the vault right now?").
//
//  ⚠️ Divergence from SecureGen (study_securegen_layers.md caveat #9):
//  SecureGen sends decoys to public DNS IPs (8.8.8.8, 1.1.1.1, 9.9.9.9).
//  In AP mode there's no internet uplink — those packets would be
//  dropped by the AP-side netif (no route to internet), generating
//  noise in AP logs and wasting battery for zero effect. Instead,
//  we send decoys to the local subnet broadcast (192.168.4.255) and
//  a few random 192.168.4.x addresses — same effect (traffic-pattern
//  obfuscation against a passive sniffer on the same AP), no
//  unreachable-destination waste.
//
//  The decoy packet shape mirrors SecureGen exactly (HTTP/1.1 GET
//  with a fake User-Agent picked from 5 candidates) so a passive
//  sniffer sees the same fingerprint.
//
//  Tick: called from APModeManager::tick() every loop iteration.
//  Internally rate-limits via lastDecoyTraffic + decoyInterval.
// ═══════════════════════════════════════════════════════════════════════════════
#include <Arduino.h>
#include <WiFiUdp.h>

class TrafficObfuscationManager {
public:
  static TrafficObfuscationManager& getInstance();

  // Picks a random decoyInterval (20-60s). Idempotent.
  // F8: Sets _initialized = true.
  bool begin();

  // Clears state. Does NOT close the UDP socket (caller's responsibility).
  void end();

  // F8: Check whether begin() has been called.
  bool isInitialized() const { return _initialized; }

  // Called every loop iteration. Fires a decoy packet if enough time
  // has elapsed since the last one.
  void tick();

  // Manually fire a decoy packet (used for testing).
  void generateDecoyTraffic();

  int getDecoyRequestCount() const { return _totalDecoyRequests; }

private:
  TrafficObfuscationManager() = default;
  TrafficObfuscationManager(const TrafficObfuscationManager&) = delete;
  TrafficObfuscationManager& operator=(const TrafficObfuscationManager&) = delete;

  // F8: Initialization tracking
  bool _initialized = false;

  unsigned long _lastDecoyTraffic = 0;
  unsigned long _decoyInterval = 30000;  // ms, re-randomized after each packet
  int _totalDecoyRequests = 0;
  WiFiUDP _udp;

  // Picks a random 192.168.4.x destination.
  IPAddress _randomLocalSubnetDest() const;
  // Picks a random User-Agent from the 5-candidate list.
  const char* _randomUserAgent() const;
};

inline TrafficObfuscationManager& trafficObf() { return TrafficObfuscationManager::getInstance(); }
