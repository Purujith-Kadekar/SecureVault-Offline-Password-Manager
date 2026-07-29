#pragma once
// CryptoBuffer — unified memory allocator for SecureVault.
// Enforces DMA-safe allocation for crypto operations by API design.
//
// ESP32-S3 AES-GCM hardware engine uses DMA, which requires:
//   - Buffer in internal SRAM (not PSRAM — DMA can't reach SPIRAM)
//   - 4-byte aligned (MALLOC_CAP_DMA guarantees this)
//   - NOT allocated with new/malloc (which may land in PSRAM for >16KB)
//
// Rule: If a buffer will be passed to aesGcmEncrypt/Decrypt or any
// mbedtls crypto function, use cryptoAlloc(). If it's a large non-crypto
// buffer (e.g., JSON scratch, UI strings), use largeAlloc() for PSRAM.
//
// All cryptoAlloc'd buffers must be freed with cryptoFree().
// All largeAlloc'd buffers must be freed with largeFree().
//
// Author: Purujith Kadekar

#include <esp_heap_caps.h>
#include <Arduino.h>

// Allocate a DMA-safe buffer in internal SRAM for crypto operations.
// Returns nullptr on failure. Guaranteed to be:
//   - In internal SRAM (not PSRAM)
//   - 4-byte aligned (DMA requirement)
//   - Safe for ESP32-S3 AES-GCM hardware engine
inline void* cryptoAlloc(size_t size) {
  void* p = heap_caps_malloc(size, MALLOC_CAP_DMA | MALLOC_CAP_INTERNAL);
  if (!p) {
    Serial.printf("[CryptoBuffer] DMA alloc failed for %u bytes (internal SRAM exhausted)\n", (unsigned)size);
  }
  return p;
}

// Free a cryptoAlloc'd buffer.
inline void cryptoFree(void* ptr) {
  if (ptr) heap_caps_free(ptr);
}

// Allocate a large buffer in PSRAM for non-crypto use (JSON, UI, etc).
// PSRAM has 8MB but DMA can't reach it. DO NOT use for crypto buffers.
// Returns nullptr on failure.
inline void* largeAlloc(size_t size) {
  // Try PSRAM first, fall back to internal if size < threshold
  void* p = heap_caps_malloc(size, MALLOC_CAP_SPIRAM);
  if (!p) {
    // Fallback to internal SRAM for small allocations
    p = heap_caps_malloc(size, MALLOC_CAP_INTERNAL);
  }
  if (!p) {
    Serial.printf("[CryptoBuffer] PSRAM+internal alloc failed for %u bytes\n", (unsigned)size);
  }
  return p;
}

// Free a largeAlloc'd buffer.
inline void largeFree(void* ptr) {
  if (ptr) heap_caps_free(ptr);
}

// Convenience: typed crypto allocation. Returns nullptr on failure.
template<typename T>
T* cryptoAllocArray(size_t count) {
  return static_cast<T*>(cryptoAlloc(count * sizeof(T)));
}

// Convenience: typed large allocation. Returns nullptr on failure.
template<typename T>
T* largeAllocArray(size_t count) {
  return static_cast<T*>(largeAlloc(count * sizeof(T)));
}
