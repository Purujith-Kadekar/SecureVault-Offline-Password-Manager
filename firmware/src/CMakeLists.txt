# Overrides PlatformIO's auto-generated component registration for src/.
#
# WHY THIS FILE EXISTS: PlatformIO's dual-framework mode
# (framework = arduino, espidf) auto-generates a CMakeLists.txt for src/
# when one isn't provided, registering it as an ESP-IDF component with a
# default REQUIRES list. That default list has no way of knowing this
# project needs `driver`+`esp_driver_i2s` (for driver/i2s_std.h, used by
# audio_manager.h and diagnostics.cpp), `nvs_flash`/
# `esp_event`/`esp_tinyusb` (for serial_protocol.cpp's raw USB-CDC calls),
# `esp_littlefs` (for LittleFS.h), `mbedtls` (for ECDH/AES-GCM), and
# `esp_hw_support` (for deep sleep).
#
# v5.4 AP MODE: added `esp_wifi` (for WiFi.mode(WIFI_AP)/softAP, used by
# ap_mode_manager.cpp), `esp_netif` (for the AP-side netif creation), and
# `esp_timer` (used by the AsyncTCP library internally). All are required
# because the AP-mode stack bypasses Arduino's WiFi.h wrapper for the
# softAP TX-power cap and reads esp_wifi_types.h directly.
#
# NOTE on mDNS: intentionally NOT added. In ESP-IDF 5.5.4, `mdns` is a
# managed component (not in core components/), and this project has
# IDF_COMPONENT_MANAGER=0 set (see disable_component_manager.py) because
# PlatformIO's framework-espidf package isn't a git checkout. We don't
# need mDNS anyway — the DNS hijack (DNSServer.start(53, "*", softAPIP))
# makes every hostname resolve to 192.168.4.1, so the user can type
# "192.168.4.1" OR "securevault.local" OR any hostname — they all work.
file(GLOB APP_SOURCES ${CMAKE_CURRENT_LIST_DIR}/*.cpp)

idf_component_register(
    SRCS ${APP_SOURCES}
    INCLUDE_DIRS "../include"
    REQUIRES
        driver
        esp_driver_i2s
        nvs_flash
        esp_event
        esp_tinyusb
        esp_littlefs
        mbedtls
        esp_hw_support
        esp_wifi
        esp_netif
        esp_timer
)
