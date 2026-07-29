cmake_minimum_required(VERSION 3.16.0)

# Excludes esp_lcd -- this project's display (Adafruit_ILI9341 over SPI,
# display_manager.cpp) has nothing to do with this component; esp_lcd is
# ESP-IDF's driver for the ESP32-S3's separate RGB-parallel LCD_CAM
# peripheral, which nothing here uses.
#
# This works around a confirmed, documented GCC toolchain bug (not a bug
# in this project or in ESP-IDF's actual logic): compiling
# esp_lcd/rgb/esp_lcd_panel_rgb.c crashes the Windows xtensa-esp32s3-elf
# GCC with "internal compiler error: Segmentation fault" during the "ira"
# (register allocation) RTL pass, on certain toolchain/Windows
# combinations -- see espressif/esp-idf#10568 and #12180 (still open,
# Windows-specific, GCC crashing on this one function). Espressif's own
# engineer (suda-morris) confirms in #12180 this isn't fixable from the
# project side, just worked around -- excluding the whole component
# (since it's unused here anyway) is the same fix others confirm working
# in that same thread.
set(EXCLUDE_COMPONENTS esp_lcd)

# Tell ESP-IDF to also look in the project's components/ directory for
# vendored components (esp_tinyusb, tinyusb, esp_littlefs). Use
# list(APPEND) NOT set() — PlatformIO's dual-framework mode sets
# EXTRA_COMPONENT_DIRS itself to include the Arduino core framework
# path. Using set() overwrites that and the Arduino core disappears,
# causing "Couldn't find the main target of the project!" (no app_main).
#
# FIX for "Failed to resolve component 'esp_tinyusb'" on Windows:
# PlatformIO's pioarduino dual-framework integration may copy/ symlink
# this CMakeLists.txt to the build directory where CMAKE_CURRENT_LIST_DIR
# no longer resolves to the project source directory (components/ doesn't
# exist in the build dir). PlatformIO sets PROJECT_DIR as a cmake cache
# variable (-DPROJECT_DIR=<source_dir>) that reliably points to the
# project source root regardless of build directory layout. Use it as
# the primary path, falling back to CMAKE_CURRENT_LIST_DIR for direct
# ESP-IDF builds (idf.py build) where no PlatformIO wrapper exists.
if(PROJECT_DIR)
    list(APPEND EXTRA_COMPONENT_DIRS "${PROJECT_DIR}/components")
    message(STATUS "EXTRA_COMPONENT_DIRS: using PROJECT_DIR = ${PROJECT_DIR}")
else()
    list(APPEND EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/components")
    message(STATUS "EXTRA_COMPONENT_DIRS: using CMAKE_CURRENT_LIST_DIR = ${CMAKE_CURRENT_LIST_DIR}")
endif()

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(SecureVault-master)
