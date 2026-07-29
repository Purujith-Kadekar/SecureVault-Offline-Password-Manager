# Vendored base TinyUSB stack (from github.com/espressif/tinyusb, the fork
# ESP-IDF's component registry actually packages "tinyusb" from).
#
# WHY VENDORED INSTEAD OF PULLED FROM THE REGISTRY: the ESP-IDF component
# manager cannot determine the local IDF version under PlatformIO's
# framework-espidf package (no .git dir -> `git describe` fails), so any
# online dependency resolution -- including this one -- fails with
# "Component 'idf' not found" / "no versions of idf match >=5.0". See the
# comment in ../esp_tinyusb/CMakeLists.txt and the top-level platformio.ini
# for the disable_component_manager.py hook that this vendoring depends on.
#
# DEVICE-ONLY, NCM-ONLY: only sources actually needed for
# network_manager.cpp's USB-NCM adapter are built, to keep flash/build time
# down. If usb_hid_manager.cpp or ble_keyboard_manager.cpp ever need raw
# TinyUSB HID class sources directly (they currently go through Arduino's
# own native-USB stack instead, not this component), add
# class/hid/hid_device.c to the srcs list below.

set(TUSB_ROOT "${CMAKE_CURRENT_LIST_DIR}/src")

set(srcs
    "${TUSB_ROOT}/tusb.c"
    "${TUSB_ROOT}/common/tusb_fifo.c"
    "${TUSB_ROOT}/device/usbd.c"
    "${TUSB_ROOT}/class/net/ncm_device.c"
    # DWC2 is the USB-OTG peripheral on ESP32-S3 (confirmed against
    # src/portable/synopsys/dwc2/dwc2_esp32.h, which lists ESP32-S2/S3
    # register offsets explicitly)
    "${TUSB_ROOT}/portable/synopsys/dwc2/dcd_dwc2.c"
    "${TUSB_ROOT}/portable/synopsys/dwc2/dwc2_common.c"
    )

idf_component_register(
    SRCS ${srcs}
    INCLUDE_DIRS "${TUSB_ROOT}" "${TUSB_ROOT}/.."
    PRIV_REQUIRES driver esp_hw_support freertos esp_timer
    REQUIRES esp_common
)

# CFG_TUSB_MCU has no auto-detection in tusb_option.h (confirmed by reading
# it directly) -- it must be supplied externally. tusb_config.h in
# ../esp_tinyusb/include already sets CFG_TUSB_OS, so only MCU is added
# here to avoid a duplicate-macro warning.
target_compile_definitions(${COMPONENT_LIB} PUBLIC
    CFG_TUSB_MCU=OPT_MCU_ESP32S3
)

# NOTE: tusb_config.h itself (which defines CFG_TUD_NCM, endpoint counts,
# etc.) is injected into this component's include path by
# ../esp_tinyusb/CMakeLists.txt, via a COMPONENT_LIB property lookup at the
# bottom of that file -- not from here. That's the existing, unmodified
# upstream mechanism; see the last few lines of that file.
