# Vendored components

Both of these are here because PlatformIO's ESP-IDF component manager
cannot resolve online dependencies under `framework-espidf` (see the
comment block in `platformio.ini` above `extra_scripts` for the full
explanation, and `disable_component_manager.py`). With the component
manager disabled, PlatformIO auto-discovers anything under `components/`
directly -- no manifest resolution involved.

## esp_tinyusb/

Espressif's USB-NCM/CDC/MSC wrapper around TinyUSB, needed by
`network_manager.cpp`'s raw `tinyusb_net`/`tinyusb_init` calls.

- Source: https://github.com/espressif/esp-usb, `device/esp_tinyusb/`
- `test_apps/`, `idf_component.yml`, `sbom.yml` stripped (not needed, and
  the manifest would be misleading since the manager is off)
- `CMakeLists.txt` is **unmodified upstream** -- it already has a real,
  working fallback for the component-manager-disabled case:
  ```cmake
  idf_build_get_property(idf_component_manager IDF_COMPONENT_MANAGER)
  if(NOT idf_component_manager)
      list(APPEND req tinyusb)
  endif()
  ```
  and correctly detects whether `tinyusb` is a local or managed component
  when wiring up `tusb_config.h`'s include path. Confirmed by reading the
  live file, not assumed.

## tinyusb/

Base TinyUSB stack. Source:
https://github.com/espressif/tinyusb (the fork the registry actually
packages "tinyusb" from -- confirmed by checking; the plain upstream
`hathach/tinyusb` has no ESP-IDF `idf_component_register` integration at
its root).

Only the sources actually needed for **device-mode USB-NCM** are built
(see `CMakeLists.txt` in this folder): core (`tusb.c`, `tusb_fifo.c`),
`usbd.c`, `ncm_device.c`, and the DWC2 port (`dcd_dwc2.c`,
`dwc2_common.c` -- DWC2 is ESP32-S3's USB-OTG peripheral, confirmed
against `src/portable/synopsys/dwc2/dwc2_esp32.h`, which lists the
ESP32-S2/S3 register base address and endpoint count explicitly). If HID
or CDC over raw TinyUSB is ever needed here too, add the relevant
`class/*/*.c` file to `srcs` and the matching `CFG_TUD_*` Kconfig option.

`CFG_TUD_NCM` / endpoint buffer sizes / etc. come from
`esp_tinyusb/include/tusb_config.h`, driven by `sdkconfig.defaults`
(`CONFIG_TINYUSB_NET_MODE_NCM=y`) -- not duplicated here.

## Resolved: Arduino core's USBCDC.cpp doesn't see this vendored TinyUSB

`usb_hid_manager.cpp` no longer exists in this project (native USB HID
was dropped -- see the `HidMode` comment in `include/ui_screens.h`), so
the duplicate-TinyUSB linker-collision risk that used to be documented
here is moot. But the same underlying gap surfaced a different way:
Arduino-ESP32's own core file `cores/esp32/USBCDC.cpp` is compiled
unconditionally as part of the Arduino core -- a separate, prebuilt
framework component whose own `CMakeLists.txt` has no `REQUIRES
esp_tinyusb`. Its body is gated by `#if CONFIG_TINYUSB_CDC_ENABLED`
(globally visible via `sdkconfig.h`), but everything *inside* that guard
(`CFG_TUD_CDC`, `TU_VERIFY`, `TUD_CDC_DESCRIPTOR`, etc.) comes from
`esp_tinyusb/include/tusb_config.h` -- a header only visible to
components that actually `REQUIRES esp_tinyusb` (like `src/`, via
`src/CMakeLists.txt`). Arduino core isn't one of them, so the guard
opens and immediately hits a wall of "not declared in this scope".

Since nothing in this app needs TinyUSB's CDC or HID class (NCM in
`network_manager.cpp` talks to `tinyusb_net.h` directly, never through
`USBCDC`/`USBHID`), the fix is to keep both off rather than try to wire
Arduino core into this vendoring: `sdkconfig.defaults` now sets
`CONFIG_TINYUSB_CDC_ENABLED=n` explicitly. That's a real symbol owned by
`components/esp_tinyusb/Kconfig` (confirmed by reading it directly), and
disabling it compiles `USBCDC.cpp`'s whole guarded body out to nothing --
no symbols referenced, no error. Serial-over-USB is unaffected: it runs
through the separate Hardware-CDC/JTAG peripheral (`HWCDC.cpp`), gated
only by `ARDUINO_USB_MODE=1` in `platformio.ini`, which never touched
TinyUSB at all.

The old hand-rolled `components/tinyusb/Kconfig.projbuild` (written
before the *real* `esp_tinyusb` above was vendored in full) redefined
`TINYUSB_CDC_ENABLED`/`TINYUSB_HID_ENABLED` a second time with different
defaults -- a genuine Kconfig symbol collision with the real
`esp_tinyusb/Kconfig`, and `TINYUSB_HID_ENABLED` wasn't even a symbol the
real `tusb_config.h` reads (it reads `TINYUSB_HID_COUNT`). That file has
been deleted; `components/tinyusb/CMakeLists.txt` never branched on it
anyway (its source list is static), so nothing else depended on it.

## Known version-mismatch patch

`esp_tinyusb/usb_descriptors.c` had two `TUD_CDC_NCM_DESCRIPTOR(...)` call
sites written against an older `tinyusb` API (9 args). The vendored
`tinyusb` (pulled from current `master` -- the exact version esp_tinyusb
2.2.1 was written against wasn't fetchable, see the risk notes in
`tinyusb/CMakeLists.txt`) has since added two trailing parameters
(`_ep_notif_interval`, `_capability`) to that macro. Patched both call
sites directly with `16, 0` (standard notification interval, no optional
NCM capabilities advertised) rather than hunting down and re-vendoring an
exact-matching older `tinyusb` tag. If a future esp_tinyusb update is
vendored, check whether this patch is still needed or whether the
upstream file has been fixed to match.
