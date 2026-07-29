Import("env")
import os

# Disables the ESP-IDF component manager before CMake configure runs.
#
# WHY: PlatformIO's framework-espidf package isn't a git checkout, so the
# component manager can't run `git describe` to determine the local IDF
# version. Every online dependency (espressif/esp_tinyusb, declared in
# src/idf_component.yml previously) then fails to resolve, because its
# manifest requires idf>=5.0 and the resolver sees idf's version as
# unknown -- producing repeated "WARNING: Component "idf" not found" and a
# final "no versions of idf match >=5.0" solver failure.
#
# This is a documented PlatformIO/ESP-IDF integration gap, not specific to
# this project or to dual-framework mode -- see
# platformio/platform-espressif32 issues #1238, #1633, and
# espressif/arduino-esp32 #10055 for the identical error under both
# `framework = espidf` alone and `framework = arduino, espidf`.
#
# FIX: disable the resolver entirely, and vendor esp_tinyusb + its own
# tinyusb dependency locally under components/ instead (PlatformIO
# auto-discovers anything there with no resolver involved). See
# components/README.md for what's vendored and why.
os.environ["IDF_COMPONENT_MANAGER"] = "0"
