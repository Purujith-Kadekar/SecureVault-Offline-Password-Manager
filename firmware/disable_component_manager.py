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

# ---- Fix Windows [WinError 5] Access Denied during framework cleanup ----
# PlatformIO's safe_remove_directory_pattern tries to delete .git/objects
# in the framework package directory, which Windows blocks when another
# process (git daemon, antivirus, Arduino IDE) holds those pack files open.
# This is a well-known PlatformIO issue on Windows.
#
# The fix: monkey-patch PlatformIO's safe_remove to be non-fatal on Windows.
# Instead of crashing the build, it just skips directories it can't delete.
# The .git directories in framework packages are not needed for building —
# they're leftover from git-based package installation and get cleaned up
# on next successful run anyway.
if os.name == "nt":
    try:
        from platformio.fs import safe_remove_directory_pattern
        import shutil

        def _patched_safe_remove(directory, pattern):
            try:
                safe_remove_directory_pattern(directory, pattern)
            except (OSError, PermissionError):
                # Windows: .git pack files locked by another process.
                # Not fatal — just skip and continue building.
                pass

        # Monkey-patch the function in the module
        import platformio.fs as pio_fs
        pio_fs.safe_remove_directory_pattern = _patched_safe_remove
    except ImportError:
        pass  # Old PlatformIO version without this function — no fix needed
