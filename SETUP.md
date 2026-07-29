# SecureVault — New-Machine Setup

Everything you need to compile + flash the firmware and run the companion apps on a **fresh machine**.

---

## 1. Firmware (PlatformIO + ESP-IDF)

### Install PlatformIO

```bash
pip install platformio
```

### First-time flash

```bash
cd firmware
pio run -t erase    # Erase flash (only needed on first flash or partition change)
pio run -t upload   # Build + flash
pio device monitor  # Serial output at 115200 baud
```

### Board configuration

The firmware is configured for the **EdgeHax ESP32-S3 S3-PRO (N16R8)**:

| Setting | Value |
|---|---|
| Board | ESP32-S3 (custom via `platformio.ini`) |
| Flash Size | **16MB (128Mb)** |
| PSRAM | **8MB OPI PSRAM** ← REQUIRED (canvas lives here) |
| Partition Scheme | Custom — see `partitions.csv` |
| USB Mode | USB-OTG (TinyUSB) |
| Framework | `arduino` + `espidf` (dual) |

All settings are in `platformio.ini` and `sdkconfig.defaults` — PlatformIO handles them automatically.

### Troubleshooting

| Symptom | Cause → Fix |
|---|---|
| `[WinError 5] Access is denied` on Windows | PlatformIO trying to delete `.git` files in its framework package — **close Arduino IDE, VS Code, git bash, and any serial monitor**, then retry. Or run `pio run` again (the error is usually non-fatal on second run). The `disable_component_manager.py` script includes a monkey-patch that skips locked directories on Windows. |
| `missing SConscript file 'disable_component_manager.py'` | The script must be in the **same directory as `platformio.ini`** (the firmware root) — make sure `disable_component_manager.py` is in `firmware/`, not in a subfolder |
| Build fails on `mbedtls/ecdh.h` not found | Run `pio run -t clean` then `pio run` — stale build cache |
| Black screen after flash | PSRAM not enabled → verify `sdkconfig.defaults` has `CONFIG_SPIRAM_MODE_OPI=y` |
| BLE doesn't pair | Make sure NimBLE is installed via `platformio.ini` lib_deps |
| USB HID not typing | Use a **data** USB cable, not a charging-only cable |
| AP Mode webapp won't load | Join the WiFi first, then open `http://192.168.4.1/` |

---

## 2. Electron Desktop App

### Prerequisites

- **Node.js** 18+ (LTS recommended)
- **npm** 9+

### Install & run

```bash
cd electron
npm install
npm start
```

The app auto-detects ESP32 serial ports. Make sure Dashboard Mode is active on the device (TFT shows 6-digit code) before clicking Connect.

### Build a packaged executable

```bash
# Install electron-builder
npm install --save-dev electron-builder

# Build for your platform
npx electron-builder --win    # Windows (.exe)
npx electron-builder --mac    # macOS (.dmg)
npx electron-builder --linux  # Linux (.AppImage)
```

Output goes to `electron/dist/`.

---

## 3. Chrome Extension

### Load unpacked

1. Open `chrome://extensions/`
2. Enable **Developer mode** (toggle in top-right)
3. Click **Load unpacked**
4. Select the `extension/` folder from this repo
5. The SecureVault icon appears in your toolbar

### Update after changes

Click the **Reload** button on the extension card in `chrome://extensions/`.

---

## 4. Web Flasher (self-flasher)

The `flasher/` directory contains a standalone HTML page that uses [ESP Web Tools](https://esphome.io/esp-web-tools/) to flash the firmware directly from a browser. No IDE, no command line — just USB + Chrome/Edge/Brave.

### Host the flasher

You can host `flasher/` on GitHub Pages:

1. Push this repo to GitHub
2. Go to Settings → Pages → Source: Deploy from branch → `main` → `/flasher`
3. The flasher page is live at `https://github.com/Purujith-Kadekar/SecureVault-Offline-Password-Manager`

Or host it anywhere — it's a static HTML page with no server-side dependencies.

### Add firmware binaries

Place the compiled `.bin` files in `flasher/firmware/`:

```
flasher/firmware/
├── bootloader.bin        (offset 0x0)
├── partitions.bin        (offset 0x8000)
├── boot_app0.bin         (offset 0xe000)
└── firmware.bin           (offset 0x10000)
```

The `manifest.json` in `flasher/` maps each file to its flash offset.

---

## 5. Full CI build

The `.github/workflows/build.yml` compiles the firmware on every push/PR. It uses PlatformIO on an Ubuntu runner with pinned dependencies. If CI is red, your branch isn't ready to merge.

---

## Quick reference

| Command | What it does |
|---|---|
| `pio run -t upload` | Build + flash firmware |
| `pio run -t erase` | Erase entire flash (first-time or partition change) |
| `pio device monitor` | Open serial monitor (115200 baud) |
| `cd electron && npm start` | Launch Electron desktop app |
| Chrome → Load unpacked → `extension/` | Install Chrome extension |
